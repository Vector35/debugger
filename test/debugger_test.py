#!/usr/bin/env python3
#
# unit tests for debugger

import os
import sys
import time
import platform
import shutil
import threading
import subprocess
import tempfile
import unittest

from binaryninja import load, Settings
from binaryninja.enums import SettingsScope
try:
    from debugger import DebuggerController, DebugStopReason, DebugBreakpointType
except:
    from binaryninja.debugger import DebuggerController, DebugStopReason, DebugBreakpointType

# 'helloworld' -> '{BN_SOURCE_ROOT}\public\debugger\test\binaries\Windows-x64\helloworld.exe' (windows)
# 'helloworld' -> '{BN_SOURCE_ROOT}/public/debugger/test/binaries/Darwin/arm64/helloworld' (linux, macOS)
def name_to_fpath(testbin, arch=None, os_str=None):
    if arch is None:
        arch = platform.machine()

    if os_str is None:
        os_str = platform.system()

    if os_str == 'Windows' and not testbin.endswith('.exe'):
        testbin += '.exe'

    signed = ''
    if os_str == 'Darwin':
        signed = '-signed'

    base_path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.realpath(os.path.join(base_path, 'binaries', f'{os_str}-{arch}{signed}', testbin))
    return path


def shared_lib_filename():
    os_str = platform.system()
    if os_str == 'Darwin':
        return 'shared_lib.dylib'
    elif os_str == 'Windows':
        return 'shared_lib.dll'
    else:
        return 'shared_lib.so'


def is_wow64(fpath):
    if 'x86' not in fpath:
        return False
    a, b = platform.architecture()
    return a == '64bit' and b.startswith('Windows')


def can_attach_to_unrelated_process():
    """Attaching to a process that is not a descendant needs root, or a Yama scope of 0 (or no Yama)"""
    if os.name != 'posix':
        return False
    if os.geteuid() == 0:
        return True
    try:
        with open('/proc/sys/kernel/yama/ptrace_scope') as f:
            return f.read().strip() == '0'
    except OSError:
        return True


def sleep_and_go(dbg):
    return dbg.go_and_wait()


def sleep_and_step_into(dbg):
    return dbg.step_into_and_wait()


class DebuggerAPI(unittest.TestCase):
    # Always skip the base class so it will never be executed
    @unittest.skip("do not run the base test class")
    def setUp(self) -> None:
        self.arch = ''
        self.adapter_type = None  # None means use default adapter

    def create_debugger(self, bv):
        """Helper to create debugger with the correct adapter type"""
        dbg = DebuggerController(bv)
        if self.adapter_type:
            dbg.adapter_type = self.adapter_type
        return dbg

    def test_repeated_use(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)

        def run_once():
            dbg = self.create_debugger(bv)
            dbg.cmd_line = 'foobar'
            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

            # continue execution to the entry point, and check the stop reason
            reason = sleep_and_step_into(dbg)
            self.assertEqual(reason, DebugStopReason.SingleStep)
            reason = sleep_and_step_into(dbg)
            self.assertEqual(reason, DebugStopReason.SingleStep)
            reason = sleep_and_step_into(dbg)
            self.assertEqual(reason, DebugStopReason.SingleStep)
            # go until executing done
            reason = sleep_and_go(dbg)
            self.assertEqual(reason, DebugStopReason.ProcessExited)

        # Do the same thing for 10 times
        n = 10
        for i in range(n):
            run_once()

    def test_debug_shared_library(self):
        # Analyze a shared library, but point the executable path at the program that loads it.
        # The debugger must launch the loader, not try to exec the library directly (which on macOS
        # made dyld fall back to launching /bin/sh, failing under SIP).
        # See https://github.com/Vector35/debugger/issues/540 and
        # https://github.com/Vector35/debugger/issues/1104
        lib_path = name_to_fpath(shared_lib_filename(), self.arch)
        exec_path = name_to_fpath('load_shared_lib', self.arch)
        if not (os.path.exists(lib_path) and os.path.exists(exec_path)):
            self.skipTest('shared library test binaries not built (configure with -DBUILD_DEBUGGER_TEST_BINARIES=ON)')
        bv = load(lib_path)
        dbg = self.create_debugger(bv)
        dbg.executable_path = exec_path

        # The program entry-point breakpoint comes from the analyzed library, which the loader never
        # hits, so stop at the system entry point instead to inspect the launched process.
        settings = Settings()
        previous = settings.get_bool('debugger.stopAtSystemEntryPoint')
        settings.set_bool('debugger.stopAtSystemEntryPoint', True)
        try:
            # The bug either failed to launch (InternalError, SIP enabled) or launched /bin/sh.
            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            module_names = [(m.name or '') for m in dbg.modules]
            # The loader executable must be the launched program, not the library or /bin/sh.
            self.assertTrue(any(os.path.realpath(exec_path) == os.path.realpath(name) for name in module_names),
                            f"loader executable not among launched modules: {module_names}")
            self.assertFalse(any('/bin/sh' in name for name in module_names),
                             f"debugger incorrectly launched /bin/sh: {module_names}")
            # Running to completion exercises loading the dependent library and calling into it; the
            # loader returns 0 only if the shared library was actually loaded and invoked.
            self.assertEqual(sleep_and_go(dbg), DebugStopReason.ProcessExited)
            self.assertEqual(dbg.exit_code, 0)
        finally:
            settings.set_bool('debugger.stopAtSystemEntryPoint', previous)
            if dbg.connected:
                dbg.quit_and_wait()

    def test_load_module_symbols(self):
        # Load symbols from the debugger backend on demand, then remove them, checking that the number
        # of symbols in the BinaryView increases when they are loaded and returns to the original value
        # when they are removed (i.e. nothing is left behind). See
        # https://github.com/Vector35/debugger/issues/210
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        try:
            self.assertGreater(len(dbg.modules), 0)
            # No backend symbols are loaded by default.
            self.assertEqual(len(dbg.modules_with_loaded_symbols), 0)

            def symbol_count():
                return len(dbg.data.get_symbols())

            before = symbol_count()
            # Track the feature's *own* data variables by address. Loading symbols defines a data variable
            # at each symbol address; pinning those down lets the removal check ignore data variables that
            # appear for reasons unrelated to this feature -- e.g. the null-pointer data variable at 0x0 that
            # stack-variable annotation creates, or reference-site variables that analysis materializes --
            # which otherwise make the global data-variable count an unstable, environment-dependent oracle.
            sym_addrs_before = {s.address for s in dbg.data.get_symbols()}
            data_var_addrs_before = {v.address for v in dbg.data.data_vars.values()}

            def describe(addrs):
                # Render an address set for an assertion failure message: each address with its data
                # variable type (if any) and the symbols defined there.
                lines = []
                for a in sorted(addrs):
                    dv = dbg.data.data_vars.get(a)
                    type_desc = repr(dv.type) if dv is not None else None
                    syms = [(s.type.name, s.name) for s in dbg.data.get_symbols(a, 1)]
                    lines.append(f"      {a:#x} type={type_desc} symbols={syms}")
                return "\n".join(lines)

            # We do not know up front which module the backend has symbols for, so try each one until a
            # module actually contributes symbols. Skip the main executable so the symbols are added into
            # otherwise-unannotated address space, making the add/remove counts unambiguous.
            main_path = os.path.realpath(fpath)
            loaded_module = None
            added = 0
            for m in dbg.modules:
                name = m.name or m.short_name
                if not name:
                    continue
                if os.path.realpath(name) == main_path:
                    continue
                count = dbg.load_symbols_for_module(name)
                if count > 0:
                    loaded_module = name
                    added = count
                    break

            if loaded_module is None:
                self.skipTest('no non-main module reported backend symbols for this adapter')

            self.assertGreater(added, 0)
            self.assertEqual(len(dbg.modules_with_loaded_symbols), 1)
            # The per-module count (surfaced in the Modules widget's Symbols column) matches what was added.
            self.assertEqual(dbg.loaded_symbol_count_for_module(loaded_module), added)

            # The addresses where this load introduced symbols. The feature defines one data variable per
            # symbol address; restrict to addresses that did not already have a data variable so the checks
            # below concern only what the feature itself created.
            loaded_addrs = {s.address for s in dbg.data.get_symbols()} - sym_addrs_before
            feature_dv_addrs = loaded_addrs - data_var_addrs_before
            self.assertGreater(len(feature_dv_addrs), 0)

            # Loading symbols increases the number of symbols in the BinaryView, and each gets a data
            # variable so it renders in the views.
            after_load = symbol_count()
            self.assertGreater(after_load, before)
            current_dv_addrs = {v.address for v in dbg.data.data_vars.values()}
            self.assertTrue(feature_dv_addrs.issubset(current_dv_addrs),
                            "loaded symbols did not all get a data variable:\n"
                            + describe(feature_dv_addrs - current_dv_addrs))

            # Removing the symbols must undefine every data variable the feature created, leaving nothing
            # behind. Data variables that exist for unrelated reasons (stack-variable annotation, analysis
            # reference sites, ...) are ignored by construction.
            removed = dbg.remove_symbols_for_module(loaded_module)
            self.assertEqual(removed, added)
            self.assertLess(symbol_count(), after_load)
            # Every symbol the feature added must be gone. As with data variables, check the feature's own
            # addresses rather than the global symbol count: that count drifts with symbols created for
            # unrelated reasons (analysis, stack-variable annotation) and with background analysis that is
            # still settling when the baseline is captured, which is stable on some platforms but not others.
            leaked_syms = {a for a in loaded_addrs if dbg.data.get_symbols(a, 1)}
            self.assertEqual(leaked_syms, set(),
                             "symbols the feature added were not removed:\n" + describe(leaked_syms))
            leaked = feature_dv_addrs & {v.address for v in dbg.data.data_vars.values()}
            self.assertEqual(leaked, set(),
                             "data variables the feature created were not removed:\n" + describe(leaked))
            self.assertEqual(len(dbg.modules_with_loaded_symbols), 0)
            self.assertEqual(dbg.loaded_symbol_count_for_module(loaded_module), 0)

            # Regression: a load/remove/load cycle must recreate the data variables. Removal undefines them
            # without blacklisting their addresses; if it blacklisted them, this re-load's auto data
            # variables would be suppressed and the reloaded symbols would not render in the linear view.
            self.assertGreater(dbg.load_symbols_for_module(loaded_module), 0)
            # A correct re-load recreates a data variable at each of the feature's addresses; the blacklist
            # bug would leave them undefined.
            reloaded_dv_addrs = {v.address for v in dbg.data.data_vars.values()}
            self.assertTrue(feature_dv_addrs.issubset(reloaded_dv_addrs),
                            "re-load did not recreate the feature's data variables:\n"
                            + describe(feature_dv_addrs - reloaded_dv_addrs))
            self.assertEqual(dbg.loaded_symbol_count_for_module(loaded_module), added)

            # Loading the same module twice must not register it twice or accumulate duplicate tracking.
            # This is checked via the debugger's own tracking rather than the BinaryView's global symbol
            # count: some backends (e.g. DbgEng) resolve a module's symbols lazily and may enumerate them
            # slightly differently across calls, so the global count is not a stable idempotency oracle.
            self.assertGreater(dbg.load_symbols_for_module(loaded_module), 0)
            self.assertEqual(len(dbg.modules_with_loaded_symbols), 1)
            self.assertGreater(dbg.remove_symbols_for_module(loaded_module), 0)
            self.assertEqual(len(dbg.modules_with_loaded_symbols), 0)
        finally:
            if dbg.connected:
                dbg.quit_and_wait()

    def test_return_code(self):
        # return code tests
        fpath = name_to_fpath('exitcode', self.arch)
        bv = load(fpath)

        # some systems return byte, or low byte of 32-bit code and others return 32-bit code
        testvals = [('-11', [245, 4294967285]),
                    ('-1', [4294967295, 255]),
                    ('-3', [4294967293, 253]),
                    ('0', [0]),
                    ('3', [3]),
                    ('7', [7]),
                    ('123', [123])]

        for arg, expected in testvals:
            dbg = self.create_debugger(bv)
            dbg.cmd_line = arg

            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            reason = sleep_and_go(dbg)
            self.assertEqual(reason, DebugStopReason.ProcessExited)
            exit_code = dbg.exit_code
            self.assertIn(exit_code, expected)

    def expect_segfault(self, reason):
        if platform.system() == 'Linux':
            self.assertEqual(reason, DebugStopReason.SignalSegv)
        else:
            self.assertEqual(reason, DebugStopReason.AccessViolation)

    def test_exception_segfault(self):
        fpath = name_to_fpath('do_exception', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)

        dbg.cmd_line = 'segfault'
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        # time.sleep(1)
        reason = sleep_and_go(dbg)
        self.expect_segfault(reason)
        dbg.quit_and_wait()

    # # This would not work until we fix the test binary
    # def test_exception_illegalinstr(self):
    #     fpath = name_to_fpath('do_exception', self.arch)
    #     bv = load(fpath)
    #     dbg = DebuggerController(bv)
    #     dbg.cmd_line = 'illegalinstr'
    #     self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
    #     dbg.go()
    #     reason = dbg.go()
    #     if platform.system() in ['Windows', 'Linux']:
    #         expected = DebugStopReason.AccessViolation
    #     else:
    #         expected = DebugStopReason.IllegalInstruction
    #
    #     self.assertEqual(reason, expected)
    #     dbg.quit_and_wait()

    def expect_divide_by_zero(self, reason):
        if platform.system() == 'Linux':
            self.assertEqual(reason, DebugStopReason.SignalFpe)
        else:
            self.assertEqual(reason, DebugStopReason.Calculation)

    def test_exception_divzero(self):
        fpath = name_to_fpath('do_exception', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        if not self.arch == 'arm64':
            dbg.cmd_line = 'divzero'
            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            reason = sleep_and_go(dbg)
            self.expect_divide_by_zero(reason)
            dbg.quit_and_wait()

    def test_step_into(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        dbg.cmd_line = 'foobar'
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        reason = sleep_and_step_into(dbg)
        self.assertEqual(reason, DebugStopReason.SingleStep)
        reason = sleep_and_step_into(dbg)
        self.assertEqual(reason, DebugStopReason.SingleStep)
        reason = sleep_and_go(dbg)
        self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_breakpoint(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        # TODO: right now we are not returning whether the operation succeeds, so we cannot use assertTrue/assertFalse
        # breakpoint set/clear should fail at 0
        self.assertIsNone(dbg.add_breakpoint(0))
        self.assertIsNone(dbg.delete_breakpoint(0))

        # breakpoint set/clear should succeed at entrypoint
        entry = dbg.data.entry_point
        self.assertIsNone(dbg.delete_breakpoint(entry))
        self.assertIsNone(dbg.add_breakpoint(entry))

        self.assertEqual(dbg.ip, entry)
        dbg.quit_and_wait()

    def test_remove_breakpoint_after_exit(self):
        """Removing a logical breakpoint after DbgEng teardown must not call the backend."""
        if self.adapter_type != 'DBGENG':
            self.skipTest('Regression is specific to DbgEng teardown')

        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertEqual(sleep_and_go(dbg), DebugStopReason.ProcessExited)

        entry = dbg.data.entry_point
        dbg.add_breakpoint(entry)
        self.assertTrue(any(bp.address == entry for bp in dbg.breakpoints))
        dbg.delete_breakpoint(entry)
        self.assertFalse(any(bp.address == entry for bp in dbg.breakpoints))

    def test_breakpoint_condition(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        entry = dbg.data.entry_point
        dbg.add_breakpoint(entry)

        arch_name = bv.arch.name
        if arch_name == 'x86':
            reg1, reg2 = '$eax', '$ebx'
        elif arch_name == 'x86_64':
            reg1, reg2 = '$rax', '$rbx'
        else:
            reg1, reg2 = '$x0', '$x1'

        cond1 = f"{reg1} == 0x1234"
        self.assertTrue(dbg.set_breakpoint_condition(entry, cond1))
        self.assertEqual(dbg.get_breakpoint_condition(entry), cond1)

        cond2 = f"{reg2} != 0"
        self.assertTrue(dbg.set_breakpoint_condition(entry, cond2))
        self.assertEqual(dbg.get_breakpoint_condition(entry), cond2)

        self.assertTrue(dbg.set_breakpoint_condition(entry, ""))
        self.assertEqual(dbg.get_breakpoint_condition(entry), "")

        self.assertFalse(dbg.set_breakpoint_condition(0x12345678, f"{reg1} == 0"))
        self.assertEqual(dbg.get_breakpoint_condition(0x12345678), "")
        dbg.quit_and_wait()

    def test_breakpoints_list_and_repr(self):
        """Test that dbg.breakpoints returns correctly and repr includes condition"""
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        entry = dbg.data.entry_point
        second_addr = entry + 4

        # Add breakpoint without condition
        dbg.add_breakpoint(entry)
        # Add breakpoint with condition
        dbg.add_breakpoint(second_addr)
        arch_name = bv.arch.name
        if arch_name == 'x86':
            reg = 'eax'
        elif arch_name == 'x86_64':
            reg = 'rax'
        else:
            reg = 'x0'
        condition = f"{reg} == 0x1234"
        self.assertTrue(dbg.set_breakpoint_condition(second_addr, condition))

        # Access dbg.breakpoints - this should not raise an error
        # (regression test for issue #953 where None condition caused AttributeError)
        breakpoints = dbg.breakpoints
        self.assertGreaterEqual(len(breakpoints), 2)

        # Test repr contains condition when set
        bp_repr = repr(breakpoints)
        self.assertIn(condition, bp_repr)

        # Test individual breakpoint repr
        for bp in breakpoints:
            bp_str = repr(bp)
            if bp.address == second_addr:
                self.assertIn("condition=", bp_str)
                self.assertIn(condition, bp_str)
            elif bp.address == entry:
                # Breakpoint without condition should not have condition in repr
                self.assertNotIn("condition=", bp_str)

        dbg.quit_and_wait()

    def test_hardware_breakpoint(self):
        """Test hardware breakpoint add and delete"""
        if platform.system() == 'Linux' and self.adapter_type != 'PTRACE':
            self.skipTest('Hardware breakpoints not yet supported on Linux')
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        entry = dbg.data.entry_point

        # Test adding hardware execution breakpoint
        self.assertTrue(dbg.add_hardware_breakpoint(entry, DebugBreakpointType.BNHardwareExecuteBreakpoint))

        # Test adding hardware write watchpoint at a different address
        # Note: Hardware data breakpoints must be aligned to their size on x86/x64
        # A 4-byte watchpoint must be at a 4-byte aligned address
        watch_addr = (entry + 0x100) & ~0x3  # Align to 4-byte boundary
        self.assertTrue(dbg.add_hardware_breakpoint(watch_addr, DebugBreakpointType.BNHardwareWriteBreakpoint, size=4))

        # Test deleting hardware breakpoints
        self.assertTrue(dbg.delete_hardware_breakpoint(entry, DebugBreakpointType.BNHardwareExecuteBreakpoint))
        self.assertTrue(dbg.delete_hardware_breakpoint(watch_addr, DebugBreakpointType.BNHardwareWriteBreakpoint, size=4))

        dbg.quit_and_wait()

    def test_register_read_write(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        arch_name = bv.arch.name
        if arch_name == 'x86':
            (xax, xbx) = ('eax', 'ebx')
            (testval_a, testval_b) = (0xDEADBEEF, 0xCAFEBABE)
        elif arch_name == 'x86_64':
            (xax, xbx) = ('rax', 'rbx')
            (testval_a, testval_b) = (0xAAAAAAAADEADBEEF, 0xBBBBBBBBCAFEBABE)
        else:
            (xax, xbx) = ('x0', 'x1')
            (testval_a, testval_b) = (0xAAAAAAAADEADBEEF, 0xBBBBBBBBCAFEBABE)

        rax = dbg.get_reg_value(xax)
        rbx = dbg.get_reg_value(xbx)

        dbg.set_reg_value(xax, testval_a)
        self.assertEqual(dbg.get_reg_value(xax), testval_a)
        dbg.set_reg_value(xbx, testval_b)
        self.assertEqual(dbg.get_reg_value(xbx), testval_b)

        dbg.set_reg_value(xax, rax)
        self.assertEqual(dbg.get_reg_value(xax), rax)
        dbg.set_reg_value(xbx, rbx)
        self.assertEqual(dbg.get_reg_value(xbx), rbx)

        dbg.quit_and_wait()

    def test_memory_read_write(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        # Due to https://github.com/Vector35/debugger/issues/124, we have to skip the bytes at the entry point
        addr = dbg.ip + 10
        data = dbg.read_memory(addr, 256)
        self.assertFalse(dbg.write_memory(0, b'heheHAHAherherHARHAR'), False)
        data2 = b'\xAA' * 256
        dbg.write_memory(addr, data2)

        self.assertEqual(len(dbg.read_memory(0, 256)), 0)
        self.assertEqual(dbg.read_memory(addr, 256), data2)
        dbg.write_memory(addr, data)
        self.assertEqual(dbg.read_memory(addr, 256), data)

        dbg.quit_and_wait()

    # @unittest.skip
    def test_thread(self):
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        dbg.go()
        time.sleep(1)
        dbg.pause_and_wait()

        # print('switching to bad thread')
        # self.assertFalse(dbg.thread_select(999))

        threads = dbg.threads
        self.assertGreater(len(threads), 1)

        dbg.go()
        time.sleep(1)
        dbg.pause_and_wait()

        threads = dbg.threads
        self.assertGreater(len(threads), 1)
        dbg.quit_and_wait()

    def test_go_and_wait_timeout(self):
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        try:
            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            reason = dbg.go_and_wait(5000)
            self.assertEqual(reason, DebugStopReason.TimedOut)
        finally:
            dbg.quit_and_wait()

    @unittest.skipIf(platform.system() == 'Windows', 'Skip restart test on Windows for now')
    def test_restart(self):
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        dbg.go()
        time.sleep(1)
        dbg.pause_and_wait()
        self.assertGreater(len(dbg.threads), 1)

        ret = dbg.restart_and_wait()
        self.assertNotIn(ret, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        dbg.go()
        time.sleep(1)
        ret = dbg.restart_and_wait()
        self.assertNotIn(ret, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        dbg.quit_and_wait()

    def test_assembly_code(self):
        if self.arch == 'x86_64':
            fpath = name_to_fpath('asmtest', 'x86_64')
            bv = load(fpath)
            dbg = self.create_debugger(bv)
            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            # Align the stack so the binary does not crash
            dbg.set_reg_value('rsp', dbg.get_reg_value('rsp') & 0xfffffffffffffff0)

            entry = dbg.data.entry_point
            self.assertEqual(dbg.ip, entry)

            # TODO: we can use BN to disassemble the binary and find out how long is the instruction
            # step into nop
            sleep_and_step_into(dbg)
            self.assertEqual(dbg.ip, entry+1)
            # step into call, return
            sleep_and_step_into(dbg)
            sleep_and_step_into(dbg)
            # back
            self.assertEqual(dbg.ip, entry+6)
            sleep_and_step_into(dbg)
            # step into call, return
            sleep_and_step_into(dbg)
            sleep_and_step_into(dbg)
            # back
            self.assertEqual(dbg.ip, entry+12)

            reason = sleep_and_go(dbg)
            self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_attach(self):
        if platform.system() == 'Linux' and not (self.adapter_type == 'PTRACE' and can_attach_to_unrelated_process()):
            self.skipTest('Cannot attach to pid unless running as root')
        from attach_test_runner import run_attach_test
        fpath = name_to_fpath('helloworld_loop', self.arch)
        worker = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'attach_test_runner.py')
        run_attach_test([fpath], lambda pid: [sys.executable, worker, fpath, str(pid),
                                            self.adapter_type or ''], timeout=60)


@unittest.skipUnless(platform.system() == 'Linux', 'GDB MI local launch is only supported on Linux')
class GdbMiLinuxTest(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'arm64' if platform.machine() in ['arm64', 'aarch64'] else platform.machine()
        self.adapter_type = 'GDB MI'

    def create_debugger(self, bv):
        dbg = super().create_debugger(bv)

        # Debugger settings are registered lazily when the first controller is
        # constructed, so configure them here rather than in setUp.
        if not hasattr(self, '_entry_settings_configured'):
            settings = Settings()
            previous_system_entry = settings.get_bool('debugger.stopAtSystemEntryPoint')
            previous_program_entry = settings.get_bool('debugger.stopAtEntryPoint')
            self.assertTrue(settings.set_bool('debugger.stopAtSystemEntryPoint', False))
            self.assertTrue(settings.set_bool('debugger.stopAtEntryPoint', True))
            self.addCleanup(settings.set_bool, 'debugger.stopAtEntryPoint', previous_program_entry)
            self.addCleanup(settings.set_bool, 'debugger.stopAtSystemEntryPoint', previous_system_entry)
            self._entry_settings_configured = True

        return dbg

    def test_local_launch_stops_at_stripped_pie_entry_point(self):
        gdb_path = shutil.which('gdb')
        strip_path = shutil.which('strip')
        if gdb_path is None:
            self.skipTest('gdb is not installed')
        if strip_path is None:
            self.skipTest('strip is not installed')

        source_path = name_to_fpath('helloworld_pie', self.arch)
        if not os.path.exists(source_path):
            self.skipTest('PIE test binary not built (configure with -DBUILD_DEBUGGER_TEST_BINARIES=ON)')

        with tempfile.TemporaryDirectory() as temp_dir:
            stripped_path = os.path.join(temp_dir, 'helloworld_pie_stripped')
            shutil.copy2(source_path, stripped_path)
            subprocess.run([strip_path, '--strip-all', stripped_path], check=True)

            bv = load(stripped_path)
            dbg = self.create_debugger(bv)
            dbg.executable_path = stripped_path
            dbg.set_adapter_property('gdb.path', gdb_path)

            try:
                reason = dbg.launch_and_wait(20000)
                self.assertEqual(reason, DebugStopReason.Breakpoint)

                remote_base = dbg.get_remote_base()
                self.assertIsNotNone(remote_base)
                expected_entry = remote_base + (bv.entry_point - bv.start)
                self.assertEqual(dbg.ip, expected_entry)
            finally:
                if dbg.connected:
                    dbg.quit_and_wait()


class PtraceAdapterTests:
    """The tests for what only the PTRACE adapter does. They come on top of the ones of DebuggerAPI."""

    def create_debugger(self, bv):
        dbg = super().create_debugger(bv)

        # Debugger settings are registered lazily when the first controller is constructed
        if not hasattr(self, '_entry_settings_configured'):
            settings = Settings()
            previous_system_entry = settings.get_bool('debugger.stopAtSystemEntryPoint')
            previous_program_entry = settings.get_bool('debugger.stopAtEntryPoint')
            self.assertTrue(settings.set_bool('debugger.stopAtSystemEntryPoint', False))
            self.assertTrue(settings.set_bool('debugger.stopAtEntryPoint', True))
            self.addCleanup(settings.set_bool, 'debugger.stopAtEntryPoint', previous_program_entry)
            self.addCleanup(settings.set_bool, 'debugger.stopAtSystemEntryPoint', previous_system_entry)
            self._entry_settings_configured = True

        return dbg

    def set_redirects(self, bv, redirects):
        # The settings of the adapter exist once the controller has created the adapter, which setting the path does
        settings = Settings('PtraceAdapterSettings')
        self.assertTrue(settings.contains('launch.redirectFileDescriptors'))
        self.assertTrue(settings.set_string_list('launch.redirectFileDescriptors', redirects, bv,
                                                 SettingsScope.SettingsResourceScope))

    def test_redirect_stdout(self):
        fpath = name_to_fpath('helloworld', self.arch)
        expected = subprocess.run([fpath], capture_output=True, timeout=30).stdout
        self.assertTrue(expected)

        bv = load(fpath)
        dbg = self.create_debugger(bv)
        dbg.executable_path = fpath
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = os.path.join(temp_dir, 'out.txt')
            self.set_redirects(bv, ['1>' + out_path])
            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            self.assertEqual(sleep_and_go(dbg), DebugStopReason.ProcessExited)
            with open(out_path, 'rb') as f:
                self.assertEqual(f.read(), expected)

    def test_redirect_stdin(self):
        fpath = name_to_fpath('cat', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        dbg.executable_path = fpath
        with tempfile.TemporaryDirectory() as temp_dir:
            in_path = os.path.join(temp_dir, 'in.txt')
            out_path = os.path.join(temp_dir, 'out.txt')
            with open(in_path, 'w') as f:
                f.write('read from a file\n')
            self.set_redirects(bv, ['0<' + in_path, '1>' + out_path])
            self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            self.assertEqual(sleep_and_go(dbg), DebugStopReason.ProcessExited)
            with open(out_path) as f:
                self.assertEqual(f.read(), 'read from a file\n')

    def test_redirect_bad_file(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        dbg.executable_path = fpath
        self.set_redirects(bv, ['0</nonexistent/directory/file'])
        self.assertIn(dbg.launch_and_wait(), [DebugStopReason.InternalError])

    def test_detach_lets_the_target_run(self):
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        pid = dbg.active_pid
        self.assertGreater(pid, 0)
        try:
            dbg.go()
            time.sleep(1)
            dbg.pause_and_wait()
            dbg.detach_and_wait()
            time.sleep(0.5)

            with open(f'/proc/{pid}/status') as f:
                state = [line for line in f if line.startswith('State:')][0].split()[1]
            # Not stopped by the tracing, and not a zombie either
            self.assertNotIn(state, ['t', 'T', 'Z'])
        finally:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass

    def wait_until_stopped(self, dbg, timeout=10):
        deadline = time.monotonic() + timeout
        while dbg.running and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(dbg.running)

    def test_backend_syscall_commands(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = self.create_debugger(bv)
        self.assertNotIn(dbg.launch_and_wait(), [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        try:
            self.assertIn('syscall-info', dbg.execute_backend_command('help'))
            # Stopped at the entry point, and not at a system call
            self.assertIn('not stopped at a system call', dbg.execute_backend_command('syscall-info'))

            # Run to a system call and back out of it: an entry, and then the exit of the same call
            dbg.execute_backend_command('syscall')
            self.wait_until_stopped(dbg)
            self.assertIn('system call entry', dbg.execute_backend_command('syscall-info'))
            call = dbg.get_adapter_property('syscall')
            self.assertEqual(call['op'], 'entry')
            self.assertEqual(len(call['args']), 6)
            dbg.execute_backend_command('syscall')
            self.wait_until_stopped(dbg)
            self.assertIn('system call exit', dbg.execute_backend_command('syscall-info'))
            self.assertEqual(dbg.get_adapter_property('syscall')['op'], 'exit')

            # sysemu stops at an entry and never at an exit, because the call is not made
            dbg.execute_backend_command('sysemu')
            self.wait_until_stopped(dbg)
            self.assertEqual(dbg.get_adapter_property('syscall')['op'], 'entry')

            self.assertIn('unknown command', dbg.execute_backend_command('no-such-command'))
        finally:
            dbg.quit_and_wait()

    def test_stripped_pie_entry_point(self):
        strip_path = shutil.which('strip')
        if strip_path is None:
            self.skipTest('strip is not installed')

        source_path = name_to_fpath('helloworld_pie', self.arch)
        if not os.path.exists(source_path):
            self.skipTest('PIE test binary not built')

        with tempfile.TemporaryDirectory() as temp_dir:
            stripped_path = os.path.join(temp_dir, 'helloworld_pie_stripped')
            shutil.copy2(source_path, stripped_path)
            subprocess.run([strip_path, '--strip-all', stripped_path], check=True)

            bv = load(stripped_path)
            dbg = self.create_debugger(bv)
            dbg.executable_path = stripped_path

            try:
                reason = dbg.launch_and_wait(20000)
                self.assertEqual(reason, DebugStopReason.Breakpoint)

                remote_base = dbg.get_remote_base()
                self.assertIsNotNone(remote_base)
                self.assertEqual(dbg.ip, remote_base + (bv.entry_point - bv.start))
            finally:
                if dbg.connected:
                    dbg.quit_and_wait()


@unittest.skipUnless(platform.system() == 'Linux', 'The PTRACE adapter only works on Linux')
@unittest.skipIf(platform.machine() in ['arm64', 'aarch64'], 'The PTRACE adapter only supports x86 and x86_64')
class PtraceLinuxx64Test(PtraceAdapterTests, DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86_64'
        self.adapter_type = 'PTRACE'


@unittest.skipUnless(platform.system() == 'Linux', 'The PTRACE adapter only works on Linux')
@unittest.skipIf(platform.machine() in ['arm64', 'aarch64'], 'The PTRACE adapter only supports x86 and x86_64')
class PtraceLinuxx86Test(PtraceAdapterTests, DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86'
        self.adapter_type = 'PTRACE'


@unittest.skipIf(platform.machine() not in ['arm64', 'aarch64'], "Only run arm64 tests on arm Mac or Linux")
class DebuggerArm64Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'arm64'
        # Use LLDB on macOS/Linux, DbgEng on Windows
        if platform.system() in ['Darwin', 'Linux']:
            self.adapter_type = 'LLDB'
        else:
            self.adapter_type = 'DBGENG'


@unittest.skipIf(platform.system() == 'Linux' and platform.machine() in ['arm64', 'aarch64'], 'x86 tests not supported on arm64 macOS or Linux')
class Debuggerx64Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86_64'
        # Use LLDB on macOS/Linux, DbgEng on Windows
        if platform.system() in ['Darwin', 'Linux']:
            self.adapter_type = 'LLDB'
        else:
            self.adapter_type = 'DBGENG'


@unittest.skipIf(platform.machine() in ['arm64', 'aarch64'], 'x86 tests not supported on macOS or arm64 Linux')
class Debuggerx86Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86'
        # Use LLDB on macOS/Linux, DbgEng on Windows
        if platform.system() in ['Darwin', 'Linux']:
            self.adapter_type = 'LLDB'
        else:
            self.adapter_type = 'DBGENG'


# Windows Native Adapter Tests - only run on Windows
@unittest.skipUnless(platform.system() == 'Windows', 'Windows Native adapter only works on Windows')
@unittest.skipIf(platform.system() == 'Linux' and platform.machine() in ['arm64', 'aarch64'], 'x86 tests not supported on arm64 Linux')
class WindowsNativex64Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86_64'
        self.adapter_type = 'WINDOWS_NATIVE'


@unittest.skipUnless(platform.system() == 'Windows', 'Windows Native adapter only works on Windows')
@unittest.skipIf(platform.machine() in ['arm64', 'aarch64'], 'x86 tests not supported on arm64')
class WindowsNativex86Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86'
        self.adapter_type = 'WINDOWS_NATIVE'


def filter_test_suite(suite, keyword):
    result = unittest.TestSuite()
    for child in suite._tests:
        if type(child) == unittest.suite.TestSuite:
            result.addTest(filter_test_suite(child, keyword))
        elif keyword.lower() in child._testMethodName.lower():
            result.addTest(child)
    return result


def main():
    test_keyword = None
    if len(sys.argv) > 1:
        test_keyword = sys.argv[1]

    runner = unittest.TextTestRunner(verbosity=2)
    # Hack way to load the tests from the current file
    test_suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    # if test keyword supplied, filter
    if test_keyword:
        test_suite = filter_test_suite(test_suite, test_keyword)

    sys.exit(0 if runner.run(test_suite).wasSuccessful() else 1)


if __name__ == "__main__":
    main()
