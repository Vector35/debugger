#!/usr/bin/env python3
#
# unit tests for debugger

import os
import sys
import time
import platform
import threading
import subprocess
import unittest

from binaryninja import BinaryView, BinaryViewType, LowLevelILOperation, mainthread, Settings
try:
    from binaryninja.debugger import DebuggerController, DebugStopReason
except:
    from debugger import DebuggerController, DebugStopReason


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


def is_wow64(fpath):
    if 'x86' not in fpath:
        return False
    a, b = platform.architecture()
    return a == '64bit' and b.startswith('Windows')


class DebuggerAPI(unittest.TestCase):
    # Always skip the base class so it will never be executed
    @unittest.skip("do not run the base test class")
    def setUp(self) -> None:
        self.arch = ''

    def test_repeated_use(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)

        def run_once():
            dbg = DebuggerController(bv)
            dbg.cmd_line = 'foobar'
            self.assertTrue(dbg.launch())

            # continue execution to the entry point, and check the stop reason
            reason = dbg.step_into_and_wait()
            self.assertEqual(reason, DebugStopReason.SingleStep)
            reason = dbg.step_into_and_wait()
            self.assertEqual(reason, DebugStopReason.SingleStep)
            reason = dbg.step_into_and_wait()
            self.assertEqual(reason, DebugStopReason.SingleStep)
            # go until executing done
            reason = dbg.go_and_wait()
            self.assertEqual(reason, DebugStopReason.ProcessExited)

        # Do the same thing for 10 times
        n = 10
        for i in range(n):
            run_once()

    def test_return_code(self):
        # return code tests
        fpath = name_to_fpath('exitcode', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)

        # some systems return byte, or low byte of 32-bit code and others return 32-bit code
        testvals = [('-11', [245, 4294967285]),
                    ('-1', [4294967295, 255]),
                    ('-3', [4294967293, 253]),
                    ('0', [0]),
                    ('3', [3]),
                    ('7', [7]),
                    ('123', [123])]

        for arg, expected in testvals:
            dbg = DebuggerController(bv)
            dbg.cmd_line = arg

            self.assertTrue(dbg.launch())
            reason = dbg.go_and_wait()
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
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)

        dbg.cmd_line = 'segfault'
        self.assertTrue(dbg.launch())
        # time.sleep(1)
        reason = dbg.go_and_wait()
        self.expect_segfault(reason)
        dbg.quit()

    # # This would not work until we fix the test binary
    # def test_exception_illegalinstr(self):
    #     fpath = name_to_fpath('do_exception', self.arch)
    #     bv = BinaryViewType.get_view_of_file(fpath)
    #     dbg = DebuggerController(bv)
    #     dbg.cmd_line = 'illegalinstr'
    #     self.assertTrue(dbg.launch())
    #     dbg.go()
    #     reason = dbg.go()
    #     if platform.system() in ['Windows', 'Linux']:
    #         expected = DebugStopReason.AccessViolation
    #     else:
    #         expected = DebugStopReason.IllegalInstruction
    #
    #     self.assertEqual(reason, expected)
    #     dbg.quit()

    def expect_divide_by_zero(self, reason):
        if platform.system() == 'Linux':
            self.assertEqual(reason, DebugStopReason.SignalFpe)
        else:
            self.assertEqual(reason, DebugStopReason.Calculation)

    def test_exception_divzero(self):
        fpath = name_to_fpath('do_exception', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        if not self.arch == 'arm64':
            dbg.cmd_line = 'divzero'
            self.assertTrue(dbg.launch())
            reason = dbg.go_and_wait()
            self.expect_divide_by_zero(reason)
            dbg.quit()

    def test_step_into(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        dbg.cmd_line = 'foobar'
        self.assertTrue(dbg.launch())
        reason = dbg.step_into_and_wait()
        self.assertEqual(reason, DebugStopReason.SingleStep)
        reason = dbg.step_into_and_wait()
        self.assertEqual(reason, DebugStopReason.SingleStep)
        reason = dbg.go_and_wait()
        self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_breakpoint(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        self.assertTrue(dbg.launch())
        # TODO: right now we are not returning whether the operation succeeds, so we cannot use assertTrue/assertFalse
        # breakpoint set/clear should fail at 0
        self.assertIsNone(dbg.add_breakpoint(0))
        self.assertIsNone(dbg.delete_breakpoint(0))

        # breakpoint set/clear should succeed at entrypoint
        entry = dbg.live_view.entry_point
        self.assertIsNone(dbg.delete_breakpoint(entry))
        self.assertIsNone(dbg.add_breakpoint(entry))

        self.assertEqual(dbg.ip, entry)
        dbg.quit()

    def test_register_read_write(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        self.assertTrue(dbg.launch())

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

        dbg.quit()

    def test_memory_read_write(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        self.assertTrue(dbg.launch())

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

        dbg.quit()

    # @unittest.skip
    def test_thread(self):
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        self.assertTrue(dbg.launch())

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
        dbg.quit()

    def test_assembly_code(self):
        if self.arch == 'x86_64':
            fpath = name_to_fpath('asmtest', 'x86_64')
            bv = BinaryViewType.get_view_of_file(fpath)
            dbg = DebuggerController(bv)
            if platform.system() == 'Linux':
                Settings().set_bool('debugger.stopAtSystemEntryPoint', True)

            self.assertTrue(dbg.launch())
            if platform.system() == 'Linux':
                Settings().set_bool('debugger.stopAtSystemEntryPoint', False)

            entry = dbg.live_view.entry_point
            self.assertEqual(dbg.ip, entry)

            # TODO: we can use BN to disassemble the binary and find out how long is the instruction
            # step into nop
            dbg.step_into_and_wait()
            self.assertEqual(dbg.ip, entry+1)
            # step into call, return
            dbg.step_into_and_wait()
            dbg.step_into_and_wait()
            # back
            self.assertEqual(dbg.ip, entry+6)
            dbg.step_into_and_wait()
            # step into call, return
            dbg.step_into_and_wait()
            dbg.step_into_and_wait()
            # back
            self.assertEqual(dbg.ip, entry+12)

            reason = dbg.go_and_wait()
            self.assertEqual(reason, DebugStopReason.ProcessExited)

    @unittest.skipIf(platform.system() == 'Linux', 'Cannot attach to pid unless running as root')
    def test_attach(self):
        pid = None
        if platform.system() == 'Windows':
            fpath = name_to_fpath('helloworld_loop', self.arch)
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_CONSOLE = 0x00000010
            cmds = [fpath]
            pid = subprocess.Popen(cmds, creationflags=CREATE_NEW_CONSOLE).pid
        elif platform.system() in ['Darwin', 'Linux']:
            fpath = name_to_fpath('helloworld_loop', self.arch)
            cmds = [fpath]
            pid = subprocess.Popen(cmds).pid
        else:
            print('attaching test not yet implemented on %s' % platform.system())

        self.assertIsNotNone(pid)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        self.assertTrue(dbg.attach(pid))
        self.assertGreater(len(dbg.regs), 0)

        dbg.quit()


@unittest.skipIf(platform.system() != 'Darwin' or platform.machine() != 'arm64', "Only run arm64 tests on arm Mac")
class DebuggerArm64Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'arm64'


class Debuggerx64Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86_64'


@unittest.skipIf(platform.system() in ['Darwin'], 'x86 tests not supported on macOS/Windows')
class Debuggerx86Test(DebuggerAPI):
    def setUp(self) -> None:
        self.arch = 'x86'


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

    runner.run(test_suite)


if __name__ == "__main__":
    main()
