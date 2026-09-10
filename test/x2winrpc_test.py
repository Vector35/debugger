#!/usr/bin/env python3
#
# unit tests for X2WinRpcAdapter <-> x2winstub (see x2winstub/STATUS.md)
#
# Modeled on the "connect to a real, locally-spawned debug server over loopback" pattern used for
# remote debugging elsewhere in this test suite (debugger_test.py's DebuggerAPI.test_remote_debugging,
# specifically _remote_debugging_dbgeng() / _remote_debugging_lldb() -- see upstream PR #1168 / issue
# #805): spawn the real server binary as a local subprocess listening on 127.0.0.1, connect the real
# adapter to it, and drive the session through the same DebuggerController API any local test uses.
# No mocking of the adapter or the wire protocol -- this is an integration test.
#
# Kept in its own file rather than folded into debugger_test.py because X2WinRpcTest doesn't share
# DebuggerAPI's per-OS/arch launch-a-local-target model (it spawns and owns its own x2winstub.exe
# subprocess instead), and because X2WinRpcAdapter is still unmerged, draft-PR-only work (#1174) that
# depends on a local x2winstub.exe build -- it doesn't run as part of the main suite or CI yet.
#
# Run: cd test && python3 x2winrpc_test.py
# Pass a keyword to run a subset, e.g. python3 x2winrpc_test.py breakpoint

import os
import sys
import time
import socket
import platform
import subprocess
import unittest

import binaryninja
from binaryninja import load
try:
    from debugger import DebuggerController, DebugStopReason, DebugBreakpointType
except ImportError:
    from binaryninja.debugger import DebuggerController, DebugStopReason, DebugBreakpointType

# Reuse debugger_test.py's path-resolution and step helpers rather than duplicating them.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from debugger_test import name_to_fpath, sleep_and_step_into


def find_local_x2winstub():
    """Locate the x2winstub.exe built alongside this debugger build. $X2WINSTUB_PATH overrides
    (useful when it landed in a standalone build's out/plugins instead of BN's own plugin dir --
    see x2winstub/CMakeLists.txt's BN_INTERNAL_BUILD split); otherwise look next to the other
    bundled debug-server tools (BN_CORE_PLUGIN_DIR in an internal build), the same place
    debugger_test.py's find_local_dbgsrv()/find_local_lldb_debug_server() (PR #1168) look for theirs."""
    override = os.environ.get('X2WINSTUB_PATH')
    if override and os.path.isfile(override):
        return override
    path = os.path.join(binaryninja.bundled_plugin_path(), 'x2winstub.exe')
    return path if os.path.isfile(path) else None


def free_loopback_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_port_ready(host, port, deadline_seconds=10):
    """Poll until something is listening on host:port. Unlike debugserver/lldb-server (single
    accept slot -- see debugger_test.py's _remote_debugging_lldb comment), x2winstub's server mode
    loops accept()ing new connections forever (main.cpp's `for(;;)`), so a throwaway probe
    connection here doesn't consume the real connection's slot -- it just shows up in the stub's
    log as a client that immediately disconnected."""
    deadline = time.time() + deadline_seconds
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def terminate_process(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@unittest.skipUnless(platform.system() == 'Windows', 'x2winstub only builds and runs on Windows')
@unittest.skipIf(platform.machine() in ['arm64', 'aarch64'], 'x2winstub test binaries are x86/x64 only')
class X2WinRpcTest(unittest.TestCase):
    """Exercises X2WinRpcAdapter <-> x2winstub end to end over the real FlatBuffers RPC wire
    protocol. Server-mode tests share one x2winstub.exe (see setUpClass) since its "server" mode
    loops accept()ing new connections for the life of the process -- each test gets its own
    DebuggerController/connection, and `disconnect_from_debug_server()` in cleanup returns the stub
    to a fresh state for the next test. Target-mode tests spawn their own x2winstub.exe per test
    instead, since target mode launches one specific target at startup and serves only that one
    debuggee's lifetime.
    """

    arch = 'x86_64'

    @classmethod
    def setUpClass(cls):
        cls.stub_path = find_local_x2winstub()
        if cls.stub_path is None:
            raise unittest.SkipTest(
                'x2winstub.exe not found next to this build (checked $X2WINSTUB_PATH and '
                'binaryninja.bundled_plugin_path()); build the debugger with x2winstub enabled '
                '(Windows-only, see top-level CMakeLists.txt) to get it')

        cls.host = '127.0.0.1'
        cls.port = free_loopback_port()
        cls.stub_proc = subprocess.Popen(
            [cls.stub_path, 'server', '--ip', cls.host, '--port', str(cls.port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if not wait_for_port_ready(cls.host, cls.port):
            output = cls.stub_proc.stdout.read() if cls.stub_proc.poll() is not None else '(still running)'
            terminate_process(cls.stub_proc)
            raise unittest.SkipTest(f'x2winstub server never started listening: {output}')

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'stub_proc', None) is not None:
            terminate_process(cls.stub_proc)

    def _connect(self, fpath=None):
        """Load fpath (default helloworld) and return (bv, dbg) with dbg pointed at the shared
        server-mode stub, connected but with nothing launched/attached yet."""
        if fpath is None:
            fpath = name_to_fpath('helloworld', self.arch)
        bv = load(fpath)
        dbg = DebuggerController(bv)
        dbg.adapter_type = 'X2WIN_RPC'
        dbg.remote_host = self.host
        dbg.remote_port = self.port

        def cleanup():
            if dbg.connected:
                dbg.quit_and_wait()
            dbg.disconnect_from_debug_server()  # no-op if we never connected
        self.addCleanup(cleanup)

        self.assertTrue(dbg.connect_to_debug_server(), 'failed to connect to the local x2winstub')
        return bv, dbg

    def _launch_and_stop_at_entry(self, dbg, fpath, cmd_line=''):
        """launch_and_wait() alone isn't reliable for a stable stopping point here: x2winstub's
        WindowsDebugEngine only kept the "stop at system entry point" half of the initial-breakpoint
        logic it was ported from (core/adapters/windowsnativeadapter.cpp) -- the half that plants a
        breakpoint at BN's *analyzed* entry function needs BinaryView analysis data this standalone
        engine doesn't have (see the file header comment in windows_debug_engine.cpp), so it was
        dropped. Set our own breakpoint at BN's entry point explicitly instead -- the same
        workaround debugger_test.py's _remote_debugging_lldb uses for the analogous gap over a real
        gdbserver."""
        dbg.executable_path = fpath
        dbg.cmd_line = cmd_line
        reason = dbg.launch_and_wait()
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        entry = dbg.data.entry_point
        dbg.delete_breakpoint(entry)  # in case something already left one here
        dbg.add_breakpoint(entry)
        reason = dbg.go_and_wait()
        self.assertEqual(reason, DebugStopReason.Breakpoint)
        self.assertEqual(dbg.ip, entry)
        dbg.delete_breakpoint(entry)
        return entry

    def test_server_mode_launch(self):
        """Server-mode two-phase connect (ConnectToDebugServer then Launch), basic execution."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)
        self.assertGreater(len(dbg.regs), 0)

        reason = dbg.go_and_wait()
        self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_target_mode_connect(self):
        """Target-mode one-phase connect: the stub launches the target itself at startup and
        stops at its initial breakpoint before any adapter is connected; Connect() (not
        ConnectToDebugServer()) attaches to that already-stopped session."""
        fpath = name_to_fpath('helloworld', self.arch)
        host = '127.0.0.1'
        port = free_loopback_port()
        proc = subprocess.Popen(
            [self.stub_path, 'target', fpath, '--ip', host, '--port', str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: terminate_process(proc))
        if not wait_for_port_ready(host, port, deadline_seconds=15):
            self.fail('x2winstub target mode never started listening (target failed to launch?)')

        bv = load(fpath)
        dbg = DebuggerController(bv)
        dbg.adapter_type = 'X2WIN_RPC'
        dbg.remote_host = host
        dbg.remote_port = port
        self.addCleanup(lambda: dbg.quit_and_wait() if dbg.connected else None)

        reason = dbg.connect_and_wait()
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertGreater(len(dbg.regs), 0)

    def test_software_breakpoint(self):
        """_launch_and_stop_at_entry() already covers add-then-hit (it sets a breakpoint at entry
        and asserts the stop lands there); what's left to check here is that delete actually takes
        effect. This used to also re-add a breakpoint at `entry` and assert go_and_wait() hits it
        again immediately -- but Go() correctly steps over a breakpoint sitting at the current IP
        before resuming (core/adapters/windows_debug_engine.cpp's WindowsDebugEngine::Go(), same
        semantics as any real debugger: otherwise `continue` from your own breakpoint could never
        make progress), and `entry` executes exactly once, so that breakpoint could never trigger
        again -- the assertion was wrong, not the engine. See STATUS.md discussion for detail."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)  # deletes its own entry breakpoint before returning

        reason = dbg.go_and_wait()
        self.assertEqual(reason, DebugStopReason.ProcessExited,
                          'continuing after delete_breakpoint() re-trapped -- delete did not take effect')

    def test_hardware_breakpoint(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)

        self.assertTrue(dbg.add_hardware_breakpoint(entry, DebugBreakpointType.BNHardwareExecuteBreakpoint))
        watch_addr = (entry + 0x100) & ~0x3
        self.assertTrue(dbg.add_hardware_breakpoint(watch_addr, DebugBreakpointType.BNHardwareWriteBreakpoint, size=4))
        self.assertTrue(dbg.delete_hardware_breakpoint(entry, DebugBreakpointType.BNHardwareExecuteBreakpoint))
        self.assertTrue(dbg.delete_hardware_breakpoint(watch_addr, DebugBreakpointType.BNHardwareWriteBreakpoint, size=4))

    def test_step_return(self):
        """Regression for the general "step to return doesn't land after the call" bug class
        (see e.g. upstream issue #1195/#977, filed against the BN-hosted native Windows adapter
        this engine was ported from). asmtest.exe is a hand-built binary whose first bytes are a
        known nop/call/call sequence (see debugger_test.py's test_assembly_code for the same
        layout), so the expected landing address after each call is exact, not inferred."""
        fpath = name_to_fpath('asmtest', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)
        dbg.set_reg_value('rsp', dbg.get_reg_value('rsp') & 0xfffffffffffffff0)

        sleep_and_step_into(dbg)  # over the nop -> entry+1, the first call
        self.assertEqual(dbg.ip, entry + 1)

        sleep_and_step_into(dbg)  # into the first call's body
        reason = dbg.step_return_and_wait()
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertEqual(dbg.ip, entry + 6, 'step_return landed somewhere other than right after the call')

        sleep_and_step_into(dbg)  # into the second call's body
        reason = dbg.step_return_and_wait()
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertEqual(dbg.ip, entry + 12, 'step_return landed somewhere other than right after the call')

    def test_register_read_write(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        rax = dbg.get_reg_value('rax')
        dbg.set_reg_value('rax', 0xAAAAAAAADEADBEEF)
        self.assertEqual(dbg.get_reg_value('rax'), 0xAAAAAAAADEADBEEF)
        dbg.set_reg_value('rax', rax)
        self.assertEqual(dbg.get_reg_value('rax'), rax)
        self.assertGreater(len(dbg.regs), 0)

    def test_memory_read_write(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        addr = dbg.ip + 0x100
        original = dbg.read_memory(addr, 256)
        pattern = b'\xAA' * 256
        dbg.write_memory(addr, pattern)
        self.assertEqual(dbg.read_memory(addr, 256), pattern)
        dbg.write_memory(addr, original)
        self.assertEqual(dbg.read_memory(addr, 256), original)

    def test_memory_map(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        regions = dbg.memory_map
        self.assertGreater(len(regions), 0)
        self.assertTrue(any(r.start <= dbg.ip < r.start + r.size for r in regions),
                         'no memory region in the map covers the current IP')

    def test_module_list(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        modules = dbg.modules
        self.assertGreater(len(modules), 0)
        self.assertTrue(any('helloworld' in m.name.lower() for m in modules),
                         'launched executable not found in the module list')

    def test_stack_frames_and_stack_pointer(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        self.assertEqual(dbg.stack_pointer, dbg.get_reg_value('rsp'))
        frames = dbg.frames_of_thread(dbg.active_thread.tid)
        self.assertGreater(len(frames), 0)
        self.assertEqual(frames[0].pc, dbg.ip)
        self.assertEqual(frames[0].sp, dbg.stack_pointer)

    def test_thread_list_suspend_resume(self):
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        dbg.go()
        time.sleep(1)
        dbg.pause_and_wait()
        threads = dbg.threads
        self.assertGreater(len(threads), 1)

        other = next((t for t in threads if t.tid != dbg.active_thread.tid), None)
        self.assertIsNotNone(other, 'need at least one non-active thread to suspend/resume')
        self.assertTrue(dbg.suspend_thread(other.tid))
        self.assertTrue(dbg.resume_thread(other.tid))

    def test_break_into(self):
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        dbg.go()
        time.sleep(0.5)
        reason = dbg.pause_and_wait()
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

    def test_process_list_and_attach(self):
        fpath = name_to_fpath('helloworld_loop', self.arch)
        CREATE_NEW_CONSOLE = 0x00000010
        pid = subprocess.Popen([fpath], creationflags=CREATE_NEW_CONSOLE).pid

        bv, dbg = self._connect(fpath)
        self.assertGreater(len(dbg.processes), 0)
        dbg.pid_attach = pid
        reason = dbg.attach_and_wait()
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertGreater(len(dbg.regs), 0)

    def test_detach_leaves_target_running(self):
        """Best-effort regression for STATUS.md #1 (detach could terminate a multi-threaded
        target). This drives the same DebugLoop() cleanup path the fix touches -- detaching while
        the target is actively running rather than stopped at a breakpoint -- but does not
        reproduce the exact original race (two threads hitting one shared breakpoint at the same
        instant, needing WaitForDebugEvent to have two events genuinely queued at once); that
        needs a purpose-built repro binary and is not attempted here."""
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        dbg.go()
        time.sleep(0.5)  # let multiple worker threads actually start running
        dbg.detach_and_wait()

        # Detach tore the process down if it's no longer in the stub's process list.
        procs = dbg.processes
        self.assertTrue(any('helloworld_thread' in p.name.lower() for p in procs),
                         'target process is gone after detach -- detach likely killed it')

        # Clean up the now-detached, still-running process so it doesn't leak on the test box.
        leaked = next(p for p in procs if 'helloworld_thread' in p.name.lower())
        dbg.pid_attach = leaked.pid
        dbg.attach_and_wait()
        dbg.quit_and_wait()

    def test_breakpoint_does_not_carry_over_reused_connection(self):
        """Regression for STATUS.md #2. Uses one adapter/connection across two Launch cycles (the
        precondition from the issue -- Detach() in server mode keeps the stub TCP connection alive,
        see X2WinRpcAdapter::Detach()/ResetSessionState() vs TeardownConnection()) and deletes the
        breakpoint from BN-core's own list before the second launch, so BN-core's own
        ApplyBreakPoints() has nothing to resend -- isolating whether the *stub* silently re-arms
        a stale breakpoint on its own from leftover state, independent of what BN-core asks for."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)

        addr = entry + 0x10
        dbg.add_breakpoint(addr)
        dbg.delete_breakpoint(addr)  # BN-core no longer intends to send this anywhere
        dbg.detach_and_wait()        # server mode: connection stays up (ResetSessionState(), not TeardownConnection())

        self._launch_and_stop_at_entry(dbg, fpath)  # second Launch cycle, same connection
        reason = dbg.go_and_wait()
        self.assertEqual(reason, DebugStopReason.ProcessExited,
                          'process stopped (likely at the stale, BN-core-deleted breakpoint) instead of exiting -- '
                          'the stub re-armed a breakpoint on its own that BN-core never asked it to')

    def test_go_posts_resume_event(self):
        """Regression for the Go()-doesn't-post-ResumeEventType fix (core/adapters/x2winrpcadapter.cpp,
        not yet committed as of this writing): `running` should flip promptly after go(), not stay
        stuck at the last-stopped state until the next stop event."""
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        self.assertFalse(dbg.running)
        dbg.go()
        deadline = time.time() + 5
        while time.time() < deadline and not dbg.running:
            time.sleep(0.05)
        self.assertTrue(dbg.running, 'dbg.running never flipped True after go() -- ResumeEventType not posted?')
        dbg.pause_and_wait()

    def test_breakpoint_set_on_running_target_triggers(self):
        """Best-effort regression for STATUS.md #4 (missing FlushInstructionCache after INT3
        writes). Needs an address genuinely inside the target's repeating loop body to have any
        chance of re-triggering -- this used to (wrongly) assume helloworld_loop.exe's *entry
        point* was such an address ("true for a trivial 'loop forever' test binary, but not
        verified by disassembly here" -- it wasn't true: disassembly shows entry is just the
        one-shot CRT startup thunk, a `jmp` away with no path back, so a breakpoint there can
        never fire again once the target has moved past it). Sample a real in-loop address
        instead by breaking into the already-running target once; then resume and arm the
        breakpoint on that address while the target is live and running -- preserving the actual
        regression scenario (writing an INT3 into a *running* process's code, per STATUS.md #4)."""
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        dbg.go()
        time.sleep(0.3)  # let it actually run past entry into the loop before sampling
        reason = dbg.pause_and_wait()
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        loop_addr = dbg.ip  # an address confirmed to be live inside the loop right now

        dbg.go()  # back to actively running (not stopped) before arming the breakpoint
        time.sleep(0.1)
        dbg.add_breakpoint(loop_addr)
        reason = dbg.go_and_wait(5000)
        self.assertEqual(reason, DebugStopReason.Breakpoint,
                          'breakpoint set on the already-running target never triggered within 5s')
        self.assertEqual(dbg.ip, loop_addr)


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
    test_suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    if test_keyword:
        test_suite = filter_test_suite(test_suite, test_keyword)

    runner.run(test_suite)


if __name__ == '__main__':
    main()
