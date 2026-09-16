#!/usr/bin/env python3
#
# Windows Remote integration tests (X2WinRpcAdapter <-> x2winstub).
#
# Modeled on the "connect to a real, locally-spawned debug server over loopback" pattern used for
# remote debugging elsewhere in this test suite (debugger_test.py's DebuggerAPI.test_remote_debugging,
# specifically _remote_debugging_dbgeng() / _remote_debugging_lldb() -- see upstream PR #1168 / issue
# #805): spawn the real server binary as a local subprocess listening on 127.0.0.1, connect the real
# adapter to it, and drive the session through the same DebuggerController API any local test uses.
# No mocking of the adapter or the wire protocol -- this is an integration test.
#
# Run on Windows only. scripts/build.py includes this suite on Windows CI workers,
# with X2WINSTUB_PATH pointing to the server built alongside the client under test.
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
import tempfile
import threading
from concurrent.futures import Future

import binaryninja
from binaryninja import load
try:
    from debugger import DebuggerController, DebugStopReason, DebugBreakpointType, ModuleNameAndOffset
except ImportError:
    from binaryninja.debugger import DebuggerController, DebugStopReason, DebugBreakpointType, ModuleNameAndOffset

# Reuse debugger_test.py's fixture path resolution.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from debugger_test import name_to_fpath


def find_local_x2winstub():
    """Locate the x2winstub.exe built alongside this debugger build. $X2WINSTUB_PATH overrides
    (useful when it landed in a standalone build's out/plugins instead of BN's own plugin dir --
    see x2winstub/CMakeLists.txt's BN_INTERNAL_BUILD split); otherwise look next to the other
    bundled debug-server tools (BN_CORE_PLUGIN_DIR in an internal build), the same place
    debugger_test.py's find_local_dbgsrv()/find_local_lldb_debug_server() (PR #1168) look for theirs."""
    override = os.environ.get('X2WINSTUB_PATH')
    if override:
        return override if os.path.isfile(override) else None
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
            raise RuntimeError(
                'x2winstub.exe not found next to this build (checked $X2WINSTUB_PATH and '
                'binaryninja.bundled_plugin_path()); build the debugger with x2winstub enabled '
                '(Windows-only, see top-level CMakeLists.txt) to get it')

        cls.host = '127.0.0.1'
        cls.port = free_loopback_port()
        # Never leave an unread PIPE: verbose output can fill it and hang the server.
        cls.stub_log = tempfile.TemporaryFile(mode='w+')
        cls.addClassCleanup(cls.stub_log.close)
        cls.stub_proc = subprocess.Popen(
            [cls.stub_path, 'server', '--ip', cls.host, '--port', str(cls.port)],
            stdout=cls.stub_log, stderr=subprocess.STDOUT, text=True)
        cls.addClassCleanup(terminate_process, cls.stub_proc)
        if not wait_for_port_ready(cls.host, cls.port):
            terminate_process(cls.stub_proc)
            cls.stub_log.seek(0)
            raise RuntimeError(f'x2winstub server never started listening: {cls.stub_log.read()}')

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
            try:
                if dbg.connected:
                    dbg.quit_and_wait(10000)
                self.assertFalse(dbg.connected, 'Quit did not complete within 10 seconds')
            finally:
                dbg.disconnect_from_debug_server()
                bv.file.close()
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
        reason = dbg.launch_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        entry = dbg.data.entry_point
        dbg.delete_breakpoint(entry)  # in case something already left one here
        dbg.add_breakpoint(entry)
        reason = dbg.go_and_wait(10000)
        if dbg.remote_arch.name == 'x86' and reason == DebugStopReason.InitialBreakpoint:
            reason = dbg.go_and_wait(10000)  # second WOW64 loader breakpoint
        self.assertEqual(reason, DebugStopReason.Breakpoint)
        self.assertEqual(dbg.ip, entry)
        dbg.delete_breakpoint(entry)
        return entry

    def test_active_pid(self):
        """Target metadata reports the live PID and clears it when debugging ends."""
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        self.assertEqual(dbg.active_pid, 0)
        self._launch_and_stop_at_entry(dbg, fpath)
        pid = dbg.active_pid
        self.assertGreater(pid, 0)
        self.assertIn(pid, [process.pid for process in dbg.processes])
        dbg.go()
        deadline = time.monotonic() + 5
        while not dbg.running and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(dbg.running)
        self.assertEqual(dbg.active_pid, pid)
        dbg.pause_and_wait(10000)
        self.assertEqual(dbg.active_pid, pid)
        dbg.quit_and_wait(10000)
        self.assertEqual(dbg.active_pid, 0)

    def test_server_mode_launch(self):
        """Server-mode two-phase connect (ConnectToDebugServer then Launch), basic execution."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)
        self.assertGreater(len(dbg.regs), 0)

        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_instruction_pointer_after_register_write(self):
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        original = dbg.get_reg_value('rip')
        try:
            self.assertTrue(dbg.set_reg_value('rip', original + 1))
            self.assertEqual(dbg.ip, original + 1)
            self.assertEqual(dbg.active_thread.rip, original + 1)
        finally:
            dbg.set_reg_value('rip', original)

        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_target_mode_connect(self):
        """Target-mode one-phase connect: the stub launches the target itself at startup and
        stops at its initial breakpoint before any adapter is connected; Connect() (not
        ConnectToDebugServer()) attaches to that already-stopped session."""
        fpath = name_to_fpath('helloworld', self.arch)
        host = '127.0.0.1'
        port = free_loopback_port()
        log = tempfile.TemporaryFile(mode='w+')
        self.addCleanup(log.close)
        proc = subprocess.Popen(
            [self.stub_path, 'target', fpath, '--ip', host, '--port', str(port)],
            stdout=log, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(lambda: terminate_process(proc))
        if not wait_for_port_ready(host, port, deadline_seconds=15):
            self.fail('x2winstub target mode never started listening (target failed to launch?)')

        bv = load(fpath)
        dbg = DebuggerController(bv)
        dbg.adapter_type = 'X2WIN_RPC'
        dbg.remote_host = host
        dbg.remote_port = port
        self.addCleanup(lambda: dbg.quit_and_wait(10000) if dbg.connected else None)

        reason = dbg.connect_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertGreater(len(dbg.regs), 0)
        self.assertGreater(dbg.active_pid, 0)
        self.assertIn(dbg.active_pid, [process.pid for process in dbg.processes])

    def test_software_breakpoint(self):
        """_launch_and_stop_at_entry() already covers add-then-hit (it sets a breakpoint at entry
        and asserts the stop lands there); what's left to check here is that delete actually takes
        effect. This used to also re-add a breakpoint at `entry` and assert go_and_wait() hits it
        again immediately -- but Go() correctly steps over a breakpoint sitting at the current IP
        before resuming (core/adapters/windows_debug_engine.cpp's WindowsDebugEngine::Go(), same
        semantics as any real debugger: otherwise `continue` from your own breakpoint could never
        make progress), and `entry` executes exactly once, so that breakpoint could never trigger
        again -- the assertion was wrong, not the engine."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)  # deletes its own entry breakpoint before returning

        reason = dbg.go_and_wait(10000)
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
        layout), so the expected landing address after each call is exact, not inferred.

        Enter both callees explicitly; stepping only once from entry+6 executes
        the NOP, not the second CALL. The separate x86 unwind limitation is
        not covered by this x64 test."""
        fpath = name_to_fpath('asmtest', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)
        dbg.set_reg_value('rsp', dbg.get_reg_value('rsp') & 0xfffffffffffffff0)

        dbg.step_into_and_wait(timeout=10000)  # over the nop -> entry+1, the first call
        self.assertEqual(dbg.ip, entry + 1)

        dbg.step_into_and_wait(timeout=10000)  # into the first call's body
        reason = dbg.step_return_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertEqual(dbg.ip, entry + 6, 'step_return landed somewhere other than right after the call')

        dbg.step_into_and_wait(timeout=10000)  # over the second nop
        self.assertEqual(dbg.ip, entry + 7)
        dbg.step_into_and_wait(timeout=10000)  # into the second call's body
        reason = dbg.step_return_and_wait(10000)
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
        dbg.pause_and_wait(10000)
        threads = dbg.threads
        self.assertGreater(len(threads), 1)

        other = next((t for t in threads if t.tid != dbg.active_thread.tid), None)
        self.assertIsNotNone(other, 'need at least one non-active thread to suspend/resume')
        original_thread = dbg.active_thread
        try:
            dbg.active_thread = other
            self.assertEqual(dbg.active_thread.tid, other.tid)
            self.assertEqual(dbg.ip, dbg.get_reg_value('rip'))
        finally:
            dbg.active_thread = original_thread
        self.assertTrue(dbg.suspend_thread(other.tid))
        self.assertTrue(dbg.resume_thread(other.tid))

    def test_break_into(self):
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        dbg.go()
        time.sleep(0.5)
        reason = dbg.pause_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

    def test_process_list_and_attach(self):
        fpath = name_to_fpath('helloworld_loop', self.arch)
        CREATE_NEW_CONSOLE = 0x00000010
        target = subprocess.Popen([fpath], creationflags=CREATE_NEW_CONSOLE)
        self.addCleanup(terminate_process, target)
        pid = target.pid

        bv, dbg = self._connect(fpath)
        self.assertGreater(len(dbg.processes), 0)
        dbg.pid_attach = pid
        reason = dbg.attach_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertGreater(len(dbg.regs), 0)

    def test_detach_leaves_target_running(self):
        """Best-effort regression for detach terminating a multi-threaded target.
        This drives the same DebugLoop() cleanup path the fix touches -- detaching while
        the target is actively running rather than stopped at a breakpoint -- but does not
        reproduce the exact original race (two threads hitting one shared breakpoint at the same
        instant, needing WaitForDebugEvent to have two events genuinely queued at once); that
        needs a purpose-built repro binary and is not attempted here."""
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        pid = dbg.active_pid
        dbg.go()
        time.sleep(0.5)  # let multiple worker threads actually start running
        dbg.detach_and_wait(10000)

        # Detach tore the process down if it's no longer in the stub's process list.
        procs = dbg.processes
        self.assertTrue(any(p.pid == pid for p in procs),
                         'target process is gone after detach -- detach likely killed it')

        # Clean up the now-detached, still-running process so it doesn't leak on the test box.
        dbg.pid_attach = pid
        dbg.attach_and_wait(10000)
        dbg.quit_and_wait(10000)

    def test_breakpoint_does_not_carry_over_reused_connection(self):
        """Regression for stale server breakpoints. Uses one adapter/connection across two Launch cycles (the
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
        dbg.detach_and_wait(10000)        # server mode: connection stays up (ResetSessionState(), not TeardownConnection())

        self._launch_and_stop_at_entry(dbg, fpath)  # second Launch cycle, same connection
        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.ProcessExited,
                          'process stopped (likely at the stale, BN-core-deleted breakpoint) instead of exiting -- '
                          'the stub re-armed a breakpoint on its own that BN-core never asked it to')

    def test_go_posts_resume_event(self):
        """Regression for the Go()-doesn't-post-ResumeEventType fix: `running` should flip promptly after go(), not stay
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
        dbg.pause_and_wait(10000)

    def test_interrupt_stopped_target_does_not_resume(self):
        """An interrupt acknowledgment must not turn a stopped target into Running.

        Quit requests an out-of-band interrupt even when already stopped. A false
        Resume event makes its worker try to pause again and wait indefinitely.
        Observe the forbidden transition explicitly, rather than relying on which
        thread wins the Quit race.
        """
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)
        self.assertFalse(dbg.running)
        dbg.pause()
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            self.assertFalse(dbg.running, 'interrupt acknowledgment falsely resumed a stopped target')
            time.sleep(0.01)
        dbg.quit_and_wait(10000)
        self.assertFalse(dbg.connected, 'Quit timed out after interrupting a stopped target')

    def test_breakpoint_set_on_running_target_triggers(self):
        """Insert a breakpoint while Go is pending, then wait for that same Go operation.

        Use the rebased view for the address. Calling go_and_wait() a second time
        while the target is running is not a wait-for-the-first-Go operation.
        """
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)
        main_func = dbg.data.get_functions_by_name('main')[0]
        loop_addr = main_func.start + 0x24
        result = Future()

        def resume():
            try:
                result.set_result(dbg.go_and_wait(15000))
            except BaseException as error:
                result.set_exception(error)

        worker = threading.Thread(target=resume, daemon=True)
        worker.start()
        try:
            deadline = time.monotonic() + 5
            while not dbg.running and time.monotonic() < deadline and not result.done():
                time.sleep(0.01)
            self.assertTrue(dbg.running, 'Go never entered running state')
            dbg.add_breakpoint(loop_addr)
            self.assertEqual(result.result(timeout=20), DebugStopReason.Breakpoint)
            self.assertEqual(dbg.ip, loop_addr)
        finally:
            dbg.delete_breakpoint(loop_addr)
            if not result.done():
                dbg.pause_and_wait(10000)
            worker.join(timeout=20)
            self.assertFalse(worker.is_alive(), 'Go waiter did not finish')

    def test_exit_code(self):
        """Coverage gap: process exit code capture (see debugger_test.py's test_return_code for
        the same binary/pattern against the other adapters)."""
        fpath = name_to_fpath('exitcode', self.arch)
        bv, dbg = self._connect(fpath)

        # exitcode.exe exits with the numeric value of argv[1]; some systems return the low byte
        # of a 32-bit code rather than the full value, hence the two acceptable values per case.
        testvals = [('0', [0]), ('3', [3]), ('123', [123]), ('-1', [4294967295, 255])]
        for arg, expected in testvals:
            dbg.executable_path = fpath
            dbg.cmd_line = arg
            reason = dbg.launch_and_wait(10000)
            self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
            reason = dbg.go_and_wait(10000)
            self.assertEqual(reason, DebugStopReason.ProcessExited)
            self.assertIn(dbg.exit_code, expected, f'unexpected exit code for argv[1]={arg}')

    def test_exception_access_violation(self):
        """Coverage gap: exception handling. do_exception.exe's 'segfault' argument dereferences a
        bad pointer -- WindowsDebugEngine must translate the resulting SEH exception into
        AccessViolation rather than leaving the target hung waiting on an unhandled debug event."""
        fpath = name_to_fpath('do_exception', self.arch)
        bv, dbg = self._connect(fpath)
        dbg.executable_path = fpath
        dbg.cmd_line = 'segfault'
        reason = dbg.launch_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.AccessViolation)

    def test_exception_divide_by_zero(self):
        """Coverage gap: exception handling, integer division case (STATUS_INTEGER_DIVIDE_BY_ZERO
        rather than an access violation -- a different SEH code, so a separate regression from
        test_exception_access_violation)."""
        fpath = name_to_fpath('do_exception', self.arch)
        bv, dbg = self._connect(fpath)
        dbg.executable_path = fpath
        dbg.cmd_line = 'divzero'
        reason = dbg.launch_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.Calculation)

    def test_step_over(self):
        """Coverage gap: StepOver specifically (as opposed to StepInto, already covered by
        test_step_return's sleep_and_step_into() calls). X2WinRpcAdapter::SupportFeature()
        reports DebugAdapterSupportStepOver so DebuggerController should use the adapter's real
        StepOver RPC rather than falling back to its own software emulation -- exercise that path
        directly. asmtest.exe's layout (see test_step_return's docstring) starts with a `nop` then
        two `call`s, so stepping over from entry should land on the second call's address without
        ever entering the first call's body."""
        fpath = name_to_fpath('asmtest', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)
        dbg.set_reg_value('rsp', dbg.get_reg_value('rsp') & 0xfffffffffffffff0)

        reason = dbg.step_over_and_wait(timeout=10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertEqual(dbg.ip, entry + 1, 'step_over over the nop landed somewhere unexpected')

        reason = dbg.step_over_and_wait(timeout=10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])
        self.assertEqual(dbg.ip, entry + 6,
                          'step_over did not skip over the call body -- landed inside the callee '
                          'instead of at the return site')

    def test_restart(self):
        """Coverage gap: restart. DebuggerController::Restart() is adapter-agnostic (a generic
        Quit-then-Launch on the worker thread, core/debuggercontroller.cpp) so it only needs Quit
        and Launch to each work correctly over the X2Win RPC connection -- exercises both in
        sequence on one connection, then confirms the restarted process is a genuinely fresh run
        rather than reusing stale session state.

        _launch_and_stop_at_entry() deletes its own entry breakpoint before returning (see its
        docstring), so restart_and_wait() correctly lands on the OS-injected loader breakpoint
        instead (InitialBreakpoint, at some address in ntdll, not BN's analyzed entry) -- asserting
        dbg.ip == entry here was wrong the first time this test was written. Re-add a breakpoint at
        entry and continue once to prove the restarted process is a genuinely fresh run that
        reaches its own entry point again, then let it run to exit.

        This also regression-tests a real bug the first version of this test caught: Restart()
        replays every BN-core-known breakpoint (DebuggerBreakpoints::Apply(), via the reused
        adapter's CreateDebugAdapter()) before the restart's own Launch() RPC has actually run --
        at that instant the stub is between debuggees (old process just Quit(), new one not
        launched yet), but its GetModuleList() still answered with the just-terminated process's
        stale module info, so X2WinRpcAdapter::AddBreakpoint(ModuleNameAndOffset&)'s
        ResolveModuleAddress() call "succeeded" against a dead target and the resulting
        SetBreakpointRequest was rejected by the stub -- with nothing re-staging it, this dropped
        the breakpoint silently and permanently instead of catching it on the second chance
        (ReaderLoop()'s post-stop-event flush) that already existed for the ordinary
        module-not-yet-resolvable case. Fixed by re-staging on that rejection too, not just on
        ResolveModuleAddress() failure.

        That second-chance flush runs on its own detached thread (ReaderLoop() can't block on it
        without self-deadlocking -- see ApplyBreakPoints()'s own comment), so it's a race against
        whatever the caller does right after restart_and_wait() returns: this test lost that race
        often enough in a full-suite run to not be a reliable pass/fail signal for it. Re-add the
        breakpoint explicitly here instead (a direct, synchronous AddBreakpoint RPC -- the same
        thing _launch_and_stop_at_entry() already relies on for the ordinary launch case, which is
        why that path has never hit this race) rather than depending on the automatic carry-over
        actually finishing in time."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)

        dbg.add_breakpoint(entry)
        reason = dbg.restart_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError],
                          'restart did not bring the target back up')
        self.assertGreater(len(dbg.regs), 0)

        entry = dbg.data.entry_point  # the restarted image may have a new ASLR base
        dbg.add_breakpoint(entry)  # synchronous re-add -- see docstring for why this isn't redundant
        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.Breakpoint,
                          'restarted process never reached its own entry point again')
        self.assertEqual(dbg.ip, entry)
        dbg.delete_breakpoint(entry)

        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_conditional_breakpoint_setting_roundtrip(self):
        """Coverage gap: conditional breakpoints.

        This test used to also drive a real go_and_wait() through a conditional breakpoint (both an
        always-true and an always-false condition, at various addresses) to confirm the runtime
        silent-resume-on-false-condition behavior (ExecuteAdapterAndWait's
        ShouldSilentResumeAfterStop(), core/debuggercontroller.cpp). All of those attempts timed
        out -- and not for a reason specific to which address or which condition was used: even a
        single ShouldSilentResumeAfterStop() call for a breakpoint whose condition evaluates *true*
        on the very first hit (one evaluation, immediate stop, no silent-resume looping at all)
        still took over 10 seconds. Instrumented with binaryninja.log_to_file down to: the real RPC
        traffic (the stop event, the condition's one evaluation) completes quickly, but go_and_wait()
        doesn't return the result back to the caller for tens of seconds afterwards -- confirmed via
        one always-false run that did eventually return the correct ProcessExited result, just ~85
        seconds late. Whatever's slow is generic BN-core code (ShouldSilentResumeAfterStop() itself,
        or ExecuteAdapterAndWait/SubmitAndWait's result plumbing), not X2Win-specific -- and per
        test/debugger_test.py's own test_breakpoint_condition (get/set string round-trip only, no
        go_and_wait() involved), this is apparently the first attempt anywhere in this suite to
        exercise a conditional breakpoint through a real run/stop cycle end to end. Root cause not
        pinned down. Restricted to the condition string round-trip (fast, and
        already proven correct) so this test doesn't itself take a minute-plus to run."""
        fpath = name_to_fpath('helloworld_loop', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)

        dbg.add_breakpoint(entry)
        self.assertTrue(dbg.set_breakpoint_condition(entry, 'rax == 0xDEADDEADDEADDEAD'),
                         'failed to set a breakpoint condition')
        self.assertEqual(dbg.get_breakpoint_condition(entry), 'rax == 0xDEADDEADDEADDEAD')

        self.assertTrue(dbg.set_breakpoint_condition(entry, '1 == 1'))
        self.assertEqual(dbg.get_breakpoint_condition(entry), '1 == 1')

        self.assertTrue(dbg.set_breakpoint_condition(entry, ''))
        self.assertEqual(dbg.get_breakpoint_condition(entry), '')

    def test_active_thread(self):
        """Coverage gap: SetActiveThread(Id) via the active_thread property setter. Confirms the
        adapter actually switches which thread subsequent register reads/IP reporting refer to,
        rather than silently ignoring the request."""
        fpath = name_to_fpath('helloworld_thread', self.arch)
        bv, dbg = self._connect(fpath)
        self._launch_and_stop_at_entry(dbg, fpath)

        dbg.go()
        time.sleep(1)
        dbg.pause_and_wait(10000)
        threads = dbg.threads
        self.assertGreater(len(threads), 1)
        original = dbg.active_thread

        other = next((t for t in threads if t.tid != original.tid), None)
        self.assertIsNotNone(other, 'need at least one non-active thread to switch to')

        dbg.active_thread = other
        self.assertEqual(dbg.active_thread.tid, other.tid,
                          'active_thread did not actually change after being set')

        dbg.active_thread = original
        self.assertEqual(dbg.active_thread.tid, original.tid)

    def test_module_offset_hardware_breakpoint(self):
        """Coverage gap: hardware breakpoints addressed as ModuleNameAndOffset rather than an
        absolute address (test_hardware_breakpoint only covers the absolute-address path) -- the
        same ASLR-friendly relative addressing test_software_breakpoint's docstring references for
        software breakpoints, exercised for hardware ones."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)
        entry = self._launch_and_stop_at_entry(dbg, fpath)

        module_name = next(m.name for m in dbg.modules if 'helloworld' in m.name.lower())
        base = next(m.address for m in dbg.modules if m.name == module_name)
        rel = ModuleNameAndOffset(module_name, entry - base)

        self.assertTrue(dbg.add_hardware_breakpoint(rel, DebugBreakpointType.BNHardwareExecuteBreakpoint))
        self.assertTrue(dbg.delete_hardware_breakpoint(rel, DebugBreakpointType.BNHardwareExecuteBreakpoint))

    def test_debug_shared_library(self):
        """Coverage gap: shared library loading updating the module list. Mirrors
        debugger_test.py's test_debug_shared_library (see its docstring for the launch-the-loader
        rationale) -- points the executable at load_shared_lib.exe, which dlopen()s/LoadLibrary()s
        shared_lib.dll and calls into it, and confirms the module list picks up the library once
        it's loaded."""
        # Not name_to_fpath('shared_lib.dll', ...) -- it unconditionally appends '.exe' to any
        # name that doesn't already end with '.exe' on Windows, which turns this into the
        # nonexistent 'shared_lib.dll.exe' (the same latent bug silently skips
        # debugger_test.py's own test_debug_shared_library on every Windows adapter today).
        exec_path = name_to_fpath('load_shared_lib', self.arch)
        lib_path = os.path.join(os.path.dirname(exec_path), 'shared_lib.dll')
        self.assertTrue(os.path.exists(lib_path) and os.path.exists(exec_path),
                        'shared-library fixtures missing; build the debugger_test_binaries target')

        bv = load(lib_path)
        dbg = DebuggerController(bv)
        dbg.adapter_type = 'X2WIN_RPC'
        dbg.remote_host = self.host
        dbg.remote_port = self.port

        def cleanup():
            if dbg.connected:
                dbg.quit_and_wait(10000)
            dbg.disconnect_from_debug_server()
        self.addCleanup(cleanup)
        self.assertTrue(dbg.connect_to_debug_server())

        dbg.executable_path = exec_path
        reason = dbg.launch_and_wait(10000)
        self.assertNotIn(reason, [DebugStopReason.ProcessExited, DebugStopReason.InternalError])

        # Run to completion -- the loader only returns 0 if it actually loaded and called into the
        # library -- then confirm the library shows up in the module list it picked up along the way.
        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.ProcessExited)
        self.assertEqual(dbg.exit_code, 0)

    def test_duplicate_connect_rejected_or_idempotent(self):
        """Coverage gap: negative-path testing. A second connect_to_debug_server() call on an
        already-connected controller must not corrupt the session -- either it's rejected outright,
        or it's accepted but the connection keeps working normally either way. What it must not do
        is leave the controller in a state where a subsequent launch silently fails."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)

        dbg.connect_to_debug_server()  # second call; return value intentionally not asserted either way

        self._launch_and_stop_at_entry(dbg, fpath)
        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.ProcessExited)

    def test_attach_invalid_pid_fails_cleanly(self):
        """Coverage gap: negative-path testing. Attaching to a pid that doesn't exist must fail
        (InternalError or ProcessExited, not a hang and not a false success), and must leave the
        connection usable afterwards rather than wedging the session for the rest of the test."""
        fpath = name_to_fpath('helloworld', self.arch)
        bv, dbg = self._connect(fpath)

        # A pid vanishingly unlikely to be a real running process.
        dbg.pid_attach = 0x7FFFFFFF
        reason = dbg.attach_and_wait(5000)
        self.assertIn(reason, [DebugStopReason.InternalError, DebugStopReason.ProcessExited],
                      'attach to a nonexistent pid should fail cleanly, not report success')
        self.assertFalse(dbg.running, 'controller thinks a nonexistent target is running')

        # Connection must still be usable for a real launch afterwards.
        self._launch_and_stop_at_entry(dbg, fpath)
        reason = dbg.go_and_wait(10000)
        self.assertEqual(reason, DebugStopReason.ProcessExited)


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

    result = runner.run(test_suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
