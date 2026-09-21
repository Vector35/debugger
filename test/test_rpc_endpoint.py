"""Tests for api/python/rpc_server.py that need no Binary Ninja.

The binaryninja, binaryninja.debugger and binaryninjaui modules are replaced by stubs, so this checks the endpoint's own
logic (validation, session handling, error codes, what each call returns) and not the debugger behind it.

    python3 test/test_rpc_endpoint.py
"""
import gc
import json
import os
import sys
import threading
import time
import types
import unittest
import weakref

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api", "python")


class FakeFile:
    def __init__(self, sid, name):
        self.session_id = sid
        self.original_filename = name


class FakeBV:
    def __init__(self, sid, name="/bin/x"):
        self.file = FakeFile(sid, name)


class Frame:
    def __init__(self, bv):
        self._bv = bv

    def getCurrentBinaryView(self):
        return self._bv


class Window:
    def __init__(self, bv):
        self._frame = Frame(bv) if bv else None

    def getCurrentViewFrame(self):
        return self._frame


class FileCtx:
    def __init__(self, bv, with_frame=True):
        self._bv = bv
        self._with_frame = with_frame

    def getRawData(self):
        return self._bv

    def getCurrentViewFrame(self):
        return Frame(self._bv) if self._with_frame else None


class Ui:
    """What the GUI thread would report; mutated by the tests."""
    windows = []
    files = []
    files_raise = False
    ui_enabled = True
    mode = "run"  # run | stuck | refuse
    queued = []
    hops = 0


def execute_on_main_thread(func):
    Ui.hops += 1
    if Ui.mode == "refuse":
        return None
    if Ui.mode == "stuck":
        Ui.queued.append(func)
        return object()
    threading.Thread(target=func).start()  # stands in for the GUI thread
    return object()


def install_stubs():
    bn = types.ModuleType("binaryninja")
    bn.core_ui_enabled = lambda: Ui.ui_enabled
    bn.user_directory = lambda: "/tmp"
    bn.logged = []
    bn.log_error_for_exception = lambda text: bn.logged.append(text)
    bn.mainthread = types.SimpleNamespace(execute_on_main_thread=execute_on_main_thread)
    dbg = types.ModuleType("binaryninja.debugger")
    dbg.DebuggerController = object
    dbg.DebugAdapterType = types.SimpleNamespace(get_available_adapters=lambda bv: ["LLDB", "GDB RSP"])

    class DebugStopReason:
        InternalError, InvalidStatusOrOperation = "ie", "iso"
        TimedOut, ProcessExited = "TimedOut", "ProcessExited"

    dbg.DebugStopReason = DebugStopReason
    dbg._debuggercore = types.ModuleType("_debuggercore")
    dbg._debuggercore.BNDebuggerGetStopReasonString = lambda r: r
    enums = types.ModuleType("binaryninja.debugger.debugger_enums")
    enums.DebugAdapterTargetStatus = types.SimpleNamespace(
        DebugAdapterRunningStatus="running", DebugAdapterPausedStatus="paused")
    import enum

    class DebugBreakpointType(enum.IntEnum):
        BNSoftwareBreakpoint = 0
        BNHardwareExecuteBreakpoint = 1
        BNHardwareReadBreakpoint = 2
        BNHardwareWriteBreakpoint = 3
        BNHardwareAccessBreakpoint = 4

    enums.DebugBreakpointType = DebugBreakpointType
    ui = types.ModuleType("binaryninjaui")

    class UIContext:
        @staticmethod
        def allContexts():
            return Ui.windows

    class FileContext:
        @staticmethod
        def getOpenFileContexts():
            if Ui.files_raise:
                raise RuntimeError("binding missing")
            return Ui.files

    ui.UIContext, ui.FileContext = UIContext, FileContext
    for name, mod in (("binaryninja", bn), ("binaryninja.debugger", dbg),
                      ("binaryninja.debugger._debuggercore", dbg._debuggercore),
                      ("binaryninja.debugger.debugger_enums", enums), ("binaryninjaui", ui)):
        sys.modules[name] = mod
    sys.path.insert(0, SCRIPTS)
    sys.dont_write_bytecode = True


install_stubs()
import rpc_server as rpc  # noqa: E402


def reset():
    Ui.windows, Ui.files, Ui.files_raise, Ui.ui_enabled, Ui.mode, Ui.queued, Ui.hops = [], [], False, True, "run", [], 0


class SessionTableTests(unittest.TestCase):
    def setUp(self):
        reset()
        rpc.UI_HOP_TIMEOUT_MS = 300
        self.table = rpc.SessionTable()

    def test_closed_file_is_pruned_and_released(self):
        a, b = FakeBV(1), FakeBV(2)
        Ui.windows, Ui.files = [Window(a)], [FileCtx(a), FileCtx(b)]
        self.assertEqual(set(self.table.snapshot()), {1, 2})
        ref = weakref.ref(a)
        Ui.windows, Ui.files = [Window(b)], [FileCtx(b)]
        del a
        self.assertEqual(set(self.table.snapshot()), {2})
        gc.collect()
        self.assertIsNone(ref(), "the registry still keeps the closed file's view alive")

    def test_background_tab_file_is_found(self):
        front, back = FakeBV(1), FakeBV(2)
        Ui.windows, Ui.files = [Window(front)], [FileCtx(front), FileCtx(back)]
        self.assertIs(self.table.resolve({"session": "2"}), back)

    def test_open_file_without_frame_is_kept_not_pruned(self):
        a = FakeBV(1)
        Ui.windows, Ui.files = [Window(a)], [FileCtx(a)]
        self.table.snapshot()
        Ui.windows, Ui.files = [], [FileCtx(a, with_frame=False)]  # still open, nothing displayed
        self.assertEqual(set(self.table.snapshot()), {1})

    def test_file_context_failure_falls_back_to_windows_and_never_prunes(self):
        a, b = FakeBV(1), FakeBV(2)
        Ui.windows, Ui.files = [Window(a)], [FileCtx(a), FileCtx(b)]
        self.table.snapshot()
        Ui.windows, Ui.files_raise = [Window(b)], True
        self.assertEqual(set(self.table.snapshot()), {1, 2})  # 1 unknown-open, so kept

    def test_pinned_views_survive_pruning(self):
        pinned = FakeBV(9)
        self.table.register(pinned)
        Ui.windows, Ui.files = [], []
        self.assertEqual(set(self.table.snapshot()), {9})
        self.table.unregister(9)
        self.assertEqual(set(self.table.snapshot()), set())

    def test_reopened_file_is_not_ambiguous_by_filename(self):
        old = FakeBV(1, "/bin/ls")
        Ui.windows, Ui.files = [Window(old)], [FileCtx(old)]
        self.table.snapshot()
        new = FakeBV(2, "/bin/ls")
        Ui.windows, Ui.files = [Window(new)], [FileCtx(new)]
        self.assertIs(self.table.resolve({"session": "77", "filename": "/bin/ls"}), new)

    def test_stuck_ui_times_out_serves_cache_and_issues_one_hop(self):
        a = FakeBV(1)
        Ui.windows, Ui.files = [Window(a)], [FileCtx(a)]
        self.table.snapshot()
        hops_before = Ui.hops
        Ui.mode = "stuck"
        started = time.monotonic()
        self.assertIs(self.table.resolve({"session": "1"}), a)
        self.assertLess(time.monotonic() - started, 1.0)
        with self.assertRaises(rpc.RpcError) as ctx:
            self.table.resolve({"session": "2"})
        self.assertEqual(ctx.exception.code, "ui_unavailable")
        for _ in range(5):
            self.table.snapshot()
        self.assertEqual(Ui.hops - hops_before, 1, "callers queued more work behind a stuck GUI thread")

    def test_stuck_ui_recovers_when_the_queued_hop_finally_runs(self):
        a = FakeBV(1)
        Ui.windows, Ui.files = [Window(a)], [FileCtx(a)]
        Ui.mode = "stuck"
        self.table.snapshot()
        Ui.queued.pop()()  # the GUI thread wakes up and runs the abandoned callback
        Ui.mode = "run"
        self.assertEqual(set(self.table.snapshot()), {1})

    def test_concurrent_callers_share_one_hop(self):
        Ui.mode = "stuck"
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.table.snapshot())) for _ in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.05)
        a = FakeBV(1)
        Ui.windows, Ui.files = [Window(a)], [FileCtx(a)]
        Ui.queued.pop()()
        for t in threads:
            t.join()
        self.assertEqual(Ui.hops, 1)
        self.assertTrue(all(set(r) == {1} for r in results))

    def test_refused_hop_does_not_wait(self):
        Ui.mode = "refuse"
        started = time.monotonic()
        with self.assertRaises(rpc.RpcError) as ctx:
            self.table.resolve({"session": "1"})
        self.assertEqual(ctx.exception.code, "ui_unavailable")
        self.assertLess(time.monotonic() - started, 0.25)

    def test_headless_uses_pinned_only_without_hopping(self):
        Ui.ui_enabled = False
        self.table.register(FakeBV(5))
        self.assertEqual(set(self.table.snapshot()), {5})
        with self.assertRaises(rpc.RpcError) as ctx:
            self.table.resolve({"session": "6"})
        self.assertEqual(ctx.exception.code, "unknown_session")
        self.assertEqual(Ui.hops, 0)

    def test_non_numeric_session_is_invalid_params(self):
        Ui.ui_enabled = False
        with self.assertRaises(rpc.RpcError) as ctx:
            self.table.resolve({"session": "abc"})
        self.assertEqual(ctx.exception.code, "invalid_params")



class RespondTests(unittest.TestCase):
    def test_unhandled_exception_is_logged_and_summarized(self):
        conn = rpc._Connection.__new__(rpc._Connection)
        conn.server = types.SimpleNamespace(token="t", handlers=types.SimpleNamespace(status=lambda p: 1 / 0))
        sys.modules["binaryninja"].logged.clear()
        reply = conn._respond(b'{"id": 7, "token": "t", "method": "status", "params": {}}')
        self.assertEqual(reply["error"]["code"], "internal_error")
        self.assertIn("ZeroDivisionError", reply["error"]["message"])
        self.assertEqual(len(sys.modules["binaryninja"].logged), 1)
        self.assertIn("'status'", sys.modules["binaryninja"].logged[0])

    def test_rpc_errors_are_not_logged(self):
        def refuse(params):
            raise rpc.RpcError("no_controller", "nope")
        conn = rpc._Connection.__new__(rpc._Connection)
        conn.server = types.SimpleNamespace(token="t", handlers=types.SimpleNamespace(status=refuse))
        sys.modules["binaryninja"].logged.clear()
        reply = conn._respond(b'{"id": 1, "token": "t", "method": "status"}')
        self.assertEqual(reply["error"]["code"], "no_controller")
        self.assertEqual(sys.modules["binaryninja"].logged, [])



class ControlReplyShapeTests(unittest.TestCase):
    def handlers(self, wait, stop_reason="Breakpoint", **extra):
        dbg = types.SimpleNamespace(connected=True, target_status="paused", adapter_type="LLDB", cmd_line="a b",
                                    ip=0x10, stop_reason_str=stop_reason, exit_code=0, **extra)
        dbg.go_and_wait = lambda ms: wait(dbg)
        dbg.pause_and_wait = lambda ms: wait(dbg)
        dbg.quit_and_wait = lambda ms: None
        bv = FakeBV(1, "/bin/x")
        handlers = rpc.Handlers(types.SimpleNamespace(resolve=lambda p: bv))
        handlers.controller = lambda params, create=False: (dbg, bv)
        return handlers

    def test_reason_replaces_stop_reason_in_control_replies(self):
        h = self.handlers(lambda dbg: "Breakpoint")
        full = h.control({"action": "go"})
        self.assertEqual(full["reason"], "Breakpoint")
        self.assertNotIn("stopReason", full)
        self.assertEqual({"session", "filename", "adapter", "arguments", "connected"} - set(full), set())
        brief = h.control({"action": "go", "brief": True})
        self.assertEqual(set(brief), {"state", "ip", "reason", "timedOut"})

    def test_pause_reports_why_the_call_returned_not_the_signal(self):
        h = self.handlers(lambda dbg: "UserRequestedBreak", stop_reason="SignalStop")
        reply = h.control({"action": "pause", "brief": True})
        self.assertEqual(reply["reason"], "UserRequestedBreak")
        self.assertNotIn("stopReason", reply)

    def test_timeout_and_exit_are_still_reported(self):
        def time_out(dbg):
            dbg.target_status = "running"
            return "TimedOut"
        reply = self.handlers(time_out).control({"action": "go", "brief": True})
        self.assertEqual((reply["state"], reply["reason"], reply["timedOut"]), ("running", "TimedOut", True))

    def test_status_still_reports_stop_reason_while_paused(self):
        reply = self.handlers(lambda dbg: "Breakpoint").status({})
        self.assertEqual(reply["stopReason"], "Breakpoint")
        self.assertNotIn("reason", reply)

    def test_no_call_reason_keeps_stop_reason(self):
        reply = self.handlers(lambda dbg: "Breakpoint").control({"action": "quit"})  # quit yields no reason
        self.assertNotIn("reason", reply)
        self.assertEqual(reply["stopReason"], "Breakpoint")



class AdapterSwitchTests(unittest.TestCase):
    def setUp(self):
        self.launched = []
        self.dbg = types.SimpleNamespace(connected=False, target_status="idle", adapter_type="LLDB", cmd_line="old",
                                         ip=0, stop_reason_str="", exit_code=0)
        self.dbg.launch_and_wait = lambda ms: self.launched.append(self.dbg.adapter_type) or "Breakpoint"
        bv = FakeBV(1, "/bin/x")
        self.h = rpc.Handlers(types.SimpleNamespace(resolve=lambda p: bv))
        self.h.controller = lambda params, create=False: (self.dbg, bv)

    def test_launch_switches_adapter_before_launching(self):
        reply = self.h.control({"action": "launch", "adapter": "GDB RSP"})
        self.assertEqual(self.launched, ["GDB RSP"])
        self.assertEqual(reply["adapter"], "GDB RSP")

    def test_unknown_adapter_lists_choices_and_changes_nothing(self):
        with self.assertRaises(rpc.RpcError) as ctx:
            self.h.control({"action": "launch", "adapter": "Bogus", "arguments": "new"})
        self.assertEqual(ctx.exception.code, "unknown_adapter")
        self.assertIn("LLDB", ctx.exception.message)
        self.assertIn("GDB RSP", ctx.exception.message)
        self.assertEqual((self.dbg.adapter_type, self.dbg.cmd_line, self.launched), ("LLDB", "old", []))

    def test_cannot_change_adapter_while_connected(self):
        self.dbg.connected, self.dbg.target_status = True, "paused"
        with self.assertRaises(rpc.RpcError) as ctx:
            self.h.control({"action": "launch", "adapter": "GDB RSP"})
        self.assertEqual(ctx.exception.code, "target_connected")
        self.assertEqual(self.dbg.adapter_type, "LLDB")

    def test_naming_the_current_adapter_is_a_no_op_even_when_connected(self):
        self.dbg.connected, self.dbg.target_status = True, "paused"
        rpc.Handlers.select_adapter(self.dbg, FakeBV(1), "LLDB")  # must not raise
        self.assertEqual(self.dbg.adapter_type, "LLDB")

    def test_adapter_is_only_valid_with_launch(self):
        for bad in ({"action": "go", "adapter": "LLDB"}, {"action": "launch", "adapter": 5},
                    {"action": "launch", "adapter": ""}, {"action": "launch", "adapter": "a\0b"}):
            with self.assertRaises(rpc.RpcError) as ctx:
                self.h.control(bad)
            self.assertEqual(ctx.exception.code, "invalid_params", bad)



class RegDict(dict):
    """The real register collection answers None for a name it does not have."""

    def __missing__(self, key):
        return None


class FakeDbg:
    """Just enough of DebuggerController for the handlers, recording what they do to it."""

    def __init__(self, connected=False, status="idle"):
        self.connected, self.target_status = connected, status
        self.adapter_type, self.cmd_line, self.ip, self.stop_reason_str, self.exit_code = "LLDB", "", 0x10, "Breakpoint", 0
        self.pid_attach, self.remote_host, self.remote_port = 0, "", 0
        self.executable_path, self.working_directory = "/bin/x", "/"
        self.calls, self.breakpoints, self.modules, self.memory_map, self.processes, self.props = [], [], [], [], [], {}
        self.remote_base, self.rebase_ok, self.hardware_ok, self.output = None, True, True, ""
        self.memory, self.write_ok, self.read_ok, self.reg_fail = bytearray(range(256)), True, True, set()
        self.regs = RegDict(x0=types.SimpleNamespace(value=1), x1=types.SimpleNamespace(value=2))

    def read_memory(self, address, length):
        if not self.read_ok or address + length > len(self.memory):
            return None
        return bytes(self.memory[address:address + length])

    def write_memory(self, address, data):
        if self.write_ok:
            self.memory[address:address + len(data)] = data
        return self.write_ok

    def set_reg_value(self, name, value):
        if name in self.reg_fail:
            return False
        self.regs[name].value = value
        return True

    def _stop(self, name, reason="InitialBreakpoint"):
        self.calls.append(name)
        self.connected, self.target_status = True, "paused"
        return reason

    def attach_and_wait(self, ms): return self._stop("attach")
    def connect_and_wait(self, ms): return self._stop("connect")
    def launch_and_wait(self, ms): return self._stop("launch")

    def detach_and_wait(self, ms):
        self.calls.append("detach")
        self.connected, self.target_status = False, "idle"

    def add_breakpoint(self, address):
        self.breakpoints.append(types.SimpleNamespace(address=address, module="", offset=address, enabled=True,
                                                      condition="", type=0))

    def delete_breakpoint(self, address):
        self.breakpoints = [b for b in self.breakpoints if b.address != address]

    def add_hardware_breakpoint(self, address, kind, size):
        self.calls.append(("hw_add", address, kind, size))
        return self.hardware_ok

    def delete_hardware_breakpoint(self, address, kind, size):
        self.calls.append(("hw_delete", address, kind, size))
        return self.hardware_ok

    def enable_breakpoint(self, address): self._toggle(address, True)
    def disable_breakpoint(self, address): self._toggle(address, False)

    def _toggle(self, address, enabled):
        for b in self.breakpoints:
            if b.address == address:
                b.enabled = enabled

    def get_remote_base(self): return self.remote_base

    def rebase_to_remote_base(self):
        self.calls.append("rebase_remote")
        return self.rebase_ok

    def rebase_to_address(self, address):
        self.calls.append(("rebase", address))
        self.remote_base = address
        return self.rebase_ok

    def write_stdin(self, text): self.calls.append(("stdin", text))

    def execute_backend_command(self, command):
        self.calls.append(("command", command))
        return self.output

    def get_adapter_property(self, name):
        if name not in self.props:
            raise KeyError(name)
        return self.props[name]

    def set_adapter_property(self, name, value):
        self.props[name] = value
        return name != "readonly"


def make_handlers(dbg):
    bv = FakeBV(1, "/bin/x")
    handlers = rpc.Handlers(types.SimpleNamespace(resolve=lambda p: bv))
    handlers.controller = lambda params, create=False: (dbg, bv)
    return handlers


def module(name, base, size): return types.SimpleNamespace(name="/lib/" + name, short_name=name, address=base, size=size, loaded=True)


class TargetSetupTests(unittest.TestCase):
    def error(self, fn, *args):
        with self.assertRaises(rpc.RpcError) as ctx:
            fn(*args)
        return ctx.exception

    def test_attach_sets_the_pid_and_attaches(self):
        dbg = FakeDbg()
        reply = make_handlers(dbg).control({"action": "attach", "pid": 4242, "brief": True})
        self.assertEqual((dbg.pid_attach, dbg.calls), (4242, ["attach"]))
        self.assertEqual((reply["state"], reply["reason"]), ("paused", "InitialBreakpoint"))

    def test_attach_uses_a_remembered_pid_but_needs_one(self):
        dbg = FakeDbg()
        self.assertEqual(self.error(make_handlers(dbg).control, {"action": "attach"}).code, "invalid_params")
        dbg.pid_attach = 77
        make_handlers(dbg).control({"action": "attach"})
        self.assertEqual(dbg.calls, ["attach"])

    def test_connect_sets_host_and_port(self):
        dbg = FakeDbg()
        make_handlers(dbg).control({"action": "connect", "host": "10.0.0.5", "port": 1234})
        self.assertEqual((dbg.remote_host, dbg.remote_port, dbg.calls), ("10.0.0.5", 1234, ["connect"]))
        self.assertEqual(self.error(make_handlers(FakeDbg()).control, {"action": "connect", "host": "h"}).code,
                         "invalid_params")

    def test_attach_and_connect_refuse_a_connected_target(self):
        for action, extra in (("attach", {"pid": 1}), ("connect", {"host": "h", "port": 1})):
            dbg = FakeDbg(connected=True, status="paused")
            self.assertEqual(self.error(make_handlers(dbg).control, {"action": action, **extra}).code, "target_connected")
            self.assertEqual((dbg.calls, dbg.pid_attach, dbg.remote_host), ([], 0, ""))

    def test_detach_needs_a_paused_target(self):
        self.assertEqual(self.error(make_handlers(FakeDbg()).control, {"action": "detach"}).code, "target_not_paused")
        running = FakeDbg(connected=True, status="running")
        self.assertEqual(self.error(make_handlers(running).control, {"action": "detach"}).code, "target_running")
        paused = FakeDbg(connected=True, status="paused")
        reply = make_handlers(paused).control({"action": "detach"})
        self.assertEqual((paused.calls, reply["state"], "reason" in reply), (["detach"], "not_connected", False))

    def test_settings_only_apply_to_their_actions(self):
        h = make_handlers(FakeDbg(connected=True, status="paused"))
        for bad in ({"action": "go", "pid": 5}, {"action": "launch", "pid": 5}, {"action": "attach", "host": "h"},
                    {"action": "go", "port": 5}, {"action": "attach", "port": 5}, {"action": "go", "executablePath": "/x"},
                    {"action": "connect", "workingDirectory": "/"}, {"action": "attach", "pid": 0},
                    {"action": "attach", "pid": True}, {"action": "connect", "host": "h", "port": 70000},
                    {"action": "launch", "executablePath": ""}, {"action": "launch", "workingDirectory": 5}):
            self.assertEqual(self.error(h.control, bad).code, "invalid_params", bad)

    def test_launch_applies_paths_and_a_rejected_call_changes_nothing(self):
        dbg = FakeDbg()
        make_handlers(dbg).control({"action": "launch", "executablePath": "/opt/t", "workingDirectory": "/tmp",
                                    "arguments": "-v"})
        self.assertEqual((dbg.executable_path, dbg.working_directory, dbg.cmd_line), ("/opt/t", "/tmp", "-v"))
        dbg = FakeDbg()
        err = self.error(make_handlers(dbg).control, {"action": "launch", "adapter": "Bogus", "executablePath": "/opt/t"})
        self.assertEqual((err.code, dbg.executable_path), ("unknown_adapter", "/bin/x"))


class BreakpointManagementTests(unittest.TestCase):
    def setUp(self):
        self.dbg = FakeDbg(connected=True, status="paused")
        self.h = make_handlers(self.dbg)

    def error(self, params):
        with self.assertRaises(rpc.RpcError) as ctx:
            self.h.breakpoints(params)
        return ctx.exception.code

    def test_enable_and_disable_show_up_in_the_list(self):
        self.h.breakpoints({"action": "add", "address": 0x20})
        self.assertFalse(self.h.breakpoints({"action": "disable", "address": 0x20})["breakpoints"][0]["enabled"])
        self.assertTrue(self.h.breakpoints({"action": "enable", "address": 0x20})["breakpoints"][0]["enabled"])
        self.assertEqual(self.error({"action": "disable", "address": 0x99}), "unknown_breakpoint")

    def test_hardware_breakpoints_use_the_requested_kind_and_size(self):
        DBT = sys.modules["binaryninja.debugger.debugger_enums"].DebugBreakpointType
        self.h.breakpoints({"action": "add", "address": 0x30, "hardware": "write", "size": 4})
        self.h.breakpoints({"action": "add", "address": 0x40, "hardware": "execute"})
        self.h.breakpoints({"action": "remove", "address": 0x30, "hardware": "write", "size": 4})
        self.assertEqual(self.dbg.calls, [("hw_add", 0x30, DBT.BNHardwareWriteBreakpoint, 4),
                                          ("hw_add", 0x40, DBT.BNHardwareExecuteBreakpoint, 1),
                                          ("hw_delete", 0x30, DBT.BNHardwareWriteBreakpoint, 4)])

    def test_hardware_failures_and_bad_combinations(self):
        self.dbg.hardware_ok = False
        self.assertEqual(self.error({"action": "add", "address": 1, "hardware": "read"}), "write_failed")
        self.assertEqual(self.error({"action": "remove", "address": 1, "hardware": "read"}), "write_failed")
        for bad in ({"action": "list", "hardware": "read"}, {"action": "add", "address": 1, "hardware": "bogus"},
                    {"action": "add", "address": 1, "hardware": "read", "condition": "x0 == 1"},
                    {"action": "add", "address": 1, "size": 4}, {"action": "add", "address": 1, "hardware": "read", "size": 0},
                    {"action": "add", "address": 1, "hardware": "read", "size": 65}, {"action": "enable", "address": 1, "size": 2}):
            self.assertEqual(self.error(bad), "invalid_params", bad)


class ModulesTests(unittest.TestCase):
    def setUp(self):
        self.dbg = FakeDbg(connected=True, status="paused")
        self.dbg.modules = [module("app", 0x1000, 0x500), module("libc", 0x7000, 0x2000), module("dyld", 0x9000, 0x100)]
        self.dbg.memory_map = [types.SimpleNamespace(start=0x1000, size=0x500, name="app", permissions="r-x", shared=False)]
        self.h = make_handlers(self.dbg)

    def test_modules_are_paged_and_report_the_remote_base(self):
        self.dbg.remote_base = 0x1000
        reply = self.h.modules({"limit": 2})
        self.assertEqual((reply["total"], len(reply["modules"]), reply["remoteBase"]), (3, 2, "0x1000"))
        self.assertEqual(reply["modules"][0], {"name": "/lib/app", "shortName": "app", "base": "0x1000",
                                               "size": "0x500", "loaded": True})
        self.assertEqual(self.h.modules({"offset": 2})["modules"][0]["shortName"], "dyld")
        self.dbg.remote_base = None
        self.assertIsNone(self.h.modules({})["remoteBase"])  # the debugger has not detected a base

    def test_memory_map_and_the_empty_note(self):
        self.assertEqual(self.h.modules({"action": "memory_map"})["regions"][0]["permissions"], "r-x")
        self.dbg.memory_map = []
        self.assertIn("does not report", self.h.modules({"action": "memory_map"})["note"])

    def test_resolve_finds_the_containing_module_or_none(self):
        hit = self.h.modules({"action": "resolve", "address": 0x7010})
        self.assertEqual((hit["shortName"], hit["base"], hit["offset"]), ("libc", "0x7000", "0x10"))
        self.assertIsNone(self.h.modules({"action": "resolve", "address": 0x5000})["module"])
        self.assertIsNone(self.h.modules({"action": "resolve", "address": 0x1500})["module"])  # one past the end

    def test_rebase_to_the_detected_or_a_given_base(self):
        with self.assertRaises(rpc.RpcError) as ctx:
            self.dbg.rebase_ok = False
            self.h.modules({"action": "rebase"})
        self.assertEqual(ctx.exception.code, "action_failed")
        self.dbg.rebase_ok, self.dbg.remote_base = True, 0x2000
        self.assertEqual(self.h.modules({"action": "rebase"}), {"rebased": True, "remoteBase": "0x2000"})
        self.assertEqual(self.h.modules({"action": "rebase", "address": 0x4000})["remoteBase"], "0x4000")
        self.assertEqual(self.dbg.calls, ["rebase_remote", "rebase_remote", ("rebase", 0x4000)])

    def test_needs_a_paused_target_and_a_known_action(self):
        for dbg, code in ((FakeDbg(), "target_not_paused"), (FakeDbg(connected=True, status="running"), "target_not_paused")):
            with self.assertRaises(rpc.RpcError) as ctx:
                make_handlers(dbg).modules({})
            self.assertEqual(ctx.exception.code, code)
        with self.assertRaises(rpc.RpcError) as ctx:
            self.h.modules({"action": "bogus"})
        self.assertEqual(ctx.exception.code, "invalid_params")


class InputAndPropertiesTests(unittest.TestCase):
    def error(self, fn, params):
        with self.assertRaises(rpc.RpcError) as ctx:
            fn(params)
        return ctx.exception.code

    def test_processes_filter_and_page(self):
        dbg = FakeDbg()
        dbg.processes = [types.SimpleNamespace(pid=i, name=n, command_line=c) for i, (n, c) in
                         enumerate([("bash", ""), ("Crackme", "/x/crackme --v"), ("zsh", None)])]
        h = make_handlers(dbg)
        self.assertEqual([p["pid"] for p in h.processes({"filter": "CRACK"})["processes"]], [1])
        self.assertEqual(h.processes({"limit": 1, "offset": 2})["processes"][0]["commandLine"], "")

        class Broken(FakeDbg):
            @property
            def processes(self):
                raise RuntimeError("adapter not connected")

            @processes.setter
            def processes(self, value):
                pass

        self.assertEqual(self.error(make_handlers(Broken()).processes, {}), "processes_unavailable")

    def test_stdin_works_while_running_but_needs_a_connection(self):
        running = FakeDbg(connected=True, status="running")
        self.assertEqual(make_handlers(running).input({"stdin": "ASGARD\n"}), {"written": 7})
        self.assertEqual(running.calls, [("stdin", "ASGARD\n")])
        self.assertEqual(self.error(make_handlers(FakeDbg()).input, {"stdin": "x"}), "target_not_connected")

    def test_backend_commands_need_a_paused_target_and_truncate(self):
        dbg = FakeDbg(connected=True, status="paused")
        dbg.output = "x" * (rpc.MAX_TEXT_CHARS + 5)
        reply = make_handlers(dbg).input({"command": "image list"})
        self.assertEqual((len(reply["output"]), reply["truncated"]), (rpc.MAX_TEXT_CHARS, True))
        self.assertEqual(self.error(make_handlers(FakeDbg(connected=True, status="running")).input, {"command": "x"}),
                         "target_not_paused")

    def test_input_needs_exactly_one_valid_field(self):
        h = make_handlers(FakeDbg(connected=True, status="paused"))
        for bad in ({}, {"stdin": "a", "command": "b"}, {"stdin": 5}, {"command": ""}, {"stdin": "a\0b"}):
            self.assertEqual(self.error(h.input, bad), "invalid_params", bad)

    def test_properties_get_set_and_roundtrip(self):
        dbg = FakeDbg()
        dbg.props = {"a": b"\x01\x02", "readonly": 1}
        h = make_handlers(dbg)
        self.assertEqual(h.properties({"get": ["a"]}), {"properties": {"a": "0102"}})
        self.assertEqual(h.properties({"set": {"b": True, "c": 2.5}})["properties"], {"b": True, "c": 2.5})
        self.assertEqual(self.error(h.properties, {"get": ["missing"], "set": {"z": 1}}), "unknown_property")
        self.assertNotIn("z", dbg.props)                      # nothing was written after the failed read
        self.assertEqual(self.error(h.properties, {"set": {"readonly": 2}}), "write_failed")

    def test_properties_validation(self):
        h = make_handlers(FakeDbg())
        for bad in ({}, {"get": "a"}, {"get": [""]}, {"set": []}, {"set": {"a": [1]}}, {"set": {"a": None}}):
            self.assertEqual(self.error(h.properties, bad), "invalid_params", bad)



class ErrorCodeTests(unittest.TestCase):
    def test_an_unknown_code_is_refused_at_the_raise(self):
        with self.assertRaises(ValueError):
            rpc.RpcError("target_runing", "typo")

    def test_ping_reports_every_code_and_the_transport_codes_are_included(self):
        codes = make_handlers(FakeDbg()).ping({})["errorCodes"]
        self.assertEqual(codes, sorted(rpc.ERROR_CODES))
        for code in ("unauthorized", "parse_error", "unknown_method", "internal_error", "target_running"):
            self.assertIn(code, codes)

    def test_no_string_literal_codes_remain_in_the_source(self):
        import re
        with open(rpc.__file__) as handle:
            source = handle.read()
        self.assertEqual(re.findall(r'RpcError\(\s*"', source), [])


class PagingAndBreakpointNameTests(unittest.TestCase):
    def test_pages_carry_the_repo_pagination_fields(self):
        dbg = FakeDbg(connected=True, status="paused")
        dbg.modules = [module("a", 1, 1), module("b", 2, 1), module("c", 3, 1)]
        h = make_handlers(dbg)
        first = h.modules({"limit": 2})
        self.assertEqual({k: first[k] for k in ("count", "total", "offset", "limit", "nextOffset", "truncated")},
                         {"count": 2, "total": 3, "offset": 0, "limit": 2, "nextOffset": 2, "truncated": True})
        last = h.modules({"limit": 2, "offset": 2})
        self.assertEqual((last["count"], last["nextOffset"], last["truncated"]), (1, None, False))
        beyond = h.modules({"offset": 9})
        self.assertEqual((beyond["count"], beyond["nextOffset"], beyond["truncated"]), (0, None, False))

    def test_breakpoint_kinds_use_the_words_of_the_hardware_parameter(self):
        dbg = FakeDbg(connected=True, status="paused")
        h = make_handlers(dbg)
        h.breakpoints({"action": "add", "address": 0x20})
        for kind in (1, 2, 3, 4):
            dbg.breakpoints.append(types.SimpleNamespace(address=0x30 + kind, module="", offset=0, enabled=True,
                                                         condition="", type=kind))
        self.assertEqual([b["type"] for b in h.breakpoints({})["breakpoints"]],
                         ["software", "execute", "read", "write", "access"])


class MutationReportingTests(unittest.TestCase):
    def setUp(self):
        self.dbg = FakeDbg(connected=True, status="paused")
        self.h = make_handlers(self.dbg)

    def error(self, params):
        with self.assertRaises(rpc.RpcError) as ctx:
            self.h.registers_write(params)
        return ctx.exception

    def test_memory_write_reports_before_and_after_and_is_never_undoable(self):
        reply = self.h.memory_write({"address": 0x10, "hex": "9090"})
        self.assertEqual(reply["mutation"], {"operation": "debugger.memory_write", "before": {"hex": "1011"},
                                             "after": {"hex": "9090"}, "undoable": False})
        self.assertEqual((reply["changed"], reply["address"], reply["length"]), (True, "0x10", 2))

    def test_rewriting_the_same_bytes_is_not_a_change(self):
        self.assertFalse(self.h.memory_write({"address": 0x10, "hex": "1011"})["changed"])

    def test_large_writes_skip_the_capture_and_say_so(self):
        big = "aa" * (rpc.MAX_MUTATION_CAPTURE_BYTES + 1)
        self.dbg.memory = bytearray(4096)
        reply = self.h.memory_write({"address": 0, "hex": big})
        self.assertEqual((reply["mutation"]["before"], reply["mutation"]["after"], reply["changed"]), (None, None, None))
        self.assertIn("not captured", reply["mutation"]["note"])
        self.assertEqual(bytes(self.dbg.memory[:2]), b"\xaa\xaa")          # the write itself still happened

    def test_an_unreadable_before_does_not_block_the_write(self):
        self.dbg.memory, self.dbg.read_ok = bytearray(4), False           # the debugger can write here but not read
        reply = self.h.memory_write({"address": 2, "hex": "ffff"})
        self.assertEqual(self.dbg.memory, bytearray([0, 0, 0xff, 0xff]))
        self.assertEqual((reply["mutation"]["before"], reply["changed"]), (None, None))

    def test_a_rejected_memory_write_raises(self):
        self.dbg.write_ok = False
        with self.assertRaises(rpc.RpcError) as ctx:
            self.h.memory_write({"address": 0x10, "hex": "90"})
        self.assertEqual(ctx.exception.code, "write_failed")

    def test_registers_write_reports_before_and_after(self):
        reply = self.h.registers_write({"values": {"x0": "0x10", "x1": "2"}})
        self.assertEqual(reply["mutation"], {"operation": "debugger.registers_write", "before": {"x0": "0x1", "x1": "0x2"},
                                             "after": {"x0": "0x10", "x1": "0x2"}, "undoable": False})
        self.assertTrue(reply["changed"])
        self.assertNotIn("registers", reply)
        self.assertFalse(self.h.registers_write({"values": {"x0": "0x10"}})["changed"])

    def test_a_bad_value_rejects_the_whole_call_before_any_write(self):
        err = self.error({"values": {"x0": "0x10", "x1": "not a number"}})
        self.assertEqual(err.code, "invalid_params")
        self.assertEqual(self.dbg.regs["x0"].value, 1)
        self.assertEqual(self.error({"values": {"x0": "0x10", "nope": "1"}}).code, "unknown_register")
        self.assertEqual(self.dbg.regs["x0"].value, 1)

    def test_a_failed_write_names_what_was_already_written(self):
        self.dbg.reg_fail = {"x1"}
        err = self.error({"values": {"x0": "0x10", "x1": "0x20"}})
        self.assertEqual(err.code, "write_failed")
        self.assertIn("x0", err.message)
        self.assertIn("already written", err.message)


class ThreadChangedTests(unittest.TestCase):
    """thread's "changed" says whether the call altered anything; selecting the thread that is already active does not."""

    def setUp(self):
        self.dbg = FakeDbg(connected=True, status="paused")
        self.dbg.threads = [types.SimpleNamespace(tid=1), types.SimpleNamespace(tid=2)]
        self.dbg.active_thread = self.dbg.threads[0]
        self.dbg.suspended = set()
        self.dbg.suspend_thread = lambda tid: self.dbg.suspended.add(tid) or True
        self.dbg.resume_thread = lambda tid: self.dbg.suspended.discard(tid) or True
        self.original = rpc.Handlers.raw_threads
        rpc.Handlers.raw_threads = staticmethod(lambda d: [(t.tid, 0x10, t.tid in d.suspended) for t in d.threads])
        self.h = make_handlers(self.dbg)

    def tearDown(self):
        rpc.Handlers.raw_threads = self.original

    def test_selecting_the_active_thread_changes_nothing(self):
        self.assertFalse(self.h.thread({"threadId": 1})["changed"])

    def test_selecting_another_thread_changes_the_active_one(self):
        reply = self.h.thread({"threadId": 2})
        self.assertEqual((reply["changed"], reply["activeThread"]), (True, 2))

    def test_suspend_and_resume_report_only_real_transitions(self):
        self.assertTrue(self.h.thread({"action": "suspend", "threadId": 2})["changed"])
        self.assertFalse(self.h.thread({"action": "suspend", "threadId": 2})["changed"])
        self.assertTrue(self.h.thread({"action": "resume", "threadId": 2})["changed"])
        self.assertFalse(self.h.thread({"action": "resume", "threadId": 2})["changed"])


class DiscoveryFileTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.saved = os.environ.pop("BN_DEBUGGER_RPC", None)
        sys.modules["binaryninja"].user_directory = lambda: self.dir

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)
        if self.saved is not None:
            os.environ["BN_DEBUGGER_RPC"] = self.saved

    def touch(self, name):
        path = os.path.join(self.dir, name)
        open(path, "w").close()
        return path

    def test_the_default_file_belongs_to_this_process(self):
        self.assertEqual(rpc.discovery_path(), os.path.join(self.dir, f"debugger-rpc-{os.getpid()}.json"))

    def test_the_environment_can_override_it(self):
        os.environ["BN_DEBUGGER_RPC"] = "/somewhere/else.json"
        self.assertEqual(rpc.discovery_path(), "/somewhere/else.json")

    def test_only_files_of_processes_that_are_gone_are_removed(self):
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        dead = self.touch(f"debugger-rpc-{child.pid}.json")
        mine = self.touch(f"debugger-rpc-{os.getpid()}.json")
        parent = self.touch(f"debugger-rpc-{os.getppid()}.json")   # alive and not ours
        others = [self.touch("debugger-rpc.json"), self.touch("debugger-rpc-abc.json"), self.touch("notes.txt")]
        rpc.remove_stale_discovery_files(self.dir)
        self.assertFalse(os.path.exists(dead))
        self.assertTrue(all(os.path.exists(p) for p in [mine, parent] + others))

    def test_a_missing_directory_is_not_an_error(self):
        rpc.remove_stale_discovery_files(os.path.join(self.dir, "nope"))


class WireProtocolTests(unittest.TestCase):
    """The endpoint over a real loopback socket, as the MCP layer talks to it."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "endpoint.json")
        self.saved = os.environ.get("BN_DEBUGGER_RPC")
        os.environ["BN_DEBUGGER_RPC"] = self.path
        self.server = rpc.DebuggerRpcServer().start()
        with open(self.path) as handle:
            self.info = json.loads(handle.read())

    def tearDown(self):
        import shutil
        self.server.stop()
        shutil.rmtree(self.dir, ignore_errors=True)
        if self.saved is None:
            os.environ.pop("BN_DEBUGGER_RPC", None)
        else:
            os.environ["BN_DEBUGGER_RPC"] = self.saved

    def call(self, request, raw=None):
        import socket
        with socket.create_connection(("127.0.0.1", self.info["port"]), timeout=5) as sock:
            sock.sendall(raw if raw is not None else (json.dumps(request) + "\n").encode())
            reply = b""
            while not reply.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                reply += chunk
        return json.loads(reply)

    def test_it_advertises_itself_privately(self):
        self.assertEqual((self.info["host"], self.info["pid"]), ("127.0.0.1", os.getpid()))
        self.assertEqual(self.info["token"], self.server.token)
        if sys.platform != "win32":
            self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_a_valid_request_gets_its_result_and_the_error_codes(self):
        reply = self.call({"id": 7, "token": self.info["token"], "method": "ping", "params": {}})
        self.assertEqual(reply["id"], 7)
        self.assertEqual(reply["result"]["errorCodes"], sorted(rpc.ERROR_CODES))

    def test_the_wrong_token_is_refused_before_any_work(self):
        reply = self.call({"id": 1, "token": "nope", "method": "ping"})
        self.assertEqual(reply["error"]["code"], "unauthorized")

    def test_unknown_methods_and_junk_are_answered_with_errors(self):
        self.assertEqual(self.call({"id": 1, "token": self.info["token"], "method": "sessions"})["error"]["code"],
                         "unknown_method")
        self.assertEqual(self.call(None, raw=b"POST / HTTP/1.1\n")["error"]["code"], "parse_error")

    def test_a_handler_bug_becomes_an_error_and_the_endpoint_keeps_serving(self):
        original = rpc.Handlers.ping
        rpc.Handlers.ping = lambda self, params: 1 / 0
        try:
            reply = self.call({"id": 1, "token": self.info["token"], "method": "ping"})
        finally:
            rpc.Handlers.ping = original
        self.assertEqual(reply["error"]["code"], "internal_error")
        self.assertIn("ZeroDivisionError", reply["error"]["message"])
        self.assertIn("result", self.call({"id": 2, "token": self.info["token"], "method": "ping"}))

    def test_stopping_removes_the_file_and_starting_again_works(self):
        self.server.stop()
        self.assertFalse(os.path.exists(self.path))
        self.server = rpc.DebuggerRpcServer().start()
        self.assertTrue(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
