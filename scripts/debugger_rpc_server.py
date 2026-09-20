#!/usr/bin/env python3
"""
Loopback JSON endpoint that exposes DebuggerController to out-of-process clients (prototype).

Wire format: one request per TCP connection, newline-terminated JSON in each direction.

    -> {"id": 1, "token": "<secret>", "method": "status", "params": {"session": 3, "filename": "/bin/ls"}}
    <- {"id": 1, "result": {...}}            or            {"id": 1, "error": {"code": "...", "message": "..."}}

The endpoint binds 127.0.0.1 only, requires the token on every request, and advertises itself by
writing <user directory>/debugger-rpc.json (mode 0600) containing {host, port, token, pid}.
Override the discovery file with BN_DEBUGGER_RPC.

Sessions are identified by FileMetadata.session_id (a 64-bit value, so it travels as a decimal string), with the
original filename as a fallback. The endpoint has to run in the same process as the views it drives for
the debugger state to be shared with the UI; a separate process only ever sees the files it opened itself.

Run inside Binary Ninja (Python console):    import debugger_rpc_server; debugger_rpc_server.start(bv)
Run headless:                                python3 debugger_rpc_server.py /path/to/binary
"""

import ctypes
import json
import os
import secrets
import socketserver
import sys
import threading
import time

import binaryninja
from binaryninja.debugger import DebuggerController, DebugStopReason
from binaryninja.debugger import _debuggercore as dbgcore
from binaryninja.debugger.debugger_enums import DebugAdapterTargetStatus, DebugBreakpointType

DEFAULT_WAIT_MS = 5000
MAX_WAIT_MS = 30000
MAX_READ_BYTES = 0x10000
MAX_LINE_BYTES = 1 << 20
MAX_ARGUMENTS_CHARS = 4096
MAX_TRACE_ROWS = 5000
MIN_TRACE_STEP_MS = 500
MAX_TRACE_REGISTERS = 64
MAX_CONDITION_CHARS = 1024
_BRIEF_KEYS = ("state", "ip", "stopReason", "reason", "timedOut", "exitCode")

_ACTIONS_WHILE_RUNNING = {"pause", "quit"}
_STEP_ACTIONS = {"step_into", "step_over", "step_return"}
_FAILED_REASONS = {DebugStopReason.InternalError, DebugStopReason.InvalidStatusOrOperation}


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def discovery_path():
    override = os.environ.get("BN_DEBUGGER_RPC")
    if override:
        return override
    return os.path.join(binaryninja.user_directory(), "debugger-rpc.json")


def controller_exists(bv):
    """DebuggerController(bv) always creates a controller, so probe the registry through the C ABI first."""
    handle = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
    return bool(dbgcore.BNDebuggerControllerExists(handle))


def _hex(value):
    return f"0x{value:x}"


def _int(params, name, required=True, default=None):
    if name not in params:
        if required:
            raise RpcError("invalid_params", f"Missing required parameter '{name}'")
        return default
    value = params[name]
    if isinstance(value, bool):
        raise RpcError("invalid_params", f"Parameter '{name}' must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise RpcError("invalid_params", f"Parameter '{name}' must be an integer")


class SessionTable:
    """View registry. In the UI the registry is refreshed from open tabs; headless it holds what we opened."""

    def __init__(self):
        self._lock = threading.Lock()
        self._views = {}

    def register(self, bv):
        with self._lock:
            self._views[bv.file.session_id] = bv

    def _ui_views(self):
        # Best effort: only available inside the Binary Ninja UI process, and only for each window's current tab.
        if not binaryninja.core_ui_enabled():
            return []
        try:
            from binaryninjaui import UIContext
        except Exception:
            return []

        views = []

        def collect():
            for context in UIContext.allContexts():
                frame = context.getCurrentViewFrame()
                bv = frame.getCurrentBinaryView() if frame else None
                if bv is not None:
                    views.append(bv)

        # Qt objects must only be touched from the GUI thread; request handlers run on worker threads.
        binaryninja.mainthread.execute_on_main_thread_and_wait(collect)
        return views

    def snapshot(self):
        for bv in self._ui_views():
            self.register(bv)
        with self._lock:
            return dict(self._views)

    def resolve(self, params):
        views = self.snapshot()
        session = params.get("session")
        if session is not None and int(session) in views:
            return views[int(session)]
        filename = params.get("filename")
        if filename:
            matches = [v for v in views.values() if v.file.original_filename == filename]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise RpcError("ambiguous_session", f"{len(matches)} sessions have original filename {filename}")
        known = [{"session": str(sid), "filename": v.file.original_filename} for sid, v in views.items()]
        raise RpcError("unknown_session", "No debugger-capable session matches the request "
                                          f"(session={session}, filename={filename}); known sessions: {known}")


class Handlers:
    def __init__(self, sessions):
        self.sessions = sessions

    def controller(self, params, create=False):
        bv = self.sessions.resolve(params)
        # BNGetDebuggerController creates a controller as a side effect, so only touch it when asked to.
        if not create and not controller_exists(bv):
            return None, bv
        return DebuggerController(bv), bv

    @staticmethod
    def state(dbg):
        if not dbg.connected:
            return "not_connected"
        status = dbg.target_status
        if status == DebugAdapterTargetStatus.DebugAdapterRunningStatus:
            return "running"
        if status == DebugAdapterTargetStatus.DebugAdapterPausedStatus:
            return "paused"
        return "unknown"

    @staticmethod
    def _not_paused_message(state, what):
        if state in ("not_connected", "no_controller"):
            return f"There is no live target ({state}); {what} needs a paused target. Use action 'launch' first."
        return f"Target is {state}; {what} needs a paused target"

    def require_paused(self, dbg):
        state = self.state(dbg)
        if state != "paused":
            raise RpcError("target_not_paused", self._not_paused_message(state, "this operation"))

    def summarize(self, dbg, bv):
        state = self.state(dbg)
        out = {"session": str(bv.file.session_id), "filename": bv.file.original_filename,
               "adapter": dbg.adapter_type, "state": state, "connected": bool(dbg.connected),
               "arguments": dbg.cmd_line or ""}
        if state == "paused":
            out["ip"] = _hex(dbg.ip)
            out["stopReason"] = dbg.stop_reason_str
        return out

    def ping(self, params):
        return {"pid": os.getpid(), "version": 1}

    def sessions_list(self, params):
        result = []
        for sid, bv in self.sessions.snapshot().items():
            exists = controller_exists(bv)
            entry = {"session": str(sid), "filename": bv.file.original_filename, "hasController": exists}
            if exists:
                entry.update(self.summarize(DebuggerController(bv), bv))
            result.append(entry)
        return {"sessions": result}

    def status(self, params):
        dbg, bv = self.controller(params)
        if dbg is None:
            return {"session": str(bv.file.session_id), "filename": bv.file.original_filename,
                    "state": "no_controller", "connected": False}
        return self.summarize(dbg, bv)

    @staticmethod
    def launch_arguments(params, action):
        """Command-line arguments for launch/restart, or None."""
        if "arguments" not in params:
            return None
        arguments = params["arguments"]
        if action not in ("launch", "restart"):
            raise RpcError("invalid_params", "arguments can only be given with the launch or restart action")
        if not isinstance(arguments, str):
            raise RpcError("invalid_params", "arguments must be a string")
        # A NUL would silently cut the string short where it crosses into C.
        if len(arguments) > MAX_ARGUMENTS_CHARS or "\0" in arguments:
            raise RpcError("invalid_params",
                           f"arguments must be at most {MAX_ARGUMENTS_CHARS} characters and contain no NUL")
        return arguments

    def control(self, params):
        action = params.get("action")
        arguments = self.launch_arguments(params, action)
        wait_ms = max(0, min(_int(params, "timeoutMs", required=False, default=DEFAULT_WAIT_MS), MAX_WAIT_MS))
        dbg, bv = self.controller(params, create=(action in ("launch",)))
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session; use action 'launch' first")

        state = self.state(dbg)
        if state == "running" and action not in _ACTIONS_WHILE_RUNNING:
            raise RpcError("target_running", f"Refusing '{action}' while the target is running: the controller "
                                             "queues commands behind the running one and would run it later. "
                                             "Use 'pause' first.")
        if action in ("go", "step_into", "step_over", "step_return", "run_to") and state != "paused":
            raise RpcError("target_not_paused", self._not_paused_message(state, f"'{action}'"))

        if action in _STEP_ACTIONS:
            active = dbg.active_thread.tid
            if any(tid == active and suspended for tid, _, suspended in self.raw_threads(dbg)):
                raise RpcError("thread_suspended",
                               f"Thread {active} is the active thread but it is suspended, so '{action}' would never "
                               "complete and would leave the rest of the target running. Resume the thread, or make "
                               "another thread active, first.")

        if arguments is not None:
            dbg.cmd_line = arguments

        ms = wait_ms
        if action == "launch":
            reason = dbg.launch_and_wait(ms)
        elif action == "go":
            reason = dbg.go_and_wait(ms)
        elif action == "step_into":
            reason = dbg.step_into_and_wait(timeout=ms)
        elif action == "step_over":
            reason = dbg.step_over_and_wait(timeout=ms)
        elif action == "step_return":
            reason = dbg.step_return_and_wait(ms)
        elif action == "run_to":
            reason = dbg.run_to_and_wait(_int(params, "address"), ms)
        elif action == "pause":
            reason = dbg.pause_and_wait(ms)
        elif action == "quit":
            dbg.quit_and_wait(ms)
            reason = None
        elif action == "restart":
            reason = dbg.restart_and_wait(ms)
        else:
            raise RpcError("invalid_params", f"Unknown action '{action}'")

        out = self.summarize(dbg, bv)
        out["action"] = action
        if reason is not None:
            reason_text = dbgcore.BNDebuggerGetStopReasonString(reason)
            if reason in _FAILED_REASONS:
                raise RpcError("action_failed", f"'{action}' did not run: the debugger reported {reason_text} "
                                                f"(target state: {out['state']})")
            out["reason"] = reason_text
            out["timedOut"] = reason == DebugStopReason.TimedOut
            if reason == DebugStopReason.ProcessExited:
                out["exitCode"] = dbg.exit_code
        if params.get("brief"):
            out = {key: out[key] for key in _BRIEF_KEYS if key in out}
        return out

    def registers(self, params):
        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session")
        self.require_paused(dbg)
        names = params.get("names")
        regs = dbg.regs
        selected = names if names else sorted(regs.regs.keys())
        out = {}
        for name in selected:
            reg = regs[name]
            if reg is None:
                raise RpcError("unknown_register", f"Unknown register '{name}'")
            out[name] = {"value": _hex(reg.value), "width": reg.width}
        return {"registers": out}

    def memory_read(self, params):
        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session")
        self.require_paused(dbg)
        address = _int(params, "address")
        length = _int(params, "length")
        if length <= 0 or length > MAX_READ_BYTES:
            raise RpcError("invalid_params", f"length must be between 1 and {MAX_READ_BYTES}")
        data = dbg.read_memory(address, length)
        raw = bytes(data) if data is not None else b""
        if len(raw) != length:
            raise RpcError("read_failed", f"Read {len(raw)} of {length} bytes at {_hex(address)}")
        return {"address": _hex(address), "length": length, "hex": raw.hex()}

    def memory_write(self, params):
        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session")
        self.require_paused(dbg)
        address = _int(params, "address")
        hex_data = params.get("hex")
        if not isinstance(hex_data, str):
            raise RpcError("invalid_params", "hex is required and must be a string")
        try:
            data = bytes.fromhex(hex_data)
        except ValueError:
            raise RpcError("invalid_params", "hex must be a hex string with an even number of digits")
        if not data:
            raise RpcError("invalid_params", "hex must not be empty")
        if len(data) > MAX_READ_BYTES:
            raise RpcError("invalid_params", f"length must be at most {MAX_READ_BYTES}")
        if not dbg.write_memory(address, data):
            raise RpcError("write_failed", f"Failed to write {len(data)} bytes at {_hex(address)}")
        return {"address": _hex(address), "length": len(data)}

    def registers_write(self, params):
        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session")
        self.require_paused(dbg)
        values = params.get("values")
        if not isinstance(values, dict) or not values:
            raise RpcError("invalid_params", "values must be a non-empty object of register name -> value")
        regs = dbg.regs
        for name in values:
            if regs[name] is None:
                raise RpcError("unknown_register", f"Unknown register '{name}'")
        written = {}
        for name, raw in values.items():
            value = _int({"value": raw}, "value")
            if value < 0 or value >= (1 << 512):
                raise RpcError("invalid_params", f"Value for register '{name}' is out of range")
            if not dbg.set_reg_value(name, value):
                raise RpcError("write_failed", f"Failed to set register '{name}'")
            written[name] = _hex(dbg.regs[name].value)
        return {"registers": written}

    def trace(self, params):
        """Repeat go/step and record registers at every stop, so one call replaces hundreds."""
        action = params.get("action", "go")
        if action not in ("go", "step_into", "step_over"):
            raise RpcError("invalid_params", "trace action must be go, step_into or step_over")
        count = _int(params, "count", required=False, default=100)
        if count < 1 or count > MAX_TRACE_ROWS:
            raise RpcError("invalid_params", f"count must be between 1 and {MAX_TRACE_ROWS}")
        names = params.get("registers") or ["pc"]
        if (not isinstance(names, list) or not names or len(names) > MAX_TRACE_REGISTERS
                or not all(isinstance(n, str) for n in names)):
            raise RpcError("invalid_params", f"registers must be a list of 1 to {MAX_TRACE_REGISTERS} names")
        budget_ms = max(1, min(_int(params, "budgetMs", required=False, default=10000), MAX_WAIT_MS))
        step_timeout_ms = max(1, min(_int(params, "timeoutMs", required=False, default=DEFAULT_WAIT_MS), MAX_WAIT_MS))
        include_reason = bool(params.get("includeReason"))

        until = params.get("until")
        until_name = until_value = None
        if until is not None:
            if not isinstance(until, dict) or not isinstance(until.get("register"), str) or "value" not in until:
                raise RpcError("invalid_params", "until must be an object with a register name and a value")
            until_name, until_value = until["register"], _int(until, "value")

        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session; launch first")
        state = self.state(dbg)
        if state == "running":
            raise RpcError("target_running", f"Refusing to trace while the target is running. Use 'pause' first.")
        if state != "paused":
            raise RpcError("target_not_paused", self._not_paused_message(state, "trace"))
        if action in _STEP_ACTIONS:
            active = dbg.active_thread.tid
            if any(tid == active and suspended for tid, _, suspended in self.raw_threads(dbg)):
                raise RpcError("thread_suspended", f"Thread {active} is the active thread but it is suspended, so "
                                                   f"'{action}' would never complete.")
        regs = dbg.regs
        for name in names + ([until_name] if until_name else []):
            if regs[name] is None:
                raise RpcError("unknown_register", f"Unknown register '{name}'")

        deadline = time.monotonic() + budget_ms / 1000.0
        rows, stopped, failure, exit_code = [], "count", None, None
        for _ in range(count):
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            # Don't start a stop that the budget cannot cover: it would time out and leave a stop in flight.
            if remaining_ms < min(step_timeout_ms, MIN_TRACE_STEP_MS):
                stopped = "budget"
                break
            wait = max(1, min(step_timeout_ms, remaining_ms))
            if action == "go":
                reason = dbg.go_and_wait(wait)
            elif action == "step_into":
                reason = dbg.step_into_and_wait(timeout=wait)
            else:
                reason = dbg.step_over_and_wait(timeout=wait)
            if reason == DebugStopReason.TimedOut:
                stopped = "budget" if wait < step_timeout_ms else "timeout"
                break
            if reason == DebugStopReason.ProcessExited:
                stopped, exit_code = "process_exited", dbg.exit_code
                break
            if reason in _FAILED_REASONS:
                stopped, failure = "failed", dbgcore.BNDebuggerGetStopReasonString(reason)
                break
            row = [_hex(dbg.get_reg_value(name)) for name in names]
            if include_reason:
                row.append(dbgcore.BNDebuggerGetStopReasonString(reason))
            rows.append(row)
            if until_name is not None and dbg.get_reg_value(until_name) == until_value:
                stopped = "until"
                break

        out = self.summarize(dbg, bv)
        result = {"action": action, "columns": names + (["reason"] if include_reason else []), "rows": rows,
                  "count": len(rows), "stoppedBecause": stopped, "state": out["state"]}
        for key in ("ip", "stopReason"):
            if key in out:
                result[key] = out[key]
        if failure:
            result["failure"] = failure
        if exit_code is not None:
            result["exitCode"] = exit_code
        return result

    def breakpoints(self, params):
        action = params.get("action", "list")
        dbg, bv = self.controller(params, create=(action == "add"))
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session")
        condition = params.get("condition")
        if condition is not None:
            if action not in ("add", "condition"):
                raise RpcError("invalid_params", "condition can only be given with the add or condition action")
            if not isinstance(condition, str) or len(condition) > MAX_CONDITION_CHARS or "\0" in condition:
                raise RpcError("invalid_params", f"condition must be a string of at most {MAX_CONDITION_CHARS} characters")
        if action == "add":
            address = _int(params, "address")
            dbg.add_breakpoint(address)
            if condition and not dbg.set_breakpoint_condition(address, condition):
                dbg.delete_breakpoint(address)
                raise RpcError("write_failed", f"The debugger rejected the condition {condition!r}; breakpoint not added")
        elif action == "condition":
            if condition is None:
                raise RpcError("invalid_params", "condition is required (use an empty string to clear it)")
            address = _int(params, "address")
            if address not in {b.address for b in dbg.breakpoints}:
                raise RpcError("unknown_breakpoint", f"No breakpoint at {_hex(address)}")
            if not dbg.set_breakpoint_condition(address, condition):
                raise RpcError("write_failed", f"The debugger rejected the condition {condition!r}")
        elif action == "remove":
            dbg.delete_breakpoint(_int(params, "address"))
        elif action != "list":
            raise RpcError("invalid_params", f"Unknown breakpoint action '{action}'")
        result = [{"address": _hex(b.address), "module": b.module, "offset": _hex(b.offset),
                   "enabled": bool(b.enabled), "condition": b.condition, "type": DebugBreakpointType(b.type).name}
                  for b in dbg.breakpoints]
        return {"breakpoints": result}

    @staticmethod
    def raw_threads(dbg):
        """(tid, ip, suspended) for every thread. The Python DebugThread drops the frozen flag, the C ABI keeps it."""
        count = ctypes.c_ulonglong()
        raw = dbgcore.BNDebuggerGetThreads(dbg.handle, count)
        try:
            return [(raw[i].m_tid, raw[i].m_rip, bool(raw[i].m_isFrozen)) for i in range(count.value)]
        finally:
            dbgcore.BNDebuggerFreeThreads(raw, count.value)

    def thread_list(self, dbg):
        active = dbg.active_thread.tid
        return [{"tid": tid, "ip": _hex(ip), "active": tid == active, "suspended": suspended}
                for tid, ip, suspended in self.raw_threads(dbg)]

    def thread(self, params):
        action = params.get("action", "select")
        if action not in ("select", "suspend", "resume"):
            raise RpcError("invalid_params", f"Unknown thread action '{action}'")
        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session")
        self.require_paused(dbg)

        tid = _int(params, "threadId")
        threads = {t.tid: t for t in dbg.threads}
        if tid not in threads:
            raise RpcError("unknown_thread", f"No thread with id {tid}; known threads: {sorted(threads)}")
        was_suspended = {t: sus for t, _, sus in self.raw_threads(dbg)}.get(tid, False)

        if action == "select":
            dbg.active_thread = threads[tid]
            if dbg.active_thread.tid != tid:
                raise RpcError("action_failed", f"The debugger did not make thread {tid} active")
        elif action == "suspend":
            if not dbg.suspend_thread(tid):
                raise RpcError("action_failed", f"The debugger could not suspend thread {tid}")
        else:
            if not dbg.resume_thread(tid):
                raise RpcError("action_failed", f"The debugger could not resume thread {tid}")

        out = self.summarize(dbg, bv)
        out.update({"action": action, "threadId": tid, "activeThread": dbg.active_thread.tid,
                    "changed": (action == "suspend" and not was_suspended) or (action == "resume" and was_suspended)
                               or action == "select",
                    "threads": self.thread_list(dbg)})
        return out

    def backtrace(self, params):
        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError("no_controller", "No debugger controller exists for this session")
        self.require_paused(dbg)
        active = dbg.active_thread
        tid = _int(params, "threadId", required=False, default=active.tid)
        threads = self.thread_list(dbg)
        if tid not in {t.tid for t in dbg.threads}:
            raise RpcError("unknown_thread", f"No thread with id {tid}; known threads: {[t.tid for t in dbg.threads]}")
        frames = [{"index": f.index, "pc": _hex(f.pc), "sp": _hex(f.sp), "fp": _hex(f.fp),
                   "function": f.func_name, "module": f.module} for f in dbg.frames_of_thread(tid)]
        return {"threads": threads, "threadId": tid, "frames": frames}


METHODS = {
    "ping": "ping", "sessions": "sessions_list", "status": "status", "control": "control",
    "registers": "registers", "memory.read": "memory_read", "breakpoints": "breakpoints",
    "backtrace": "backtrace", "thread": "thread", "trace": "trace",
    "memory.write": "memory_write", "registers.write": "registers_write",
}


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handlers, token):
        super().__init__(address, _Connection)
        self.handlers = handlers
        self.token = token


class _Connection(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            line = self.rfile.readline(MAX_LINE_BYTES + 1)
        except OSError:
            return
        if not line or len(line) > MAX_LINE_BYTES:
            return
        response = self._respond(line)
        try:
            self.wfile.write((json.dumps(response) + "\n").encode())
        except OSError:
            pass

    def _respond(self, line):
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError
        except ValueError:
            # Anything that is not a JSON object (e.g. a browser's "POST / HTTP/1.1") gets no token check and no work.
            return {"id": None, "error": {"code": "parse_error", "message": "Request must be one JSON object"}}
        rid = request.get("id")
        if not secrets.compare_digest(str(request.get("token", "")), self.server.token):
            return {"id": rid, "error": {"code": "unauthorized", "message": "Missing or invalid token"}}
        handler_name = METHODS.get(request.get("method"))
        if handler_name is None:
            return {"id": rid, "error": {"code": "unknown_method", "message": f"Unknown method {request.get('method')!r}"}}
        params = request.get("params") or {}
        try:
            return {"id": rid, "result": getattr(self.server.handlers, handler_name)(params)}
        except RpcError as ex:
            return {"id": rid, "error": {"code": ex.code, "message": ex.message}}
        except Exception as ex:  # never let a handler take the endpoint down
            return {"id": rid, "error": {"code": "internal_error", "message": f"{type(ex).__name__}: {ex}"}}


class DebuggerRpcServer:
    def __init__(self):
        self.sessions = SessionTable()
        self.token = secrets.token_hex(16)
        self._server = _Server(("127.0.0.1", 0), Handlers(self.sessions), self.token)
        self._thread = threading.Thread(target=self._server.serve_forever, name="debugger-rpc", daemon=True)
        self._path = discovery_path()

    @property
    def port(self):
        return self._server.server_address[1]

    def start(self):
        self._thread.start()
        info = {"host": "127.0.0.1", "port": self.port, "token": self.token, "pid": os.getpid()}
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(info, f)
        os.chmod(self._path, 0o600)
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
        try:
            os.remove(self._path)
        except OSError:
            pass


_server = None


def start(*views):
    global _server
    if _server is None:
        _server = DebuggerRpcServer().start()
    for bv in views:
        _server.sessions.register(bv)
    return _server


def stop():
    global _server
    if _server is not None:
        _server.stop()
        _server = None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <binary> [<binary>...]")
    opened = [binaryninja.load(path, update_analysis=False) for path in sys.argv[1:]]
    server = start(*opened)
    print(f"debugger-rpc listening on 127.0.0.1:{server.port}; discovery file {discovery_path()}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop()
