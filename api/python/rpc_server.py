#!/usr/bin/env python3
"""
Loopback JSON endpoint that exposes DebuggerController to out-of-process clients (prototype).

Binary Ninja's MCP server starts this by itself the first time a debugger tool needs it (when the
ui.mcp.debugger.enabled setting is on), so nothing has to run it by hand. To start it yourself, in Binary Ninja's
Python console:

    import binaryninja.debugger.rpc_server as rpc; rpc.start()

Wire format: one request per TCP connection, newline-terminated JSON in each direction.

    -> {"id": 1, "token": "<secret>", "method": "status", "params": {"session": 3, "filename": "/bin/ls"}}
    <- {"id": 1, "result": {...}}            or            {"id": 1, "error": {"code": "...", "message": "..."}}

The endpoint binds 127.0.0.1 only, requires the token on every request, and advertises itself by writing
<user directory>/debugger-rpc-<pid>.json (mode 0600) containing {host, port, token, pid}. There is one file per
process, so two Binary Ninja instances never overwrite each other's; files left behind by a process that died are
removed the next time an endpoint starts. Override the file with BN_DEBUGGER_RPC.

Sessions are identified by FileMetadata.session_id (a 64-bit value, so it travels as a decimal string), with the
original filename as a fallback. The endpoint has to run in the same process as the views it drives for
the debugger state to be shared with the UI; a separate process only ever sees the files it opened itself.

Headless:    python3 -m binaryninja.debugger.rpc_server /path/to/binary
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
from binaryninja.debugger import DebugAdapterType, DebuggerController, DebugStopReason
from binaryninja.debugger import _debuggercore as dbgcore
from binaryninja.debugger.debugger_enums import DebugAdapterTargetStatus, DebugBreakpointType

DEFAULT_WAIT_MS = 5000
MAX_WAIT_MS = 30000
MAX_READ_BYTES = 0x10000
MAX_LINE_BYTES = 1 << 20
MAX_SETTING_CHARS = 4096
MAX_TEXT_CHARS = 0x10000
MAX_HARDWARE_SIZE = 64
MAX_MUTATION_CAPTURE_BYTES = 1024
DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 1000
MAX_TRACE_ROWS = 5000
MIN_TRACE_STEP_MS = 500
MAX_TRACE_REGISTERS = 64
MAX_CONDITION_CHARS = 1024
UI_HOP_TIMEOUT_MS = 3000
_BRIEF_KEYS = ("state", "ip", "reason", "timedOut", "exitCode")

_ACTIONS_WHILE_RUNNING = {"pause", "quit"}
_ACTIONS_NEEDING_PAUSE = {"go", "step_into", "step_over", "step_return", "run_to", "detach"}
_ACTIONS_THAT_CREATE_CONTROLLER = {"launch", "attach", "connect"}
_HARDWARE_KINDS = {"execute": DebugBreakpointType.BNHardwareExecuteBreakpoint,
                   "read": DebugBreakpointType.BNHardwareReadBreakpoint,
                   "write": DebugBreakpointType.BNHardwareWriteBreakpoint,
                   "access": DebugBreakpointType.BNHardwareAccessBreakpoint}
_BREAKPOINT_KIND_NAMES = {kind: name for name, kind in _HARDWARE_KINDS.items()}
_BREAKPOINT_KIND_NAMES[DebugBreakpointType.BNSoftwareBreakpoint] = "software"
_STEP_ACTIONS = {"step_into", "step_over", "step_return"}
_FAILED_REASONS = {DebugStopReason.InternalError, DebugStopReason.InvalidStatusOrOperation}


class Err:
    """Every error code the endpoint can return. The MCP layer keeps a matching list, checked by its tests."""

    ACTION_FAILED = "action_failed"
    AMBIGUOUS_SESSION = "ambiguous_session"
    INTERNAL_ERROR = "internal_error"
    INVALID_PARAMS = "invalid_params"
    NO_CONTROLLER = "no_controller"
    PARSE_ERROR = "parse_error"
    PROCESSES_UNAVAILABLE = "processes_unavailable"
    READ_FAILED = "read_failed"
    TARGET_CONNECTED = "target_connected"
    TARGET_NOT_CONNECTED = "target_not_connected"
    TARGET_NOT_PAUSED = "target_not_paused"
    TARGET_RUNNING = "target_running"
    THREAD_SUSPENDED = "thread_suspended"
    UI_UNAVAILABLE = "ui_unavailable"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN_ADAPTER = "unknown_adapter"
    UNKNOWN_BREAKPOINT = "unknown_breakpoint"
    UNKNOWN_METHOD = "unknown_method"
    UNKNOWN_PROPERTY = "unknown_property"
    UNKNOWN_REGISTER = "unknown_register"
    UNKNOWN_SESSION = "unknown_session"
    UNKNOWN_THREAD = "unknown_thread"
    WRITE_FAILED = "write_failed"


ERROR_CODES = frozenset(v for k, v in vars(Err).items() if k.isupper())


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        if code not in ERROR_CODES:  # a typo here would otherwise ship as an error code nobody documents
            raise ValueError(f"{code!r} is not an Err code")
        self.code = code
        self.message = message


DISCOVERY_PREFIX = "debugger-rpc-"
DISCOVERY_SUFFIX = ".json"


def discovery_path():
    override = os.environ.get("BN_DEBUGGER_RPC")
    if override:
        return override
    return os.path.join(binaryninja.user_directory(), f"{DISCOVERY_PREFIX}{os.getpid()}{DISCOVERY_SUFFIX}")


def _process_exists(pid):
    if sys.platform == "win32":
        return True  # os.kill(pid, 0) would terminate the process there, so never guess that it is gone
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:  # PermissionError and the like: it exists, it just is not ours
        return True
    return True


def remove_stale_discovery_files(directory):
    """Deletes the discovery files of processes that no longer exist; a crashed Binary Ninja never got to stop()."""
    try:
        names = os.listdir(directory or ".")
    except OSError:
        return
    for name in names:
        if not (name.startswith(DISCOVERY_PREFIX) and name.endswith(DISCOVERY_SUFFIX)):
            continue
        pid_text = name[len(DISCOVERY_PREFIX):-len(DISCOVERY_SUFFIX)]
        if not pid_text.isdigit() or int(pid_text) == os.getpid() or _process_exists(int(pid_text)):
            continue
        try:
            os.remove(os.path.join(directory or ".", name))
        except OSError:
            pass


def controller_exists(bv):
    """DebuggerController(bv) always creates a controller, so probe the registry through the C ABI first."""
    handle = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
    return bool(dbgcore.BNDebuggerControllerExists(handle))


def _hex(value):
    return f"0x{value:x}"


def _int(params, name, required=True, default=None):
    if name not in params:
        if required:
            raise RpcError(Err.INVALID_PARAMS, f"Missing required parameter '{name}'")
        return default
    value = params[name]
    if isinstance(value, bool):
        raise RpcError(Err.INVALID_PARAMS, f"Parameter '{name}' must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise RpcError(Err.INVALID_PARAMS, f"Parameter '{name}' must be an integer")


class _GuiRequest:
    """One hop to the GUI thread that a caller is allowed to walk away from."""

    def __init__(self):
        self.done = threading.Event()
        self.result = None


def _collect_gui_state():
    """({session id: view}, open session ids) for the files open in the UI. Must run on the GUI thread.

    open_ids is None when the set of open files could not be determined; nothing may be pruned then.
    """
    from binaryninjaui import FileContext, UIContext

    views = {}

    def add(frame):
        bv = frame.getCurrentBinaryView() if frame else None
        if bv is not None:
            views[bv.file.session_id] = bv

    for context in UIContext.allContexts():
        add(context.getCurrentViewFrame())

    # A file open in a background tab is not any window's current tab, but it still has a file context.
    open_ids = None
    try:
        ids = set()
        for file_context in FileContext.getOpenFileContexts():
            raw = file_context.getRawData()
            if raw is not None:
                ids.add(raw.file.session_id)
            add(file_context.getCurrentViewFrame())
        open_ids = ids | set(views)
    except Exception:
        pass
    return views, open_ids


def _page(params, items):
    """One page of items and its metadata, from the offset and limit parameters."""
    offset = _int(params, "offset", required=False, default=0)
    limit = min(_int(params, "limit", required=False, default=DEFAULT_PAGE_LIMIT), MAX_PAGE_LIMIT)
    if offset < 0 or limit < 0:
        raise RpcError(Err.INVALID_PARAMS, "offset and limit must not be negative")
    page = items[offset:offset + limit]
    end = offset + len(page)
    truncated = end < len(items)
    return page, {"count": len(page), "total": len(items), "offset": offset, "limit": limit,
                  "nextOffset": end if truncated else None, "truncated": truncated}


def _jsonable(value):
    """Adapter properties come back as Binary Ninja metadata values, which are not all JSON."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)


class SessionTable:
    """View registry: the views the caller pinned, plus the view of every file open in the UI.

    Views discovered in the UI follow it: they are dropped once their file closes, so the registry never keeps a
    closed file alive. Pinned views (register, used headless) are the caller's to release with unregister.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._pinned = {}
        self._seen = {}
        self._pending = None

    def register(self, bv):
        with self._lock:
            self._pinned[bv.file.session_id] = bv

    def unregister(self, session_id):
        with self._lock:
            self._pinned.pop(session_id, None)

    def _finish(self, request, result):
        request.result = result
        with self._lock:
            if self._pending is request:
                self._pending = None
        request.done.set()

    def _run_on_gui_thread(self, request):
        try:
            result = _collect_gui_state()
        except Exception:  # e.g. binaryninjaui is unavailable; an exception here would otherwise vanish in ctypes
            result = None
        self._finish(request, result)

    def _gui_state(self):
        """(views, open_ids) from the GUI thread, or None if there is no UI or it did not answer in time.

        Never blocks longer than UI_HOP_TIMEOUT_MS, and at most one hop is in flight: while the GUI thread is
        stuck, later callers wait on that same request instead of queuing more work behind it.
        """
        if not binaryninja.core_ui_enabled():
            return None
        with self._lock:
            request = self._pending
            issue = request is None
            if issue:
                request = self._pending = _GuiRequest()
        if issue and binaryninja.mainthread.execute_on_main_thread(lambda: self._run_on_gui_thread(request)) is None:
            self._finish(request, None)
        if not request.done.wait(UI_HOP_TIMEOUT_MS / 1000.0):
            return None
        return request.result

    def _refresh(self):
        """(views by session id, fresh). fresh is False when the UI exists but could not be consulted in time."""
        state = self._gui_state()
        with self._lock:
            if state is not None:
                views, open_ids = state
                self._seen.update(views)
                if open_ids is not None:
                    self._seen = {sid: bv for sid, bv in self._seen.items() if sid in open_ids}
            merged = {**self._seen, **self._pinned}
        return merged, state is not None or not binaryninja.core_ui_enabled()

    def snapshot(self):
        return self._refresh()[0]

    def resolve(self, params):
        views, fresh = self._refresh()
        session = params.get("session")
        if session is not None:
            try:
                session_id = int(session)
            except (TypeError, ValueError):
                raise RpcError(Err.INVALID_PARAMS, "session must be an integer session id")
            if session_id in views:
                return views[session_id]
        filename = params.get("filename")
        if filename:
            matches = [v for v in views.values() if v.file.original_filename == filename]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise RpcError(Err.AMBIGUOUS_SESSION, f"{len(matches)} sessions have original filename {filename}")
        if not fresh:
            raise RpcError(Err.UI_UNAVAILABLE, f"Binary Ninja's UI thread did not answer within {UI_HOP_TIMEOUT_MS} ms "
                                             "and the session is not among the last known ones. The UI is probably "
                                             "busy (a modal dialog or a long UI operation); retry when it is idle.")
        known = [{"session": str(sid), "filename": v.file.original_filename} for sid, v in views.items()]
        raise RpcError(Err.UNKNOWN_SESSION, "No debugger-capable session matches the request "
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

    def existing_controller(self, params):
        """The session's controller, which must already exist (only launching, attaching and connecting create one)."""
        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError(Err.NO_CONTROLLER, "No debugger controller exists for this session")
        return dbg, bv

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

    @staticmethod
    def action_string(params, action, name, actions, allow_empty=False):
        """A string argument that only makes sense with some actions, or None when it is absent."""
        if name not in params:
            return None
        if action not in actions:
            raise RpcError(Err.INVALID_PARAMS, f"{name} can only be given with the {' or '.join(actions)} action")
        value = params[name]
        # A NUL would silently cut the string short where it crosses into C.
        if (not isinstance(value, str) or (not value and not allow_empty) or len(value) > MAX_SETTING_CHARS
                or "\0" in value):
            raise RpcError(Err.INVALID_PARAMS, f"{name} must be a {'' if allow_empty else 'non-empty '}string of at most "
                                             f"{MAX_SETTING_CHARS} characters with no NUL")
        return value

    @staticmethod
    def action_int(params, action, name, actions, minimum, maximum):
        """An integer argument that only makes sense with some actions, or None when it is absent."""
        if name not in params:
            return None
        if action not in actions:
            raise RpcError(Err.INVALID_PARAMS, f"{name} can only be given with the {' or '.join(actions)} action")
        value = _int(params, name)
        if not minimum <= value <= maximum:
            raise RpcError(Err.INVALID_PARAMS, f"{name} must be between {minimum} and {maximum}")
        return value

    def target_settings(self, params, action):
        """The launch and connection settings a call carries, validated but not yet applied."""
        launch = ("launch", "restart")
        settings = {
            "arguments": self.action_string(params, action, "arguments", launch, allow_empty=True),
            "adapter": self.action_string(params, action, "adapter", ("launch",)),
            "executablePath": self.action_string(params, action, "executablePath", launch),
            "workingDirectory": self.action_string(params, action, "workingDirectory", launch),
            "host": self.action_string(params, action, "host", ("connect",)),
            "port": self.action_int(params, action, "port", ("connect",), 1, 65535),
            "pid": self.action_int(params, action, "pid", ("attach",), 1, 0xFFFFFFFF),
        }
        return {name: value for name, value in settings.items() if value is not None}

    def apply_settings(self, dbg, bv, settings):
        # The adapter first: an unknown one is rejected before anything else changes.
        if "adapter" in settings:
            self.select_adapter(dbg, bv, settings["adapter"])
        for key, attribute in (("arguments", "cmd_line"), ("executablePath", "executable_path"),
                               ("workingDirectory", "working_directory"), ("host", "remote_host"),
                               ("port", "remote_port"), ("pid", "pid_attach")):
            if key in settings:
                setattr(dbg, attribute, settings[key])

    @staticmethod
    def select_adapter(dbg, bv, adapter):
        """Makes adapter the one the next launch uses. The debugger stores the name without checking it and only
        applies it when it next creates an adapter, so an unknown name would fail later and silently, and a change
        while a target is connected would not take effect."""
        if adapter == dbg.adapter_type:
            return
        available = DebugAdapterType.get_available_adapters(bv)
        if adapter not in available:
            raise RpcError(Err.UNKNOWN_ADAPTER, f"'{adapter}' cannot debug this binary view; available adapters: {available}")
        if dbg.connected:
            raise RpcError(Err.TARGET_CONNECTED, "The adapter can only be changed while no target is connected; "
                                               "use action 'quit' first.")
        dbg.adapter_type = adapter

    def require_paused(self, dbg):
        state = self.state(dbg)
        if state != "paused":
            raise RpcError(Err.TARGET_NOT_PAUSED, self._not_paused_message(state, "this operation"))

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
        return {"pid": os.getpid(), "version": 1, "errorCodes": sorted(ERROR_CODES)}

    def status(self, params):
        dbg, bv = self.controller(params)
        if dbg is None:
            return {"session": str(bv.file.session_id), "filename": bv.file.original_filename,
                    "state": "no_controller", "connected": False}
        return self.summarize(dbg, bv)

    def control(self, params):
        action = params.get("action")
        settings = self.target_settings(params, action)
        wait_ms = max(0, min(_int(params, "timeoutMs", required=False, default=DEFAULT_WAIT_MS), MAX_WAIT_MS))
        dbg, bv = self.controller(params, create=(action in _ACTIONS_THAT_CREATE_CONTROLLER))
        if dbg is None:
            raise RpcError(Err.NO_CONTROLLER, "No debugger controller exists for this session; use action 'launch' first")

        state = self.state(dbg)
        if state == "running" and action not in _ACTIONS_WHILE_RUNNING:
            raise RpcError(Err.TARGET_RUNNING, f"Refusing '{action}' while the target is running: the controller "
                                             "queues commands behind the running one and would run it later. "
                                             "Use 'pause' first.")
        if action in _ACTIONS_NEEDING_PAUSE and state != "paused":
            raise RpcError(Err.TARGET_NOT_PAUSED, self._not_paused_message(state, f"'{action}'"))
        if action in ("attach", "connect"):
            if dbg.connected:
                raise RpcError(Err.TARGET_CONNECTED, f"'{action}' needs no connected target; use 'quit' or 'detach' first.")
            if action == "attach" and not settings.get("pid", dbg.pid_attach):
                raise RpcError(Err.INVALID_PARAMS, "attach needs a pid")
            if action == "connect" and not (settings.get("host", dbg.remote_host) and settings.get("port", dbg.remote_port)):
                raise RpcError(Err.INVALID_PARAMS, "connect needs a host and a port")

        if action in _STEP_ACTIONS:
            active = dbg.active_thread.tid
            if any(tid == active and suspended for tid, _, suspended in self.raw_threads(dbg)):
                raise RpcError(Err.THREAD_SUSPENDED,
                               f"Thread {active} is the active thread but it is suspended, so '{action}' would never "
                               "complete and would leave the rest of the target running. Resume the thread, or make "
                               "another thread active, first.")

        self.apply_settings(dbg, bv, settings)

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
        elif action == "attach":
            reason = dbg.attach_and_wait(ms)
        elif action == "connect":
            reason = dbg.connect_and_wait(ms)
        elif action == "detach":
            dbg.detach_and_wait(ms)
            reason = None
        else:
            raise RpcError(Err.INVALID_PARAMS, f"Unknown action '{action}'")

        out = self.summarize(dbg, bv)
        out["action"] = action
        if reason is not None:
            reason_text = dbgcore.BNDebuggerGetStopReasonString(reason)
            if reason in _FAILED_REASONS:
                raise RpcError(Err.ACTION_FAILED, f"'{action}' did not run: the debugger reported {reason_text} "
                                                f"(target state: {out['state']})")
            out["reason"] = reason_text
            # reason already says why the call returned, and also covers TimedOut and ProcessExited, which stopReason
            # cannot; while paused the two matched in 480 of 481 logged replies. So it replaces stopReason here.
            out.pop("stopReason", None)
            out["timedOut"] = reason == DebugStopReason.TimedOut
            if reason == DebugStopReason.ProcessExited:
                out["exitCode"] = dbg.exit_code
        if params.get("brief"):
            out = {key: out[key] for key in _BRIEF_KEYS if key in out}
        return out

    def registers(self, params):
        dbg, bv = self.existing_controller(params)
        self.require_paused(dbg)
        names = params.get("names")
        regs = dbg.regs
        selected = names if names else sorted(regs.regs.keys())
        out = {}
        for name in selected:
            reg = regs[name]
            if reg is None:
                raise RpcError(Err.UNKNOWN_REGISTER, f"Unknown register '{name}'")
            out[name] = {"value": _hex(reg.value), "width": reg.width}
        return {"registers": out}

    def memory_read(self, params):
        dbg, bv = self.existing_controller(params)
        self.require_paused(dbg)
        address = _int(params, "address")
        length = _int(params, "length")
        if length <= 0 or length > MAX_READ_BYTES:
            raise RpcError(Err.INVALID_PARAMS, f"length must be between 1 and {MAX_READ_BYTES}")
        data = dbg.read_memory(address, length)
        raw = bytes(data) if data is not None else b""
        if len(raw) != length:
            raise RpcError(Err.READ_FAILED, f"Read {len(raw)} of {length} bytes at {_hex(address)}")
        return {"address": _hex(address), "length": length, "hex": raw.hex()}

    @staticmethod
    def read_hex(dbg, address, length):
        """The bytes at address as hex, or None when they cannot be read."""
        try:
            data = dbg.read_memory(address, length)
        except Exception:
            return None
        raw = bytes(data) if data is not None else b""
        return raw.hex() if len(raw) == length else None

    def memory_write(self, params):
        dbg, bv = self.existing_controller(params)
        self.require_paused(dbg)
        address = _int(params, "address")
        hex_data = params.get("hex")
        if not isinstance(hex_data, str):
            raise RpcError(Err.INVALID_PARAMS, "hex is required and must be a string")
        try:
            data = bytes.fromhex(hex_data)
        except ValueError:
            raise RpcError(Err.INVALID_PARAMS, "hex must be a hex string with an even number of digits")
        if not data:
            raise RpcError(Err.INVALID_PARAMS, "hex must not be empty")
        if len(data) > MAX_READ_BYTES:
            raise RpcError(Err.INVALID_PARAMS, f"length must be at most {MAX_READ_BYTES}")
        # Nothing on a live process can be undone, but the bytes it held before are what lets a caller restore them.
        capture = len(data) <= MAX_MUTATION_CAPTURE_BYTES
        before = self.read_hex(dbg, address, len(data)) if capture else None
        if not dbg.write_memory(address, data):
            raise RpcError(Err.WRITE_FAILED, f"Failed to write {len(data)} bytes at {_hex(address)}")
        after = self.read_hex(dbg, address, len(data)) if capture else None
        mutation = {"operation": "debugger.memory_write", "before": {"hex": before} if before else None,
                    "after": {"hex": after} if after else None, "undoable": False}
        if not capture:
            mutation["note"] = f"before and after are not captured for writes over {MAX_MUTATION_CAPTURE_BYTES} bytes"
        changed = (before != after) if before and after else None  # None: the bytes could not be compared
        return {"address": _hex(address), "length": len(data), "changed": changed, "mutation": mutation}

    def registers_write(self, params):
        dbg, bv = self.existing_controller(params)
        self.require_paused(dbg)
        values = params.get("values")
        if not isinstance(values, dict) or not values:
            raise RpcError(Err.INVALID_PARAMS, "values must be a non-empty object of register name -> value")
        regs = dbg.regs
        for name in values:
            if regs[name] is None:
                raise RpcError(Err.UNKNOWN_REGISTER, f"Unknown register '{name}'")
        parsed = {}
        for name, raw in values.items():  # Everything is checked before anything is written.
            value = _int({"value": raw}, "value")
            if value < 0 or value >= (1 << 512):
                raise RpcError(Err.INVALID_PARAMS, f"Value for register '{name}' is out of range")
            parsed[name] = value
        before = {name: _hex(regs[name].value) for name in parsed}
        after = {}
        for name, value in parsed.items():
            if not dbg.set_reg_value(name, value):
                done = f" (already written: {', '.join(after)})" if after else ""
                raise RpcError(Err.WRITE_FAILED, f"Failed to set register '{name}'{done}")
            after[name] = _hex(dbg.regs[name].value)
        return {"changed": after != before,
                "mutation": {"operation": "debugger.registers_write", "before": before, "after": after,
                             "undoable": False}}

    def trace(self, params):
        """Repeat go/step and record registers at every stop, so one call replaces hundreds."""
        action = params.get("action", "go")
        if action not in ("go", "step_into", "step_over"):
            raise RpcError(Err.INVALID_PARAMS, "trace action must be go, step_into or step_over")
        count = _int(params, "count", required=False, default=100)
        if count < 1 or count > MAX_TRACE_ROWS:
            raise RpcError(Err.INVALID_PARAMS, f"count must be between 1 and {MAX_TRACE_ROWS}")
        names = params.get("registers") or ["pc"]
        if (not isinstance(names, list) or not names or len(names) > MAX_TRACE_REGISTERS
                or not all(isinstance(n, str) for n in names)):
            raise RpcError(Err.INVALID_PARAMS, f"registers must be a list of 1 to {MAX_TRACE_REGISTERS} names")
        budget_ms = max(1, min(_int(params, "budgetMs", required=False, default=10000), MAX_WAIT_MS))
        step_timeout_ms = max(1, min(_int(params, "timeoutMs", required=False, default=DEFAULT_WAIT_MS), MAX_WAIT_MS))
        include_reason = bool(params.get("includeReason"))

        until = params.get("until")
        until_name = until_value = None
        if until is not None:
            if not isinstance(until, dict) or not isinstance(until.get("register"), str) or "value" not in until:
                raise RpcError(Err.INVALID_PARAMS, "until must be an object with a register name and a value")
            until_name, until_value = until["register"], _int(until, "value")

        dbg, bv = self.controller(params)
        if dbg is None:
            raise RpcError(Err.NO_CONTROLLER, "No debugger controller exists for this session; launch first")
        state = self.state(dbg)
        if state == "running":
            raise RpcError(Err.TARGET_RUNNING, f"Refusing to trace while the target is running. Use 'pause' first.")
        if state != "paused":
            raise RpcError(Err.TARGET_NOT_PAUSED, self._not_paused_message(state, "trace"))
        if action in _STEP_ACTIONS:
            active = dbg.active_thread.tid
            if any(tid == active and suspended for tid, _, suspended in self.raw_threads(dbg)):
                raise RpcError(Err.THREAD_SUSPENDED, f"Thread {active} is the active thread but it is suspended, so "
                                                   f"'{action}' would never complete.")
        regs = dbg.regs
        for name in names + ([until_name] if until_name else []):
            if regs[name] is None:
                raise RpcError(Err.UNKNOWN_REGISTER, f"Unknown register '{name}'")

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
            raise RpcError(Err.NO_CONTROLLER, "No debugger controller exists for this session")
        condition = params.get("condition")
        if condition is not None:
            if action not in ("add", "condition"):
                raise RpcError(Err.INVALID_PARAMS, "condition can only be given with the add or condition action")
            if not isinstance(condition, str) or len(condition) > MAX_CONDITION_CHARS or "\0" in condition:
                raise RpcError(Err.INVALID_PARAMS, f"condition must be a string of at most {MAX_CONDITION_CHARS} characters")
        hardware = params.get("hardware")
        if hardware is not None:
            if action not in ("add", "remove"):
                raise RpcError(Err.INVALID_PARAMS, "hardware can only be given with the add or remove action")
            if hardware not in _HARDWARE_KINDS:
                raise RpcError(Err.INVALID_PARAMS, f"hardware must be one of {sorted(_HARDWARE_KINDS)}")
            if condition is not None:
                raise RpcError(Err.INVALID_PARAMS, "condition is only supported on software breakpoints")
        size = self.action_int(params, action, "size", ("add", "remove"), 1, MAX_HARDWARE_SIZE)
        if size is not None and hardware is None:
            raise RpcError(Err.INVALID_PARAMS, "size only applies to hardware breakpoints")
        if action == "add":
            address = _int(params, "address")
            if hardware:
                if not dbg.add_hardware_breakpoint(address, _HARDWARE_KINDS[hardware], size or 1):
                    raise RpcError(Err.WRITE_FAILED, f"The debugger could not add a hardware {hardware} breakpoint of "
                                                   f"{size or 1} byte(s) at {_hex(address)}")
            else:
                dbg.add_breakpoint(address)
                if condition and not dbg.set_breakpoint_condition(address, condition):
                    dbg.delete_breakpoint(address)
                    raise RpcError(Err.WRITE_FAILED,
                                   f"The debugger rejected the condition {condition!r}; breakpoint not added")
        elif action == "condition":
            if condition is None:
                raise RpcError(Err.INVALID_PARAMS, "condition is required (use an empty string to clear it)")
            address = _int(params, "address")
            if address not in {b.address for b in dbg.breakpoints}:
                raise RpcError(Err.UNKNOWN_BREAKPOINT, f"No breakpoint at {_hex(address)}")
            if not dbg.set_breakpoint_condition(address, condition):
                raise RpcError(Err.WRITE_FAILED, f"The debugger rejected the condition {condition!r}")
        elif action == "remove":
            address = _int(params, "address")
            if hardware:
                if not dbg.delete_hardware_breakpoint(address, _HARDWARE_KINDS[hardware], size or 1):
                    raise RpcError(Err.WRITE_FAILED, f"The debugger could not remove a hardware {hardware} breakpoint "
                                                   f"of {size or 1} byte(s) at {_hex(address)}")
            else:
                dbg.delete_breakpoint(address)
        elif action in ("enable", "disable"):
            address = _int(params, "address")
            if address not in {b.address for b in dbg.breakpoints}:
                raise RpcError(Err.UNKNOWN_BREAKPOINT, f"No breakpoint at {_hex(address)}")
            (dbg.enable_breakpoint if action == "enable" else dbg.disable_breakpoint)(address)
        elif action != "list":
            raise RpcError(Err.INVALID_PARAMS, f"Unknown breakpoint action '{action}'")
        result = [{"address": _hex(b.address), "module": b.module, "offset": _hex(b.offset),
                   "enabled": bool(b.enabled), "condition": b.condition,
                   "type": _BREAKPOINT_KIND_NAMES.get(DebugBreakpointType(b.type), DebugBreakpointType(b.type).name)}
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
            raise RpcError(Err.INVALID_PARAMS, f"Unknown thread action '{action}'")
        dbg, bv = self.existing_controller(params)
        self.require_paused(dbg)

        tid = _int(params, "threadId")
        threads = {t.tid: t for t in dbg.threads}
        if tid not in threads:
            raise RpcError(Err.UNKNOWN_THREAD, f"No thread with id {tid}; known threads: {sorted(threads)}")
        was_suspended = {t: sus for t, _, sus in self.raw_threads(dbg)}.get(tid, False)
        previously_active = dbg.active_thread.tid

        if action == "select":
            dbg.active_thread = threads[tid]
            if dbg.active_thread.tid != tid:
                raise RpcError(Err.ACTION_FAILED, f"The debugger did not make thread {tid} active")
        elif action == "suspend":
            if not dbg.suspend_thread(tid):
                raise RpcError(Err.ACTION_FAILED, f"The debugger could not suspend thread {tid}")
        else:
            if not dbg.resume_thread(tid):
                raise RpcError(Err.ACTION_FAILED, f"The debugger could not resume thread {tid}")

        out = self.summarize(dbg, bv)
        out.update({"action": action, "threadId": tid, "activeThread": dbg.active_thread.tid,
                    "changed": (action == "select" and previously_active != tid)
                               or (action == "suspend" and not was_suspended) or (action == "resume" and was_suspended),
                    "threads": self.thread_list(dbg)})
        return out

    def backtrace(self, params):
        dbg, bv = self.existing_controller(params)
        self.require_paused(dbg)
        active = dbg.active_thread
        tid = _int(params, "threadId", required=False, default=active.tid)
        threads = self.thread_list(dbg)
        if tid not in {t.tid for t in dbg.threads}:
            raise RpcError(Err.UNKNOWN_THREAD, f"No thread with id {tid}; known threads: {[t.tid for t in dbg.threads]}")
        frames = [{"index": f.index, "pc": _hex(f.pc), "sp": _hex(f.sp), "fp": _hex(f.fp),
                   "function": f.func_name, "module": f.module} for f in dbg.frames_of_thread(tid)]
        return {"threads": threads, "threadId": tid, "frames": frames}


    def paused_controller(self, params):
        dbg, bv = self.existing_controller(params)
        self.require_paused(dbg)
        return dbg, bv

    def modules(self, params):
        action = params.get("action", "modules")
        if action not in ("modules", "memory_map", "resolve", "rebase"):
            raise RpcError(Err.INVALID_PARAMS, f"Unknown modules action '{action}'")
        dbg, bv = self.paused_controller(params)

        if action == "modules":
            items = [{"name": m.name, "shortName": m.short_name, "base": _hex(m.address), "size": _hex(m.size),
                      "loaded": bool(m.loaded)} for m in dbg.modules]
            page, meta = _page(params, items)
            base = dbg.get_remote_base()
            return {**meta, "remoteBase": _hex(base) if base is not None else None, "modules": page}
        if action == "memory_map":
            items = [{"start": _hex(r.start), "size": _hex(r.size), "name": r.name, "permissions": r.permissions,
                      "shared": bool(r.shared)} for r in dbg.memory_map]
            page, meta = _page(params, items)
            out = {**meta, "regions": page}
            if not items:
                out["note"] = "This adapter does not report a memory map."
            return out
        if action == "resolve":
            address = _int(params, "address")
            for m in dbg.modules:
                if m.address <= address < m.address + m.size:
                    return {"address": _hex(address), "module": m.name, "shortName": m.short_name,
                            "base": _hex(m.address), "offset": _hex(address - m.address)}
            return {"address": _hex(address), "module": None}

        explicit = "address" in params
        rebased = dbg.rebase_to_address(_int(params, "address")) if explicit else dbg.rebase_to_remote_base()
        if not rebased:
            raise RpcError(Err.ACTION_FAILED, "The debugger could not rebase the binary view"
                                            + ("" if explicit else " (it has not detected the target's base address)"))
        base = dbg.get_remote_base()
        return {"rebased": True, "remoteBase": _hex(base) if base is not None else None}

    def processes(self, params):
        dbg, bv = self.controller(params, create=True)
        try:
            found = list(dbg.processes)
        except Exception as ex:
            raise RpcError(Err.PROCESSES_UNAVAILABLE, f"The adapter could not list processes: {ex}")
        needle = params.get("filter")
        if needle is not None:
            if not isinstance(needle, str):
                raise RpcError(Err.INVALID_PARAMS, "filter must be a string")
            needle = needle.lower()
            found = [p for p in found if needle in p.name.lower() or needle in (p.command_line or "").lower()]
        items = [{"pid": p.pid, "name": p.name, "commandLine": p.command_line or ""} for p in found]
        page, meta = _page(params, items)
        return {**meta, "processes": page}

    def input(self, params):
        if ("stdin" in params) == ("command" in params):
            raise RpcError(Err.INVALID_PARAMS, "Give exactly one of stdin or command")
        name = "stdin" if "stdin" in params else "command"
        text = params[name]
        if (not isinstance(text, str) or (name == "command" and not text) or len(text) > MAX_TEXT_CHARS
                or "\0" in text):
            raise RpcError(Err.INVALID_PARAMS, f"{name} must be a{'' if name == 'stdin' else ' non-empty'} string of at "
                                             f"most {MAX_TEXT_CHARS} characters with no NUL")
        dbg, bv = self.existing_controller(params)
        if not dbg.connected:
            raise RpcError(Err.TARGET_NOT_CONNECTED, "There is no live target; use action 'launch', 'attach' or "
                                                   "'connect' first.")
        if name == "stdin":
            # The target is usually running while it waits for input, so this does not need it paused.
            dbg.write_stdin(text)
            return {"written": len(text)}
        self.require_paused(dbg)
        output = dbg.execute_backend_command(text) or ""
        return {"output": output[:MAX_TEXT_CHARS], "truncated": len(output) > MAX_TEXT_CHARS}

    def properties(self, params):
        names = params.get("get", [])
        values = params.get("set", {})
        if (not isinstance(names, list) or not all(isinstance(n, str) and n for n in names)
                or not isinstance(values, dict)
                or not all(isinstance(v, (bool, int, float, str)) for v in values.values())):
            raise RpcError(Err.INVALID_PARAMS, "get must be a list of property names and set an object of property "
                                             "name to a string, number or boolean")
        if not names and not values:
            raise RpcError(Err.INVALID_PARAMS, "Give get, set or both")
        dbg, bv = self.existing_controller(params)

        def read(name):
            try:
                return _jsonable(dbg.get_adapter_property(name))
            except KeyError:
                raise RpcError(Err.UNKNOWN_PROPERTY, f"The adapter has no property '{name}'")

        out = {name: read(name) for name in names}  # Reading first, so an unknown name is rejected before any change.
        for name, value in values.items():
            if not dbg.set_adapter_property(name, value):
                raise RpcError(Err.WRITE_FAILED, f"The adapter rejected property '{name}'")
            out[name] = read(name)
        return {"properties": out}


METHODS = {
    "ping": "ping", "status": "status", "control": "control",
    "registers": "registers", "memory.read": "memory_read", "breakpoints": "breakpoints",
    "backtrace": "backtrace", "thread": "thread", "trace": "trace",
    "memory.write": "memory_write", "registers.write": "registers_write",
    "modules": "modules", "processes": "processes", "input": "input", "properties": "properties",
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
            return {"id": None, "error": {"code": Err.PARSE_ERROR, "message": "Request must be one JSON object"}}
        rid = request.get("id")
        if not secrets.compare_digest(str(request.get("token", "")), self.server.token):
            return {"id": rid, "error": {"code": Err.UNAUTHORIZED, "message": "Missing or invalid token"}}
        handler_name = METHODS.get(request.get("method"))
        if handler_name is None:
            return {"id": rid, "error": {"code": Err.UNKNOWN_METHOD, "message": f"Unknown method {request.get('method')!r}"}}
        params = request.get("params") or {}
        try:
            return {"id": rid, "result": getattr(self.server.handlers, handler_name)(params)}
        except RpcError as ex:
            return {"id": rid, "error": {"code": ex.code, "message": ex.message}}
        except Exception as ex:  # never let a handler take the endpoint down
            # The caller only gets the one-line summary below; the traceback is what makes it diagnosable.
            binaryninja.log_error_for_exception(f"debugger-rpc: unhandled exception in {request.get('method')!r}")
            return {"id": rid, "error": {"code": Err.INTERNAL_ERROR, "message": f"{type(ex).__name__}: {ex}"}}


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
        remove_stale_discovery_files(os.path.dirname(self._path))
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
        sys.exit("usage: python3 -m binaryninja.debugger.rpc_server <binary> [<binary>...]")
    opened = [binaryninja.load(path, update_analysis=False) for path in sys.argv[1:]]
    server = start(*opened)
    print(f"debugger-rpc listening on 127.0.0.1:{server.port}; discovery file {discovery_path()}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        stop()
