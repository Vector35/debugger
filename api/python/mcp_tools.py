# coding=utf-8
# Copyright 2020-2026 Vector 35 Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Registers the debugger's tools with Binary Ninja's MCP server.

Each ``debugger_*`` tool below is a thin wrapper over the existing ``DebuggerController`` Python
API (see ``debuggercontroller.py``): the MCP server resolves the session's active ``BinaryView``
before a handler runs, so a handler only has to look up (or create) that view's controller and
call the same methods a script would. Tools are registered once, when this module is imported
(see ``__init__.py``), per ``binaryninja.mcp``'s requirement that tools register when a plugin
loads.

This replaces an earlier loopback-socket RPC server prototype (see the ``debugger_mcp`` branch's
history before the revert at the root of this effort) that existed only because, at the time nothing
let a plugin add tools to Binary Ninja's MCP server in-process.
"""

import base64
import ctypes
from typing import Annotated, Any, Literal, Optional

from binaryninja import mcp

from . import _debuggercore as dbgcore
from .debuggercontroller import DebuggerController, DebugThread
from .debugger_enums import DebugBreakpointType


class Err:
    """
    Error codes used by the debugger's MCP tools. Kept as a named vocabulary (rather than inline
    string literals) so tests can check every code is covered and clients get a stable contract,
    continuing the vocabulary the old RPC-server prototype defined.
    """

    NO_CONTROLLER = "no_controller"
    TARGET_NOT_CONNECTED = "target_not_connected"
    TARGET_CONNECTED = "target_connected"
    TARGET_RUNNING = "target_running"
    TARGET_NOT_PAUSED = "target_not_paused"
    ACTION_FAILED = "action_failed"
    READ_FAILED = "read_failed"
    WRITE_FAILED = "write_failed"
    UNKNOWN_BREAKPOINT = "unknown_breakpoint"
    UNKNOWN_REGISTER = "unknown_register"
    UNKNOWN_THREAD = "unknown_thread"


_HARDWARE_KINDS = {
    "execute": DebugBreakpointType.BNHardwareExecuteBreakpoint,
    "read": DebugBreakpointType.BNHardwareReadBreakpoint,
    "write": DebugBreakpointType.BNHardwareWriteBreakpoint,
    "access": DebugBreakpointType.BNHardwareAccessBreakpoint,
}


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _controller_exists(bv) -> bool:
    # DebuggerController(bv) always creates a controller if one doesn't exist, so probe the
    # registry through the C ABI first to avoid auto-vivifying one just by inspecting a view that
    # has never been debugged.
    handle = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
    return bool(dbgcore.BNDebuggerControllerExists(handle))


# DebuggerController(bv) is a get-or-create lookup keyed by the native BinaryView, ref-counted
# through its handle: DebuggerController.__del__ frees that reference. A tool handler's local
# DebuggerController(bv) is otherwise the only reference, so it gets freed -- destroying the
# session and anything on it, like breakpoints -- the moment the handler returns, before the next
# MCP call can see it. Caching the Python wrapper here keeps a reference alive for the life of the
# process, the same way the GUI's own persistent `dbg` variable does.
_controllers: dict = {}


def _get_controller(bv) -> DebuggerController:
    session_id = bv.file.session_id
    cached = _controllers.get(session_id)
    if cached is not None and _controller_exists(bv):
        return cached
    dbg = DebuggerController(bv)
    _controllers[session_id] = dbg
    return dbg


def _require_controller(bv) -> DebuggerController:
    if not _controller_exists(bv):
        raise mcp.ToolError(Err.NO_CONTROLLER, "The active binary view has no debug session")
    return _get_controller(bv)


def _require_connected(bv) -> DebuggerController:
    dbg = _require_controller(bv)
    if not dbg.connected:
        raise mcp.ToolError(Err.TARGET_NOT_CONNECTED, "The target is not connected")
    return dbg


def _require_paused(bv) -> DebuggerController:
    dbg = _require_connected(bv)
    if dbg.running:
        raise mcp.ToolError(Err.TARGET_RUNNING, "The target is running; pause it first")
    return dbg


def _status_dict(dbg: DebuggerController) -> dict:
    status = {
        "connected": dbg.connected,
        "running": dbg.running,
    }
    if dbg.connected:
        status["activePid"] = dbg.active_pid
        if not dbg.running:
            status["ip"] = _hex(dbg.ip)
    # A resume action's most common outcome is the target exiting, which disconnects it -- so
    # stopReason/exitCode must not be conditioned on still being connected, or that exact case
    # (the "why did it stop" a caller asked for) silently drops both fields.
    if not dbg.running:
        status["stopReason"] = dbg.stop_reason.name
        status["exitCode"] = dbg.exit_code
    return status


def _breakpoint_dict(bp) -> dict:
    return {
        "address": _hex(bp.address),
        "module": bp.module,
        "offset": _hex(bp.offset),
        "enabled": bp.enabled,
        "condition": bp.condition,
        # bp.type is a plain int at runtime (the ctypes struct field isn't auto-cast to the
        # DebugBreakpointType enum the dataclass annotation claims), so cast it explicitly.
        "type": DebugBreakpointType(bp.type).name,
        "size": bp.size,
    }


def _require_existing_register(dbg: DebuggerController, name: str) -> None:
    if dbg.regs[name] is None:
        raise mcp.ToolError(Err.UNKNOWN_REGISTER, f"No register named '{name}'")


def _find_thread(dbg: DebuggerController, tid: int) -> DebugThread:
    for thread in dbg.threads:
        if thread.tid == tid:
            return thread
    raise mcp.ToolError(Err.UNKNOWN_THREAD, f"No thread with tid {tid}")


def _breakpoint_kind_type(kind: str) -> Optional[DebugBreakpointType]:
    return _HARDWARE_KINDS.get(kind)


# --------------------------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------------------------

@mcp.tool(idempotent=True)
def debugger_launch(
    call: mcp.ToolCall,
    executable_path: Optional[str] = None,
    arguments: Optional[str] = None,
    working_directory: Optional[str] = None,
) -> dict:
    """Launch the active binary view's target under the debugger.

    :param executable_path: Path of the executable to launch. Defaults to the binary view's input file.
    :param arguments: Command line arguments to pass to the target.
    :param working_directory: Working directory for the target.
    """
    bv = call.binary_view
    dbg = _get_controller(bv)
    if dbg.connected:
        raise mcp.ToolError(Err.TARGET_CONNECTED, "The target is already connected")
    if executable_path is not None:
        dbg.executable_path = executable_path
    if arguments is not None:
        dbg.cmd_line = arguments
    if working_directory is not None:
        dbg.working_directory = working_directory
    dbg.launch_and_wait()
    return _status_dict(dbg)


@mcp.tool()
def debugger_attach(call: mcp.ToolCall, pid: Optional[int] = None) -> dict:
    """Attach the debugger to a running process.

    :param pid: Process ID to attach to. Defaults to the last attached pid.
    """
    bv = call.binary_view
    dbg = _get_controller(bv)
    if dbg.connected:
        raise mcp.ToolError(Err.TARGET_CONNECTED, "The target is already connected")
    if pid is not None:
        dbg.pid_attach = pid
    dbg.attach_and_wait()
    return _status_dict(dbg)


@mcp.tool()
def debugger_connect(call: mcp.ToolCall, host: Optional[str] = None, port: Optional[int] = None) -> dict:
    """Connect the debugger to a remote target (e.g. a GDB/LLDB server).

    :param host: Remote host to connect to. Defaults to the last configured host.
    :param port: Remote port to connect to. Defaults to the last configured port.
    """
    bv = call.binary_view
    dbg = _get_controller(bv)
    if dbg.connected:
        raise mcp.ToolError(Err.TARGET_CONNECTED, "The target is already connected")
    if host is not None:
        dbg.remote_host = host
    if port is not None:
        dbg.remote_port = port
    dbg.connect_and_wait()
    return _status_dict(dbg)


@mcp.tool(destructive=True)
def debugger_detach(call: mcp.ToolCall) -> dict:
    """Detach the debugger from the target, leaving it running."""
    dbg = _require_paused(call.binary_view)
    dbg.detach_and_wait()
    return _status_dict(dbg)


@mcp.tool(destructive=True)
def debugger_quit(call: mcp.ToolCall) -> dict:
    """Terminate the target and end the debug session."""
    dbg = _require_connected(call.binary_view)
    dbg.quit_and_wait()
    return _status_dict(dbg)


@mcp.tool(destructive=True)
def debugger_restart(call: mcp.ToolCall) -> dict:
    """Restart the target under the debugger."""
    dbg = _require_connected(call.binary_view)
    dbg.restart_and_wait()
    return _status_dict(dbg)


# --------------------------------------------------------------------------------------------
# Execution control
# --------------------------------------------------------------------------------------------

@mcp.tool()
def debugger_go(call: mcp.ToolCall) -> dict:
    """Resume the target until it stops again (a breakpoint, a signal, or exit)."""
    dbg = _require_paused(call.binary_view)
    dbg.go_and_wait()
    return _status_dict(dbg)


@mcp.tool()
def debugger_step_into(call: mcp.ToolCall) -> dict:
    """Single-step the target, stepping into any call."""
    dbg = _require_paused(call.binary_view)
    dbg.step_into_and_wait()
    return _status_dict(dbg)


@mcp.tool()
def debugger_step_over(call: mcp.ToolCall) -> dict:
    """Single-step the target, stepping over any call."""
    dbg = _require_paused(call.binary_view)
    dbg.step_over_and_wait()
    return _status_dict(dbg)


@mcp.tool()
def debugger_step_return(call: mcp.ToolCall) -> dict:
    """Run the target until the current function returns."""
    dbg = _require_paused(call.binary_view)
    dbg.step_return_and_wait()
    return _status_dict(dbg)


@mcp.tool()
def debugger_run_to(call: mcp.ToolCall, address: mcp.Address) -> dict:
    """Resume the target until it reaches the given address.

    :param address: Address to run to.
    """
    dbg = _require_paused(call.binary_view)
    dbg.run_to_and_wait(address)
    return _status_dict(dbg)


@mcp.tool(idempotent=True)
def debugger_pause(call: mcp.ToolCall) -> dict:
    """Pause the running target."""
    dbg = _require_connected(call.binary_view)
    if not dbg.running:
        raise mcp.ToolError(Err.TARGET_NOT_CONNECTED, "The target is not running")
    dbg.pause_and_wait()
    return _status_dict(dbg)


# --------------------------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------------------------

@mcp.tool(read_only=True)
def debugger_status(call: mcp.ToolCall) -> dict:
    """Report whether the active binary view has a debug session and its current state."""
    bv = call.binary_view
    if not _controller_exists(bv):
        return {"connected": False, "running": False}
    return _status_dict(_get_controller(bv))


def _register_dict(reg) -> dict:
    return {"name": reg.name, "value": _hex(reg.value), "width": reg.width, "hint": reg.hint}


@mcp.tool(read_only=True)
def debugger_registers_get(call: mcp.ToolCall, name: Optional[str] = None, group: Literal["most", "all"] = "most") -> dict:
    """Read one or all registers of the target.

    :param name: Name of a single register to read. Takes priority over group.
    :param group: With no name, "most" (the default) returns general-purpose/pointer-sized
        registers (e.g. rax-r15, rip, rsp on x86_64); "all" additionally includes wide
        vector/FPU registers (e.g. xmm/ymm/zmm, NEON). Use name= to read one such register
        directly without requesting the whole "all" set.
    """
    dbg = _require_connected(call.binary_view)
    if name is not None:
        _require_existing_register(dbg, name)
        return {"registers": [_register_dict(dbg.regs[name])]}
    regs = list(dbg.regs.regs.values())
    if group == "most":
        pointer_bits = dbg.remote_arch.address_size * 8
        regs = [reg for reg in regs if reg.width <= pointer_bits]
    return {"registers": [_register_dict(reg) for reg in regs]}


@mcp.tool(idempotent=True)
def debugger_register_set(call: mcp.ToolCall, name: str, value: mcp.IntegerExpression) -> dict:
    """Write a register of the target.

    :param name: Name of the register to write.
    :param value: New value for the register.
    """
    dbg = _require_paused(call.binary_view)
    _require_existing_register(dbg, name)
    if not dbg.set_reg_value(name, value):
        raise mcp.ToolError(Err.ACTION_FAILED, f"Failed to set register '{name}'")
    return {"name": name, "value": _hex(dbg.get_reg_value(name))}


@mcp.tool(read_only=True)
def debugger_read_memory(
    call: mcp.ToolCall,
    address: mcp.Address,
    size: Annotated[int, mcp.Minimum(1), mcp.Maximum(0x10000)] = 0x10,
    encoding: Literal["hex", "base64"] = "hex",
) -> dict:
    """Read memory from the target.

    :param address: Address to read from.
    :param size: Number of bytes to read (up to 64 KiB).
    :param encoding: "hex" (default; easier to pattern-match pointers/strings by eye) or
        "base64" (more compact for larger reads).
    """
    dbg = _require_connected(call.binary_view)
    buffer = dbg.read_memory(address, size)
    if buffer is None or len(buffer) == 0:
        raise mcp.ToolError(Err.READ_FAILED, f"Failed to read memory at {_hex(address)}")
    raw = bytes(buffer)
    data = raw.hex() if encoding == "hex" else base64.b64encode(raw).decode("ascii")
    return {"address": _hex(address), "size": len(raw), "data": data, "encoding": encoding}


@mcp.tool(destructive=True)
def debugger_write_memory(call: mcp.ToolCall, address: mcp.Address, data: Annotated[str, mcp.NonEmpty()]) -> dict:
    """Write memory of the target.

    :param address: Address to write to.
    :param data: Bytes to write, as a hex string (e.g. "deadbeef").
    """
    dbg = _require_paused(call.binary_view)
    try:
        raw = bytes.fromhex(data)
    except ValueError:
        raise mcp.ToolError("invalid_params", "'data' must be a hex string")
    if not dbg.write_memory(address, raw):
        raise mcp.ToolError(Err.WRITE_FAILED, f"Failed to write memory at {_hex(address)}")
    return {"address": _hex(address), "size": len(raw)}


@mcp.tool(read_only=True)
def debugger_threads_list(call: mcp.ToolCall) -> dict:
    """List the threads of the target."""
    dbg = _require_connected(call.binary_view)
    return {
        "threads": [{"tid": thread.tid, "ip": _hex(thread.rip)} for thread in dbg.threads],
        "activeTid": dbg.active_thread.tid,
    }


@mcp.tool(idempotent=True)
def debugger_thread_select(call: mcp.ToolCall, tid: int) -> dict:
    """Select the active thread of the target.

    :param tid: Thread ID to make active.
    """
    dbg = _require_paused(call.binary_view)
    thread = _find_thread(dbg, tid)
    dbg.active_thread = thread
    return {"activeTid": dbg.active_thread.tid}


@mcp.tool(read_only=True)
def debugger_backtrace(call: mcp.ToolCall, tid: Optional[int] = None) -> dict:
    """Get the stack trace of a thread.

    :param tid: Thread ID to trace. Defaults to the active thread.
    """
    dbg = _require_paused(call.binary_view)
    thread_id = tid if tid is not None else dbg.active_thread.tid
    if tid is not None:
        _find_thread(dbg, tid)
    frames = dbg.frames_of_thread(thread_id)
    return {
        "tid": thread_id,
        "frames": [
            {
                "index": frame.index,
                "pc": _hex(frame.pc),
                "sp": _hex(frame.sp),
                "fp": _hex(frame.fp),
                "module": frame.module,
                "functionName": frame.func_name,
                "functionStart": _hex(frame.func_start),
            }
            for frame in frames
        ],
    }


@mcp.tool(read_only=True)
def debugger_modules_list(call: mcp.ToolCall) -> dict:
    """List the modules loaded in the target."""
    dbg = _require_connected(call.binary_view)
    return {
        "modules": [
            {
                "name": module.name,
                "shortName": module.short_name,
                "address": _hex(module.address),
                "size": module.size,
            }
            for module in dbg.modules
        ]
    }


@mcp.tool(read_only=True)
def debugger_memory_map(call: mcp.ToolCall) -> dict:
    """List the mapped memory regions of the target."""
    dbg = _require_connected(call.binary_view)
    return {
        "regions": [
            {
                "start": _hex(region.start),
                "size": region.size,
                "name": region.name,
                "permissions": region.permissions,
                "shared": region.shared,
            }
            for region in dbg.memory_map
        ]
    }


@mcp.tool(read_only=True)
def debugger_processes_list(call: mcp.ToolCall, query: Optional[str] = None) -> dict:
    """List processes available to attach to.

    :param query: Case-insensitive substring filter over process names.
    """
    dbg = _get_controller(call.binary_view)
    processes = dbg.processes
    if query is not None:
        needle = query.lower()
        processes = [process for process in processes if needle in process.name.lower()]
    return {
        "processes": [
            {"pid": process.pid, "name": process.name, "commandLine": process.command_line}
            for process in processes
        ]
    }


@mcp.tool(read_only=True)
def debugger_breakpoints_list(call: mcp.ToolCall) -> dict:
    """List the configured breakpoints."""
    if not _controller_exists(call.binary_view):
        return {"breakpoints": []}
    dbg = _get_controller(call.binary_view)
    return {"breakpoints": [_breakpoint_dict(bp) for bp in dbg.breakpoints]}


# --------------------------------------------------------------------------------------------
# Breakpoints
# --------------------------------------------------------------------------------------------

_BreakpointKind = Annotated[str, mcp.Schema({"type": "string", "enum": ["software", "execute", "read", "write", "access"]})]


@mcp.tool()
def debugger_breakpoint_set(
    call: mcp.ToolCall,
    address: mcp.Address,
    kind: _BreakpointKind = "software",
    size: Annotated[int, mcp.Minimum(1), mcp.Maximum(8)] = 1,
) -> dict:
    """Set a breakpoint at an address.

    :param address: Address to set the breakpoint at.
    :param kind: "software" for a normal breakpoint, or a hardware watchpoint kind.
    :param size: Size in bytes for a hardware watchpoint (1, 2, 4, or 8). Ignored for "software".

    The target must have been launched, attached to, or connected to at least once; a breakpoint
    set before that silently fails to register.
    """
    dbg = _get_controller(call.binary_view)
    hardware_kind = _breakpoint_kind_type(kind)
    # Neither add_breakpoint() (returns None always) nor add_hardware_breakpoint() (returns True
    # even on failure) reliably reports whether a breakpoint actually registered -- e.g. on a
    # controller that has never been launched/attached/connected, both silently no-op -- so success
    # has to be verified independently with has_breakpoint().
    if hardware_kind is None:
        dbg.add_breakpoint(address)
    else:
        dbg.add_hardware_breakpoint(address, hardware_kind, size)
    if not dbg.has_breakpoint(address):
        raise mcp.ToolError(
            Err.ACTION_FAILED,
            f"Failed to set a {kind} breakpoint at {_hex(address)}; launch, attach, or connect at least once first")
    return {"address": _hex(address), "kind": kind}


@mcp.tool(idempotent=True)
def debugger_breakpoint_delete(
    call: mcp.ToolCall,
    address: mcp.Address,
    kind: _BreakpointKind = "software",
    size: Annotated[int, mcp.Minimum(1), mcp.Maximum(8)] = 1,
) -> dict:
    """Delete a breakpoint at an address.

    :param address: Address of the breakpoint to delete.
    :param kind: "software" for a normal breakpoint, or a hardware watchpoint kind.
    :param size: Size in bytes for a hardware watchpoint (1, 2, 4, or 8). Ignored for "software".
    """
    dbg = _require_controller(call.binary_view)
    hardware_kind = _breakpoint_kind_type(kind)
    if hardware_kind is None:
        if not dbg.has_breakpoint(address):
            raise mcp.ToolError(Err.UNKNOWN_BREAKPOINT, f"No breakpoint at {_hex(address)}")
        dbg.delete_breakpoint(address)
    elif not dbg.delete_hardware_breakpoint(address, hardware_kind, size):
        raise mcp.ToolError(Err.UNKNOWN_BREAKPOINT, f"No {kind} breakpoint at {_hex(address)}")
    return {"address": _hex(address), "kind": kind}


@mcp.tool(idempotent=True)
def debugger_breakpoint_set_enabled(call: mcp.ToolCall, address: mcp.Address, enabled: bool = True) -> dict:
    """Enable or disable a breakpoint without deleting it.

    :param address: Address of the breakpoint.
    :param enabled: True to enable the breakpoint, False to disable it.
    """
    dbg = _require_controller(call.binary_view)
    if not dbg.has_breakpoint(address):
        raise mcp.ToolError(Err.UNKNOWN_BREAKPOINT, f"No breakpoint at {_hex(address)}")
    if enabled:
        dbg.enable_breakpoint(address)
    else:
        dbg.disable_breakpoint(address)
    return {"address": _hex(address), "enabled": enabled}


@mcp.tool(idempotent=True)
def debugger_breakpoint_condition_set(call: mcp.ToolCall, address: mcp.Address, condition: str = "") -> dict:
    """Set or clear a breakpoint's condition expression.

    :param address: Address of the breakpoint.
    :param condition: Expression evaluated when the breakpoint is hit; the debugger only stops if
        it is non-zero. Pass an empty string to clear the condition.
    """
    dbg = _require_controller(call.binary_view)
    if not dbg.has_breakpoint(address):
        raise mcp.ToolError(Err.UNKNOWN_BREAKPOINT, f"No breakpoint at {_hex(address)}")
    if not dbg.set_breakpoint_condition(address, condition):
        raise mcp.ToolError(Err.ACTION_FAILED, f"Failed to set the condition at {_hex(address)}")
    return {"address": _hex(address), "condition": condition}


# --------------------------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------------------------

@mcp.tool()
def debugger_write_stdin(call: mcp.ToolCall, data: str) -> dict:
    """Write to the target's standard input.

    :param data: Text to write.
    """
    dbg = _require_connected(call.binary_view)
    dbg.write_stdin(data)
    return {"written": len(data)}


@mcp.tool()
def debugger_execute_backend_command(call: mcp.ToolCall, command: Annotated[str, mcp.NonEmpty()]) -> dict:
    """Execute a backend-specific debugger command (e.g. a GDB/LLDB command) and return its output.

    :param command: Command text to execute.
    """
    dbg = _require_paused(call.binary_view)
    return {"output": dbg.execute_backend_command(command)}


@mcp.tool(read_only=True)
def debugger_property_get(call: mcp.ToolCall, name: Annotated[str, mcp.NonEmpty()]) -> dict:
    """Read an adapter-specific property of the target.

    :param name: Name of the property to read.
    """
    dbg = _require_connected(call.binary_view)
    return {"name": name, "value": dbg.get_adapter_property(name)}


@mcp.tool()
def debugger_property_set(
    call: mcp.ToolCall, name: Annotated[str, mcp.NonEmpty()], value: Annotated[Any, mcp.Schema({})]
) -> dict:
    """Set an adapter-specific property of the target.

    :param name: Name of the property to set.
    :param value: New value for the property.
    """
    dbg = _require_connected(call.binary_view)
    if not dbg.set_adapter_property(name, value):
        raise mcp.ToolError(Err.ACTION_FAILED, f"Failed to set property '{name}'")
    return {"name": name, "value": value}
