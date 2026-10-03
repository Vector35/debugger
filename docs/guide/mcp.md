# MCP Tools

The debugger registers its own tools with Binary Ninja's MCP server, alongside the built-in `bn_*` tools. An MCP client can launch, attach to, or connect to a target; step and resume it; and inspect or mutate its registers, memory, threads, and breakpoints, the same way a script would through [`DebuggerController`](index.md#api).

These tools are registered in-process when the debugger plugin loads -- there is no separate server, port, or authentication token to manage. They are offered by both the GUI's MCP server and the headless `binaryninja_mcp` server.

## Sessions

Every `debugger_*` tool operates on the MCP session's active BinaryView, the same way `bn_*` tools do. A view only has a debug session once a lifecycle tool (`debugger_launch`, `debugger_attach`, or `debugger_connect`) has been called for it; an inspection tool called before that returns the `no_controller` error rather than silently creating an un-launched session.

Breakpoints additionally require the target to have been launched, attached to, or connected to at least once in the session's lifetime -- a breakpoint set before that silently fails to register at the `DebuggerController` level, so `debugger_breakpoint_set` verifies the breakpoint actually took and reports `action_failed` if not. Once a target has been launched at least once, breakpoints persist across `debugger_quit` and a later relaunch.

Most tools additionally require the target to be connected (`target_not_connected`) or paused (`target_running`) before they act, matching the preconditions of the underlying `DebuggerController` methods.

## Tool Reference

Addresses are passed and returned as hex strings (`"0x401000"`), evaluated as Binary Ninja expressions against the active BinaryView, the same convention `bn_*` tools use.

### Lifecycle

| Tool | Description |
| --- | --- |
| `debugger_launch` | Launch the target. Accepts optional `executable_path`, `arguments`, `working_directory`. |
| `debugger_attach` | Attach to a running process. Accepts optional `pid`. |
| `debugger_connect` | Connect to a remote target. Accepts optional `host`, `port`. |
| `debugger_detach` | Detach, leaving the target running. |
| `debugger_quit` | Terminate the target and end the session. |
| `debugger_restart` | Restart the target. |

### Execution Control

| Tool | Description |
| --- | --- |
| `debugger_go` | Resume until the next stop. |
| `debugger_step_into` | Single-step, stepping into calls. |
| `debugger_step_over` | Single-step, stepping over calls. |
| `debugger_step_return` | Run until the current function returns. |
| `debugger_run_to` | Resume until `address` is reached. |
| `debugger_pause` | Pause a running target. |

### Inspection

| Tool | Description |
| --- | --- |
| `debugger_status` | Whether the view has a session, and its connected/running/stopped state. |
| `debugger_registers_get` | Read one register by `name`, or by `group`: `most` (default; general-purpose/pointer-sized registers) or `all` (also includes wide vector/FPU registers). |
| `debugger_register_set` | Write a register's value. |
| `debugger_read_memory` | Read up to 64 KiB of target memory, as hex (default) or base64 (`encoding`). |
| `debugger_write_memory` | Write a hex string of bytes to target memory. |
| `debugger_threads_list` | List threads and the active thread ID. |
| `debugger_thread_select` | Make a thread active by `tid`. |
| `debugger_backtrace` | Stack trace of a thread (defaults to the active one). |
| `debugger_modules_list` | List loaded modules. |
| `debugger_memory_map` | List mapped memory regions. |
| `debugger_processes_list` | List processes available to attach to, with an optional `query` filter. |
| `debugger_breakpoints_list` | List configured breakpoints. |

### Breakpoints

| Tool | Description |
| --- | --- |
| `debugger_breakpoint_set` | Set a breakpoint. `kind` is `software` (default) or a hardware watchpoint kind (`execute`, `read`, `write`, `access`), with an optional `size`. |
| `debugger_breakpoint_delete` | Delete a breakpoint. |
| `debugger_breakpoint_set_enabled` | Enable or disable (`enabled`) a breakpoint without deleting it. |
| `debugger_breakpoint_condition_set` | Set or clear (empty string) a breakpoint's condition expression. |

### Misc

| Tool | Description |
| --- | --- |
| `debugger_write_stdin` | Write text to the target's standard input. |
| `debugger_execute_backend_command` | Run a backend-specific command (e.g. a raw GDB/LLDB command) and return its output. |
| `debugger_property_get` | Read an adapter-specific property. |
| `debugger_property_set` | Write an adapter-specific property. |

Tracing (sampling registers across many steps) and code-coverage analysis are not yet exposed as MCP tools; use the [Python API](index.md#api) for those.

## Error Codes

Tools raise a machine-readable `errorCode` alongside a human-readable message, matching the `bn_*` tools' convention:

| Code | Meaning |
| --- | --- |
| `no_controller` | The view has no debug session yet. |
| `target_not_connected` | The action needs a connected target. |
| `target_connected` | A lifecycle tool was called on an already-connected target. |
| `target_running` | The action needs a paused target. |
| `action_failed` | The underlying `DebuggerController` call returned failure. |
| `read_failed` / `write_failed` | A memory read or write failed. |
| `unknown_breakpoint` / `unknown_register` / `unknown_thread` | The given address, register name, or thread ID does not exist. |
