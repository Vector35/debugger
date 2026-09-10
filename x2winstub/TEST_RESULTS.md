# X2Win integration test results

Current status of `test/x2winrpc_test.py` (X2WinRpcAdapter <-> x2winstub, over the FlatBuffers RPC
protocol). See `STATUS.md` for root-cause detail on each open issue referenced below. Both
`debuggercore.dll` and `x2winstub.exe` must be rebuilt together, since they share the wire protocol
(`protocol/x2win.fbs`).

**26/28 tests pass.**

## Failing tests

- `test_step_return` -- `InternalError` on the second `step_return_and_wait()` call in a session.
  See STATUS.md #4.
- `test_breakpoint_set_on_running_target_triggers` -- a breakpoint set on a running target is
  rejected (STATUS.md #1), and the test's own cleanup then takes about a minute (STATUS.md #2).
  Give this test a generous timeout (90s+) when scripting a batch run, or run it last/in isolation.

## Passing but limited coverage

`test_conditional_breakpoint` only checks the condition get/set round-trip, not a real run through
`go_and_wait()` -- see STATUS.md #3 for why.

## Coverage gaps

32-bit (x86) target variant, `ExecuteWithArgs` with real args/working directory beyond `cmd_line`,
the pending-breakpoint-on-unloaded-module path, `InvokeBackendCommand` and `SupportFeature` (see
STATUS.md's "Not supported" list).
