# Windows Remote integration test results

`test/x2winrpc_test.py` exercises the real `X2WinRpcAdapter` and a locally spawned
`x2winstub.exe` over loopback. Internal identifiers and the wire protocol retain
their existing names.

## Validation on 2026-09-16

A full Windows-local run passed **30 tests, with no skips, in 57.18 seconds**.
Both client and server were built from this checkout using MSVC 19.44, x64
RelWithDebInfo, on Windows 11, with Binary Ninja 6.1.10638-dev Ultimate and
Python 3.11.9 / pytest 8.1.1. Shared-library fixtures were also built locally.

An earlier full run had 28 passes, one missing-fixture skip, and one failure:
`test_step_return` completed its stepping assertions, but Quit during cleanup
did not disconnect within 10 seconds. A focused rerun passed. The fixture gap
was then resolved, and missing fixtures now fail instead of skip. The cleanup
timeout recurred in a subsequent full run: **29 passed, one failed in 63.65
seconds**, this time in cleanup of `test_process_list_and_attach`. It is not
specific to StepReturn. The assertion is retained, with no automatic retries
or skip to hide it. This was the pre-fix baseline; see the follow-up below.

### Quit-timeout fix

The root cause was a false Resume event on interrupt acknowledgment, not the
StepReturn implementation. Removing that event fixes the incorrect transition
from Stopped to Running that caused Quit to wait for another stop indefinitely.
The new `test_interrupt_stopped_target_does_not_resume` failed on the old Windows
client with both a false Running state and a cleanup timeout, then passed on
the rebuilt fixed client. The suite now contains 31 tests. No wait limits were
relaxed and no retries or skips were added.

Three consecutive full Windows-local runs of the fixed client passed **31/31**
each (45.89s, 46.33s, 45.71s), with no skips or cleanup timeouts. The native
Windows and macOS client builds also passed. The Windows client DLL SHA-256 was
`ad54a8f6762875e5c675399852bf42b819e8572b98498e668aa7de86c88a0f88`;
the server was unchanged. These runs cover this regression, not all possible
controller races or the separate x86 StepReturn limitation.

The tested server used the previously authorized, exact-executable Defender
exclusion on the QA VM. This is not validation of default Defender behavior for
a release artifact.

## CI integration

Both Jenkins pipelines invoke `scripts/build.py`. On Windows it now includes
this suite alongside `debugger_test.py`, selects the freshly built server,
and propagates pytest failures. The suite owns server startup and cleanup;
no remote VM credentials or manually running server are needed. Results go
to the existing `test/results.xml` report. A 15-minute Windows process-tree
watchdog bounds otherwise stuck native calls.

This wiring has not yet been exercised by an actual Jenkins job. The results
above are a Windows-local run of the RPC suite, not the entire CI test suite.

## Restored coverage

- The running-target breakpoint test is enabled. It uses the ASLR-rebased view
  and waits for the original Go operation instead of issuing a second Go.
- The x64 StepReturn test enters both callees, including stepping over the NOP
  preceding the second call.
- Server startup failures and missing required binaries fail the suite.
  A deliberate missing-server run was verified to return exit code 1 with a
  setup error, not a skip.

## Coverage limitations

- Targets in this suite are x64. Separate manual x86/WOW64 testing found a
  StepReturn unwind problem shared with the native Windows adapter; it is not
  fixed or covered by this suite.
- `test_conditional_breakpoint_setting_roundtrip` checks get/set only, not
  runtime condition evaluation.
- Restart explicitly re-adds its breakpoint; it does not prove that automatic
  breakpoint carry-over is race-free.
- GUI-specific behavior, pending breakpoints on unloaded modules, working
  directories, and unsupported backend commands are not covered here.
