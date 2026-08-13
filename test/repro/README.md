# RspConnector lifetime race repro

Deterministic reproducer for the use-after-free on `m_rspConnector` shared by the
Gdb / Corellium / Esreven adapters (Sentry: BINARYNINJA-4E, C1, E1, E4, BX, H8, GB,
3X, ...; issues #1074 / #1066).

`rsp_race.cpp` drives the **real** `GdbAdapter` against an in-process fake GDB-RSP
server, with one thread looping `AddBreakpoint()` while another calls `Quit()` —
the same shape as the production crash (user action racing ResponseHandler's
teardown on target exit).

The Corellium and Esreven adapters are not exercised directly: all three share the
identical raw-pointer ownership pattern, and `GdbAdapter` is the one reachable
without external hardware or a Corellium account.

## Result

Both sides built from identical harness source, same ASan flags, same parameters
(`25` iterations x `4` breakpoints):

| build | outcome | wall clock |
| --- | --- | --- |
| `dev` @ c8585ad (unfixed) | ASan `heap-use-after-free` on **iteration 0** | 8s |
| + `AtomicRspConnector` fix | **25/25 iterations clean**, no ASan report | 24s |

The fixed run still exits non-zero: after the loop prints
`completed 25 iterations with no fault`, process teardown throws an uncaught
`condition_variable timed_wait failed: Invalid argument`. That is a harness
artifact — the driver deliberately leaks each adapter, so BN's worker threads are
still live at exit — not a memory error and not related to the race.

The failing report matches the Sentry stacks:

```
READ of size 8 ... thread T28
  #0 RspConnector::SendRaw(...)              rspconnector.cpp:223
  #1 RspConnector::SendPayload(...)          rspconnector.cpp:233
  #2 RspConnector::TransmitAndReceive(...)   rspconnector.cpp:315
  #3 GdbAdapter::AddBreakpoint(...)          gdbadapter.cpp:451
freed by thread T29 here:
  #1 GdbAdapter::Quit()                      gdbadapter.cpp:345
previously allocated by thread T0 here:
  #1 GdbAdapter::Connect(...)                gdbadapter.cpp:255
```

## Building

Needs an ASan-instrumented `debuggercore` **with default symbol visibility** —
`core/CMakeLists.txt` sets `CXX_VISIBILITY_PRESET hidden`, which makes
`GdbAdapter`'s symbols local and unlinkable from an external driver. Patch that to
`default` in a scratch worktree (do not commit it).

```sh
BN="$HOME/debugger_build/dependencies/BN-dev/Binary Ninja.app/Contents/MacOS"
API="$HOME/debugger_build/dependencies/api"

cmake -G Ninja -S <repo> -B build_asan \
  -DCMAKE_BUILD_TYPE=Debug -DHEADLESS=ON \
  -DBN_API_PATH="$API" -DBN_INSTALL_DIR="$BN" \
  -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address"
ninja -C build_asan debuggercore

c++ -std=c++20 -g -O0 -fsanitize=address -fno-omit-frame-pointer \
  test/repro/rsp_race.cpp \
  -I"$API" -I"$API/vendor/fmt/include" -I<repo>/core -I<repo> \
  build_asan/core/api/out/libbinaryninjaapi.a \
  build_asan/out/plugins/libdebuggercore.dylib \
  "$BN/libbinaryninjacore.dylib" \
  build_asan/core/api/vendor/fmt/libfmtd.a \
  -Wl,-rpath,"$PWD/build_asan/out/plugins" -Wl,-rpath,"$BN" \
  -framework CoreServices -o rsp_race
```

**Recompile the driver after applying the fix** — `AtomicRspConnector` changes
`sizeof(GdbAdapter)`, and a stale driver's inlined `new` under-allocates, which
shows up as an unrelated `heap-buffer-overflow` in the constructor.

## Running

```sh
ASAN_OPTIONS=detect_leaks=0 ./rsp_race <path-to-any-binary> [iterations] [breakpoints-per-iteration]
```

Keep `breakpoints-per-iteration` small (4 is the default). `Quit()` calls
`m_socket->Kill()`, so on the *fixed* build every `AddBreakpoint` issued after that
point runs `ReceiveRspData` to its full 10s timeout instead of faulting — a large
count makes a clean run take hours. On the unfixed build this never showed, because
it crashed on the first post-`Quit` call.

Two incidental findings, neither fixed here:

- `DebugAdapter::m_controller` is never initialized by the constructor, so
  `GetData()`'s `if (!m_controller)` guard reads uninitialized memory unless
  `SetController()` has been called. The harness calls `SetController(nullptr)`.
- `GdbAdapter::Connect()` ignores its `server` / `port` arguments and reads
  `connect.ipAddress` / `connect.port` from adapter settings instead.
