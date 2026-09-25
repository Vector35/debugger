# ptrace engine test harness

This is the harness that the ptrace adapter was tested with. It is **not wired into CMake or CI**, and it is not part of
any commit. It tests the parts of the adapter that do not need Binary Ninja: the engine, the arch tables, the ELF reader,
the module grouping, the frame walker, and the stepper. It does **not** test `ptraceadapter.cpp`.

It runs real processes under real ptrace, so it needs Linux, and in a container it needs `--cap-add=SYS_PTRACE` and
`--security-opt seccomp=unconfined` (the default seccomp profile blocks `personality()`, which is used to disable ASLR).

Files:

| File | What it is |
| --- | --- |
| `driver.cpp` | The tests (87 of them). The `conf_*` tests run scenarios of `test/debugger_test.py` on the repository's own Linux test binaries, so they need `test/binaries/Linux-arm64` mounted at `/bins`, `api/` at `/api` and the Binary Ninja API at `/bnapi`. `./driver` runs all, `./driver <name>` runs one. |
| `progs.c` | The target programs the tests launch (`./progs <mode>`). |
| `libtest.c` | A small shared library, for the `dlopen` test. |
| `Dockerfile` | An Ubuntu 24.04 image with g++ and clang++. The sanitizer and `readelf` checks also need `binutils`, which comes with g++. |
| `run_all.sh` | Builds and runs everything: the full suite, then stress rounds, then single-CPU and two-CPU rounds. |
| `run_asan.sh`, `run_tsan.sh` | The same tests under AddressSanitizer + UBSan, and ThreadSanitizer. |
| `run_fork_exec.sh` | The fork and exec tests: stress rounds, single-CPU rounds, and both sanitizers. |
| `run_attach_redirect.sh` | The attach and redirect tests: the full suite, stress rounds, single-CPU rounds, and both sanitizers. Needs the `/bnapi` and `/bins` mounts as well. |
| `layout.cpp` | Checks the x86 and x86_64 register tables and debug-register offsets against the real `<sys/user.h>`. |
| `elfcmp.cpp`, `elfref.sh`, `cmp2.sh` | Compares the ELF symbol reader with `readelf`. |

The scripts expect `../../core/adapters` mounted at `/src` and this directory mounted at `/work`:

```bash
docker build -t ptrace-test test/ptrace_engine
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD/core/adapters:/src:ro" -v "$PWD/test/ptrace_engine:/work" ptrace-test bash /work/run_all.sh
```

Things to know:

- The harness was only ever run on **arm64** Linux. The engine must be given an architecture table, and the built-in
  ones are x86 and x86_64, so the tests use a **test-only aarch64 table** that is defined at the top of `driver.cpp`
  (registers, the `BRK` instruction, hardware debug registers through `NT_ARM_HW_BREAK` and `NT_ARM_HW_WATCH`). Several
  tests also decode arm64 instructions by hand (`bl`, `ret`) and read `x29`/`pc`/`sp` by offset. To run this on x86_64,
  those parts need an x86 version. That work has not been done.
- `progs.c` is built with `-no-pie -fno-omit-frame-pointer`. Some tests depend on that (the frame test, the address of
  `marker`).
- The tests named `repro_*` and `perf` print findings instead of asserting. They document known problems and
  measurements. See `PTRACE_ADAPTER_WRITEUP.md`.
