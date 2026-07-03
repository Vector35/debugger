# Build and test instructions

The full, multi-platform set of test binaries is built and signed by the
[debugger-test-binaries CI](https://github.com/Vector35/debugger/actions) and committed under
`binaries/<OS>-<arch>`. Running the unit tests does not require building any binaries.

## Run unit tests
```zsh
cd test
python3 debugger_test.py
```
Pass a keyword to run a subset, e.g. `python3 debugger_test.py shared_library`.

## Building test binaries alongside the debugger

Some test binaries are built alongside the debugger, so that adding a new test does not require a
separate build. This is on by default (`BUILD_DEBUGGER_TEST_BINARIES`), so both local and CI debugger
builds produce them; pass `-DBUILD_DEBUGGER_TEST_BINARIES=OFF` to skip.

The build stages the binaries defined in `CMakeLists.txt` into `binaries/<OS>-<arch>`, alongside the
committed test binaries. On macOS the debugger build then ad-hoc codesigns that directory into
`binaries/<OS>-<arch>-signed`, which is where the tests load them from. On a universal macOS build the
binaries are still emitted thin, one per architecture. These staged binaries are not committed. Tests
whose binaries were not built are skipped. Binaries that require additional toolchains (e.g. the nasm
assembly samples) remain pre-built by the CI.
