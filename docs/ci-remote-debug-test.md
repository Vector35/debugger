# CI Remote Debugging Test

This document describes the CI test for remote debugging functionality.

## Overview

The CI test validates the remote debugging infrastructure by:

1. Starting an `lldb-server` process on localhost (127.0.0.1)
2. Establishing a connection to the server using GDB remote protocol
3. Verifying basic communication with the debug server

## Test Details

- **Platform**: Linux (Ubuntu) with lldb installed
- **Binary**: Uses the `helloworld` test binary from `test/binaries/Linux-x86_64/`
- **Protocol**: GDB Remote Serial Protocol via `lldb-server gdbserver`
- **Scope**: Infrastructure test - validates that remote debugging setup works

## Running the Test

The test runs automatically in GitHub Actions CI on every push and pull request.

To run manually:

```bash
cd test
python3 -c "
# Test script content from .github/workflows/test.yml
"
```

## Implementation

The test is implemented in:
- `.github/workflows/test.yml` - GitHub Actions workflow
- `test/debugger_test.py` - Additional unit test (when Binary Ninja dependencies are available)

## Purpose

This test ensures that:
- Remote debugging infrastructure components work correctly
- `lldb-server` can start and accept connections
- Basic GDB remote protocol communication functions
- CI environment can validate remote debugging changes