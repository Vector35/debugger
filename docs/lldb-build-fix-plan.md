# LLDB Build Fix Plan for Arch Linux libxml2 Issue

## Problem Statement

On Arch Linux, the libxml2 library has been moved from `/usr/lib/libxml2.so.2` to `/usr/lib/libxml2.so.16`, breaking LLDB functionality in the debugger since our LLDB build links against `libxml2.so.2`.

Ubuntu (officially supported) still works because they maintain `/usr/lib/x86_64-linux-gnu/libxml2.so.2`.

## Root Cause

The LLDB binaries distributed in the lldb-artifacts releases are dynamically linked against system libraries (libxml2 and editline), causing compatibility issues across different Linux distributions.

## Proposed Solution

Build libxml2 and editline statically with LLDB to avoid system library dependencies. This requires:

1. Creating an llvm-build repository (similar to the existing qt-build repository)
2. Building libxml2 from source and statically linking it with LLDB
3. Building editline from source and statically linking it with LLDB
4. Publishing updated lldb-artifacts with bundled dependencies

## Implementation Steps

### 1. Create llvm-build Repository

Similar to Vector35/qt-build, create a new repository with:
- Build scripts for LLVM/LLDB
- Scripts to build libxml2 from source
- Scripts to build editline from source
- CMake configuration to static link dependencies
- Deployment scripts to package artifacts

### 2. Build Configuration Changes

The LLDB CMake configuration should:

```cmake
# Build libxml2 statically
set(LIBXML2_USE_STATIC_LIBS ON)
add_subdirectory(third_party/libxml2)

# Build editline statically
set(EDITLINE_USE_STATIC_LIBS ON)
add_subdirectory(third_party/editline)

# Link LLDB with static libraries
target_link_libraries(lldb PRIVATE libxml2_static editline_static)
```

### 3. Required Dependencies

#### libxml2
- Version: 2.11.x (latest stable)
- Source: http://xmlsoft.org/sources/
- Build options: `--enable-static --disable-shared --without-python --without-zlib --without-lzma`

####editline
- Version: Latest from libedit
- Source: https://thrysoee.dk/editline/
- Build options: `--enable-static --disable-shared --disable-examples`

### 4. Build Scripts

#### build_linux
```bash
#!/bin/bash
export PATH=~/.local/bin:$PATH
export PYTHONUNBUFFERED=1
poetry install --sync --no-root
poetry run python3 scripts/llvm_build.py "$@"
```

#### llvm_build.py (main build script)
```python
#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

# 1. Clone LLVM project
# 2. Build libxml2 statically
# 3. Build editline statically  
# 4. Configure LLVM/LLDB with static dependencies
# 5. Build LLDB
# 6. Package artifacts
```

### 5. Testing Plan

1. Build on Ubuntu 22.04 (verify no regression)
2. Build on Arch Linux (verify libxml2 issue is fixed)
3. Test debugger functionality:
   - Launch local process
   - Attach to process
   - Remote debugging
   - LLDB commands
4. Verify no system library dependencies:
   ```bash
   ldd liblldb.so | grep libxml2  # Should not find system libxml2
   ldd liblldb.so | grep editline # Should not find system editline
   ```

### 6. Documentation Updates

Update the following files:
- `build.md` - Add note about static dependencies
- `README.md` - Update Linux requirements
- Create `docs/building-lldb.md` with detailed LLDB build instructions

## Alternative Workarounds (Temporary)

Until the proper fix is implemented, users on Arch Linux can:

1. Create a symlink:
   ```bash
   sudo ln -s /usr/lib/libxml2.so.16 /usr/lib/libxml2.so.2
   ```

2. Or install the AUR package `libxml2-2.9` which provides the old version

## References

- Issue #735: Debugger cannot load properly on arch linux due to libxml2
- Issue #147: Missing libncurses and libpanel on Archlinux (similar issue)
- qt-build repository: https://github.com/Vector35/qt-build
- lldb-artifacts repository: https://github.com/Vector35/lldb-artifacts

## Next Steps

1. Get approval to create llvm-build repository
2. Implement build scripts based on qt-build pattern
3. Test on multiple Linux distributions
4. Update lldb-artifacts with new builds
5. Update debugger documentation
