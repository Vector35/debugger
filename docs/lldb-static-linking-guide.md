# Technical Implementation Guide for LLDB Static Linking

This document provides detailed technical guidance for implementing static linking of libxml2 and editline in LLDB builds.

## Background

LLDB uses libxml2 for XML parsing (e.g., for parsing GDB-style XML target descriptions) and libedit/editline for command-line editing. By default, LLVM/LLDB builds link these dynamically, causing issues when library versions differ across Linux distributions.

## Solution Architecture

The solution involves modifying the LLDB build process to:
1. Build libxml2 from source with static library output
2. Build editline from source with static library output
3. Configure LLDB to link against these static libraries instead of system libraries
4. Ensure the resulting LLDB binary has no runtime dependencies on these libraries

## Detailed Implementation

### Step 1: Prepare Source Code

```bash
# Clone LLVM project
git clone --depth 1 --branch llvmorg-19.1.7 https://github.com/llvm/llvm-project.git
cd llvm-project

# Create third-party directory
mkdir -p third_party
cd third_party

# Download and extract libxml2
wget http://xmlsoft.org/sources/libxml2-2.11.6.tar.xz
tar -xf libxml2-2.11.6.tar.xz

# Download and extract editline
wget https://thrysoee.dk/editline/libedit-20230828-3.1.tar.gz
tar -xzf libedit-20230828-3.1.tar.gz
```

### Step 2: Build libxml2 Statically

```bash
cd libxml2-2.11.6

# Configure for static build
./configure \
    --prefix=$PWD/../install \
    --enable-static \
    --disable-shared \
    --without-python \
    --without-zlib \
    --without-lzma \
    --without-http \
    --without-ftp \
    --without-threads \
    --without-html \
    --without-docbook \
    --without-catalog \
    --without-modules \
    --without-debug \
    --without-mem-debug \
    --without-run-debug

# Build and install
make -j$(nproc)
make install
```

### Step 3: Build Editline Statically

```bash
cd ../libedit-20230828-3.1

# Configure for static build
./configure \
    --prefix=$PWD/../install \
    --enable-static \
    --disable-shared \
    --disable-examples

# Build and install
make -j$(nproc)
make install
```

### Step 4: Configure LLDB Build

Create a CMake options file `lldb-static-deps.cmake`:

```cmake
# Use static libraries for dependencies
set(LIBXML2_LIBRARY "${CMAKE_SOURCE_DIR}/third_party/install/lib/libxml2.a" CACHE FILEPATH "Path to libxml2 static library")
set(LIBXML2_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/third_party/install/include/libxml2" CACHE PATH "Path to libxml2 headers")
set(LIBXML2_DEFINITIONS "-DLIBXML_STATIC" CACHE STRING "libxml2 compiler definitions")

set(LibEdit_LIBRARY "${CMAKE_SOURCE_DIR}/third_party/install/lib/libedit.a" CACHE FILEPATH "Path to libedit static library")
set(LibEdit_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/third_party/install/include" CACHE PATH "Path to libedit headers")

# Force static linking
set(LLDB_ENABLE_LIBEDIT ON CACHE BOOL "Enable libedit support")
set(LLDB_ENABLE_LIBXML2 ON CACHE BOOL "Enable libxml2 support")

# Link flags to ensure static linking
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++" CACHE STRING "Linker flags")
```

### Step 5: Build LLDB

```bash
cd ../..
mkdir build
cd build

# Configure LLVM/LLDB with static dependencies
cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_PROJECTS="clang;lldb" \
    -DLLVM_TARGETS_TO_BUILD="X86;ARM;AArch64" \
    -DCMAKE_INSTALL_PREFIX=$PWD/install \
    -C ../third_party/lldb-static-deps.cmake \
    ../llvm

# Build
ninja lldb lldb-server

# Verify static linking
ldd bin/lldb | grep -E "libxml2|libedit"
# Should return nothing if successfully statically linked

# Check for symbols
nm bin/lldb | grep -i xml
# Should show symbols from statically linked libxml2
```

### Step 6: Verify the Build

```bash
# Test that LLDB works
./bin/lldb --version

# Verify no runtime dependencies on libxml2/editline
ldd ./bin/lldb | grep -E "libxml2|libedit|editline"
# Should produce no output

# Check linked libraries
readelf -d ./bin/lldb | grep NEEDED
# Should not list libxml2.so or libedit.so

# Test basic functionality
./bin/lldb -o "help" -o "quit"
# Should work without errors
```

## Troubleshooting

### Issue: Symbol conflicts

If you encounter symbol conflicts, ensure libxml2 is compiled with `-DLIBXML_STATIC`:

```cmake
add_compile_definitions(LIBXML_STATIC)
```

### Issue: Missing symbols at link time

Ensure all required static libraries are linked:

```cmake
target_link_libraries(lldb PRIVATE 
    ${LIBXML2_LIBRARY}
    ${LibEdit_LIBRARY}
    ncurses  # Often required by editline
)
```

### Issue: Runtime errors about missing XML support

Verify libxml2 was built with all required features:

```bash
grep -E "LIBXML_(READER|WRITER|XPATH)" third_party/libxml2-2.11.6/include/libxml/xmlversion.h
```

## Testing Checklist

- [ ] LLDB binary has no runtime dependency on libxml2.so
- [ ] LLDB binary has no runtime dependency on libedit.so/editline.so
- [ ] LLDB starts and shows version information
- [ ] LLDB can parse target XML (test with gdbserver)
- [ ] LLDB command-line editing works (arrow keys, history)
- [ ] LLDB can launch a simple program
- [ ] LLDB can attach to a running process
- [ ] LLDB can set and hit breakpoints

## Integration with Build System

The final build script should:

1. Download/extract LLVM, libxml2, and editline sources
2. Build dependencies statically
3. Configure and build LLDB with static dependencies
4. Package the resulting binaries into a zip file
5. Upload to lldb-artifacts releases

Example Python build script structure:

```python
def build_libxml2(source_dir, install_dir):
    """Build libxml2 statically"""
    configure_cmd = [
        "./configure",
        f"--prefix={install_dir}",
        "--enable-static",
        "--disable-shared",
        "--without-python",
        # ... other options
    ]
    subprocess.run(configure_cmd, cwd=source_dir, check=True)
    subprocess.run(["make", "-j", str(os.cpu_count())], cwd=source_dir, check=True)
    subprocess.run(["make", "install"], cwd=source_dir, check=True)

def build_editline(source_dir, install_dir):
    """Build editline statically"""
    # Similar to libxml2
    pass

def build_lldb(llvm_dir, deps_dir, install_dir):
    """Build LLDB with static dependencies"""
    cmake_cmd = [
        "cmake", "-G", "Ninja",
        f"-DCMAKE_BUILD_TYPE=Release",
        f"-DLLVM_ENABLE_PROJECTS=clang;lldb",
        f"-DLIBXML2_LIBRARY={deps_dir}/lib/libxml2.a",
        # ... other options
        f"{llvm_dir}/llvm"
    ]
    subprocess.run(cmake_cmd, cwd=build_dir, check=True)
    subprocess.run(["ninja", "lldb", "lldb-server"], cwd=build_dir, check=True)
```

## References

- LLVM CMake Documentation: https://llvm.org/docs/CMake.html
- libxml2 Build Documentation: http://www.xmlsoft.org/FAQ.html#Compilatio
- Editline Repository: https://github.com/troglobit/editline

## Notes

- This approach works for Linux. macOS and Windows may require different configurations.
- On macOS, you may need to adjust RPATH settings
- On Windows, static linking may require different flags and library names
- Consider building for multiple architectures (x86_64, aarch64, etc.)
