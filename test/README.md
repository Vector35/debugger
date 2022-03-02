# Build and test instructions

The debugger test binaries are now built by CMake. If you wish to run the unit test, there is no need to build these binaries. One only needs to build it when there are changes to the binaries.

## Run unit tests
```zsh
cd test
python3 unit.py
```

## macOS

- arm64
```zsh
cd test
cmake -DCMAKE_OSX_ARCHITECTURES=arm64 .
make
```
Build results are in `binaries/Darwin-arm64`.
- x86_64
```zsh
cd test
cmake -DCMAKE_OSX_ARCHITECTURES=x86_64 .
make
```
Build results are in `binaries/Darwin-x8_64`.

## Linux
- x86_64
- x86

## Windows
- x86_64
- x86