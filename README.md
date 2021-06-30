# native_debugger
Native Debugger for Binary Ninja


## Building

```
# Get the source
git clone https://github.com/Vector35/binaryninja-api.git
git clone https://github.com/Vector35/debugger_native.git
cd debugger_native
git checkout test_porting

# Do an out-of-source build
cd ../
mkdir build
cd build

# Build it
cmake -DBN_API_PATH=../binaryninja-api -DBN_INSTALL_DIR=/path/to/binaryninja/installation -DQT6=on ../debugger_native/
make -j8
```

Finally, copy the built `libdebugger.so/dll` to the user plugin folder and relaunch BinaryNinja.
