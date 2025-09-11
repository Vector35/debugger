# Wine Debugging

Binary Ninja debugger supports debugging Windows PE files running under Wine on Linux. This is accomplished by using Wine's built-in `winedbg` debugger as a bridge between the Windows PE and Binary Ninja's LLDB adapter.

## Support Status

- **Supported**: Windows PE files running on Linux via Wine using Binary Ninja's LLDB adapter
- **Platform**: Linux hosts only
- **Target**: Windows PE executables (x86, x86_64)
- **Performance**: Comparable to GDB, slightly slower than native debugging

## Prerequisites

### Wine Installation

First, ensure Wine is installed on your Linux system:

```bash
# On Ubuntu/Debian
sudo apt update
sudo apt install wine

# On Fedora/RHEL
sudo dnf install wine

# On Arch Linux
sudo pacman -S wine
```

### Verify Wine Installation

Test that Wine can run Windows executables:

```bash
wine --version
```

## Setup Process

### 1. Start winedbg Debug Server

Launch `winedbg` in GDB server mode for your Windows PE executable:

```bash
winedbg --gdb --port 31337 --no-start /path/to/your/program.exe
```

**Parameters:**
- `--gdb`: Enable GDB server mode
- `--port 31337`: Listen on port 31337 (you can use any available port)
- `--no-start`: Don't automatically start the program (wait for debugger connection)
- `/path/to/your/program.exe`: Path to your Windows PE executable

### 2. Configure Binary Ninja Debugger

1. Open your Windows PE file in Binary Ninja
2. Open the debugger sidebar
3. Click the settings (wheel) button to open "Debug Adapter Settings"
4. Select **LLDB** as the debug adapter
5. Navigate to the "connect" settings group
6. Configure the connection:
   - **IP Address**: `localhost` (or `127.0.0.1`)
   - **Port**: `31337` (or whatever port you specified)
   - **Process Plugin**: `gdb-remote`

### 3. Connect to the Debug Server

1. Click "Accept" to save the settings
2. Click "Debugger" → "Connect to Remote Process" in the main menu
3. The debugger will connect to the winedbg server
4. You can now debug the Windows PE as if it were running natively

## Debugging Workflow

### Basic Operations

Once connected, all standard debugging operations are available:

- **Breakpoints**: Set breakpoints by clicking in the gutter or using `F2`
- **Step Into**: `F7` or step into button
- **Step Over**: `F8` or step over button  
- **Continue**: `F9` or continue button
- **Registers**: View and modify register values in the register widget
- **Memory**: View and edit memory in the hex view
- **Stack**: View call stack in the stack trace widget

### Setting Breakpoints

You can set breakpoints before or after connecting to the target:

```python
# Using the Python API
dbg.add_breakpoint(0x140001010)  # Set breakpoint at specific address
```

Or use the UI:
- Right-click on a line and select "Toggle Breakpoint"
- Press `F2` on the desired line

### Example Session

```bash
# Terminal 1: Start winedbg server
$ winedbg --gdb --port 31337 --no-start ./helloworld.exe
011c:0120: create process 'Z:\path\to\helloworld.exe'/0000000000000000 @0000000140001338
# Server now listening...
```

Then in Binary Ninja:
1. Open `helloworld.exe`
2. Configure LLDB adapter to connect to `localhost:31337`
3. Connect to remote process
4. Set breakpoint at entry point or main function
5. Continue execution
6. Debug normally

## Known Limitations and Workarounds

### Stepping Over at Main Function Start

**Issue**: There is a known bug in winedbg where stepping over (`F8`) at the very beginning of the main function may cause the target to run free and exit unexpectedly.

**Workarounds**:
1. **Use Step Into**: Use `F7` (Step Into) instead of `F8` (Step Over) at the start of main
2. **Use Breakpoints**: Set a breakpoint a few instructions into the main function and continue to it
3. **Skip Initial Instructions**: Let the program run past the first few instructions of main before stepping

**Example**:
```python
# Instead of stepping over at the start of main:
# 1. Set a breakpoint a few instructions in
dbg.add_breakpoint(main_addr + 0x10)  # Skip first few instructions
dbg.go()  # Continue to breakpoint
# 2. Now step normally
dbg.step_over()
```

### Performance Considerations

- Wine debugging is slightly slower than native Linux debugging
- Performance is comparable to using GDB directly with winedbg
- Large applications may have longer startup times due to Wine overhead

### Compatibility

- Works with both 32-bit and 64-bit Windows PE files
- Tested with standard Windows executables
- May have issues with executables that use advanced Windows features
- System DLLs are emulated by Wine and may behave differently than on native Windows

## Troubleshooting

### Connection Issues

**Problem**: Binary Ninja cannot connect to winedbg server

**Solutions**:
1. Verify winedbg is running and listening:
   ```bash
   netstat -tlnp | grep 31337
   ```
2. Check firewall settings
3. Try a different port number
4. Ensure Wine can run the executable:
   ```bash
   wine /path/to/your/program.exe
   ```

### Debugging Session Hangs

**Problem**: Target appears to hang or becomes unresponsive

**Solutions**:
1. Check if stepping over at main function start (see Known Limitations)
2. Try using Step Into instead of Step Over
3. Set breakpoints instead of single-stepping
4. Restart both winedbg and Binary Ninja

### Symbol Loading Issues

**Problem**: Function names or symbols not appearing correctly

**Solutions**:
1. Ensure the PE file has debug information
2. Binary Ninja's analysis should provide function names
3. Wine may not load all system symbols - this is expected

## Advanced Usage

### Multiple Debug Sessions

You can debug multiple Wine processes by using different ports:

```bash
# Terminal 1
winedbg --gdb --port 31337 --no-start ./app1.exe

# Terminal 2  
winedbg --gdb --port 31338 --no-start ./app2.exe
```

### Using with Different Wine Prefixes

```bash
# Set up a specific Wine prefix for debugging
export WINEPREFIX=~/.wine-debug
winecfg  # Configure as needed

# Launch winedbg in that prefix
WINEPREFIX=~/.wine-debug winedbg --gdb --port 31337 --no-start ./program.exe
```

### Integration with Existing Wine Applications

If you have a complex Wine setup or need to debug an application that's already installed in Wine:

```bash
# Navigate to the Wine prefix
cd ~/.wine/drive_c/path/to/application/
winedbg --gdb --port 31337 --no-start ./application.exe
```

## Comparison with Other Methods

| Method | Pros | Cons |
|--------|------|------|
| Wine + winedbg + Binary Ninja LLDB | Full BN UI, good performance | Setup complexity, wine limitations |
| Wine + GDB directly | Simple setup | Command-line only, no BN integration |
| Windows VM + Remote debugging | Native Windows debugging | Requires Windows license, VM overhead |
| Wine + winedbg + GDB | More stable | Command-line only |

## Related Documentation

- [Remote Debugging Guide](remote-debugging.md) - For other remote debugging scenarios
- [LLDB Adapter Documentation](index.md#lldb-adapter) - More details on LLDB adapter configuration
- [Wine Documentation](https://www.winehq.org/documentation) - Official Wine documentation

## Contributing

If you encounter issues or have improvements for Wine debugging support, please:

1. Test with the `helloworld.exe` in the test suite
2. File an issue with reproduction steps
3. Include Wine version, Linux distribution, and Binary Ninja version
4. Provide sample executables when possible (if they can be shared publicly)