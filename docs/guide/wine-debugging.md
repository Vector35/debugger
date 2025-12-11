# Wine Debugging

Binary Ninja debugger supports debugging Windows PE files running under Wine on Linux. This is accomplished by using Wine's built-in `winedbg` debugger as a bridge between the Windows PE and Binary Ninja's LLDB adapter.

## Support Status

- **Supported**: Windows PE files running on Linux via Wine using Binary Ninja's LLDB adapter
- **Platform**: Linux hosts (not tested on macOS)
- **Target**: Windows PE executables (x86, x86_64)
- **Usability**: It works up to the limit of wine/winedbg itself, but is generally less stable than a true Windows debugging

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
3. Select **LLDB** as the debug adapter from the dropdown
4. Click the settings (wheel) button to open "Debug Adapter Settings"
5. Navigate to the "connect" settings group
6. Configure the connection:
   - **IP Address**: e.g., `127.0.0.1`
   - **Port**: `31337` (or whatever port you specified)
   - **Process Plugin**: `gdb-remote`

### 3. Connect to the Debug Server

1. Click "Accept" to save the settings
2. Click "Debugger" → "Connect to Remote Process" in the main menu
3. The debugger will connect to the winedbg server
4. You can now debug the Windows PE as if it were running natively

## Known Limitations and Workarounds

It is generally less stable than a true Windows debugging, please try to debug a Windows PE on Windows if possible.

### Stepping Over at Main Function Start

**Issue**: There is a known bug in winedbg where stepping over (`F8`) at the very beginning of the main function may cause the target to run free and exit unexpectedly.



## Related Documentation

- [Remote Debugging Guide](remote-debugging.md) - For other remote debugging scenarios
- [Wine Documentation](https://www.winehq.org/documentation) - Official Wine documentation