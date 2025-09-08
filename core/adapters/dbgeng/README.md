# WinDbg/TTD Installer Implementation

This directory contains the C++ implementation of the WinDbg/TTD automatic installer for Binary Ninja.

## Overview

The installer was rewritten from Python to C++ to allow it to work with both paid and free versions of Binary Ninja. The original Python implementation (`install_windbg.py`) was restricted to only work with paid versions due to the `#ifdef DEMO_EDITION` check in the UI code.

## Files

- `install_windbg.h` - Header file with function declarations
- `install_windbg.cpp` - Main implementation with Windows-specific code

## Functionality

The installer performs these steps:

1. **Download AppInstaller**: Downloads the appinstaller XML file from Microsoft's WinDbg download URL
2. **Parse XML**: Extracts the MSIX bundle URL from the appinstaller XML using pugixml
3. **Download MSIX Bundle**: Downloads the MSIX bundle containing WinDbg
4. **Extract Inner MSIX**: Extracts the `windbg_win-x64.msix` file from the bundle
5. **Extract WinDbg**: Extracts the actual WinDbg files to the user directory
6. **Validate Installation**: Checks that required files (dbgeng.dll, TTD.exe, etc.) are present
7. **Update Settings**: Sets the `debugger.x64dbgEngPath` setting to point to the installation

## Dependencies

- **Windows APIs**: URLDownloadToFileA for HTTP downloads, CreateProcess for PowerShell execution
- **pugixml**: For XML parsing (already included in the project)
- **PowerShell**: Used for ZIP extraction via System.IO.Compression.FileSystem
- **Standard C++20**: filesystem, string handling, etc.

## Libraries Required

- urlmon.lib - For URL downloading
- shell32.lib - For shell operations
- ole32.lib - For GUID generation

## UI Integration

The installer is called from `ui/ui.cpp` in the `GlobalDebuggerUI::installTTD()` function, which:
- Shows a progress dialog
- Runs the installer asynchronously using QTimer
- Displays success/failure messages

## Error Handling

The implementation includes comprehensive error handling:
- HTTP download failures
- XML parsing errors
- ZIP extraction failures
- File system errors
- Process execution errors

All errors are logged using Binary Ninja's logging system and reported to the user via message boxes.

## Testing

Basic functionality can be tested by compiling the XML parsing component separately. The ZIP extraction relies on PowerShell and Windows APIs, so it requires a Windows environment for full testing.