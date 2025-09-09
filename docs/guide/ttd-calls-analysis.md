# TTD.Calls Analysis in Binary Ninja Debugger

This document describes how to use the TTD.Calls analysis feature in the Binary Ninja debugger, which allows you to extract and analyze function call information from Time Travel Debugging (TTD) traces.

## Overview

TTD.Calls provides detailed information about function calls captured during TTD recording sessions. This feature is based on Microsoft's TTD.Calls object documentation and supports both basic and filtered queries.

## Requirements

- Windows system with WinDbg/TTD installed
- DbgEng TTD adapter configured
- A TTD trace file (.run file)

## Accessing TTD.Calls

### Via Menu
1. Open a binary view associated with a TTD trace
2. Connect to the TTD trace using the DbgEng TTD adapter
3. Navigate to **Debugger → TTD → TTD Calls Analysis**
4. The TTD Calls sidebar widget will open

### Via Sidebar
The TTD Calls widget is available in the sidebar under "TTD Calls" when working with TTD traces.

## Using the TTD.Calls Widget

### Query Interface

#### Symbol Patterns
Enter one or more symbol patterns in the "Symbol(s)" field:

**Examples:**
- `"kernel32!*"` - All calls to functions in kernel32.dll
- `"kernel32!GetProcAddress"` - Calls to specific function
- `"module!symbol1", "module!symbol2"` - Multiple specific functions
- `"*!CreateFile*"` - Functions containing "CreateFile" in any module

#### Address Range Filtering (Optional)
Enable "Filter by Return Address Range" to limit results to calls that return to specific address ranges:

**Format:** `0x7ff7967a0000-0x7ff7967a7000`

This is useful for focusing on calls from specific modules or code regions.

### Results Display

The results table shows the following information for each function call:

| Column | Description |
|--------|-------------|
| Index | Call event index |
| Thread ID | OS thread ID that made the call |
| Unique Thread ID | Unique thread identifier across the trace |
| Function | Symbolic name of the called function |
| Function Address | Memory address of the function |
| Return Address | Instruction address to return to after the call |
| Return Value | Function return value (if available) |
| Time Start | TTD position when call started (format: sequence:step) |
| Time End | TTD position when call ended |
| Parameters | Function parameters (if available) |

### Navigation and Actions

#### Double-Click Actions
- **Function Address/Return Address columns**: Navigate to the address in Binary Ninja

#### Context Menu (Right-Click)
- **Copy**: Copy selected rows to clipboard
- **Go to Function**: Navigate to the function address
- **Go to Return Address**: Navigate to the return address
- **Set TTD Position to Start**: Set the TTD playback position to the call's start time

### Exporting Results

Click the **Export...** button to save results to a CSV file for further analysis.

## Query Examples

### Basic Usage
```
Symbol: "kernel32!*"
```
Finds all calls to functions in kernel32.dll.

### Multiple Functions
```
Symbol: "kernel32!GetProcAddress", "kernel32!LoadLibrary", "ntdll!LdrLoadDll"
```
Finds calls to specific functions across multiple modules.

### With Address Filter
```
Symbol: "*!*"
Address Range: 0x7ff7967a0000-0x7ff7967a7000
```
Finds all function calls where the return address is within the specified range.

### Specific Module Analysis
```
Symbol: "mymodule!*"
```
Analyzes all function calls within a specific module.

## Technical Details

### Query Translation
The widget translates your input into WinDbg commands:

**Basic Query:**
```
dx -g @$cursession.TTD.Calls("symbol1", "symbol2")
```

**Filtered Query:**
```
dx -g @$cursession.TTD.Calls("symbol1").Where(c => c.ReturnAddress >= 0x... && c.ReturnAddress < 0x...)
```

### TTD Position Format
TTD positions are displayed in hexadecimal format as `sequence:step` (e.g., `1A:3F5`).

## Troubleshooting

### "TTD features are not available"
- Ensure you're using the DbgEng TTD adapter
- Verify that a TTD trace is loaded
- Check that WinDbg/TTD is properly installed

### Empty Results
- Verify symbol patterns are correct
- Check if the trace contains the specified functions
- Try broader patterns like `"*!*"` to see all calls

### Performance Considerations
- Large traces may take time to query
- Use specific symbol patterns rather than wildcards when possible
- Address range filtering can improve performance for large result sets

## API Usage

The TTD.Calls functionality is also available programmatically:

```python
from debugger import DebuggerController

controller = DebuggerController.get_controller(bv)
if controller.is_ttd():
    # Basic query
    calls = controller.get_ttd_calls(["kernel32!*"])
    
    # Filtered query
    filtered_calls = controller.get_ttd_calls_with_address_filter(
        ["kernel32!*"], 0x7ff7967a0000, 0x7ff7967a7000)
    
    # Position control
    position = controller.get_current_ttd_position()
    controller.set_ttd_position(position)
```

## Related Documentation

- [DbgEng TTD Adapter Setup](dbgeng-ttd.md)
- [Microsoft TTD.Calls Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-calls-objects)
- [Binary Ninja Debugger Guide](https://docs.binary.ninja/guide/debugger/)