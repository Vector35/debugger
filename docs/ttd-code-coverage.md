# TTD Code Coverage Analysis

This document describes the TTD Code Coverage functionality added to the Binary Ninja debugger.

## Overview

The TTD Code Coverage feature analyzes Time Travel Debugging (TTD) traces to determine which instructions were executed during the recorded session. This information is then displayed as visual highlights in the disassembly view, allowing you to quickly see which code paths were taken.

## Features

### 1. Code Coverage Analysis
- **Purpose**: Extract executed instruction addresses from TTD traces
- **Method**: Queries TTD memory access events for execute operations
- **Output**: Set of executed instruction addresses stored in memory
- **Performance**: Single efficient query covering entire executable range

### 2. Visual Highlighting
- **Executed Instructions**: Highlighted with green background (light transparency)
- **Current Instruction**: Blue highlight (existing functionality)
- **Breakpoints**: Red highlight (existing functionality)
- **Combined States**: Magenta for breakpoint + current instruction

### 3. Analysis Dialog
- **Location**: Debugger menu → "TTD Analysis..."
- **Features**:
  - Progress tracking with threaded execution
  - Result metrics (number of executed instructions)
  - Cache management (save/load results)
  - Extensible for future analysis types

### 4. Caching System
- **Metadata**: JSON format with analysis information
- **Data**: Binary format for executed instruction addresses
- **Auto-detection**: Shows cache status on dialog startup
- **Manual Control**: Save/load/clear cache operations

## Usage

### Prerequisites
- Binary Ninja with debugger plugin
- TTD-capable debug adapter (e.g., DbgEng TTD adapter)
- Active TTD trace

### Running Code Coverage Analysis

1. **Open the Analysis Dialog**
   - Menu: `Debugger → TTD Analysis...`
   - Requires active TTD session

2. **Start Analysis**
   - Select "Code Coverage" from the list
   - Click "Run Analysis"
   - Monitor progress bar and status

3. **View Results**
   - Executed instructions appear with green highlights
   - Check result count in dialog
   - Optionally save results to cache

4. **Cache Management**
   - **Auto-save**: Enable "Automatically cache results"
   - **Manual save**: Click "Save Results" after analysis
   - **Load cache**: Click "Load Results" to restore previous analysis
   - **Clear cache**: Remove all cached analysis files

## API Reference

### New DebuggerController Methods

```cpp
// Check if specific instruction was executed
bool IsInstructionExecuted(uint64_t address);

// Run complete code coverage analysis
bool RunCodeCoverageAnalysis();

// Get number of executed instructions found
size_t GetExecutedInstructionCount() const;

// Save/load analysis results to/from file
bool SaveCodeCoverageToFile(const std::string& filePath) const;
bool LoadCodeCoverageFromFile(const std::string& filePath);
```

### Usage Example (C++)

```cpp
// Get debugger controller
auto controller = DebuggerController::GetController(binaryView);
if (!controller || !controller->IsTTD()) {
    return; // TTD not available
}

// Run analysis
if (controller->RunCodeCoverageAnalysis()) {
    size_t executedCount = controller->GetExecutedInstructionCount();
    LogInfo("Found {} executed instructions", executedCount);

    // Check specific instruction
    if (controller->IsInstructionExecuted(0x401000)) {
        LogInfo("Instruction at 0x401000 was executed");
    }

    // Save results
    controller->SaveCodeCoverageToFile("/path/to/cache.data");
}
```

## Technical Details

### Data Storage
- **In-memory**: `std::unordered_set<uint64_t>` for O(1) lookup performance
- **Cache format**: Binary file with magic number (0x54544443) and version
- **Metadata**: JSON file with analysis details and statistics

### Analysis Algorithm
1. Enumerate all instruction addresses from all functions
2. Query TTD for execute access events in entire executable range
3. Filter results to only include actual instruction addresses
4. Store executed addresses in unordered set for fast lookup

### Render Layer Integration
- Hooks into existing DebuggerRenderLayer
- Minimal changes to existing highlighting logic
- Green highlight with 64/255 alpha for executed instructions
- Preserves existing breakpoint and PC highlighting

### Thread Safety
- Analysis runs in separate QThread worker
- Mutex protection for result data access
- Progress signals for UI updates

## Cache File Format

### Metadata (.json)
```json
{
    "type": 0,
    "name": "Code Coverage",
    "description": "...",
    "resultCount": 1234,
    "lastRun": "2023-12-07T10:30:00Z",
    "status": 2
}
```

### Data (.data)
```
[4 bytes] Magic: 0x54544443 ("TTDC")
[4 bytes] Version: 1
[8 bytes] Count: number of addresses
[8*Count bytes] Addresses: executed instruction addresses
```

## Troubleshooting

### Common Issues

1. **"TTD not available"**
   - Ensure TTD-capable adapter is active
   - Check that trace is loaded and accessible

2. **"Analysis failed"**
   - Verify TTD trace contains execute events
   - Check available memory and disk space
   - Review log output for specific errors

3. **No highlights visible**
   - Confirm analysis completed successfully
   - Check that cache was loaded properly
   - Verify you're viewing the correct binary/view

### Performance Considerations

- **Large traces**: Analysis time scales with trace size
- **Memory usage**: ~8 bytes per executed instruction
- **Cache size**: Depends on number of unique executed instructions
- **Disk I/O**: Caching improves subsequent analysis speed

## Future Enhancements

The analysis framework is designed to be extensible:

- **Additional analysis types**: Memory access patterns, branch coverage, etc.
- **Export formats**: Integration with external coverage tools
- **Statistics**: Coverage percentages, hot paths, etc.
- **Filtering**: Analysis of specific time ranges or threads

## Implementation Notes

This feature maintains the existing debugger architecture with minimal changes:

- **5 new API methods** added to DebuggerController
- **Backward compatible** with existing functionality
- **Thread-safe** analysis with progress reporting
- **Extensible design** for future analysis types
- **Robust error handling** and validation

The implementation follows Binary Ninja plugin patterns and integrates cleanly with the existing TTD infrastructure.