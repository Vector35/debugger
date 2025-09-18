# TTD Memory Analysis

This document describes the TTD (Time Travel Debugging) memory analysis functionality that allows extracting detailed memory access information from TTD traces.

## Overview

The TTD memory analysis feature provides APIs to extract memory read/write/execute events from TTD traces recorded with WinDbg. This functionality uses the Microsoft DbgEng TTD C++ APIs rather than JavaScript for better performance and integration.

## Data Structures

### TTDMemoryAccessType
Enumeration for memory access types:
- `TTDMemoryRead` - Memory read access
- `TTDMemoryWrite` - Memory write access  
- `TTDMemoryExecute` - Memory execute access

### TTDPosition
Represents a position in the TTD trace:
```cpp
struct TTDPosition {
    uint64_t sequence;  // Sequence number in trace
    uint64_t step;      // Step within sequence
};
```

### TTDMemoryEvent
Represents a memory access event:
```cpp
struct TTDMemoryEvent {
    TTDPosition position;           // Position in trace when event occurred
    TTDMemoryAccessType accessType; // Type of memory access
    uint64_t address;              // Memory address accessed
    uint64_t size;                 // Size of memory access
    uint32_t threadId;             // Thread ID that performed the access
    uint64_t instructionAddress;   // Address of instruction that caused the access
};
```

## API Methods

### Core TTD Adapter Methods

```cpp
class DbgEngTTDAdapter {
public:
    // Get memory events within a position range
    std::vector<TTDMemoryEvent> GetMemoryEvents(
        const TTDPosition& startPos, 
        const TTDPosition& endPos, 
        TTDMemoryAccessType accessType = TTDMemoryRead);
    
    // Get memory events for a specific address range
    std::vector<TTDMemoryEvent> GetMemoryEventsForAddress(
        uint64_t address, 
        uint64_t size, 
        TTDMemoryAccessType accessType = TTDMemoryRead);
    
    // Get current position in TTD trace
    TTDPosition GetCurrentTTDPosition();
    
    // Navigate to a specific position in TTD trace
    bool SetTTDPosition(const TTDPosition& position);
};
```

### Debugger Controller Methods

```cpp
class DebuggerController {
public:
    // Check if current adapter supports TTD
    bool IsTTD();
    
    // TTD memory analysis methods (same as adapter methods)
    std::vector<TTDMemoryEvent> GetTTDMemoryEvents(
        const TTDPosition& startPos, 
        const TTDPosition& endPos, 
        TTDMemoryAccessType accessType = TTDMemoryRead);
    
    std::vector<TTDMemoryEvent> GetTTDMemoryEventsForAddress(
        uint64_t address, 
        uint64_t size, 
        TTDMemoryAccessType accessType = TTDMemoryRead);
    
    TTDPosition GetCurrentTTDPosition();
    bool SetTTDPosition(const TTDPosition& position);
};
```

## Usage Examples

### Basic Usage

```cpp
// Check if TTD is available
if (controller->IsTTD()) {
    // Get current position
    TTDPosition currentPos = controller->GetCurrentTTDPosition();
    
    // Query memory read events for a specific address
    std::vector<TTDMemoryEvent> events = controller->GetTTDMemoryEventsForAddress(
        0x401000, 4, TTDMemoryRead);
    
    for (const auto& event : events) {
        LogInfo("Memory read at 0x%llx, position %llx:%llx, thread %d", 
            event.address, event.position.sequence, event.position.step, event.threadId);
    }
}
```

### Position-Based Query

```cpp
// Query events within a specific range
TTDPosition startPos(0x1A0, 0);
TTDPosition endPos(0x1B0, 0);

std::vector<TTDMemoryEvent> writes = controller->GetTTDMemoryEvents(
    startPos, endPos, TTDMemoryWrite);

for (const auto& event : writes) {
    LogInfo("Write to 0x%llx at position %llx:%llx from instruction 0x%llx",
        event.address, event.position.sequence, event.position.step, event.instructionAddress);
}
```

### Navigation

```cpp
// Save current position
TTDPosition savedPos = controller->GetCurrentTTDPosition();

// Navigate to earlier position
TTDPosition targetPos(0x100, 0x50);
if (controller->SetTTDPosition(targetPos)) {
    // Analyze state at target position
    // ...
    
    // Return to saved position
    controller->SetTTDPosition(savedPos);
}
```

## Implementation Details

### Windows-Only Functionality
TTD memory analysis is only available on Windows as it requires the Microsoft DbgEng TTD APIs. On other platforms, the methods will return empty results or default values.

### Microsoft TTD Integration
The implementation uses the following Microsoft APIs:
- `IDataModelManager` - For accessing TTD data model objects
- `IDebugHost` - For host debugging interface
- DbgEng TTD memory objects - For querying memory access events

### Performance Considerations
- Memory event queries can return large amounts of data for long traces
- Consider using position-based queries to limit the scope
- Address-specific queries may be more efficient for targeted analysis

## Error Handling

All methods include proper error handling:
- Return empty vectors for failed queries
- Log detailed error messages
- Handle cases where TTD is not available or not initialized

## Future Enhancements

Potential areas for future development:
1. Function call extraction
2. Event filtering by instruction type
3. Statistical analysis of memory access patterns
4. Integration with Binary Ninja's analysis pipeline

## See Also

- [TTD Setup Guide](dbgeng-ttd.md) - How to set up TTD with Binary Ninja
- [Microsoft TTD Documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-memory-objects) - Microsoft's official TTD memory objects documentation