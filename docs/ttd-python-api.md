# TTD Python API

This document describes the Python API for TTD (Time Travel Debugging) functionality in the Binary Ninja Debugger.

## Overview

The TTD Python API provides access to Time Travel Debugging capabilities, allowing you to:

- Query memory access events (reads, writes, executes) from TTD traces
- Query function call events from TTD traces  
- Navigate through TTD trace positions
- Analyze historical execution data

## Prerequisites

The TTD functionality is only available when:
1. Using a TTD-capable debugger adapter (e.g., DbgEngTTD)
2. Debugging a TTD trace file (not live debugging)
3. The debugger session supports TTD operations

Always check `debugger_controller.is_ttd` before using TTD-specific methods.

## Classes

### TTDPosition

Represents a position in a TTD trace.

```python
class TTDPosition:
    """
    TTDPosition represents a position in a TTD trace.
    
    Attributes:
        sequence (int): Sequence number in the trace
        step (int): Step number within the sequence
    """
```

### TTDMemoryEvent

Represents a memory access event in a TTD trace.

```python
class TTDMemoryEvent:
    """
    TTDMemoryEvent represents a memory access event in a TTD trace.
    
    Attributes:
        event_type (str): Type of the event (e.g., "Memory")
        thread_id (int): OS thread ID that performed the memory access
        unique_thread_id (int): Unique thread ID across the trace
        time_start (TTDPosition): TTD position when the memory access started
        time_end (TTDPosition): TTD position when the memory access ended
        address (int): Memory address that was accessed
        size (int): Size of the memory access
        memory_address (int): Actual memory address (may differ from address field)
        instruction_address (int): Address of the instruction that performed the access
        value (int): Value that was read/written/executed
        access_type (int): Type of access (TTDMemoryRead/Write/Execute)
    """
```

### TTDCallEvent

Represents a function call event in a TTD trace.

```python
class TTDCallEvent:
    """
    TTDCallEvent represents a function call event in a TTD trace.
    
    Attributes:
        event_type (str): Type of the event (always "Call" for TTD.Calls objects)
        thread_id (int): OS thread ID that made the call
        unique_thread_id (int): Unique thread ID across the trace
        function (str): Symbolic name of the function
        function_address (int): Function's address in memory
        return_address (int): Instruction to return to after the call
        return_value (int): Return value of the function (if not void)
        has_return_value (bool): Whether the function has a return value
        parameters (List[str]): List of parameters passed to the function
        time_start (TTDPosition): TTD position when call started
        time_end (TTDPosition): TTD position when call ended
    """
```

## Constants

```python
# TTD Memory Access Types
TTDMemoryRead = 1      # Memory read operations
TTDMemoryWrite = 2     # Memory write operations  
TTDMemoryExecute = 4   # Memory execute operations

# Can be combined with bitwise OR:
# TTDMemoryRead | TTDMemoryWrite  # Both reads and writes
# TTDMemoryRead | TTDMemoryWrite | TTDMemoryExecute  # All access types
```

## DebuggerController Methods

### is_ttd (property)

```python
@property
def is_ttd(self) -> bool:
    """Check if the current debugging session supports TTD."""
```

### get_ttd_memory_access_for_address()

```python
def get_ttd_memory_access_for_address(
    self, 
    address: int, 
    size: int, 
    access_type: int = TTDMemoryRead
) -> List[TTDMemoryEvent]:
    """
    Get TTD memory access events for a specific address range.
    
    Args:
        address: Starting memory address to query
        size: Size of memory region to query  
        access_type: Type of memory access to query (can be combined with |)
        
    Returns:
        List of TTDMemoryEvent objects
    """
```

### get_ttd_calls_for_symbols()

```python
def get_ttd_calls_for_symbols(
    self,
    symbols: str,
    start_return_address: int = 0,
    end_return_address: int = 0
) -> List[TTDCallEvent]:
    """
    Get TTD call events for specific symbols/functions.
    
    Args:
        symbols: Symbol or function name to query (e.g., "MessageBoxA")
        start_return_address: Optional start return address filter (0 = no filter)
        end_return_address: Optional end return address filter (0 = no filter)
        
    Returns:
        List of TTDCallEvent objects
    """
```

### get_current_ttd_position()

```python
def get_current_ttd_position(self) -> TTDPosition:
    """Get the current position in the TTD trace."""
```

### set_ttd_position()

```python
def set_ttd_position(self, position: TTDPosition) -> bool:
    """
    Set the current position in the TTD trace.
    
    Args:
        position: TTDPosition object to navigate to
        
    Returns:
        True if successful, False otherwise
    """
```

## Usage Examples

### Basic TTD Check

```python
# Always check TTD availability first
if not dbg.is_ttd:
    print("TTD is not available in this session")
    return
```

### Memory Access Analysis

```python
from debuggercontroller import TTDMemoryRead, TTDMemoryWrite, TTDMemoryExecute

# Get memory read events for a specific address
address = 0x401000
size = 4
memory_events = dbg.get_ttd_memory_access_for_address(address, size, TTDMemoryRead)

print(f"Found {len(memory_events)} memory read events at {address:#x}")
for event in memory_events:
    print(f"  Thread {event.thread_id}: read {event.value:#x} at {event.time_start}")

# Get all memory access types
all_events = dbg.get_ttd_memory_access_for_address(
    address, size, TTDMemoryRead | TTDMemoryWrite | TTDMemoryExecute
)
```

### Function Call Analysis

```python
# Get all calls to a specific function
call_events = dbg.get_ttd_calls_for_symbols("MessageBoxA")

print(f"Found {len(call_events)} calls to MessageBoxA")
for call in call_events:
    print(f"  Call at {call.time_start}:")
    print(f"    Function: {call.function} @ {call.function_address:#x}")
    print(f"    Return address: {call.return_address:#x}")
    print(f"    Parameters: {call.parameters}")
    if call.has_return_value:
        print(f"    Return value: {call.return_value:#x}")
```

### TTD Navigation

```python
# Save current position
current_pos = dbg.get_current_ttd_position()
print(f"Current position: {current_pos.sequence:#x}:{current_pos.step:#x}")

# Navigate to a specific memory event
if memory_events:
    target_event = memory_events[0]
    if dbg.set_ttd_position(target_event.time_start):
        print(f"Navigated to position {target_event.time_start}")
    else:
        print("Failed to navigate to target position")

# Return to saved position
dbg.set_ttd_position(current_pos)
```

### Advanced Analysis Example

```python
def analyze_function_memory_usage(dbg, function_name, address_range):
    """Analyze memory usage during specific function calls."""
    
    if not dbg.is_ttd:
        print("TTD not available")
        return
    
    # Get function calls
    calls = dbg.get_ttd_calls_for_symbols(function_name)
    print(f"Analyzing {len(calls)} calls to {function_name}")
    
    for call in calls:
        print(f"\\nCall at {call.time_start}:")
        
        # Get memory events during this call
        start_addr, size = address_range
        memory_events = dbg.get_ttd_memory_access_for_address(
            start_addr, size, TTDMemoryRead | TTDMemoryWrite
        )
        
        # Filter events that occurred during this call
        call_memory_events = [
            event for event in memory_events
            if (call.time_start.sequence <= event.time_start.sequence <= call.time_end.sequence)
        ]
        
        print(f"  Memory accesses during call: {len(call_memory_events)}")
        for event in call_memory_events[:5]:  # Show first 5
            access_type = "read" if event.access_type == TTDMemoryRead else "write"
            print(f"    {access_type} @ {event.address:#x}: {event.value:#x}")

# Usage
analyze_function_memory_usage(dbg, "CreateFileA", (0x401000, 0x100))
```

## Error Handling

TTD methods may raise exceptions if:
- TTD is not available in the current session
- Invalid parameters are provided  
- The underlying TTD system encounters an error

Always wrap TTD calls in try-catch blocks for production code:

```python
try:
    if dbg.is_ttd:
        events = dbg.get_ttd_memory_access_for_address(address, size)
        # Process events...
    else:
        print("TTD not available")
except Exception as e:
    print(f"TTD operation failed: {e}")
```

## Performance Considerations

- TTD queries can be expensive for large traces or wide address ranges
- Consider filtering by specific access types to reduce result sets
- Use return address filters for call queries when analyzing specific code regions
- Cache TTD results when possible to avoid repeated queries

## See Also

- [TTD Memory Analysis Documentation](../docs/draft/ttd-memory-analysis.md)
- Binary Ninja Debugger Documentation
- WinDbg TTD Documentation