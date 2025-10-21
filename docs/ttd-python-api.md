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
        access_type (int): Type of access (DebuggerTTDMemoryAccessType enum)
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

### TTDEvent

Represents important events that happened during a TTD trace.

```python
class TTDEvent:
    """
    TTDEvent represents important events that happened during a TTD trace.
    
    Attributes:
        type (int): Type of event (TTDEventType enum value)
        position (TTDPosition): Position where event occurred
        module (TTDModule or None): Module information for ModuleLoaded/ModuleUnloaded events
        thread (TTDThread or None): Thread information for ThreadCreated/ThreadTerminated events
        exception (TTDException or None): Exception information for Exception events
    """
```

### TTDModule

Represents information about modules that were loaded/unloaded during a TTD trace.

```python
class TTDModule:
    """
    TTDModule represents information about modules that were loaded/unloaded during a TTD trace.
    
    Attributes:
        name (str): Name and path of the module
        address (int): Address where the module was loaded
        size (int): Size of the module in bytes
        checksum (int): Checksum of the module
        timestamp (int): Timestamp of the module
    """
```

### TTDThread

Represents information about threads and their lifetime during a TTD trace.

```python
class TTDThread:
    """
    TTDThread represents information about threads and their lifetime during a TTD trace.
    
    Attributes:
        unique_id (int): Unique ID for the thread across the trace
        id (int): TID of the thread
        lifetime_start (TTDPosition): Lifetime start position
        lifetime_end (TTDPosition): Lifetime end position
        active_time_start (TTDPosition): Active time start position
        active_time_end (TTDPosition): Active time end position
    """
```

### TTDException

Represents information about exceptions that occurred during a TTD trace.

```python
class TTDException:
    """
    TTDException represents information about exceptions that occurred during a TTD trace.
    
    Attributes:
        type (int): Type of exception (TTDExceptionType.Software or TTDExceptionType.Hardware)
        program_counter (int): Instruction where exception was thrown
        code (int): Exception code
        flags (int): Exception flags
        record_address (int): Where in memory the exception record is found
        position (TTDPosition): Position where exception occurred
    """
```

### TTDEventType

TTD Event Type enumeration for different types of events in TTD traces.

```python
class TTDEventType:
    """
    TTD Event Type enumeration for different types of events in TTD traces.
    """
    ThreadCreated = 0      # Thread creation events
    ThreadTerminated = 1   # Thread termination events
    ModuleLoaded = 2       # Module load events
    ModuleUnloaded = 3     # Module unload events
    Exception = 4          # Exception events
```

### TTDExceptionType

TTD Exception Type enumeration for different types of exceptions.

```python
class TTDExceptionType:
    """
    TTD Exception Type enumeration for different types of exceptions.
    """
    Software = 0  # Software exceptions
    Hardware = 1  # Hardware exceptions
```

## Constants and Access Types

### DebuggerTTDMemoryAccessType Enum

TTD memory access types are provided through the auto-generated `DebuggerTTDMemoryAccessType` enum:

```python
# TTD Memory Access Types (auto-generated enum)
DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead       # Memory read operations
DebuggerTTDMemoryAccessType.DebuggerTTDMemoryWrite      # Memory write operations  
DebuggerTTDMemoryAccessType.DebuggerTTDMemoryExecute    # Memory execute operations

# Can be combined with bitwise OR:
DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead | DebuggerTTDMemoryAccessType.DebuggerTTDMemoryWrite
```

### String-based Access Type Parsing

For convenience, you can also specify access types using string notation:

```python
# String specifications (case-insensitive)
"r"     # Read only
"w"     # Write only  
"e"     # Execute only
"rw"    # Read and write
"rwe"   # Read, write, and execute
"we"    # Write and execute
# etc.
```

### Access Type Parsing Function

```python
def parse_ttd_access_type(access_spec):
    """
    Parse TTD memory access type from string specification.
    
    Args:
        access_spec: String containing access type specification or enum value
                     
    Returns:
        DebuggerTTDMemoryAccessType enum value
    """
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
    access_type = DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead
) -> List[TTDMemoryEvent]:
    """
    Get TTD memory access events for a specific address range.
    
    Args:
        address: Starting memory address to query
        size: Size of memory region to query  
        access_type: Type of memory access to query - can be:
                    - DebuggerTTDMemoryAccessType enum values
                    - String specification like "r", "w", "e", "rw", "rwe", etc.
                    - Integer values (for backward compatibility)
        
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

### get_ttd_events()

```python
def get_ttd_events(self, event_type: int) -> List[TTDEvent]:
    """
    Get TTD events for a specific event type.
    
    Args:
        event_type: Type of event to query (TTDEventType enum value)
                   - TTDEventType.ThreadCreated: Thread creation events
                   - TTDEventType.ThreadTerminated: Thread termination events  
                   - TTDEventType.ModuleLoaded: Module load events
                   - TTDEventType.ModuleUnloaded: Module unload events
                   - TTDEventType.Exception: Exception events
                   
    Returns:
        List of TTDEvent objects containing event details
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
# Using enum values
memory_events = dbg.get_ttd_memory_access_for_address(
    0x401000, 4, DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead
)

# Using string specification (more convenient)
memory_events = dbg.get_ttd_memory_access_for_address(0x401000, 4, "r")

print(f"Found {len(memory_events)} memory read events at {0x401000:#x}")
for event in memory_events:
    print(f"  Thread {event.thread_id}: read {event.value:#x} at {event.time_start}")

# Get all memory access types - using string specification
all_events = dbg.get_ttd_memory_access_for_address(0x401000, 4, "rwe")

# Or using enum values with bitwise OR
all_events = dbg.get_ttd_memory_access_for_address(
    0x401000, 4, 
    DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead | 
    DebuggerTTDMemoryAccessType.DebuggerTTDMemoryWrite | 
    DebuggerTTDMemoryAccessType.DebuggerTTDMemoryExecute
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

### TTD Events Analysis

```python
# Query different types of events
thread_events = dbg.get_ttd_events(TTDEventType.ThreadCreated)
print(f"Found {len(thread_events)} thread creation events")

for event in thread_events:
    print(f"Thread created at {event.position}")
    if event.thread:
        print(f"  TID: {event.thread.id}, Unique ID: {event.thread.unique_id}")
        print(f"  Lifetime: {event.thread.lifetime_start} to {event.thread.lifetime_end}")

# Query module load events
module_events = dbg.get_ttd_events(TTDEventType.ModuleLoaded)
print(f"\\nFound {len(module_events)} module load events")

for event in module_events:
    if event.module:
        print(f"Module loaded: {event.module.name} @ {event.module.address:#x}")
        print(f"  Size: {event.module.size} bytes")
        print(f"  Position: {event.position}")

# Query exception events
exception_events = dbg.get_ttd_events(TTDEventType.Exception)
print(f"\\nFound {len(exception_events)} exception events")

for event in exception_events:
    if event.exception:
        exc_type = "Hardware" if event.exception.type == TTDExceptionType.Hardware else "Software"
        print(f"{exc_type} exception at {event.exception.program_counter:#x}")
        print(f"  Code: {event.exception.code:#x}, Flags: {event.exception.flags:#x}")
        print(f"  Position: {event.position}")
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
        
        # Get memory events during this call (using string specification)
        start_addr, size = address_range
        memory_events = dbg.get_ttd_memory_access_for_address(start_addr, size, "rw")
        
        # Filter events that occurred during this call
        call_memory_events = [
            event for event in memory_events
            if (call.time_start.sequence <= event.time_start.sequence <= call.time_end.sequence)
        ]
        
        print(f"  Memory accesses during call: {len(call_memory_events)}")
        for event in call_memory_events[:5]:  # Show first 5
            access_type = "read" if event.access_type == DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead else "write"
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