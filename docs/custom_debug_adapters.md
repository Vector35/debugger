# Custom Debug Adapter API

This document describes how to create custom debug adapters using the Binary Ninja Debugger API.

## Overview

The Binary Ninja Debugger now supports custom debug adapters that can be implemented in both C++ and Python. This allows developers to extend the debugger with support for new debugging protocols, targets, or specialized debugging scenarios.

## Architecture

Custom debug adapters work through a bridge system:

1. **Core Layer**: The debugger core contains bridge classes (`CustomDebugAdapter`, `CustomDebugAdapterType`) that forward calls to user-provided callbacks
2. **FFI Layer**: A foreign function interface layer provides C-style callbacks for maximum compatibility
3. **API Layer**: C++ and Python classes provide convenient object-oriented interfaces for implementing custom adapters

## C++ API

### Creating a Custom Debug Adapter

To create a custom debug adapter in C++:

1. Inherit from `BinaryNinjaDebuggerAPI::CustomDebugAdapter`
2. Implement all required abstract methods
3. Create an adapter type by inheriting from `BinaryNinjaDebuggerAPI::CustomDebugAdapterType`
4. Register your adapter type

```cpp
#include "debuggerapi.h"

class MyDebugAdapter : public BinaryNinjaDebuggerAPI::CustomDebugAdapter
{
public:
    MyDebugAdapter() : CustomDebugAdapter() {}
    
    // Implement required methods
    bool Execute(const std::string& path) override {
        // Your implementation
        return false;
    }
    
    bool Attach(uint32_t pid) override {
        // Your implementation  
        return false;
    }
    
    // ... implement all other required methods
};

class MyDebugAdapterType : public BinaryNinjaDebuggerAPI::CustomDebugAdapterType
{
public:
    MyDebugAdapterType() : CustomDebugAdapterType("MyAdapter") {}
    
    std::unique_ptr<CustomDebugAdapter> Create(Ref<BinaryView> data) override {
        return std::make_unique<MyDebugAdapter>();
    }
    
    bool IsValidForData(Ref<BinaryView> data) override {
        // Check if this adapter can handle the binary
        return true;
    }
    
    bool CanExecute(Ref<BinaryView> data) override {
        // Can this adapter execute binaries?
        return false;
    }
    
    bool CanConnect(Ref<BinaryView> data) override {
        // Can this adapter connect to remote targets?
        return true;
    }
};

// Register the adapter
void RegisterMyAdapter() {
    static MyDebugAdapterType adapterType;
    adapterType.Register();
}
```

### Required Methods

All custom debug adapters must implement these methods:

#### Connection Management
- `Execute(path)` - Execute a binary
- `ExecuteWithArgs(path, args, workingDir)` - Execute with arguments
- `Attach(pid)` - Attach to a process
- `Connect(server, port)` - Connect to remote target
- `ConnectToDebugServer(server, port)` - Connect to debug server
- `Detach()` - Detach from target
- `Quit()` - Terminate debug session

#### Process/Thread Management
- `GetProcessList()` - List available processes
- `GetThreadList()` - List threads in target
- `GetActiveThread()` - Get current thread
- `SetActiveThread(thread)` - Set active thread
- `SuspendThread(tid)` - Suspend a thread
- `ResumeThread(tid)` - Resume a thread

#### Breakpoint Management
- `AddBreakpoint(address)` - Add breakpoint
- `RemoveBreakpoint(address)` - Remove breakpoint
- `GetBreakpointList()` - List breakpoints

#### Memory/Register Access
- `ReadMemory(address, size)` - Read memory
- `WriteMemory(address, data)` - Write memory
- `ReadRegister(name)` - Read register
- `WriteRegister(name, value)` - Write register
- `ReadAllRegisters()` - Read all registers

#### Execution Control
- `Go()` - Continue execution
- `StepInto()` - Step into
- `StepOver()` - Step over
- `BreakInto()` - Break execution

#### Information
- `GetTargetArchitecture()` - Get target architecture
- `GetModuleList()` - List loaded modules
- `StopReason()` - Get reason for stop
- `ExitCode()` - Get exit code
- `GetInstructionOffset()` - Get current instruction
- `GetStackPointer()` - Get stack pointer

## Python API

### Creating a Custom Debug Adapter

To create a custom debug adapter in Python:

```python
from debugger.customdebugadapter import CustomDebugAdapter, CustomDebugAdapterType

class MyPythonDebugAdapter(CustomDebugAdapter):
    def __init__(self):
        super().__init__()
    
    def execute(self, path: str) -> bool:
        # Your implementation
        return False
    
    def attach(self, pid: int) -> bool:
        # Your implementation
        return False
    
    # ... implement all other required methods

class MyPythonDebugAdapterType(CustomDebugAdapterType):
    def __init__(self):
        super().__init__("MyPythonAdapter")
    
    def create(self, bv):
        return MyPythonDebugAdapter()
    
    def is_valid_for_data(self, bv):
        return True
    
    def can_execute(self, bv):
        return False
    
    def can_connect(self, bv):
        return True

# Register the adapter
def register_my_adapter():
    adapter_type = MyPythonDebugAdapterType()
    adapter_type.register()
```

## Data Types

The API uses these data types for communication:

### DebugProcess
- `pid` - Process ID
- `name` - Process name

### DebugThread  
- `tid` - Thread ID
- `rip` - Instruction pointer
- `frozen` - Whether thread is suspended

### DebugBreakpoint
- `address` - Breakpoint address
- `id` - Breakpoint ID
- `active` - Whether breakpoint is enabled

### DebugRegister
- `name` - Register name
- `value` - Register value
- `width` - Register width in bytes
- `index` - Register index
- `hint` - Display hint

### DebugModule
- `name` - Module name/path
- `short_name` - Short module name
- `address` - Module base address
- `size` - Module size
- `loaded` - Whether module is loaded

## Optional Features

Some methods are optional and have default implementations:

- Reverse debugging (`GoReverse`, `StepIntoReverse`, etc.)
- Backend commands (`InvokeBackendCommand`)
- Properties (`GetProperty`, `SetProperty`)
- Settings (`GetAdapterSettings`)
- Standard I/O (`WriteStdin`)

## Error Handling

- Return `false` from boolean methods to indicate failure
- Return empty collections for list methods when no data is available
- Return `0` or empty strings for scalar methods when no data is available
- The debugger core will handle error propagation to the UI

## Registration

### C++
Call `Register()` on your adapter type instance, typically in a plugin initialization function.

### Python
Call `register()` on your adapter type instance.

## Examples

See the `test/` directory for complete examples:
- `example_custom_adapter.cpp` - C++ example
- `test_custom_adapter.py` - Python example

## Limitations

- Custom adapters cannot currently be unregistered at runtime
- Some advanced features may require additional core support
- Performance characteristics depend on the callback overhead

## Future Enhancements

Planned improvements include:
- Dynamic adapter loading/unloading
- Additional callback events
- Performance optimizations
- More helper utilities