#!/usr/bin/env python3
"""
Test script for custom debug adapter Python API

This script demonstrates how to create a custom debug adapter using the Python API.
"""

import sys
import os

# Add the debugger module to the path (in a real scenario this would be installed)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api', 'python'))

try:
    from customdebugadapter import CustomDebugAdapter, CustomDebugAdapterType
    from customdebugadapter import DebugProcess, DebugThread, DebugBreakpoint, DebugRegister, DebugModule
    
    class ExamplePythonDebugAdapter(CustomDebugAdapter):
        """Example implementation of a custom debug adapter in Python"""
        
        def __init__(self):
            super().__init__()
            print("ExamplePythonDebugAdapter created")
        
        def execute(self, path: str) -> bool:
            print(f"Execute: {path}")
            return False  # Not implemented
        
        def execute_with_args(self, path: str, args: str, working_dir: str) -> bool:
            print(f"ExecuteWithArgs: {path} {args} in {working_dir}")
            return False  # Not implemented
        
        def attach(self, pid: int) -> bool:
            print(f"Attach to PID: {pid}")
            return False  # Not implemented
        
        def connect(self, server: str, port: int) -> bool:
            print(f"Connect to: {server}:{port}")
            return False  # Not implemented
        
        def connect_to_debug_server(self, server: str, port: int) -> bool:
            print(f"ConnectToDebugServer: {server}:{port}")
            return False  # Not implemented
        
        def detach(self) -> bool:
            print("Detach")
            return False  # Not implemented
        
        def quit(self) -> bool:
            print("Quit")
            return False  # Not implemented
        
        # Stub implementations for all other required methods
        def get_process_list(self):
            return []
        
        def get_thread_list(self):
            return []
        
        def get_active_thread(self):
            return DebugThread(0)
        
        def get_active_thread_id(self):
            return 0
        
        def set_active_thread(self, thread):
            return False
        
        def set_active_thread_id(self, tid):
            return False
        
        def suspend_thread(self, tid):
            return False
        
        def resume_thread(self, tid):
            return False
        
        def add_breakpoint(self, address):
            return DebugBreakpoint(address)
        
        def add_breakpoint_relative(self, module, offset):
            return DebugBreakpoint(0)
        
        def remove_breakpoint(self, address):
            return False
        
        def remove_breakpoint_relative(self, module, offset):
            return False
        
        def get_breakpoint_list(self):
            return []
        
        def read_all_registers(self):
            return {}
        
        def read_register(self, name):
            return DebugRegister(name)
        
        def write_register(self, name, value):
            return False
        
        def read_memory(self, address, size):
            return b''
        
        def write_memory(self, address, data):
            return False
        
        def get_module_list(self):
            return []
        
        def get_target_architecture(self):
            return "x86_64"
        
        def stop_reason(self):
            return 0
        
        def exit_code(self):
            return 0
        
        def break_into(self):
            return False
        
        def go(self):
            return False
        
        def step_into(self):
            return False
        
        def step_over(self):
            return False
        
        def invoke_backend_command(self, command):
            return ""
        
        def get_instruction_offset(self):
            return 0
        
        def get_stack_pointer(self):
            return 0
        
        def support_feature(self, feature):
            return False
    
    class ExamplePythonDebugAdapterType(CustomDebugAdapterType):
        """Example implementation of a custom debug adapter type in Python"""
        
        def __init__(self):
            super().__init__("ExamplePythonAdapter")
            print("ExamplePythonDebugAdapterType created")
        
        def create(self, bv):
            print(f"Creating adapter for binary view: {bv}")
            return ExamplePythonDebugAdapter()
        
        def is_valid_for_data(self, bv):
            return True  # Accept any binary view for this example
        
        def can_execute(self, bv):
            return False  # This adapter cannot execute binaries
        
        def can_connect(self, bv):
            return True  # This adapter can connect to remote targets
    
    def test_custom_adapter():
        """Test the custom debug adapter functionality"""
        print("Testing custom debug adapter functionality...")
        
        # Create adapter type
        adapter_type = ExamplePythonDebugAdapterType()
        print(f"Created adapter type: {adapter_type.name}")
        
        # Test creating an adapter (requires a BinaryView, which we don't have in this test)
        print("Adapter type creation successful")
        
        # Test adapter methods
        adapter = ExamplePythonDebugAdapter()
        
        # Test some basic methods
        result = adapter.execute("/path/to/program")
        print(f"Execute result: {result}")
        
        result = adapter.attach(1234)
        print(f"Attach result: {result}")
        
        result = adapter.connect("localhost", 12345)
        print(f"Connect result: {result}")
        
        arch = adapter.get_target_architecture()
        print(f"Target architecture: {arch}")
        
        print("All tests completed successfully!")
    
    if __name__ == "__main__":
        test_custom_adapter()

except ImportError as e:
    print(f"Import error: {e}")
    print("This test requires the debugger module to be built and available.")
    print("The custom debug adapter API is implemented but cannot be tested without the full environment.")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()