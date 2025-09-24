#!/usr/bin/env python3
"""
Example script demonstrating hardware breakpoint usage

This script shows how to use the new hardware breakpoint functionality
introduced in the debugger.
"""

try:
    from binaryninja import load
    from debugger import DebuggerController, DebugBreakpointType
except ImportError:
    from binaryninja import load
    from binaryninja.debugger import DebuggerController, DebugBreakpointType


def hardware_breakpoint_example(binary_path):
    """
    Example showing how to use hardware breakpoints
    """
    # Load the binary
    bv = load(binary_path)
    if not bv:
        print(f"Failed to load binary: {binary_path}")
        return
    
    # Get the debugger controller
    controller = DebuggerController(bv)
    
    print("Setting up hardware breakpoints...")
    
    # Example 1: Hardware execution breakpoint at entry point
    entry_point = bv.entry_point
    print(f"Setting hardware execution breakpoint at entry point: 0x{entry_point:x}")
    success = controller.add_hardware_breakpoint(
        entry_point, 
        DebugBreakpointType.HardwareExecuteBreakpoint
    )
    if success:
        print("✓ Hardware execution breakpoint set successfully")
    else:
        print("✗ Failed to set hardware execution breakpoint")
    
    # Example 2: Hardware write watchpoint on a data address
    # In a real scenario, you'd find a data address from your binary analysis
    data_address = 0x1000  # Example address
    print(f"Setting hardware write watchpoint at 0x{data_address:x} (4 bytes)")
    success = controller.add_hardware_breakpoint(
        data_address,
        DebugBreakpointType.HardwareWriteBreakpoint,
        4  # Watch 4 bytes
    )
    if success:
        print("✓ Hardware write watchpoint set successfully")
    else:
        print("✗ Failed to set hardware write watchpoint")
    
    # Example 3: Hardware read watchpoint
    print(f"Setting hardware read watchpoint at 0x{data_address + 8:x} (8 bytes)")
    success = controller.add_hardware_breakpoint(
        data_address + 8,
        DebugBreakpointType.HardwareReadBreakpoint,
        8  # Watch 8 bytes
    )
    if success:
        print("✓ Hardware read watchpoint set successfully")
    else:
        print("✗ Failed to set hardware read watchpoint")
    
    # Example 4: Hardware access (read/write) watchpoint
    print(f"Setting hardware access watchpoint at 0x{data_address + 16:x} (1 byte)")
    success = controller.add_hardware_breakpoint(
        data_address + 16,
        DebugBreakpointType.HardwareAccessBreakpoint,
        1  # Watch 1 byte
    )
    if success:
        print("✓ Hardware access watchpoint set successfully")
    else:
        print("✗ Failed to set hardware access watchpoint")
    
    print("\nLaunching target...")
    stop_reason = controller.launch_and_wait()
    print(f"Target stopped with reason: {stop_reason}")
    
    # Continue execution to test breakpoints
    print("Continuing execution...")
    stop_reason = controller.go_and_wait()
    print(f"Target stopped with reason: {stop_reason}")
    
    # Clean up - remove hardware breakpoints
    print("\nCleaning up hardware breakpoints...")
    
    controller.remove_hardware_breakpoint(
        entry_point, 
        DebugBreakpointType.HardwareExecuteBreakpoint
    )
    
    controller.remove_hardware_breakpoint(
        data_address,
        DebugBreakpointType.HardwareWriteBreakpoint,
        4
    )
    
    controller.remove_hardware_breakpoint(
        data_address + 8,
        DebugBreakpointType.HardwareReadBreakpoint,
        8
    )
    
    controller.remove_hardware_breakpoint(
        data_address + 16,
        DebugBreakpointType.HardwareAccessBreakpoint,
        1
    )
    
    print("Hardware breakpoints removed")
    
    # Quit the debugger
    controller.quit_and_wait()
    print("Debugging session ended")


def backend_command_example(binary_path):
    """
    Example showing how to use hardware breakpoints via backend commands
    (useful for advanced scenarios or when the API is not sufficient)
    """
    bv = load(binary_path)
    controller = DebuggerController(bv)
    
    print("Using backend commands for hardware breakpoints...")
    
    # Launch the target first
    controller.launch_and_wait()
    
    # For LLDB adapter:
    if controller.get_adapter_type() == "LLDB":
        print("Using LLDB commands:")
        
        # Hardware execution breakpoint
        result = controller.send_command("breakpoint set --address 0x100000000 -H")
        print(f"LLDB hardware execution breakpoint: {result}")
        
        # Hardware write watchpoint
        result = controller.send_command("watchpoint set expression -w write -s 4 -- 0x100001000")
        print(f"LLDB hardware write watchpoint: {result}")
        
        # List breakpoints and watchpoints
        result = controller.send_command("breakpoint list")
        print(f"LLDB breakpoints: {result}")
        
        result = controller.send_command("watchpoint list")
        print(f"LLDB watchpoints: {result}")
    
    # For GDB RSP adapter:
    elif "GDB" in controller.get_adapter_type():
        print("Using GDB RSP commands:")
        
        # Hardware execution breakpoint (Z1)
        result = controller.send_command("Z1,100000000,1")
        print(f"GDB hardware execution breakpoint: {result}")
        
        # Hardware write watchpoint (Z2)
        result = controller.send_command("Z2,100001000,4")
        print(f"GDB hardware write watchpoint: {result}")
    
    controller.quit_and_wait()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python hardware_breakpoints.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    print("=== Hardware Breakpoint API Example ===")
    hardware_breakpoint_example(binary_path)
    
    print("\n=== Backend Command Example ===")
    backend_command_example(binary_path)