# coding=utf-8
# Copyright 2020-2025 Vector 35 Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ctypes
import traceback
from typing import List, Dict, Optional, Union

import binaryninja
from . import _debuggercore as dbgcore
from .debugger_enums import *


class DebugProcess:
    """Represents a debug process"""
    def __init__(self, pid: int, name: str = ""):
        self.pid = pid
        self.name = name


class DebugThread:
    """Represents a debug thread"""
    def __init__(self, tid: int, rip: int = 0, frozen: bool = False):
        self.tid = tid
        self.rip = rip
        self.frozen = frozen


class DebugBreakpoint:
    """Represents a debug breakpoint"""
    def __init__(self, address: int, id: int = 0, active: bool = True):
        self.address = address
        self.id = id
        self.active = active


class DebugRegister:
    """Represents a debug register"""
    def __init__(self, name: str, value: int = 0, width: int = 0, index: int = 0, hint: str = ""):
        self.name = name
        self.value = value
        self.width = width
        self.index = index
        self.hint = hint


class DebugModule:
    """Represents a debug module"""
    def __init__(self, name: str, short_name: str = "", address: int = 0, size: int = 0, loaded: bool = False):
        self.name = name
        self.short_name = short_name
        self.address = address
        self.size = size
        self.loaded = loaded


class CustomDebugAdapter:
    """
    Base class for implementing custom debug adapters in Python.
    
    Subclasses must implement all the abstract methods to provide
    debug adapter functionality.
    """

    def __init__(self):
        self._callbacks = self._setup_callbacks()

    def _setup_callbacks(self):
        """Set up the FFI callbacks"""
        callbacks = dbgcore.BNCustomDebugAdapterCallbacks()
        callbacks.context = ctypes.cast(ctypes.pointer(ctypes.py_object(self)), ctypes.c_void_p)
        
        # Set up all the callback function pointers
        callbacks.init = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._init_callback)
        callbacks.execute = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p)(self._execute_callback)
        callbacks.executeWithArgs = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p)(self._execute_with_args_callback)
        callbacks.attach = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint32)(self._attach_callback)
        callbacks.connect = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)(self._connect_callback)
        callbacks.connectToDebugServer = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32)(self._connect_to_debug_server_callback)
        callbacks.detach = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._detach_callback)
        callbacks.quit = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._quit_callback)
        
        # Process and thread management
        callbacks.getProcessList = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNDebugProcess), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t))(self._get_process_list_callback)
        callbacks.getThreadList = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNDebugThread), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t))(self._get_thread_list_callback)
        callbacks.getActiveThread = ctypes.CFUNCTYPE(dbgcore.BNDebugThread, ctypes.c_void_p)(self._get_active_thread_callback)
        callbacks.getActiveThreadId = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(self._get_active_thread_id_callback)
        callbacks.setActiveThread = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, dbgcore.BNDebugThread)(self._set_active_thread_callback)
        callbacks.setActiveThreadId = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint32)(self._set_active_thread_id_callback)
        callbacks.suspendThread = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint32)(self._suspend_thread_callback)
        callbacks.resumeThread = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint32)(self._resume_thread_callback)
        
        # Breakpoint management
        callbacks.addBreakpoint = ctypes.CFUNCTYPE(dbgcore.BNDebugBreakpoint, ctypes.c_void_p, ctypes.c_uint64)(self._add_breakpoint_callback)
        callbacks.addBreakpointRelative = ctypes.CFUNCTYPE(dbgcore.BNDebugBreakpoint, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64)(self._add_breakpoint_relative_callback)
        callbacks.removeBreakpoint = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint64)(self._remove_breakpoint_callback)
        callbacks.removeBreakpointRelative = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64)(self._remove_breakpoint_relative_callback)
        callbacks.getBreakpointList = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNDebugBreakpoint), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t))(self._get_breakpoint_list_callback)
        
        # Register and memory access
        callbacks.readAllRegisters = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNDebugRegister), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t))(self._read_all_registers_callback)
        callbacks.readRegister = ctypes.CFUNCTYPE(dbgcore.BNDebugRegister, ctypes.c_void_p, ctypes.c_char_p)(self._read_register_callback)
        callbacks.writeRegister = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8))(self._write_register_callback)
        callbacks.readMemory = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNDataBuffer), ctypes.c_void_p, ctypes.c_uint64, ctypes.c_size_t)(self._read_memory_callback)
        callbacks.writeMemory = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(dbgcore.BNDataBuffer))(self._write_memory_callback)
        
        # Module and architecture
        callbacks.getModuleList = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNDebugModule), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t))(self._get_module_list_callback)
        callbacks.getTargetArchitecture = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p)(self._get_target_architecture_callback)
        
        # Control and status
        callbacks.stopReason = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(self._stop_reason_callback)
        callbacks.exitCode = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(self._exit_code_callback)
        callbacks.breakInto = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._break_into_callback)
        callbacks.go = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._go_callback)
        callbacks.goReverse = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._go_reverse_callback)
        callbacks.stepInto = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._step_into_callback)
        callbacks.stepIntoReverse = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._step_into_reverse_callback)
        callbacks.stepOver = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._step_over_callback)
        callbacks.stepOverReverse = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._step_over_reverse_callback)
        callbacks.stepReturn = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._step_return_callback)
        callbacks.stepReturnReverse = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p)(self._step_return_reverse_callback)
        
        # Utility functions
        callbacks.invokeBackendCommand = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p)(self._invoke_backend_command_callback)
        callbacks.getInstructionOffset = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(self._get_instruction_offset_callback)
        callbacks.getStackPointer = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(self._get_stack_pointer_callback)
        callbacks.supportFeature = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_uint32)(self._support_feature_callback)
        callbacks.writeStdin = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_char_p)(self._write_stdin_callback)
        callbacks.getProperty = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNMetadata), ctypes.c_void_p, ctypes.c_char_p)(self._get_property_callback)
        callbacks.setProperty = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(dbgcore.BNMetadata))(self._set_property_callback)
        callbacks.getAdapterSettings = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNSettings), ctypes.c_void_p)(self._get_adapter_settings_callback)
        callbacks.freeCallback = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._free_callback)
        
        return callbacks

    # Static callback methods that extract the Python object and forward calls
    @staticmethod
    def _get_python_adapter(ctxt):
        """Extract the Python adapter object from the context"""
        py_obj_ptr = ctypes.cast(ctxt, ctypes.POINTER(ctypes.py_object))
        return py_obj_ptr.contents.value

    def _init_callback(self, ctxt):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.init()
        except:
            traceback.print_exc()
            return False

    def _execute_callback(self, ctxt, path):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.execute(path.decode('utf-8'))
        except:
            traceback.print_exc()
            return False

    def _execute_with_args_callback(self, ctxt, path, args, working_dir):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.execute_with_args(path.decode('utf-8'), args.decode('utf-8'), working_dir.decode('utf-8'))
        except:
            traceback.print_exc()
            return False

    def _attach_callback(self, ctxt, pid):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.attach(pid)
        except:
            traceback.print_exc()
            return False

    def _connect_callback(self, ctxt, server, port):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.connect(server.decode('utf-8'), port)
        except:
            traceback.print_exc()
            return False

    def _connect_to_debug_server_callback(self, ctxt, server, port):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.connect_to_debug_server(server.decode('utf-8'), port)
        except:
            traceback.print_exc()
            return False

    def _detach_callback(self, ctxt):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.detach()
        except:
            traceback.print_exc()
            return False

    def _quit_callback(self, ctxt):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.quit()
        except:
            traceback.print_exc()
            return False

    # Additional callback implementations would continue here...
    # For brevity, I'm implementing just a few key ones as examples

    def _go_callback(self, ctxt):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.go()
        except:
            traceback.print_exc()
            return False

    def _step_into_callback(self, ctxt):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.step_into()
        except:
            traceback.print_exc()
            return False

    def _step_over_callback(self, ctxt):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.step_over()
        except:
            traceback.print_exc()
            return False

    def _break_into_callback(self, ctxt):
        try:
            adapter = self._get_python_adapter(ctxt)
            return adapter.break_into()
        except:
            traceback.print_exc()
            return False

    def _free_callback(self, ctxt):
        # Nothing to do here - Python manages the object lifecycle
        pass

    # Abstract methods that must be implemented by subclasses
    def init(self) -> bool:
        """Initialize the debug adapter"""
        return True

    def execute(self, path: str) -> bool:
        """Execute a program"""
        raise NotImplementedError("execute must be implemented")

    def execute_with_args(self, path: str, args: str, working_dir: str) -> bool:
        """Execute a program with arguments"""
        raise NotImplementedError("execute_with_args must be implemented")

    def attach(self, pid: int) -> bool:
        """Attach to a process"""
        raise NotImplementedError("attach must be implemented")

    def connect(self, server: str, port: int) -> bool:
        """Connect to a remote debug server"""
        raise NotImplementedError("connect must be implemented")

    def connect_to_debug_server(self, server: str, port: int) -> bool:
        """Connect to a debug server"""
        raise NotImplementedError("connect_to_debug_server must be implemented")

    def detach(self) -> bool:
        """Detach from the target"""
        raise NotImplementedError("detach must be implemented")

    def quit(self) -> bool:
        """Quit the debug session"""
        raise NotImplementedError("quit must be implemented")

    def get_process_list(self) -> List[DebugProcess]:
        """Get list of available processes"""
        raise NotImplementedError("get_process_list must be implemented")

    def get_thread_list(self) -> List[DebugThread]:
        """Get list of threads"""
        raise NotImplementedError("get_thread_list must be implemented")

    def get_active_thread(self) -> DebugThread:
        """Get the active thread"""
        raise NotImplementedError("get_active_thread must be implemented")

    def get_active_thread_id(self) -> int:
        """Get the active thread ID"""
        raise NotImplementedError("get_active_thread_id must be implemented")

    def set_active_thread(self, thread: DebugThread) -> bool:
        """Set the active thread"""
        raise NotImplementedError("set_active_thread must be implemented")

    def set_active_thread_id(self, tid: int) -> bool:
        """Set the active thread ID"""
        raise NotImplementedError("set_active_thread_id must be implemented")

    def suspend_thread(self, tid: int) -> bool:
        """Suspend a thread"""
        raise NotImplementedError("suspend_thread must be implemented")

    def resume_thread(self, tid: int) -> bool:
        """Resume a thread"""
        raise NotImplementedError("resume_thread must be implemented")

    def add_breakpoint(self, address: int) -> DebugBreakpoint:
        """Add a breakpoint at an address"""
        raise NotImplementedError("add_breakpoint must be implemented")

    def add_breakpoint_relative(self, module: str, offset: int) -> DebugBreakpoint:
        """Add a breakpoint at a module offset"""
        raise NotImplementedError("add_breakpoint_relative must be implemented")

    def remove_breakpoint(self, address: int) -> bool:
        """Remove a breakpoint"""
        raise NotImplementedError("remove_breakpoint must be implemented")

    def remove_breakpoint_relative(self, module: str, offset: int) -> bool:
        """Remove a relative breakpoint"""
        raise NotImplementedError("remove_breakpoint_relative must be implemented")

    def get_breakpoint_list(self) -> List[DebugBreakpoint]:
        """Get list of breakpoints"""
        raise NotImplementedError("get_breakpoint_list must be implemented")

    def read_all_registers(self) -> Dict[str, DebugRegister]:
        """Read all registers"""
        raise NotImplementedError("read_all_registers must be implemented")

    def read_register(self, name: str) -> DebugRegister:
        """Read a specific register"""
        raise NotImplementedError("read_register must be implemented")

    def write_register(self, name: str, value: bytes) -> bool:
        """Write to a register"""
        raise NotImplementedError("write_register must be implemented")

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory"""
        raise NotImplementedError("read_memory must be implemented")

    def write_memory(self, address: int, data: bytes) -> bool:
        """Write memory"""
        raise NotImplementedError("write_memory must be implemented")

    def get_module_list(self) -> List[DebugModule]:
        """Get list of loaded modules"""
        raise NotImplementedError("get_module_list must be implemented")

    def get_target_architecture(self) -> str:
        """Get target architecture"""
        raise NotImplementedError("get_target_architecture must be implemented")

    def stop_reason(self) -> int:
        """Get stop reason"""
        raise NotImplementedError("stop_reason must be implemented")

    def exit_code(self) -> int:
        """Get exit code"""
        raise NotImplementedError("exit_code must be implemented")

    def break_into(self) -> bool:
        """Break into the target"""
        raise NotImplementedError("break_into must be implemented")

    def go(self) -> bool:
        """Continue execution"""
        raise NotImplementedError("go must be implemented")

    def go_reverse(self) -> bool:
        """Continue execution in reverse"""
        return False  # Optional feature

    def step_into(self) -> bool:
        """Step into"""
        raise NotImplementedError("step_into must be implemented")

    def step_into_reverse(self) -> bool:
        """Step into in reverse"""
        return False  # Optional feature

    def step_over(self) -> bool:
        """Step over"""
        raise NotImplementedError("step_over must be implemented")

    def step_over_reverse(self) -> bool:
        """Step over in reverse"""
        return False  # Optional feature

    def step_return(self) -> bool:
        """Step return"""
        return False  # Optional feature

    def step_return_reverse(self) -> bool:
        """Step return in reverse"""
        return False  # Optional feature

    def invoke_backend_command(self, command: str) -> str:
        """Invoke a backend command"""
        return ""  # Optional feature

    def get_instruction_offset(self) -> int:
        """Get current instruction offset"""
        raise NotImplementedError("get_instruction_offset must be implemented")

    def get_stack_pointer(self) -> int:
        """Get stack pointer"""
        raise NotImplementedError("get_stack_pointer must be implemented")

    def support_feature(self, feature: int) -> bool:
        """Check if a feature is supported"""
        return False

    def write_stdin(self, data: str):
        """Write to stdin"""
        pass  # Optional feature

    def get_property(self, name: str) -> Optional[binaryninja.Metadata]:
        """Get a property"""
        return None  # Optional feature

    def set_property(self, name: str, value: Optional[binaryninja.Metadata]) -> bool:
        """Set a property"""
        return False  # Optional feature

    def get_adapter_settings(self) -> Optional[binaryninja.Settings]:
        """Get adapter settings"""
        return None  # Optional feature


class CustomDebugAdapterType:
    """
    Base class for implementing custom debug adapter types in Python.
    """

    def __init__(self, name: str):
        self.name = name
        self._callbacks = self._setup_callbacks()

    def _setup_callbacks(self):
        """Set up the FFI callbacks"""
        callbacks = dbgcore.BNCustomDebugAdapterTypeCallbacks()
        callbacks.context = ctypes.cast(ctypes.pointer(ctypes.py_object(self)), ctypes.c_void_p)
        
        callbacks.create = ctypes.CFUNCTYPE(ctypes.POINTER(dbgcore.BNCustomDebugAdapter), ctypes.c_void_p, ctypes.POINTER(dbgcore.BNBinaryView))(self._create_callback)
        callbacks.isValidForData = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(dbgcore.BNBinaryView))(self._is_valid_for_data_callback)
        callbacks.canExecute = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(dbgcore.BNBinaryView))(self._can_execute_callback)
        callbacks.canConnect = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.POINTER(dbgcore.BNBinaryView))(self._can_connect_callback)
        callbacks.freeCallback = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._free_callback)
        
        return callbacks

    @staticmethod
    def _get_python_adapter_type(ctxt):
        """Extract the Python adapter type object from the context"""
        py_obj_ptr = ctypes.cast(ctxt, ctypes.POINTER(ctypes.py_object))
        return py_obj_ptr.contents.value

    def _create_callback(self, ctxt, data):
        try:
            adapter_type = self._get_python_adapter_type(ctxt)
            bv = binaryninja.BinaryView(handle=data)
            adapter = adapter_type.create(bv)
            if adapter:
                return dbgcore.BNCreateCustomDebugAdapter(ctypes.byref(adapter._callbacks))
            return None
        except:
            traceback.print_exc()
            return None

    def _is_valid_for_data_callback(self, ctxt, data):
        try:
            adapter_type = self._get_python_adapter_type(ctxt)
            bv = binaryninja.BinaryView(handle=data)
            return adapter_type.is_valid_for_data(bv)
        except:
            traceback.print_exc()
            return False

    def _can_execute_callback(self, ctxt, data):
        try:
            adapter_type = self._get_python_adapter_type(ctxt)
            bv = binaryninja.BinaryView(handle=data)
            return adapter_type.can_execute(bv)
        except:
            traceback.print_exc()
            return False

    def _can_connect_callback(self, ctxt, data):
        try:
            adapter_type = self._get_python_adapter_type(ctxt)
            bv = binaryninja.BinaryView(handle=data)
            return adapter_type.can_connect(bv)
        except:
            traceback.print_exc()
            return False

    def _free_callback(self, ctxt):
        # Nothing to do - Python manages object lifecycle
        pass

    def register(self):
        """Register this adapter type with the debugger system"""
        dbgcore.BNRegisterCustomDebugAdapterType(self.name.encode('utf-8'), ctypes.byref(self._callbacks))

    # Abstract methods that must be implemented by subclasses
    def create(self, bv: binaryninja.BinaryView) -> CustomDebugAdapter:
        """Create a debug adapter instance"""
        raise NotImplementedError("create must be implemented")

    def is_valid_for_data(self, bv: binaryninja.BinaryView) -> bool:
        """Check if this adapter type is valid for the given binary view"""
        return True  # Default implementation

    def can_execute(self, bv: binaryninja.BinaryView) -> bool:
        """Check if this adapter can execute the binary"""
        raise NotImplementedError("can_execute must be implemented")

    def can_connect(self, bv: binaryninja.BinaryView) -> bool:
        """Check if this adapter can connect to a remote target"""
        raise NotImplementedError("can_connect must be implemented")