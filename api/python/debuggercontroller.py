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

import binaryninja
# import debugger
from . import _debuggercore as dbgcore
from .debugger_enums import *
from typing import Callable, List, Union


# TTD (Time Travel Debugging) Memory Access Type parsing
def parse_ttd_access_type(access_spec):
    """
    Parse TTD memory access type from string specification.
    
    Args:
        access_spec: String containing access type specification.
                     Can be combinations of 'r' (read), 'w' (write), 'e' (execute)
                     e.g., "r", "rw", "rwe", "we", etc.
                     
    Returns:
        DebuggerTTDMemoryAccessType enum value
    """
    if isinstance(access_spec, str):
        access_value = 0
        access_spec = access_spec.lower()
        
        if 'r' in access_spec:
            access_value |= DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead
        if 'w' in access_spec:
            access_value |= DebuggerTTDMemoryAccessType.DebuggerTTDMemoryWrite
        if 'e' in access_spec:
            access_value |= DebuggerTTDMemoryAccessType.DebuggerTTDMemoryExecute
            
        if access_value == 0:
            raise ValueError(f"Invalid access type specification: '{access_spec}'. Use combinations of 'r', 'w', 'e'")
            
        return access_value
    else:
        # Assume it's already a DebuggerTTDMemoryAccessType enum value
        return access_spec


class DebugProcess:
    """
    DebugProcess represents a process in the target. It has the following fields:

    * ``pid``: the ID of the process
    * ``name``: the name of the process

    """

    def __init__(self, pid, name):
        self.pid = pid
        self.name = name

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.pid == other.pid and self.name == other.name

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.pid, self.pid))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<DebugProcess: {self.pid:#x}, {self.name}>"


class DebugThread:
    """
    DebugThread represents a thread in the target. It has the following fields:

    * ``tid``: the ID of the thread. On different systems, this may be either the system thread ID, or a sequential\
        index starting from zero.
    * ``rip``: the current address (instruction pointer) of the thread

    In the future, we should provide both the internal thread ID and the system thread ID.

    """
    def __init__(self, tid, rip):
        self.tid = tid
        self.rip = rip

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.tid == other.tid and self.rip == other.rip

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.tid, self.rip))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<DebugThread: {self.tid:#x} @ {self.rip:#x}>"


class DebugModule:
    """
    DebugModule represents a module in the target. It has the following fields:

    * ``name``: the path of the module
    * ``short_name``: the name of the module
    * ``address``: the base load address of the module
    * ``size``: the size of the module
    * ``loaded``: not used

    """
    def __init__(self, name, short_name, address, size, loaded):
        self.name = name
        self.short_name = short_name
        self.address = address
        self.size = size
        self.loaded = loaded

    @staticmethod
    def is_same_base_module(module1: Union[str, bytes], module2: Union[str, bytes]) -> bool:
        return dbgcore.BNDebuggerIsSameBaseModule(module1, module2)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.name == other.name and self.short_name == other.short_name and self.address == other.address\
            and self.size == other.size and self.loaded == other.loaded

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.name, self.short_name, self.address. self.size, self.loaded))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<DebugModule: {self.name}, {self.address:#x}, {self.size:#x}>"


class DebugRegister:
    """
    DebugRegister represents a register in the target. It has the following fields:

    * ``name``: the name of the register
    * ``value``: the value of the register
    * ``width``: the width of the register, in bits. E.g., ``rax`` register is 64-bits wide
    * ``index``: the index of the register. This is reported by the DebugAdapter and should remain unchanged
    * ``hint``: a string that shows the content of the memory pointed to by the register. It is empty if the register\
                value do not point to a valid (mapped) memory region

    """
    def __init__(self, name, value, width, index, hint):
        self.name = name
        self.value = value
        self.width = width
        self.index = index
        self.hint = hint

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.name == other.name and self.value == other.value and self.width == other.width \
               and self.index == other.index and self.hint == other.hint

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.name, self.value, self.width. self.index, self.hint))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        hint_str = f", {self.hint}" if self.hint != '' else ''
        return f"<DebugRegister: {self.name}, {self.value:#x}{hint_str}>"


class DebugRegisters:
    """
    DebugRegisters represents all registers of the target.
    """
    def __init__(self, handle):
        self.handle = handle
        self.regs = {}
        count = ctypes.c_ulonglong()
        registers = dbgcore.BNDebuggerGetRegisters(handle, count)
        for i in range(0, count.value):
            bp = DebugRegister(registers[i].m_name, int.from_bytes(registers[i].m_value, byteorder='little'),
                               registers[i].m_width, registers[i].m_registerIndex, registers[i].m_hint)
            self.regs[registers[i].m_name] = bp
        dbgcore.BNDebuggerFreeRegisters(registers, count.value)

    def __repr__(self) -> str:
        return self.regs.__repr__()

    def __getitem__(self, name):
        if name not in self.regs:
            return None

        return self.regs[name]

    def __setitem__(self, name, val):
        buffer = val.to_bytes(64, byteorder='little', signed=False)
        c_buffer = (ctypes.c_ubyte * 64)(*buffer)
        dbgcore.BNDebuggerSetRegisterValue(self.handle, name, c_buffer)

    def __len__(self):
        return len(self.regs)


class DebugBreakpoint:
    """
    DebugBreakpoint represents a breakpoint in the target. It has the following fields:

    * ``module``: the name of the module for which the breakpoint is in
    * ``offset``: the offset of the breakpoint to the start of the module
    * ``address``: the absolute address of the breakpoint
    * ``enabled``: whether the breakpoint is enabled (read-only)

    """
    def __init__(self, module, offset, address, enabled):
        self.module = module
        self.offset = offset
        self.address = address
        self.enabled = enabled

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.module == other.module and self.offset == other.offset and self.address == other.address \
               and self.enabled == other.enabled

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.module, self.offset, self.address, self.enabled))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        status = "enabled" if self.enabled else "disabled"
        return f"<DebugBreakpoint: {self.module}:{self.offset:#x}, {self.address:#x}, {status}>"


class ModuleNameAndOffset:
    """
    ModuleNameAndOffset represents an address that is relative to the start of module. It is useful when ASLR is on.

    * ``module``: the name of the module for which the address is in
    * ``offset``: the offset of the address to the start of the module

    """
    def __init__(self, module, offset):
        self.module = module
        self.offset = offset

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.module == other.module and self.offset == other.offset

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __lt__(self, other):
        if self.module < other.module:
            return True
        elif self.module > other.module:
            return False
        return self.offset < other.offset

    def __gt__(self, other):
        if self.module > other.module:
            return True
        elif self.module < other.module:
            return False
        return self.offset > other.offset

    def __hash__(self):
        return hash((self.module, self.offset))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")


class DebugFrame:
    """
    DebugFrame represents a frame in the stack trace. It has the following fields:

    * ``index``: the index of the frame
    * ``pc``: the program counter of the frame
    * ``sp``: the stack pointer of the frame
    * ``fp``: the frame pointer of the frame
    * ``func_name``: the function name which the pc is in
    * ``func_start``: the start of the function
    * ``module``: the module of the pc

    """
    def __init__(self, index, pc, sp, fp, func_name, func_start, module):
        self.index = index
        self.pc = pc
        self.sp = sp
        self.fp = fp
        self.func_name = func_name
        self.func_start = func_start
        self.module = module

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.index == other.index and self.pc == other.pc and self.sp == other.sp \
               and self.fp == other.fp and self.func_name == other.func_name and self.func_start == other.func_start \
                and self.module == other.module

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.index, self.pc, self.sp, self.fp, self.func_name, self.func_start, self.module))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        offset = self.pc - self.func_start
        if self.func_name != '':
            return f"<DebugFrame: {self.module}`{self.func_name} + {offset:#x}, sp: {self.sp:#x}, fp: {self.fp:#x}>"
        else:
            return f"<DebugFrame: {self.module} + {offset:#x}, sp: {self.sp:#x}, fp: {self.fp:#x}>"


class TargetStoppedEventData:
    """
    TargetStoppedEventData is the data associated with a TargetStoppedEvent

    * ``reason``: the reason of the stop
    * ``last_active_thread``: not used
    * ``exit_code``: not used
    * ``data``: extra data. Not used.

    """
    def __init__(self, reason: DebugStopReason, last_active_thread: int, exit_code: int, data):
        self.reason = reason
        self.last_active_thread = last_active_thread
        self.exit_code = exit_code
        self.data = data


class ErrorEventData:
    """
    ErrorEventData is the data associated with a ErrorEvent

    * ``error``: the error message
    * ``data``: extra data. Not used.

    """
    def __init__(self, error: str, data):
        self.error = error
        self.data = data


class TargetExitedEventData:
    """
    TargetExitedEventData is the data associated with a TargetExitedEvent

    * ``exit_code``: the exit code of the target

    """
    def __init__(self, exit_code: int):
        self.exit_code = exit_code


class StdOutMessageEventData:
    """
    StdOutMessageEventData is the data associated with a StdOutMessageEvent

    * ``message``: the message that the target writes to the stdout

    """
    def __init__(self, message: str):
        self.message = message


class DebuggerEventData:
    """
    DebuggerEventData is the collection of all possible data associated with the debugger events

    * ``target_stopped_data``: the data associated with a TargetStoppedEvent
    * ``error_data``: the data associated with an ErrorEvent
    * ``absolute_address``: an integer address, which is used when an absolute breakpoint is added/removed
    * ``relative_address``: a ModuleNameAndOffset, which is used when a relative breakpoint is added/removed
    * ``exit_data``: the data associated with a TargetExitedEvent
    * ``message_data``: message data, used by both StdOutMessageEvent and BackendMessageEvent

    """
    def __init__(self, target_stopped_data: TargetStoppedEventData,
                 error_data: ErrorEventData,
                 absolute_address: int,
                 relative_address: ModuleNameAndOffset,
                 exit_data: TargetExitedEventData,
                 message_data: StdOutMessageEventData):
        self.target_stopped_data = target_stopped_data
        self.error_data = error_data
        self.absolute_address = absolute_address
        self.relative_address = relative_address
        self.exit_data = exit_data
        self.message_data = message_data


class DebuggerEvent:
    """
    DebuggerEvent is the event object that a debugger event callback receives

    * ``type``: a DebuggerEventType that specifies the event type
    * ``data``: a DebuggerEventData that specifies the event data

    """
    def __init__(self, type: DebuggerEventType, data: DebuggerEventData):
        self.type = type
        self.data = data


DebuggerEventCallback = Callable[['DebuggerEvent'], None]


class DebuggerEventWrapper:

    # This has no functional purposes;
    # we just need it to stop Python from prematurely freeing the object
    _debugger_events = {}

    @classmethod
    def register(cls, controller: 'DebuggerController', callback: DebuggerEventCallback, name: Union[str, bytes]) -> int:
        callback_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(dbgcore.BNDebuggerEvent))\
                                        (lambda ctxt, event: cls._notify(event[0], callback))
        handle = dbgcore.BNDebuggerRegisterEventCallback(controller.handle, callback_obj, name, None)
        cls._debugger_events[handle] = callback_obj
        return handle

    @classmethod
    def remove(cls, controller: 'DebuggerController', index: int) -> None:
        try:
            dbgcore.BNDebuggerRemoveEventCallback(controller.handle, index)
            del cls._debugger_events[index]
        except:
            binaryninja.log_error(f'invalid debugger event callback index {index}')

    @staticmethod
    def _notify(event: dbgcore.BNDebuggerEvent, callback: DebuggerEventCallback) -> None:
        try:
            data = event.data
            target_stopped_data = TargetStoppedEventData(data.targetStoppedData.reason,
                                                         data.targetStoppedData.lastActiveThread,
                                                         data.targetStoppedData.exitCode,
                                                         data.targetStoppedData.data)
            error_data = ErrorEventData(data.errorData.error, data.errorData.data)
            absolute_addr = data.absoluteAddress
            relative_addr = ModuleNameAndOffset(data.relativeAddress.module, data.relativeAddress.offset)
            exit_data = TargetExitedEventData(data.exitData.exitCode)
            message_data = StdOutMessageEventData(data.messageData.message)
            event_data = DebuggerEventData(target_stopped_data, error_data, absolute_addr, relative_addr, exit_data,
                                           message_data)
            event = DebuggerEvent(event.type, event_data)
            callback(event)
        except:
            binaryninja.log_error(traceback.format_exc())


class TTDPosition:
    """
    TTDPosition represents a position in a time travel debugging trace.
    
    It has the following fields:
    
    * ``sequence``: the sequence number (as hex string or int)
    * ``step``: the step number within the sequence (as hex string or int)
    """
    
    def __init__(self, sequence, step):
        if isinstance(sequence, str):
            self.sequence = int(sequence, 16)
        else:
            self.sequence = int(sequence)
            
        if isinstance(step, str):
            self.step = int(step, 16)
        else:
            self.step = int(step)
    
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.sequence == other.sequence and self.step == other.step
    
    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)
    
    def __hash__(self):
        return hash((self.sequence, self.step))
    
    def __repr__(self):
        return f"<TTDPosition: {self.sequence:x}:{self.step:x}>"
    
    def __str__(self):
        return f"{self.sequence:x}:{self.step:x}"
    
    @classmethod
    def from_string(cls, timestamp_str):
        """
        Create a TTDPosition from a string in format "sequence:step"
        Both sequence and step can be in hex or decimal format.
        """
        if ':' not in timestamp_str:
            raise ValueError("Timestamp must be in format 'sequence:step'")
        
        parts = timestamp_str.strip().split(':')
        if len(parts) != 2:
            raise ValueError("Timestamp must be in format 'sequence:step'")
        
        return cls(parts[0], parts[1])


class TTDMemoryEvent:
    """
    TTDMemoryEvent represents a memory access event in a TTD trace. It has the following fields:

    * ``event_type``: type of the event (e.g., "Memory")
    * ``thread_id``: OS thread ID that performed the memory access
    * ``unique_thread_id``: unique thread ID across the trace
    * ``time_start``: TTD position when the memory access started
    * ``time_end``: TTD position when the memory access ended
    * ``address``: memory address that was accessed
    * ``size``: size of the memory access
    * ``memory_address``: actual memory address (may differ from address field)
    * ``instruction_address``: address of the instruction that performed the access
    * ``value``: value that was read/written/executed
    * ``access_type``: type of access (read/write/execute)
    """

    def __init__(self, event_type: str, thread_id: int, unique_thread_id: int,
                 time_start: TTDPosition, time_end: TTDPosition, address: int,
                 size: int, memory_address: int, instruction_address: int,
                 value: int, access_type: int):
        self.event_type = event_type
        self.thread_id = thread_id
        self.unique_thread_id = unique_thread_id
        self.time_start = time_start
        self.time_end = time_end
        self.address = address
        self.size = size
        self.memory_address = memory_address
        self.instruction_address = instruction_address
        self.value = value
        self.access_type = access_type

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.event_type == other.event_type and
                self.thread_id == other.thread_id and
                self.unique_thread_id == other.unique_thread_id and
                self.time_start == other.time_start and
                self.time_end == other.time_end and
                self.address == other.address and
                self.size == other.size and
                self.memory_address == other.memory_address and
                self.instruction_address == other.instruction_address and
                self.value == other.value and
                self.access_type == other.access_type)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.event_type, self.thread_id, self.unique_thread_id,
                     self.time_start, self.time_end, self.address, self.size,
                     self.memory_address, self.instruction_address, self.value,
                     self.access_type))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<TTDMemoryEvent: {self.event_type} @ {self.address:#x}, thread {self.thread_id}>"


class TTDCallEvent:
    """
    TTDCallEvent represents a function call event in a TTD trace. It has the following fields:

    * ``event_type``: type of the event (always "Call" for TTD.Calls objects)
    * ``thread_id``: OS thread ID that made the call
    * ``unique_thread_id``: unique thread ID across the trace
    * ``function``: symbolic name of the function
    * ``function_address``: function's address in memory
    * ``return_address``: instruction to return to after the call
    * ``return_value``: return value of the function (if not void)
    * ``has_return_value``: whether the function has a return value
    * ``parameters``: list of parameters passed to the function
    * ``time_start``: TTD position when call started
    * ``time_end``: TTD position when call ended
    """

    def __init__(self, event_type: str, thread_id: int, unique_thread_id: int,
                 function: str, function_address: int, return_address: int,
                 return_value: int, has_return_value: bool, parameters: List[str],
                 time_start: TTDPosition, time_end: TTDPosition):
        self.event_type = event_type
        self.thread_id = thread_id
        self.unique_thread_id = unique_thread_id
        self.function = function
        self.function_address = function_address
        self.return_address = return_address
        self.return_value = return_value
        self.has_return_value = has_return_value
        self.parameters = parameters
        self.time_start = time_start
        self.time_end = time_end

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.event_type == other.event_type and
                self.thread_id == other.thread_id and
                self.unique_thread_id == other.unique_thread_id and
                self.function == other.function and
                self.function_address == other.function_address and
                self.return_address == other.return_address and
                self.return_value == other.return_value and
                self.has_return_value == other.has_return_value and
                self.parameters == other.parameters and
                self.time_start == other.time_start and
                self.time_end == other.time_end)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.event_type, self.thread_id, self.unique_thread_id,
                     self.function, self.function_address, self.return_address,
                     self.return_value, self.has_return_value, tuple(self.parameters),
                     self.time_start, self.time_end))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<TTDCallEvent: {self.function} @ {self.function_address:#x}, thread {self.thread_id}>"


class TTDEventType:
    """
    TTD Event Type enumeration for different types of events in TTD traces.
    These are bitfield flags that can be combined.
    """
    NONE = 0
    ThreadCreated = 1
    ThreadTerminated = 2
    ModuleLoaded = 4
    ModuleUnloaded = 8
    Exception = 16
    ALL = ThreadCreated | ThreadTerminated | ModuleLoaded | ModuleUnloaded | Exception


class TTDModule:
    """
    TTDModule represents information about modules that were loaded/unloaded during a TTD trace.
    
    Attributes:
        name (str): name and path of the module
        address (int): address where the module was loaded
        size (int): size of the module in bytes
        checksum (int): checksum of the module
        timestamp (int): timestamp of the module
    """

    def __init__(self, name: str, address: int, size: int, checksum: int, timestamp: int):
        self.name = name
        self.address = address
        self.size = size
        self.checksum = checksum
        self.timestamp = timestamp

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.name == other.name and
                self.address == other.address and
                self.size == other.size and
                self.checksum == other.checksum and
                self.timestamp == other.timestamp)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.name, self.address, self.size, self.checksum, self.timestamp))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<TTDModule: {self.name} @ {self.address:#x}, size {self.size}>"


class TTDThread:
    """
    TTDThread represents information about threads and their lifetime during a TTD trace.
    
    Attributes:
        unique_id (int): unique ID for the thread across the trace
        id (int): TID of the thread
        lifetime_start (TTDPosition): lifetime start position
        lifetime_end (TTDPosition): lifetime end position
        active_time_start (TTDPosition): active time start position
        active_time_end (TTDPosition): active time end position
    """

    def __init__(self, unique_id: int, id: int, lifetime_start: TTDPosition, lifetime_end: TTDPosition,
                 active_time_start: TTDPosition, active_time_end: TTDPosition):
        self.unique_id = unique_id
        self.id = id
        self.lifetime_start = lifetime_start
        self.lifetime_end = lifetime_end
        self.active_time_start = active_time_start
        self.active_time_end = active_time_end

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.unique_id == other.unique_id and
                self.id == other.id and
                self.lifetime_start == other.lifetime_start and
                self.lifetime_end == other.lifetime_end and
                self.active_time_start == other.active_time_start and
                self.active_time_end == other.active_time_end)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.unique_id, self.id, self.lifetime_start, self.lifetime_end,
                     self.active_time_start, self.active_time_end))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<TTDThread: TID {self.id}, UniqueID {self.unique_id}>"


class TTDExceptionType:
    """
    TTD Exception Type enumeration for different types of exceptions.
    """
    Software = 0
    Hardware = 1


class TTDException:
    """
    TTDException represents information about exceptions that occurred during a TTD trace.
    
    Attributes:
        type (int): type of exception (TTDExceptionType.Software or TTDExceptionType.Hardware)
        program_counter (int): instruction where exception was thrown
        code (int): exception code
        flags (int): exception flags
        record_address (int): where in memory the exception record is found
        position (TTDPosition): position where exception occurred
    """

    def __init__(self, type: int, program_counter: int, code: int, flags: int, 
                 record_address: int, position: TTDPosition):
        self.type = type
        self.program_counter = program_counter
        self.code = code
        self.flags = flags
        self.record_address = record_address
        self.position = position

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.type == other.type and
                self.program_counter == other.program_counter and
                self.code == other.code and
                self.flags == other.flags and
                self.record_address == other.record_address and
                self.position == other.position)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.type, self.program_counter, self.code, self.flags,
                     self.record_address, self.position))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        type_str = "Hardware" if self.type == TTDExceptionType.Hardware else "Software"
        return f"<TTDException: {type_str} @ {self.program_counter:#x}, code {self.code:#x}>"


class TTDEvent:
    """
    TTDEvent represents important events that happened during a TTD trace.
    
    Attributes:
        type (int): type of event (TTDEventType enum value)
        position (TTDPosition): position where event occurred
        module (TTDModule or None): module information for ModuleLoaded/ModuleUnloaded events
        thread (TTDThread or None): thread information for ThreadCreated/ThreadTerminated events
        exception (TTDException or None): exception information for Exception events
    """

    def __init__(self, type: int, position: TTDPosition, module = None, thread = None, exception = None):
        self.type = type
        self.position = position
        self.module = module
        self.thread = thread
        self.exception = exception

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return (self.type == other.type and
                self.position == other.position and
                self.module == other.module and
                self.thread == other.thread and
                self.exception == other.exception)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash((self.type, self.position, self.module, self.thread, self.exception))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        type_names = {
            TTDEventType.ThreadCreated: "ThreadCreated",
            TTDEventType.ThreadTerminated: "ThreadTerminated", 
            TTDEventType.ModuleLoaded: "ModuleLoaded",
            TTDEventType.ModuleUnloaded: "ModuleUnloaded",
            TTDEventType.Exception: "Exception"
        }
        type_str = type_names.get(self.type, f"Unknown({self.type})")
        return f"<TTDEvent: {type_str} @ {self.position}>"


class DebuggerController:
    """
    The ``DebuggerController`` object is the core of the debugger. Most debugger operations can be performed on it.
    It takes in a ``BinaryView`` and creates a debugger for it. If a debugger is already existing for the very same
    BinaryView object, the debugger is returned.

    Most operations of the debugger are performed on this class. For example, we can launch the debugger as follows::

        >>> bv = load("test/binaries/helloworld")
        >>> dbg = DebuggerController(bv)
        >>> dbg.launch_and_wait()
        <DebugStopReason.Breakpoint: 6>

    When the ``launch_and_wait()`` returns ``DebugStopReason.Breakpoint``, it means the debugger has launched the target
    successfully, and the target stopped at the entry point of the binary. Now we can perform other control operations
    on it, e.g., resume the target by calling ``step_into_and_wait()``.

        >>> dbg.step_into_and_wait()
        <DebugStopReason.SingleStep: 4>

    For all the API functions that resume the target, e.g., launch go, step into, etc, there are two variants of them.
    One of them resumes the target and waits for it to stop again synchronously, ``step_into_and_wait`` will do a step
    into, and it only returns AFTER the target stops again. This is more frequently used, and is suitable for automating
    a sequence of actions. However, after calling such a synchronous API, if for any reason the target does not stop as
    expected, Binary Ninja might be confused or hang.

    The second set of API works asynchronously. For example, ``step into`` will only do a step into, but does NOT wait
    for the target to stop again. Usually the asynchronous API is used with ``register_event_callback`` to listen for
    the relevant events (e.g., target resumed, stopped, etc). The asynchronous API is harder to use and is only
    recommended when the synchronous version does not suit your need. The Binary Ninja debugger UI uses the
    asynchronous API.

    To retrieve all the registers, run `regs`:

        >>> dbg.regs
        {'x0': <DebugRegister: x0, 0x1>, ...}

    More often we only need get the value of one regisgter:

        >>> dbg.regs['x1']
        <DebugRegister: x1, 0x16fdffa70, &"/Users/xxxx//debugger/test/binaries/Darwin-arm64-signed/helloworld">

    The result contains the register value as well as a string that can be dereferenced at its value.

    ``ip`` returns the current intrudction pointer, and `stack_pointer`` returns the stack pointer:

        >>> dbg.stack_pointer
        6171916256
        >>> dbg.ip
        4294983364

    To read/write memory value, use ``read_memory``/``write_memory``. Or you can directly read/write the binary view
    object returned by `dbg.data`.

        >>> dbg.read_memory(dbg.ip, 0x10)
        <binaryninja.databuffer.DataBuffer object at 0x32ffa2f90>
        >>> dbg.data.read(dbg.ip, 0x10)
        b'\xfd{\x03\xa9\xfd\xc3\x00\x91\xbf\xc3\x1f\xb8\xa0\x83\x1f\xb8'

        >>> dbg.write_memory(dbg.stack_pointer, b'a' * 0x10)
        True
        >>> dbg.data.write(dbg.stack_pointer, b'a' * 0x10)
        16

    ``modules`` returns the list of modules, `threads` returns the list of threads.

    Breakpoints can be added via `add_breakpoint`:

        >>> dbg.add_breakpoint(0x100003ed0)

    And it will be hit after we resume the target with ``go_and_wait``:

        >>> dbg.go_and_wait()
        <DebugStopReason.Breakpoint: 6>

    We can resume it again:

        >>> dbg.go_and_wait()
        <DebugStopReason.ProcessExited: 2>

    Since there are no other breakpoints in the target, the process executes and then exits.

    For more examples of using the debugger Python API, feel free to get some inspirations from our
    [unit tests](https://github.com/Vector35/debugger/blob/dev/test/debugger_test.py)

    """
    def __init__(self, bv: binaryninja.BinaryView):
        # bv.handle has type binaryninja.core.BNBinaryView, which is different from dbgcore.BNBinaryView,
        # so the casting here is necessary
        # A different way to deal with is that instead of defining a BNBinaryView struct in the _debuggercore.py,
        # do from binaryninja._binaryninjacore import BNBinaryView
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        self.handle = dbgcore.BNGetDebuggerController(bv_obj)

    def destroy(self):
        """
        Delete the DebuggerController object. Intended for internal use. Ordinary users do not need to call it.
        """
        dbgcore.BNDebuggerDestroyController(self.handle)

    @property
    def data(self) -> binaryninja.BinaryView:
        """Get the (rebased) BinaryView of the debugger"""
        result = dbgcore.BNDebuggerGetData(self.handle)
        if result is None:
            return None
        result = ctypes.cast(result, ctypes.POINTER(binaryninja.core.BNBinaryView))
        if result is None:
            return None
        return binaryninja.BinaryView(handle=result)

    @property
    @binaryninja.deprecation.deprecated(deprecated_in="4.1.5542", details='Debugger no longer uses the live view, Use :py:attr:`data` instead')
    def live_view(self) -> binaryninja.BinaryView:
        """Get the live BinaryView of the debugger"""
        return self.data

    @property
    def remote_arch(self) -> binaryninja.Architecture:
        """
        Get the architecture of the running target (read-only). This could be different from the architecture of the original binary.
        """
        result = dbgcore.BNDebuggerGetRemoteArchitecture(self.handle)
        if result is None:
            return None
        result = ctypes.cast(result, ctypes.POINTER(binaryninja.core.BNArchitecture))
        if result is None:
            return None
        return binaryninja.CoreArchitecture(handle=result)

    @property
    def connected(self) -> bool:
        """Whether the debugger has successfully connected to the target (read-only)"""
        return dbgcore.BNDebuggerIsConnected(self.handle)

    @property
    def running(self) -> bool:
        """Whether the target is running (read-only)"""
        return dbgcore.BNDebuggerIsRunning(self.handle)

    @property
    def stack_pointer(self) -> int:
        """The stack pointer of the target (read-only)"""
        return dbgcore.BNDebuggerGetStackPointer(self.handle)

    def read_memory(self, address: int, size: int) -> binaryninja.DataBuffer:
        """
        Read memory from the target.

        One can also get the ``data`` BinaryView of the DebuggerController, and use ordinary read methods to read
        its content.

        :param address: address to read from
        :param size: number of bytes to read
        :return: always returns a DataBuffer. When the operation fails, the size of the DataBuffer is 0x0
        """
        result = dbgcore.BNDebuggerReadMemory(self.handle, address, size)
        if result is None:
            return None
        buffer = ctypes.cast(result, ctypes.POINTER(binaryninja.core.BNDataBuffer))
        if buffer is None:
            return None
        return binaryninja.DataBuffer(handle=buffer)

    def write_memory(self, address: int, buffer) -> bool:
        """
        Write memory of the target.

        One can also get the ``data`` BinaryView of the DebuggerController, and use ordinary write methods to write
        its content.

        :param address: address to write to
        :param buffer: buffer of data to write. It can be either bytes or a DataBuffer
        :return: True on success, False on failure.
        """
        if isinstance(buffer, bytes):
            buffer = binaryninja.DataBuffer(buffer)
        buffer_obj = ctypes.cast(buffer.handle, ctypes.POINTER(dbgcore.BNDataBuffer))
        return dbgcore.BNDebuggerWriteMemory(self.handle, address, buffer_obj)

    @property
    def processes(self) -> List[DebugProcess]:
        """
        The processes of the target.
        """
        count = ctypes.c_ulonglong()
        process_list = dbgcore.BNDebuggerGetProcessList(self.handle, count)
        result = []
        for i in range(0, count.value):
            process = DebugProcess(process_list[i].m_pid, process_list[i].m_processName)
            result.append(process)

        dbgcore.BNDebuggerFreeProcessList(process_list, count.value)
        return result

    @property
    def threads(self) -> List[DebugThread]:
        """
        The threads of the target.
        """
        count = ctypes.c_ulonglong()
        threads = dbgcore.BNDebuggerGetThreads(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugThread(threads[i].m_tid, threads[i].m_rip)
            result.append(bp)

        dbgcore.BNDebuggerFreeThreads(threads, count.value)
        return result

    @property
    def active_thread(self) -> DebugThread:
        """
        The active thread of the target.  (read/write)

        :getter: returns the active thread of the target
        :setter: sets the active thread of the target
        """
        active_thread = dbgcore.BNDebuggerGetActiveThread(self.handle)
        return DebugThread(active_thread.m_tid, active_thread.m_rip)

    @active_thread.setter
    def active_thread(self, thread: DebugThread) -> None:
        dbgcore.BNDebuggerSetActiveThread(self.handle, dbgcore.BNDebugThread(thread.tid, thread.rip))

    def suspend_thread(self, tid: int) -> bool:
        """
        Suspends a thread by thread id.

        :param tid: thread id
        """
        return dbgcore.BNDebuggerSuspendThread(self.handle, tid)

    def resume_thread(self, tid: int) -> bool:
        """
        Resumes a thread by thread id.

        :param tid: thread id
        """
        return dbgcore.BNDebuggerResumeThread(self.handle, tid)

    @property
    def modules(self) -> List[DebugModule]:
        """
        The modules of the target

        :return: a list of ``DebugModule``
        """
        count = ctypes.c_ulonglong()
        modules = dbgcore.BNDebuggerGetModules(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugModule(modules[i].m_name, modules[i].m_short_name, modules[i].m_address, modules[i].m_size, modules[i].m_loaded)
            result.append(bp)

        dbgcore.BNDebuggerFreeModules(modules, count.value)
        return result

    @property
    def regs(self) -> DebugRegisters:
        """
        All registers of the target

        :return: a list of ``DebugRegister``
        """
        return DebugRegisters(self.handle)

    def get_reg_value(self, reg: Union[str, bytes]) -> int:
        """
        Get the value of one register by its name

        :param reg: the name of the register
        """
        buffer = (ctypes.c_ubyte * 64)()
        dbgcore.BNDebuggerGetRegisterValue(self.handle, reg, buffer)
        return int.from_bytes(buffer, byteorder='little')

    def set_reg_value(self, reg: Union[str, bytes], value: int) -> bool:
        """
        Set value of register

        :param reg: the name of the register
        :param value: new value of the register
        """
        buffer = value.to_bytes(64, byteorder='little', signed=False)
        c_buffer = (ctypes.c_ubyte * 64)(*buffer)
        return dbgcore.BNDebuggerSetRegisterValue(self.handle, reg, c_buffer)

    # target control
    def launch(self) -> bool:
        """
        Launch the target
        """
        return dbgcore.BNDebuggerLaunch(self.handle)

    def launch_and_wait(self) -> DebugStopReason:
        """
        Launch the target and wait for all debugger events to be processed
        """
        return DebugStopReason(dbgcore.BNDebuggerLaunchAndWait(self.handle))

    def restart(self) -> None:
        """
        Restart the target
        """
        dbgcore.BNDebuggerRestart(self.handle)

    def quit(self) -> None:
        """
        Terminate the target
        """
        dbgcore.BNDebuggerQuit(self.handle)

    def quit_and_wait(self) -> None:
        """
        Terminate the target, and wait for all callback to be called
        """
        dbgcore.BNDebuggerQuitAndWait(self.handle)

    def connect(self) -> bool:
        """
        Connect to a remote target (process)

        The host and port of the remote target must first be specified by setting `remote_host` and `remote_port`
        """
        return dbgcore.BNDebuggerConnect(self.handle)

    def connect_and_wait(self) -> DebugStopReason:
        """
        Connect to a remote target (process) and wait for all debugger events to be processed

        The host and port of the remote target must first be specified by setting `remote_host` and `remote_port`
        """
        return DebugStopReason(dbgcore.BNDebuggerConnectAndWait(self.handle))

    def connect_to_debug_server(self) -> bool:
        """
        Connect to a debug server.

        The host and port of the debug server must first be specified by setting `remote_host` and `remote_port`
        """
        return dbgcore.BNDebuggerConnectToDebugServer(self.handle)

    def disconnect_from_debug_server(self) -> None:
        """`
        Disconnect from a debug server.
        """
        dbgcore.BNDebuggerDisconnectDebugServer(self.handle)

    def detach(self) -> None:
        """
        Detach the target, and let it execute on its own.
        """
        dbgcore.BNDebuggerQuit(self.handle)

    def pause(self) -> None:
        """
        Pause a running target
        """
        dbgcore.BNDebuggerPause(self.handle)

    def launch_or_connect(self) -> None:
        """
        Launch or connect to the target. Intended for internal use. Ordinary users do not need to call it.
        """
        dbgcore.BNDebuggerLaunchOrConnect(self.handle)

    def attach(self) -> bool:
        """
        Attach to a running process

        The PID of the target process must be set via DebuggerState.pid_attach
        """
        return dbgcore.BNDebuggerAttach(self.handle)

    def attach_and_wait(self) -> DebugStopReason:
        """
        Attach to a running process and wait until all debugger events are processed

        The PID of the target process must be set via DebuggerState.pid_attach
        """
        return DebugStopReason(dbgcore.BNDebuggerAttachAndWait(self.handle))

    def go(self) -> bool:
        """
        Resume the target.

        The call is asynchronous and returns before the target stops.

        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerGo(self.handle)

    # TODO: Improve the documentation on reverse-execution functions
    def go_reverse(self) -> bool:
        """
        Resume the target in reverse.

        The call is asynchronous and returns before the target stops.

        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerGoReverse(self.handle)

    def step_into(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> bool:
        """
        Perform a step into on the target.

        When the next instruction is not a call, execute the next instruction. When the next instruction is a call,
        follow the call the get into the first instruction of the call.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either executes the
        next IL instruction, or follow into the IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping into on IL.

        The call is asynchronous and returns before the target stops.

        :param il: optional IL level to perform the operation at
        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerStepInto(self.handle, il)

    def step_into_reverse(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> bool:
        """
        Perform a step into on the target in reverse.

        When the previous instruction is not a call, step backwards. When the previous instruction is a call,
        follow the call into the last instruction of the function.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either executes the
        next IL instruction, or follow into the IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping into on IL.

        The call is asynchronous and returns before the target stops.

        :param il: optional IL level to perform the operation at
        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerStepIntoReverse(self.handle, il)

    def step_over(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> bool:
        """
        Perform a step over on the target.

        When the next instruction is not a call, execute the next instruction. When the next instruction is a call,
        complete the execution of the function and break at next instruction.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either executes the
        next IL instruction, or completes the IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping over on IL.

        The call is asynchronous and returns before the target stops.

        :param il: optional IL level to perform the operation at
        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerStepOver(self.handle, il)

    def step_over_reverse(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> bool:
        """
        Perform a step over on the target in reverse.

        When the previous instruction is not a call, step backwards. When the previous instruction is a call,
        step back over the call.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either executes the
        next IL instruction, or completes the IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping over on IL.

        The call is asynchronous and returns before the target stops.

        :param il: optional IL level to perform the operation at
        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerStepOverReverse(self.handle, il)

    def step_return(self) -> bool:
        """
        Perform a step return on the target.

        Step return completes the execution of the current function and returns to its caller. This operation relies
        heavily on stack frame analysis, which is done by the DebugAdapters.

        If a DebugAdapter does not support (i.e., overload) this function, a fallback handling is provided by the
        DebuggerController. It checks the MLIL function and put breakpoints on all returning instructions and then resume
        the target. By the time it breaks, the target is about to return from the current function.

        This fallback behavior is slightly different from that offered by the LLDB and DbgEng adapter, which returns
        from the current function and break afterwards.

        The call is asynchronous and returns before the target stops.

        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerStepReturn(self.handle)

    def step_return_reverse(self) -> bool:
        """
        Perform a step return on the target in reverse.

        Step return reverses the execution of the current function and returns to its caller. This operation relies
        heavily on stack frame analysis, which is done by the DebugAdapters.

        If a DebugAdapter does not support (i.e., overload) this function, a fallback handling is provided by the
        DebuggerController. It checks the MLIL function and put breakpoints on all returning instructions and then resume
        the target. By the time it breaks, the target is about to return from the current function.

        This fallback behavior is slightly different from that offered by the LLDB and DbgEng adapter, which returns
        from the current function and break afterwards.

        The call is asynchronous and returns before the target stops.

        :return: whether the operation is successfully requested
        """
        return dbgcore.BNDebuggerStepReturnReverse(self.handle)

    def run_to(self, address) -> bool:
        """
        Resume the target, and wait for it to break at the given address(es).

        The address parameter can be either an integer, or a list of integers.

        Internally, the debugger places breakpoints on these addresses, resume the target, and wait for the target
        to break. Then the debugger removes the added breakpoints.

        The call is asynchronous and returns before the target stops.

        :return: whether the operation is successfully requested
        """
        if isinstance(address, int):
            address = [address]

        if not isinstance(address, list):
            raise NotImplementedError

        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]

        return dbgcore.BNDebuggerRunTo(self.handle, addr_list, len(address))

    def run_to_reverse(self, address) -> bool:
        """
        Resume the target in reverse, and wait for it to break at the given address(es).

        The address parameter can be either an integer, or a list of integers.

        Internally, the debugger places breakpoints on these addresses, resumes the target in reverse, and waits for the target
        to break. Then the debugger removes the added breakpoints.

        The call is asynchronous and returns before the target stops.

        :return: whether the operation is successfully requested
        """
        if isinstance(address, int):
            address = [address]

        if not isinstance(address, list):
            raise NotImplementedError

        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]

        return dbgcore.BNDebuggerRunToReverse(self.handle, addr_list, len(address))

    def go_and_wait(self) -> DebugStopReason:
        """
        Resume the target.

        The call is blocking and only returns when the target stops.

        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerGoAndWait(self.handle))

    def go_reverse_and_wait(self) -> DebugStopReason:
        """
        Resume the target in reverse.

        The call is blocking and only returns when the target stops.

        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerGoReverseAndWait(self.handle))

    def step_into_and_wait(self, il: binaryninja.FunctionGraphType =
                binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        """
        Perform a step into on the target in reverse.

        When the next instruction is not a call, execute the next instruction. When the next instruction is a call,
        follow the call the get into the first instruction of the call.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either executes the
        next IL instruction, or follow into the IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping into on IL.

        The call is blocking and only returns when the target stops.

        :param il: optional IL level to perform the operation at
        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerStepIntoAndWait(self.handle, il))


    def step_into_reverse_and_wait(self, il: binaryninja.FunctionGraphType =
    binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        """
        Perform a reverse step into on the target.

        When the previous instruction is not a call, reverse the program to the previous state. When the previous instruction is a call,
        follow the call to get into the last instruction of the call.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either reverses the current IL instruction, or follow into the previous IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping into on IL.

        The call is blocking and only returns when the target stops.

        :param il: optional IL level to perform the operation at
        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerStepIntoReverseAndWait(self.handle, il))

    def step_over_and_wait(self, il: binaryninja.FunctionGraphType =
                binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        """
        Perform a step over on the target.

        When the next instruction is not a call, execute the next instruction. When the next instruction is a call,
        complete the execution of the function and break at next instruction.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either executes the
        next IL instruction, or completes the IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping over on IL.

        The call is blocking and only returns when the target stops.

        :param il: optional IL level to perform the operation at
        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerStepOverAndWait(self.handle, il))

    def step_over_reverse_and_wait(self, il: binaryninja.FunctionGraphType =
    binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        """
        Perform a step over on the target in reverse.

        When the next instruction is not a call, execute the next instruction. When the next instruction is a call,
        complete the execution of the function and break at next instruction.

        The operation can be performed on an IL level specified by the ``il`` parameter, which then either executes the
        next IL instruction, or completes the IL function. Note, the underlying operation is still performed at the
        disassembly level because that is the only thing a debugger understands. The high-level operations are simulated
        on top of the disassembly and analysis.

        Some limitations are known with stepping over on IL.

        The call is blocking and only returns when the target stops.

        :param il: optional IL level to perform the operation at
        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerStepOverReverseAndWait(self.handle, il))

    def step_return_and_wait(self) -> DebugStopReason:
        """
        Perform a step return on the target.

        Step return completes the execution of the current function and returns to its caller. This operation relies
        heavily on stack frame analysis, which is done by the DebugAdapters.

        If a DebugAdapter does not support (i.e., overload) this function, a fallback handling is provided by the
        DebuggerController. It checks the MLIL function and put breakpoints on all returning instructions and then resume
        the target. By the time it breaks, the target is about to return from the current function.

        This fallback behavior is slightly different from that offered by the LLDB and DbgEng adapter, which returns
        from the current function and break afterwards.

        The call is blocking and only returns when the target stops.

        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerStepReturnAndWait(self.handle))

    def run_to_and_wait(self, address) -> DebugStopReason:
        """
        Resume the target, and wait for it to break at the given address(es).

        The address parameter can be either an integer, or a list of integers.

        Internally, the debugger places breakpoints on these addresses, resume the target, and wait for the target
        to break. Then the debugger removes the added breakpoints.

        The call is blocking and only returns when the target stops.

        :return: the reason for the stop
        """
        if isinstance(address, int):
            address = [address]

        if not isinstance(address, list):
            raise NotImplementedError

        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]

        return DebugStopReason(dbgcore.BNDebuggerRunToAndWait(self.handle, addr_list, len(address)))

    def run_to_reverse_and_wait(self, address) -> DebugStopReason:
        """
        Resume the target in reverse, and wait for it to break at the given address(es).

        The address parameter can be either an integer, or a list of integers.

        Internally, the debugger places breakpoints on these addresses, resumes the target in reverse, and waits for the target
        to break. Then the debugger removes the added breakpoints.

        The call is blocking and only returns when the target stops.

        :return: the reason for the stop
        """
        if isinstance(address, int):
            address = [address]

        if not isinstance(address, list):
            raise NotImplementedError

        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]

        return DebugStopReason(dbgcore.BNDebuggerRunToReverseAndWait(self.handle, addr_list, len(address)))

    def pause_and_wait(self) -> None:
        """
        Pause a running target.

        The call is blocking and only returns when the target stops.
        """
        dbgcore.BNDebuggerPauseAndWait(self.handle)

    def restart_and_wait(self) -> None:
        """
        Restart a running target.

        The call is blocking and only returns when the target stops again after the restart.
        """
        dbgcore.BNDebuggerRestartAndWait(self.handle)

    @property
    def adapter_type(self) -> str:
        """
        The name for the current DebugAdapter. (read/write)

        :getter: returns the name of the current DebugAdapter
        :setter: sets the DebugAdapter to use
        """
        return dbgcore.BNDebuggerGetAdapterType(self.handle)

    @adapter_type.setter
    def adapter_type(self, adapter: Union[str, bytes]) -> None:
        dbgcore.BNDebuggerSetAdapterType(self.handle, adapter)

    @property
    def connection_status(self) -> DebugAdapterConnectionStatus:
        """
        Get the connection status of the debugger
        """
        return DebugAdapterConnectionStatus(dbgcore.BNDebuggerGetConnectionStatus(self.handle))

    @property
    def target_status(self) -> DebugAdapterTargetStatus:
        """
        Get the status of the target
        """
        return DebugAdapterTargetStatus(dbgcore.BNDebuggerGetTargetStatus(self.handle))

    @property
    def remote_host(self) -> str:
        """
        The remote host to connect to. (read/write)

        ``remote_host`` and ``remote_port`` are only useful for remote debugging.

        :getter: returns the remote host
        :setter: sets the remote host
        """
        return dbgcore.BNDebuggerGetRemoteHost(self.handle)

    @remote_host.setter
    def remote_host(self, host: Union[str, bytes]) -> None:
        dbgcore.BNDebuggerSetRemoteHost(self.handle, host)

    @property
    def remote_port(self) -> int:
        """
        The remote port to connect to. (read/write)

        ``remote_host`` and ``remote_port`` are only useful for remote debugging.

        :getter: returns the remote port
        :setter: sets the remote port
        """
        return dbgcore.BNDebuggerGetRemotePort(self.handle)

    @remote_port.setter
    def remote_port(self, port: int) -> None:
        dbgcore.BNDebuggerSetRemotePort(self.handle, port)

    @property
    def pid_attach(self) -> int:
        """
        The PID to attach to. (read/write)

        ``pid_attach`` is only useful for connecting to a running process using PID.

        :getter: returns the remote port
        :setter: sets the remote port
        """
        return dbgcore.BNDebuggerGetPIDAttach(self.handle)

    @remote_port.setter
    def pid_attach(self, pid: int) -> None:
        dbgcore.BNDebuggerSetPIDAttach(self.handle, pid)

    @property
    def active_pid(self) -> int:
        """
        The PID of the process currently being debugged. (read-only)

        This returns the PID of the currently attached or running process.

        :return: the PID of the active process, or 0 if no process is active or the PID is unavailable
        """
        return dbgcore.BNDebuggerGetActivePID(self.handle)

    @property
    def executable_path(self) -> str:
        """
        The path of the executable. (read/write)

        This can be set before launching the target. Be default, it is the path of the FileMetadata
        (``bv.file.filename``)

        :getter: returns the executable path
        :setter: sets the executable path
        """
        return dbgcore.BNDebuggerGetExecutablePath(self.handle)

    @executable_path.setter
    def executable_path(self, path: Union[str, bytes]) -> None:
        dbgcore.BNDebuggerSetExecutablePath(self.handle, path)

    @property
    def input_file(self) -> str:
        """
        The input file used to create the database

        This should be set before launching the target. Be default, it is the path of the FileMetadata
        (``bv.file.filename``)

        :getter: returns the input file path
        :setter: sets the input file path
        """
        return dbgcore.BNDebuggerGetInputFile(self.handle)

    @input_file.setter
    def input_file(self, path: Union[str, bytes]) -> None:
        dbgcore.BNDebuggerSetInputFile(self.handle, path)

    @property
    def working_directory(self) -> str:
        """
        The path of the target. (read/write)

        This can be set before launching the target to configure a working directory. Be default, it is the path of the
        binaryninja executable. In the future, we will change the default working directory to the folder that the
        executable is in.

        :getter: returns the working directory
        :setter: sets the working directory
        """
        return dbgcore.BNDebuggerGetWorkingDirectory(self.handle)

    @working_directory.setter
    def working_directory(self, path: Union[str, bytes]) -> None:
        dbgcore.BNDebuggerSetWorkingDirectory(self.handle, path)

    @property
    def request_terminal_emulator(self) -> bool:
        """
        Whether to run the target in a separate terminal. (read/write)

        The default value is false.

        This can be set before launching the target to configure whether the target should be executed in a separate
        terminal. On Linux and macOS, when set, the target runs in its own terminal and the DebuggerController cannot
        receive notification of stdout output, or write to its stdin. All input/output must be performed in the target's
        console. On Windows, this option has no effect and the target always runs in its own terminal.

        :getter: returns whether to run the target in a separate terminal
        :setter: sets whether to run the target in a separate terminal
        """
        return dbgcore.BNDebuggerGetRequestTerminalEmulator(self.handle)

    @request_terminal_emulator.setter
    def request_terminal_emulator(self, requested: bool) -> None:
        dbgcore.BNDebuggerSetRequestTerminalEmulator(self.handle, requested)

    @property
    def cmd_line(self) -> str:
        """
        The command line arguments of the target. (read/write)

        This can be set before launching the target to specify the command line arguments. The arguments are supplied as
        a single string. The string is NOT shell expanded, which means the user must properly escape it if needed.

        :getter: returns the command line arguments
        :setter: sets the command line arguments
        """
        return dbgcore.BNDebuggerGetCommandLineArguments(self.handle)

    @cmd_line.setter
    def cmd_line(self, arguments: Union[str, bytes]) -> None:
        dbgcore.BNDebuggerSetCommandLineArguments(self.handle, arguments)

    @property
    def breakpoints(self) -> List[DebugBreakpoint]:
        """
        The list of breakpoints
        """
        count = ctypes.c_ulonglong()
        breakpoints = dbgcore.BNDebuggerGetBreakpoints(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugBreakpoint(breakpoints[i].module, breakpoints[i].offset, breakpoints[i].address, breakpoints[i].enabled)
            result.append(bp)

        dbgcore.BNDebuggerFreeBreakpoints(breakpoints, count.value)
        return result

    def delete_breakpoint(self, address):
        """
        Delete a breakpoint

        The input can be either an absolute address, or a ModuleNameAndOffset, which specifies a relative address to the
        start of a module. The latter is useful for ASLR.

        :param address: the address of breakpoint to delete
        """
        if isinstance(address, int):
            dbgcore.BNDebuggerDeleteAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            dbgcore.BNDebuggerDeleteRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    def add_breakpoint(self, address):
        """
        Add a breakpoint

        The input can be either an absolute address, or a ModuleNameAndOffset, which specifies a relative address to the
        start of a module. The latter is useful for ASLR.

        :param address: the address of breakpoint to add
        """
        if isinstance(address, int):
            dbgcore.BNDebuggerAddAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            dbgcore.BNDebuggerAddRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    def has_breakpoint(self, address) -> bool:
        """
        Checks whether a breakpoint exists at the specified address

        The input can be either an absolute address, or a ModuleNameAndOffset, which specifies a relative address to the
        start of a module. The latter is useful for ASLR.

        :param address: the address of breakpoint to query
        """
        if isinstance(address, int):
            return dbgcore.BNDebuggerContainsAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            return dbgcore.BNDebuggerContainsRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    def enable_breakpoint(self, address):
        """
        Enable a breakpoint

        The input can be either an absolute address, or a ModuleNameAndOffset, which specifies a relative address to the
        start of a module. The latter is useful for ASLR.

        :param address: the address of breakpoint to enable
        """
        if isinstance(address, int):
            dbgcore.BNDebuggerEnableAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            dbgcore.BNDebuggerEnableRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    def disable_breakpoint(self, address):
        """
        Disable a breakpoint

        The input can be either an absolute address, or a ModuleNameAndOffset, which specifies a relative address to the
        start of a module. The latter is useful for ASLR.

        :param address: the address of breakpoint to disable
        """
        if isinstance(address, int):
            dbgcore.BNDebuggerDisableAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            dbgcore.BNDebuggerDisableRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    @property
    def ip(self) -> int:
        """
        The IP (instruction pointer) of the target

        For x86_64, it returns the value of ``rip`` register.

        For x86, it returns the value of ``eip`` register.

        For armv7/aarch64, or any other architecture that is not native to BN, it returns the value of ``pc`` register.
        """
        return dbgcore.BNDebuggerGetIP(self.handle)

    @ip.setter
    def ip(self, addr: int) -> bool:
        """
        Overrides the IP (instruction pointer) of the target

        For x86_64, it set the value of ``rip`` register.

        For x86, it set the value of ``eip`` register.

        For armv7/aarch64, or any other architecture that is not native to BN, it set the value of ``pc`` register.

        :param addr: the new value of the IP
        :return: whether the operation succeeds
        """
        return dbgcore.BNDebuggerSetIP(self.handle, addr)

    @property
    def last_ip(self) -> int:
        """
        The IP (instruction pointer) when the target breaks last time.
        """
        return dbgcore.BNDebuggerGetLastIP(self.handle)

    @property
    def exit_code(self) -> int:
        """
        The exit code of the target (read-only)

        This is only meaningful after the target has executed and exited.
        """
        return dbgcore.BNDebuggerGetExitCode(self.handle)

    def register_event_callback(self, callback: DebuggerEventCallback, name: Union[str, bytes] = '') -> int:
        """
        Register a debugger event callback to receive notification when various events happen.

        The callback receives DebuggerEvent object that contains the type of the event and associated data.

        :param callback: the callback to register
        :param name: name of the callback
        :return: an integer handle to the registered event callback
        """
        return DebuggerEventWrapper.register(self, callback, name)

    def remove_event_callback(self, index: int):
        """
        Remove the debugger event callback from the DebuggerController
        """
        DebuggerEventWrapper.remove(self, index)

    def frames_of_thread(self, tid: int) -> List[DebugFrame]:
        """
        Get the stack frames of the thread specified by ``tid``

        :param tid: thread id
        :return: list of stack frames
        """
        count = ctypes.c_ulonglong()
        frames = dbgcore.BNDebuggerGetFramesOfThread(self.handle, tid, count)
        result = []
        for i in range(0, count.value):
            bp = DebugFrame(frames[i].m_index, frames[i].m_pc, frames[i].m_sp, frames[i].m_fp, frames[i].m_functionName,
                            frames[i].m_functionStart, frames[i].m_module)
            result.append(bp)

        dbgcore.BNDebuggerFreeFrames(frames, count.value)
        return result

    @property
    def stop_reason(self) -> DebugStopReason:
        """
        The reason for the target to stop

        This is the same value to the return value of the function that resumed the target, e.g., ``go()``
        """
        return DebugStopReason(dbgcore.BNDebuggerGetStopReason(self.handle))

    @property
    def stop_reason_str(self) -> str:
        """
        String description of the target stop reason
        """
        return dbgcore.BNDebuggerGetStopReasonString(self.stop_reason)

    def write_stdin(self, data: Union[str, bytes]) -> None:
        """
        Write to the stdin of the target. Only works on Linux and macOS.

        """
        dbgcore.BNDebuggerWriteStdin(self.handle, data, len(data))

    def execute_backend_command(self, command: Union[str, bytes]) -> str:
        """
        Execute a backend command and get the output

        For LLDB adapter, any LLDB commands can be executed. The returned string is what gets printed if one executes
        the command in the LLDB prompt.

        For DbgEnd adapter, any WinDbg commands can be executed. The returned string is what gets printed if one
        executes the command in WinDbg.
        """
        return dbgcore.BNDebuggerInvokeBackendCommand(self.handle, command)

    def get_adapter_property(self, name: Union[str, bytes]) -> 'binaryninja.metadata.MetadataValueType':
        md_handle = dbgcore.BNDebuggerGetAdapterProperty(self.handle, name)
        if md_handle is None:
            raise KeyError(name)
        md_handle_BN = ctypes.cast(md_handle, ctypes.POINTER(binaryninja.core.BNMetadata))
        return binaryninja.metadata.Metadata(handle=md_handle_BN).value

    def set_adapter_property(self, name: Union[str, bytes], value: binaryninja.metadata.MetadataValueType) -> bool:
        _value = value
        if not isinstance(_value, binaryninja.metadata.Metadata):
            _value = binaryninja.metadata.Metadata(_value)
        handle = ctypes.cast(_value.handle, ctypes.POINTER(dbgcore.BNMetadata))
        return dbgcore.BNDebuggerSetAdapterProperty(self.handle, name, handle)

    def get_addr_info(self, addr: int):
        return dbgcore.BNDebuggerGetAddressInformation(self.handle, addr)

    @property
    def is_first_launch(self):
        return dbgcore.BNDebuggerIsFirstLaunch(self.handle)

    @property
    def is_ttd(self):
        return dbgcore.BNDebuggerIsTTD(self.handle)

    @property
    def current_ttd_position(self):
        """
        Get the current position in the TTD trace.
        
        Returns:
            TTDPosition: Current position, or None if not in TTD mode
        """
        if not self.is_ttd:
            return None
        
        pos = dbgcore.BNDebuggerGetCurrentTTDPosition(self.handle)
        return TTDPosition(pos.sequence, pos.step)

    @current_ttd_position.setter
    def current_ttd_position(self, position):
        """
        Navigate to a specific position in the TTD trace.
        
        Args:
            position: TTDPosition object or string in format "sequence:step"
        """
        if not self.is_ttd:
            raise RuntimeError("TTD is not active")
        
        if isinstance(position, str):
            position = TTDPosition.from_string(position)
        elif not isinstance(position, TTDPosition):
            raise TypeError("Position must be TTDPosition object or string")
        
        # Create the C structure
        pos = dbgcore.BNDebuggerTTDPosition()
        pos.sequence = position.sequence
        pos.step = position.step
        
        success = dbgcore.BNDebuggerSetTTDPosition(self.handle, pos)
        if not success:
            raise RuntimeError("Failed to navigate to the specified TTD position")

    def set_ttd_position(self, position):
        """
        Navigate to a specific position in the TTD trace.
        
        Args:
            position: TTDPosition object or string in format "sequence:step"
            
        Returns:
            bool: True if navigation succeeded, False otherwise
        """
        if not self.is_ttd:
            return False
        
        if isinstance(position, str):
            position = TTDPosition.from_string(position)
        elif not isinstance(position, TTDPosition):
            raise TypeError("Position must be TTDPosition object or string")
        
        # Create the C structure
        pos = dbgcore.BNDebuggerTTDPosition()
        pos.sequence = position.sequence
        pos.step = position.step
        
        return dbgcore.BNDebuggerSetTTDPosition(self.handle, pos)

    def navigate_to_timestamp(self, timestamp_str):
        """
        Convenience method to navigate to a timestamp string.
        
        Args:
            timestamp_str: String in format "sequence:step" (hex or decimal)
            
        Returns:
            bool: True if navigation succeeded, False otherwise
        """
        try:
            position = TTDPosition.from_string(timestamp_str)
            return self.set_ttd_position(position)
        except ValueError as e:
            binaryninja.log_error(f"Invalid timestamp format: {e}")
            return False

    def get_ttd_memory_access_for_address(self, address: int, size: int, access_type = DebuggerTTDMemoryAccessType.DebuggerTTDMemoryRead) -> List[TTDMemoryEvent]:
        """
        Get TTD memory access events for a specific address range.

        This method is only available when debugging with TTD (Time Travel Debugging).
        Use the is_ttd property to check if TTD is available before calling this method.

        :param address: starting memory address to query
        :param size: size of memory region to query
        :param access_type: type of memory access to query - can be:
                           - DebuggerTTDMemoryAccessType enum values
                           - String specification like "r", "w", "e", "rw", "rwe", etc.
                           - Integer values (for backward compatibility)
        :return: list of TTDMemoryEvent objects
        :raises: May raise an exception if TTD is not available
        """
        # Parse access type if it's a string
        parsed_access_type = parse_ttd_access_type(access_type)
        
        count = ctypes.c_ulonglong()
        events = dbgcore.BNDebuggerGetTTDMemoryAccessForAddress(self.handle, address, size, parsed_access_type, count)

        if not events:
            return []

        result = []
        for i in range(count.value):
            event = events[i]
            time_start = TTDPosition(event.timeStart.sequence, event.timeStart.step)
            time_end = TTDPosition(event.timeEnd.sequence, event.timeEnd.step)

            memory_event = TTDMemoryEvent(
                event_type=event.eventType if event.eventType else "",
                thread_id=event.threadId,
                unique_thread_id=event.uniqueThreadId,
                time_start=time_start,
                time_end=time_end,
                address=event.address,
                size=event.size,
                memory_address=event.memoryAddress,
                instruction_address=event.instructionAddress,
                value=event.value,
                access_type=event.accessType
            )
            result.append(memory_event)

        dbgcore.BNDebuggerFreeTTDMemoryEvents(events, count.value)
        return result

    def get_ttd_calls_for_symbols(self, symbols: str, start_return_address: int = 0, end_return_address: int = 0) -> List[TTDCallEvent]:
        """
        Get TTD call events for specific symbols/functions.

        This method is only available when debugging with TTD (Time Travel Debugging).
        Use the is_ttd property to check if TTD is available before calling this method.

        :param symbols: symbol or function name to query (e.g., "MessageBoxA", "CreateFileA")
        :param start_return_address: optional start return address filter (0 = no filter)
        :param end_return_address: optional end return address filter (0 = no filter)
        :return: list of TTDCallEvent objects
        :raises: May raise an exception if TTD is not available
        """
        count = ctypes.c_ulonglong()
        events = dbgcore.BNDebuggerGetTTDCallsForSymbols(self.handle, symbols, start_return_address, end_return_address, count)

        if not events:
            return []

        result = []
        for i in range(count.value):
            event = events[i]
            time_start = TTDPosition(event.timeStart.sequence, event.timeStart.step)
            time_end = TTDPosition(event.timeEnd.sequence, event.timeEnd.step)

            # Convert parameters array to Python list
            parameters = []
            if event.parameters and event.parameterCount > 0:
                for j in range(event.parameterCount):
                    parameters.append(event.parameters[j])

            call_event = TTDCallEvent(
                event_type=event.eventType if event.eventType else "",
                thread_id=event.threadId,
                unique_thread_id=event.uniqueThreadId,
                function=event.function if event.function else "",
                function_address=event.functionAddress,
                return_address=event.returnAddress,
                return_value=event.returnValue,
                has_return_value=event.hasReturnValue,
                parameters=parameters,
                time_start=time_start,
                time_end=time_end
            )
            result.append(call_event)

        dbgcore.BNDebuggerFreeTTDCallEvents(events, count.value)
        return result

    def get_ttd_events(self, event_type: int) -> List[TTDEvent]:
        """
        Get TTD events for specific event types using bitfield filtering.

        This method is only available when debugging with TTD (Time Travel Debugging).
        Use the is_ttd property to check if TTD is available before calling this method.

        :param event_type: type of events to query (TTDEventType bitfield flags that can be combined with ``|``)
        :return: list of TTDEvent objects
        :rtype: List[TTDEvent]
        """
        if self.handle is None:
            return []

        count = ctypes.c_size_t()
        events = dbgcore.BNDebuggerGetTTDEvents(self.handle, event_type, ctypes.byref(count))

        result = []
        if not events or count.value == 0:
            return result

        for i in range(count.value):
            event = events[i]
            
            position = TTDPosition(event.position.sequence, event.position.step)
            
            # Convert optional module details
            module = None
            if event.module:
                module = TTDModule(
                    name=event.module.contents.name if event.module.contents.name else "",
                    address=event.module.contents.address,
                    size=event.module.contents.size,
                    checksum=event.module.contents.checksum,
                    timestamp=event.module.contents.timestamp
                )
            
            # Convert optional thread details
            thread = None
            if event.thread:
                lifetime_start = TTDPosition(event.thread.contents.lifetimeStart.sequence, event.thread.contents.lifetimeStart.step)
                lifetime_end = TTDPosition(event.thread.contents.lifetimeEnd.sequence, event.thread.contents.lifetimeEnd.step)
                active_time_start = TTDPosition(event.thread.contents.activeTimeStart.sequence, event.thread.contents.activeTimeStart.step)
                active_time_end = TTDPosition(event.thread.contents.activeTimeEnd.sequence, event.thread.contents.activeTimeEnd.step)
                
                thread = TTDThread(
                    unique_id=event.thread.contents.uniqueId,
                    id=event.thread.contents.id,
                    lifetime_start=lifetime_start,
                    lifetime_end=lifetime_end,
                    active_time_start=active_time_start,
                    active_time_end=active_time_end
                )
            
            # Convert optional exception details
            exception = None
            if event.exception:
                exception_position = TTDPosition(event.exception.contents.position.sequence, event.exception.contents.position.step)
                
                exception = TTDException(
                    type=event.exception.contents.type,
                    program_counter=event.exception.contents.programCounter,
                    code=event.exception.contents.code,
                    flags=event.exception.contents.flags,
                    record_address=event.exception.contents.recordAddress,
                    position=exception_position
                )

            ttd_event = TTDEvent(
                type=event.type,
                position=position,
                module=module,
                thread=thread,
                exception=exception
            )
            result.append(ttd_event)

        dbgcore.BNDebuggerFreeTTDEvents(events, count.value)
        return result

    def get_all_ttd_events(self) -> List[TTDEvent]:
        """
        Get all TTD events from the trace.

        This method is only available when debugging with TTD (Time Travel Debugging).
        Use the is_ttd property to check if TTD is available before calling this method.

        :return: list of all TTDEvent objects in the trace
        :rtype: List[TTDEvent]
        """
        if self.handle is None:
            return []

        count = ctypes.c_size_t()
        events = dbgcore.BNDebuggerGetAllTTDEvents(self.handle, ctypes.byref(count))

        result = []
        if not events or count.value == 0:
            return result

        for i in range(count.value):
            event = events[i]
            
            position = TTDPosition(event.position.sequence, event.position.step)
            
            # Convert optional module details
            module = None
            if event.module:
                module = TTDModule(
                    name=event.module.contents.name if event.module.contents.name else "",
                    address=event.module.contents.address,
                    size=event.module.contents.size,
                    checksum=event.module.contents.checksum,
                    timestamp=event.module.contents.timestamp
                )
            
            # Convert optional thread details
            thread = None
            if event.thread:
                lifetime_start = TTDPosition(event.thread.contents.lifetimeStart.sequence, event.thread.contents.lifetimeStart.step)
                lifetime_end = TTDPosition(event.thread.contents.lifetimeEnd.sequence, event.thread.contents.lifetimeEnd.step)
                active_time_start = TTDPosition(event.thread.contents.activeTimeStart.sequence, event.thread.contents.activeTimeStart.step)
                active_time_end = TTDPosition(event.thread.contents.activeTimeEnd.sequence, event.thread.contents.activeTimeEnd.step)
                
                thread = TTDThread(
                    unique_id=event.thread.contents.uniqueId,
                    id=event.thread.contents.id,
                    lifetime_start=lifetime_start,
                    lifetime_end=lifetime_end,
                    active_time_start=active_time_start,
                    active_time_end=active_time_end
                )
            
            # Convert optional exception details
            exception = None
            if event.exception:
                exception_position = TTDPosition(event.exception.contents.position.sequence, event.exception.contents.position.step)
                
                exception = TTDException(
                    type=event.exception.contents.type,
                    program_counter=event.exception.contents.programCounter,
                    code=event.exception.contents.code,
                    flags=event.exception.contents.flags,
                    record_address=event.exception.contents.recordAddress,
                    position=exception_position
                )

            ttd_event = TTDEvent(
                type=event.type,
                position=position,
                module=module,
                thread=thread,
                exception=exception
            )
            result.append(ttd_event)

        dbgcore.BNDebuggerFreeTTDEvents(events, count.value)
        return result

    def __del__(self):
        if dbgcore is not None:
            dbgcore.BNDebuggerFreeController(self.handle)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return not (self == other)

    def __hash__(self):
        return hash(ctypes.addressof(self.handle.contents))
