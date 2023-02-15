# coding=utf-8
# Copyright 2020-2023 Vector 35 Inc.
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
from typing import Callable, List


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
    def is_same_base_module(module1: str, module2: str) -> bool:
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
            bp = DebugRegister(registers[i].m_name, registers[i].m_value,
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
        dbgcore.BNDebuggerSetRegisterValue(self.handle, name, val)

    def __len__(self):
        return len(self.regs)


class DebugBreakpoint:
    """
    DebugBreakpoint represents a breakpoint in the target. It has the following fields:

    * ``module``: the name of the module for which the breakpoint is in
    * ``offset``: the offset of the breakpoint to the start of the module
    * ``address``: the absolute address of the breakpoint
    * ``enabled``: not used

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
        return hash((self.module, self.offset, self.address. self.enabled))

    def __setattr__(self, name, value):
        try:
            object.__setattr__(self, name, value)
        except AttributeError:
            raise AttributeError(f"attribute '{name}' is read only")

    def __repr__(self):
        return f"<DebugBreakpoint: {self.module}:{self.offset:#x}, {self.address:#x}>"


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
        return f"<DebugFrame: {self.module}`{self.func_name} + {offset:#x}, sp: {self.sp:#x}, fp: {self.fp:#x}>"


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
    def register(cls, controller: 'DebuggerController', callback: DebuggerEventCallback, name: str) -> int:
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


class DebuggerController:
    """
    The ``DebuggerController`` object is the core of the debugger. Most debugger operations can be performed on it.
    It takes in a ``BinaryView`` and creates a debugger for it. If a debugger is already existing for the very same
    BinaryView object, the debugger is returned.

    Most operations of the debugger are performed on this class. For example, we can launch the debugger as follows::

        >>> bv = BinaryViewType.get_view_of_file("test/binaries/helloworld")
        >>> dbg = DebuggerController(bv)
        >>> dbg.launch()
        True

    When the ``launch()`` returns True, it means the debugger has launched the target successfully. The target breaks at
    the entry point of the binary. Now we can perform other control operations on it, e.g., resume the target by calling
    ``go()``.

        >>> dbg.go()
        <DebugStopReason.ProcessExited: 2>

    Since there are no other breakpoints in the target, the process executes and then exits.

    All target control funciotns, e.g., ``go()``, ``step_into()``, etc, are blocking. They will not return until the
    target breaks. In the future, we will switch to an asyunchrounous communication model where these functions return
    before the operation is performed.

    For each insteance of DebuggerController, there are two BinaryViews associated with it. The first one is the
    original BinaryView that gets rebased to the proper offset according to the target's actual base. The second is a
    "live" BinaryView that represents the entire memory space of the target process. They can be accessed by ``data``
    and ``live_view``, respectively.

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
    def live_view(self) -> binaryninja.BinaryView:
        """Get the live BinaryView of the debugger"""
        result = dbgcore.BNDebuggerGetLiveView(self.handle)
        if result is None:
            return None
        result = ctypes.cast(result, ctypes.POINTER(binaryninja.core.BNBinaryView))
        if result is None:
            return None
        return binaryninja.BinaryView(handle=result)

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

        One can also get the ``live_view`` BinaryView of the DebuggerController, and use ordinary read methods to read
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

        One can also get the ``live_view`` BinaryView of the DebuggerController, and use ordinary write methods to write
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

    def get_reg_value(self, reg: str) -> int:
        """
        Get the value of one register by its name

        :param reg: the name of the register
        """
        return dbgcore.BNDebuggerGetRegisterValue(self.handle, reg)

    def set_reg_value(self, reg: str, value: int) -> bool:
        """
        Set value of register

        :param reg: the name of the register
        :param value: new value of the register
        """
        return dbgcore.BNDebuggerSetRegisterValue(self.handle, reg, value)

    # target control
    def launch(self) -> bool:
        """
        Launch the target
        """
        return dbgcore.BNDebuggerLaunch(self.handle)

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

    def connect(self) -> None:
        """
        Connect to a remote target (process)

        The host and port of the remote target must first be specified by setting `remote_host` and `remote_port`
        """
        dbgcore.BNDebuggerConnect(self.handle)

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

    def attach(self, pid: int) -> bool:
        """
        Attach to a running process by its PID

        :param pid: the PID of the process to attach to
        """
        return dbgcore.BNDebuggerAttach(self.handle, pid)

    def go(self) -> bool:
        """
        Resume the target.

        The call is asynchronous and returns before the target stops.

        :return: the reason for the stop
        """
        return dbgcore.BNDebuggerGo(self.handle)

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
        :return: the reason for the stop
        """
        return dbgcore.BNDebuggerStepInto(self.handle, il)

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
        :return: the reason for the stop
        """
        return dbgcore.BNDebuggerStepOver(self.handle, il)

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

        :return: the reason for the stop
        """
        return dbgcore.BNDebuggerStepReturn(self.handle)

    def run_to(self, address) -> bool:
        """
        Resume the target, and wait for it to break at the given address(es).

        The address parameter can be either an integer, or a list of integers.

        Internally, the debugger places breeakpoints on these addresses, resume the target, and wait for the target
        to break. Then the debugger removes the added breakpoints.

       The call is asynchronous and returns before the target stops.

        """
        if isinstance(address, int):
            address = [address]

        if not isinstance(address, list):
            raise NotImplementedError

        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]

        return dbgcore.BNDebuggerRunTo(self.handle, addr_list, len(address))

    def go_and_wait(self) -> DebugStopReason:
        """
        Resume the target.

        The call is blocking and only returns when the target stops.

        :return: the reason for the stop
        """
        return DebugStopReason(dbgcore.BNDebuggerGoAndWait(self.handle))

    def step_into_and_wait(self, il: binaryninja.FunctionGraphType =
                binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        """
        Perform a step into on the target.

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

        Internally, the debugger places breeakpoints on these addresses, resume the target, and wait for the target
        to break. Then the debugger removes the added breakpoints.

        The call is blocking and only returns when the target stops.

        """
        if isinstance(address, int):
            address = [address]

        if not isinstance(address, list):
            raise NotImplementedError

        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]

        return DebugStopReason(dbgcore.BNDebuggerRunToAndWait(self.handle, addr_list, len(address)))

    def pause_and_wait(self) -> None:
        """
        Pause a running target.

        The call is blocking and only returns when the target stops.
        """
        dbgcore.BNDebuggerPauseAndWait(self.handle)

    @property
    def adapter_type(self) -> str:
        """
        The name fo the current DebugAdapter. (read/write)

        :getter: returns the name of the current DebugAdapter
        :setter: sets the DebugAdapter to use
        """
        return dbgcore.BNDebuggerGetAdapterType(self.handle)

    @adapter_type.setter
    def adapter_type(self, adapter: str) -> None:
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
    def remote_host(self, host: str) -> None:
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
    def executable_path(self, path: str) -> None:
        dbgcore.BNDebuggerSetExecutablePath(self.handle, path)

    @property
    def working_directory(self) -> str:
        """
        The path of the target. (read/write)

        This can be set before launching the target to configure a working directory. Be default, it is the path of the
        binaryninja executable. In the future, we will change the default workding directory to the folder that the
        executable is in.

        :getter: returns the working directory
        :setter: sets the working directory
        """
        return dbgcore.BNDebuggerGetWorkingDirectory(self.handle)

    @working_directory.setter
    def working_directory(self, path: str) -> None:
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
    def cmd_line(self, arguments: str) -> None:
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

    def register_event_callback(self, callback: DebuggerEventCallback, name: str = '') -> int:
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
        Remove the debuggeer event callback from the DebuggerController
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

    def write_stdin(self, data: str) -> None:
        """
        Write to the stdin of the target. Only works on Linux and macOS.

        """
        dbgcore.BNDebuggerWriteStdin(self.handle, data, len(data))

    def execute_backend_command(self, command: str) -> str:
        """
        Execute a backend command and get the output

        For LLDB adapter (on Linux and macOS), any LLDB commands can be executed. The returned string is what gets
        printed if one executes the command in the LLDB prompt.

        For DbgEnd adapter (on Windows), any Windbg commands can be executed. However, nothing will be returned.
        This is because the backend processes the command asynchronously. By the time it returns, the commands are not
        executed yet. However, the output are still printed to the Debugger console in the global area.

        Note, the user should never run any command that resumes the target (either running or stepping). It will
        cause the UI to de-synchronize and even hang. This is a known limitation, and we will try to address it.

        """
        return dbgcore.BNDebuggerInvokeBackendCommand(self.handle, command)

    def get_adapter_property(self, name: str) -> 'binaryninja.metadata.MetadataValueType':
        md_handle = dbgcore.BNDebuggerGetAdapterProperty(self.handle, name)
        if md_handle is None:
            raise KeyError(name)
        md_handle_BN = ctypes.cast(md_handle, ctypes.POINTER(binaryninja.core.BNMetadata))
        return binaryninja.metadata.Metadata(handle=md_handle_BN).value

    def set_adapter_property(self, name: str, value: binaryninja.metadata.MetadataValueType) -> bool:
        _value = value
        if not isinstance(_value, binaryninja.metadata.Metadata):
            _value = binaryninja.metadata.Metadata(_value)
        handle = ctypes.cast(_value.handle, ctypes.POINTER(dbgcore.BNMetadata))
        return dbgcore.BNDebuggerSetAdapterProperty(self.handle, name, handle)

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
