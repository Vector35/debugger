# coding=utf-8
# Copyright (c) 2015-2022 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
import ctypes
import traceback

import binaryninja
# import debugger
from . import _debuggercore as dbgcore
from .enums import *
from typing import Callable, List


class DebugThread:
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


class DebugBreakpoint:
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


class TargetStoppedEventData:
    def __init__(self, reason: DebugStopReason, last_active_thread: int, exit_code: int, data):
        self.reason = reason
        self.last_active_thread = last_active_thread
        self.exit_code = exit_code
        self.data = data


class ErrorEventData:
    def __init__(self, error: str, data):
        self.error = error
        self.data = data


class TargetExitedEventData:
    def __init__(self, exit_code: int):
        self.exit_code = exit_code


class StdOutMessageEventData:
    def __init__(self, message: str):
        self.message = message


class DebuggerEventData:
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
    def __init__(self, type: DebuggerEventType, data: DebuggerEventData):
        self.type = type
        self.data = data


class DebuggerEventWrapper:

    DebuggerEventCallback = Callable[['DebuggerEvent'], None]
    # This has no functional purposes;
    # we just need it to stop Python from prematurely freeing the object
    _debugger_events = {}

    @classmethod
    def register(cls, controller: 'DebuggerController', callback: DebuggerEventCallback) -> int:
        callback_obj = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(dbgcore.BNDebuggerEvent))\
                                        (lambda ctxt, event: cls._notify(event[0], callback))
        handle = dbgcore.BNDebuggerRegisterEventCallback(controller.handle, callback_obj, None)
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

    def __init__(self, bv: binaryninja.BinaryView):
        # bv.handle has type binaryninja.core.BNBinaryView, which is different from dbgcore.BNBinaryView,
        # so the casting here is necessary
        # A different way to deal with is that instead of defining a BNBinaryView struct in the _debuggercore.py,
        # do from binaryninja._binaryninjacore import BNBinaryView
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        self.handle = dbgcore.BNGetDebuggerController(bv_obj)

    def destroy(self):
        dbgcore.BNDebuggerDestroyController(self.handle)

    @property
    def data(self) -> binaryninja.BinaryView:
        result = ctypes.cast(dbgcore.BNDebuggerGetData(self.handle), ctypes.POINTER(binaryninja.core.BNBinaryView))
        if result is None:
            return None
        return binaryninja.BinaryView(handle=result)

    @property
    def live_view(self) -> binaryninja.BinaryView:
        result = ctypes.cast(dbgcore.BNDebuggerGetLiveView(self.handle), ctypes.POINTER(binaryninja.core.BNBinaryView))
        if result is None:
            return None
        return binaryninja.BinaryView(handle=result)

    @property
    def remote_arch(self) -> binaryninja.Architecture:
        result = ctypes.cast(dbgcore.BNDebuggerGetRemoteArchitecture(self.handle), ctypes.POINTER(binaryninja.core.BNArchitecture))
        if result is None:
            return None
        return binaryninja.CoreArchitecture(handle=result)

    @property
    def connected(self) -> bool:
        return dbgcore.BNDebuggerIsConnected(self.handle)

    @property
    def running(self) -> bool:
        return dbgcore.BNDebuggerIsRunning(self.handle)

    @property
    def stack_pointer(self) -> int:
        return dbgcore.BNDebuggerGetStackPointer(self.handle)

    def read_memory(self, address: int, size: int) -> binaryninja.DataBuffer:
        buffer = ctypes.cast(dbgcore.BNDebuggerReadMemory(self.handle, address, size), ctypes.POINTER(binaryninja.core.BNDataBuffer))
        if buffer is None:
            return None
        return binaryninja.DataBuffer(buffer)

    def write_memory(self, address: int, buffer: binaryninja.DataBuffer) -> bool:
        buffer_obj = ctypes.cast(buffer.handle, ctypes.POINTER(dbgcore.BNDataBuffer))
        return dbgcore.BNDebuggerWriteMemory(self.handle, address, buffer_obj)

    @property
    def threads(self) -> List[DebugThread]:
        count = ctypes.c_ulonglong()
        threads = dbgcore.BNDebuggerGetThreads(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugThread(threads[i].m_tid, threads[i].m_rip)
            result.append(bp)

        dbgcore.BNDebuggerFreeThreads(threads, count)
        return result

    @property
    def active_thread(self) -> DebugThread:
        active_thread = dbgcore.BNDebuggerGetActiveThread(self.handle)
        return DebugThread(active_thread.tid, active_thread.rip)

    @active_thread.setter
    def active_thread(self, thread: DebugThread) -> None:
        dbgcore.BNDebuggerSetActiveThread(dbgcore.BNDebugThread(thread.tid, thread.rip))

    @property
    def modules(self) -> List[DebugModule]:
        count = ctypes.c_ulonglong()
        modules = dbgcore.BNDebuggerGetModules(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugModule(modules[i].m_name, modules[i].m_short_name, modules[i].m_address, modules[i].m_size, modules[i].m_loaded)
            result.append(bp)

        dbgcore.BNDebuggerFreeModules(modules, count)
        return result

    @property
    def regs(self) -> List[DebugRegister]:
        count = ctypes.c_ulonglong()
        registers = dbgcore.BNDebuggerGetRegisters(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugRegister(registers[i].m_name, registers[i].m_value, registers[i].m_width, registers[i].m_registerIndex, registers[i].m_hint)
            result.append(bp)

        dbgcore.BNDebuggerFreeRegisters(registers, count)
        return result

    # target control
    def launch(self) -> bool:
        return dbgcore.BNDebuggerLaunch(self.handle)

    def restart(self) -> None:
        dbgcore.BNDebuggerRestart(self.handle)

    def quit(self) -> None:
        dbgcore.BNDebuggerQuit(self.handle)

    def connect(self) -> None:
        dbgcore.BNDebuggerConnect(self.handle)

    def detach(self) -> None:
        dbgcore.BNDebuggerQuit(self.handle)

    def pause(self) -> None:
        dbgcore.BNDebuggerPause(self.handle)

    def launch_or_connect(self) -> None:
        dbgcore.BNDebuggerLaunchOrConnect(self.handle)

    def attach(self, pid: int) -> bool:
        return dbgcore.BNDebuggerAttach(self.handle, pid)

    def go(self) -> DebugStopReason:
        return dbgcore.BNDebuggerGo(self.handle)

    def step_into(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        return dbgcore.BNDebuggerStepInto(self.handle, il)

    def step_over(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        return dbgcore.BNDebuggerStepOver(self.handle, il)

    def step_return(self) -> DebugStopReason:
        return dbgcore.BNDebuggerStepReturn(self.handle)

    def step_to(self, address) -> DebugStopReason:
        if isinstance(address, int):
            address = [address]

        if not isinstance(address, list):
            raise NotImplementedError

        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]
        return dbgcore.BNDebuggerStepTo(self.handle, addr_list, len(address))

    @property
    def adapter_type(self) -> str:
        return dbgcore.BNDebuggerGetAdapterType(self.handle)

    @adapter_type.setter
    def adapter_type(self, adapter: str) -> None:
        dbgcore.BNDebuggerSetAdapterType(self.handle, adapter)

    @property
    def connection_status(self) -> DebugAdapterConnectionStatus:
        return dbgcore.BNDebuggerGetConnectionStatus(self.handle)

    @property
    def target_status(self) -> DebugAdapterTargetStatus:
        return dbgcore.BNDebuggerGetTargetStatus(self.handle)

    @property
    def remote_host(self) -> str:
        return dbgcore.BNDebuggerGetRemoteHost(self.handle)

    @remote_host.setter
    def remote_host(self, host: str) -> None:
        dbgcore.BNDebuggerSetRemoteHost(self.handle, host)

    @property
    def remote_port(self) -> int:
        return dbgcore.BNDebuggerGetRemotePort(self.handle)

    @remote_port.setter
    def remote_port(self, port: int) -> None:
        dbgcore.BNDebuggerSetRemotePort(self.handle, port)

    @property
    def executable_path(self) -> str:
        return dbgcore.BNDebuggerGetExecutablePath(self.handle)

    @executable_path.setter
    def executable_path(self, path: str) -> None:
        dbgcore.BNDebuggerSetExecutablePath(self.handle, path)

    @property
    def request_terminal_emulator(self) -> bool:
        return dbgcore.BNDebuggerGetRequestTerminalEmulator(self.handle)

    @request_terminal_emulator.setter
    def request_terminal_emulator(self, requested: bool) -> None:
        dbgcore.BNDebuggerSetRequestTerminalEmulator(self.handle, requested)

    @property
    def cmd_line(self) -> str:
        return dbgcore.BNDebuggerGetCommandLineArguments(self.handle)

    @cmd_line.setter
    def cmd_line(self, arguments: str) -> None:
        dbgcore.BNDebuggerSetCommandLineArguments(self.handle, arguments)

    @property
    def breakpoints(self) -> List[DebugBreakpoint]:
        count = ctypes.c_ulonglong()
        breakpoints = dbgcore.BNDebuggerGetBreakpoints(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugBreakpoint(breakpoints[i].module, breakpoints[i].offset, breakpoints[i].address, breakpoints[i].enabled)
            result.append(bp)

        dbgcore.BNDebuggerFreeBreakpoints(breakpoints, count)
        return result

    def delete_breakpoint(self, address):
        if isinstance(address, int):
            dbgcore.BNDebuggerDeleteAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            dbgcore.BNDebuggerDeleteRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    def add_breakpoint(self, address):
        if isinstance(address, int):
            dbgcore.BNDebuggerAddAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            dbgcore.BNDebuggerAddRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    def has_breakpoint(self, address) -> bool:
        if isinstance(address, int):
            return dbgcore.BNDebuggerContainsAbsoluteBreakpoint(self.handle, address)
        elif isinstance(address, ModuleNameAndOffset):
            return dbgcore.BNDebuggerContainsRelativeBreakpoint(self.handle, address.module, address.offset)
        else:
            raise NotImplementedError

    @property
    def ip(self) -> int:
        return dbgcore.BNDebuggerGetIP(self.handle)

    @property
    def last_ip(self) -> int:
        return dbgcore.BNDebuggerGetLastIP(self.handle)

    @property
    def exit_code(self) -> int:
        return dbgcore.BNDebuggerGetExitCode(self.handle)

    def register_event_callback(self, callback) -> int:
        return DebuggerEventWrapper.register(self, callback)

    def remove_event_callback(self, index: int):
        DebuggerEventWrapper.remove(self, index)
