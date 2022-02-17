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

import binaryninja
# import debugger
from . import _debuggercore as dbgcore
from .enums import *


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


class DebuggerController:

    def __init__(self, bv: binaryninja.BinaryView):
        # bv.handle has type binaryninja.core.BNBinaryView, which is different from dbgcore.BNBinaryView,
        # so the casting here is necessary
        # A different way to deal with is that instead of defining a BNBinaryView struct in the _debuggercore.py,
        # do from binaryninja._binaryninjacore import BNBinaryView
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        self.handle = dbgcore.BNGetDebuggerController(bv_obj)

    @property
    def data(self) -> binaryninja.BinaryView:
        result = ctypes.cast(dbgcore.BNDebuggerGetData(self.handle), ctypes.POINTER(binaryninja.core.BNBinaryView))
        if result is None:
            return None
        return binaryninja.BinaryView(handle=result)

    @property
    def livew_view(self) -> binaryninja.BinaryView:
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

    # target control
    def launch(self) -> None:
        dbgcore.BNDebuggerLaunch(self.handle)

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

    def go(self) -> DebugStopReason:
        return dbgcore.BNDebuggerGo(self.handle)

    def step_into(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        return dbgcore.BNDebuggerStepInto(self.handle, il)

    def step_over(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        return dbgcore.BNDebuggerStepOver(self.handle, il)

    def step_return(self) -> DebugStopReason:
        return dbgcore.BNDebuggerStepReturn(self.handle)

    def step_to(self, address: list[int]) -> DebugStopReason:
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
    def breakpoints(self) -> list[DebugBreakpoint]:
        count = ctypes.c_ulonglong()
        breakpoints = dbgcore.BNDebuggerGetBreakpoints(self.handle, count)
        result = []
        for i in range(0, count.value):
            bp = DebugBreakpoint(breakpoints[i].module, breakpoints[i].offset, breakpoints[i].address, breakpoints[i].enabled)
            result.append(bp)

        dbgcore.BNDebuggerFreeBreakpoints(breakpoints, count)
        return result