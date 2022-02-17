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
import debugger
from . import _debuggercore as dbgcore
from .enums import *


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
    def launch(self):
        dbgcore.BNDebuggerLaunch(self.handle)

    def go(self) -> DebugStopReason:
        return dbgcore.BNDebuggerGo(self.handle)

    def step_into(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        return dbgcore.BNDebuggerStepInto(self.handle, il)

    def step_over(self, il: binaryninja.FunctionGraphType = binaryninja.FunctionGraphType.NormalFunctionGraph) -> DebugStopReason:
        return dbgcore.BNDebuggerStepOver(self.handle, il)

    def step_return(self) -> DebugStopReason:
        return dbgcore.BNDebuggerStepReturn(self.handle)

    def step_to(self, address: list(int)) -> DebugStopReason:
        addr_list = (ctypes.c_uint64 * len(address))()
        for i in range(len(address)):
            addr_list[i] = address[i]
        return dbgcore.BNDebuggerStepTo(self.handle, addr_list, len(address))