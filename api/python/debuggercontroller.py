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


class DebuggerController:

    def __init__(self, bv: binaryninja.BinaryView):
        # bv.handle has type binaryninja.core.BNBinaryView, which is different from dbgcore.BNBinaryView,
        # so the casting here is necessary
        # A different way to deal with is that instead of defining a BNBinaryView struct in the _debuggercore.py,
        # do from binaryninja._binaryninjacore import BNBinaryView
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        self.handle = dbgcore.BNGetDebuggerController(bv_obj)

    @property
    def connected(self) -> bool:
        return dbgcore.BNDebuggerIsConnected(self.handle)

    @property
    def data(self) -> binaryninja.BinaryView:
        result = ctypes.cast(dbgcore.BNDebuggerGetData(self.handle), ctypes.POINTER(binaryninja.core.BNBinaryView))
        if result is None:
            return None
        return binaryninja.BinaryView(handle=result)
