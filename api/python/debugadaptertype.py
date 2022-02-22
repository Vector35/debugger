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
from typing import Callable


class DebugAdapterType:

    def __init__(self, hande: dbgcore.BNDebugAdapterType):
        self.handle = hande

    @classmethod
    def get_by_name(cls, name: str) -> None:
        cls.handle = dbgcore.BNGetDebugAdapterTypeByName(name)

    def can_execute(self, bv: binaryninja.BinaryView) -> bool:
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        return dbgcore.BNDebugAdapterTypeCanExecute(self.handle, bv_obj)

    def can_connect(self, bv: binaryninja.BinaryView) -> bool:
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        return dbgcore.BNDebugAdapterTypeCanConnect(self.handle, bv_obj)

    @staticmethod
    def get_available_adapters(bv: binaryninja.BinaryView) -> list[str]:
        count = ctypes.c_ulonglong()
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        adapters = dbgcore.BNGetAvailableDebugAdapterTypes(bv_obj, count)
        result = []
        for i in range(count.value):
            result.append(adapters[i].decode('utf-8'))
        dbgcore.BNDebuggerFreeStringList(adapters, count)
        return result
