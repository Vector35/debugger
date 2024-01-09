# coding=utf-8
# Copyright 2020-2024 Vector 35 Inc.
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
from typing import List


class DebugAdapterType:
    """
    The ``DebugAdapterType`` object is used to access the DebugAdapters. DebugAdapterType should not be directly
    instantiated; instead, use ``get_by_name`` to get an instance of DebugAdapter by name.

    Right now, the DebugAdapterType class cannot be used to create a DebuggerController. This is planned for the future.
    """

    def __init__(self, hande: dbgcore.BNDebugAdapterType):
        self.handle = hande

    @classmethod
    def get_by_name(cls, name: str) -> None:
        """
        Get a DebugAdapterType by its name.

        :param name: the name of the DebugAdapterType
        :return:
        """
        cls.handle = dbgcore.BNGetDebugAdapterTypeByName(name)

    def can_execute(self, bv: binaryninja.BinaryView) -> bool:
        """
        Whether the current DebugAdapterType can execute the specified BinaryView

        :param bv: the BinaryView to check for
        :return:
        """
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        return dbgcore.BNDebugAdapterTypeCanExecute(self.handle, bv_obj)

    def can_connect(self, bv: binaryninja.BinaryView) -> bool:
        """
        Whether the current DebugAdapterType can connect to a remote host for the specified BinaryView

        :param bv: the BinaryView to check for
        :return:
        """
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        return dbgcore.BNDebugAdapterTypeCanConnect(self.handle, bv_obj)

    @staticmethod
    def get_available_adapters(bv: binaryninja.BinaryView) -> List[str]:
        """
        Get a list of available DebugAdapters for the specified BinaryView. The DebugAdapters in the list can be used to
        debug the BinaryView.

        :param bv: the BinaryView to check for
        :return: list of available DebugAdapters
        """
        count = ctypes.c_ulonglong()
        bv_obj = ctypes.cast(bv.handle, ctypes.POINTER(dbgcore.BNBinaryView))
        adapters = dbgcore.BNGetAvailableDebugAdapterTypes(bv_obj, count)
        result = []
        for i in range(count.value):
            result.append(adapters[i].decode('utf-8'))
        dbgcore.BNDebuggerFreeStringList(adapters, count)
        return result
