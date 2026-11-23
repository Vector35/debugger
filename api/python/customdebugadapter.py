# coding=utf-8
# Copyright 2020-2026 Vector 35 Inc.
# SPDX-License-Identifier: Apache-2.0

"""Base classes for debugger adapters implemented in Python."""

import ctypes
import traceback
from dataclasses import dataclass
from functools import partial

import binaryninja
from binaryninja import _binaryninjacore as bncore
from . import _debuggercore as dbgcore
from .debugadaptertype import DebugAdapterType


@dataclass
class DebugProcess:
    pid: int
    name: str = ""
    command_line: str = ""


@dataclass
class DebugThread:
    tid: int
    rip: int = 0
    frozen: bool = False


@dataclass
class DebugBreakpoint:
    address: int
    module: str = ""
    offset: int = 0
    enabled: bool = True
    condition: str = ""
    type: int = 0
    size: int = 1


@dataclass
class DebugRegister:
    name: str
    value: int = 0
    width: int = 0
    index: int = 0
    hint: str = ""


@dataclass
class DebugModule:
    name: str
    short_name: str = ""
    address: int = 0
    size: int = 0
    loaded: bool = True


class CustomDebugAdapter:
    """Subclass this and override the operations supported by the backend."""

    _instances = {}
    name = None
    registered_adapter_type = None

    def __init__(self, view=None):
        self.view = view
        self._instances[id(self)] = self
        self._buffers = {}
        self._handle = None
        self._callbacks = dbgcore.BNCustomDebugAdapterCallbacks()
        types = dict(self._callbacks._fields_)
        self._callbacks.context = id(self)
        handlers = {
            "init": lambda c: self._safe(False, self.init),
            "execute": lambda c, p: self._safe(False, self.execute, self._text(p)),
            "executeWithArgs": lambda c, p, a, w: self._safe(False, self.execute_with_args, self._text(p), self._text(a), self._text(w)),
            "attach": lambda c, p: self._safe(False, self.attach, p),
            "connect": lambda c, h, p: self._safe(False, self.connect, self._text(h), p),
            "connectToDebugServer": lambda c, h, p: self._safe(False, self.connect_to_debug_server, self._text(h), p),
            "detach": lambda c: self._safe(False, self.detach),
            "quit": lambda c: self._safe(False, self.quit),
            "getProcessList": self._get_processes,
            "getActivePID": lambda c: self._safe(0, self.get_active_pid),
            "getThreadList": self._get_threads,
            "getActiveThread": self._get_active_thread,
            "getActiveThreadId": lambda c: self._safe(0, self.get_active_thread_id),
            "setActiveThread": lambda c, t: self._safe(False, self.set_active_thread, DebugThread(t.m_tid, t.m_rip, t.m_isFrozen)),
            "setActiveThreadId": lambda c, t: self._safe(False, self.set_active_thread_id, t),
            "suspendThread": lambda c, t: self._safe(False, self.suspend_thread, t),
            "resumeThread": lambda c, t: self._safe(False, self.resume_thread, t),
            "addBreakpoint": self._add_breakpoint,
            "addBreakpointRelative": self._add_breakpoint_relative,
            "removeBreakpoint": lambda c, a: self._safe(False, self.remove_breakpoint, a),
            "removeBreakpointRelative": lambda c, m, o: self._safe(False, self.remove_breakpoint_relative, self._text(m), o),
            "getBreakpointList": self._get_breakpoints,
            "readAllRegisters": self._get_registers,
            "readRegister": self._get_register,
            "writeRegister": lambda c, n, v: self._safe(False, self.write_register, self._text(n), bytes(v[:64])),
            "readMemory": self._read_memory,
            "writeMemory": self._write_memory,
            "getModuleList": self._get_modules,
            "getTargetArchitecture": lambda c: self._string(self._safe("", self.get_target_architecture)),
            "stopReason": lambda c: self._safe(0, self.stop_reason),
            "exitCode": lambda c: self._safe(0, self.exit_code),
            "breakInto": lambda c: self._safe(False, self.break_into),
            "go": lambda c: self._safe(False, self.go),
            "goReverse": lambda c: self._safe(False, self.go_reverse),
            "stepInto": lambda c: self._safe(False, self.step_into),
            "stepIntoReverse": lambda c: self._safe(False, self.step_into_reverse),
            "stepOver": lambda c: self._safe(False, self.step_over),
            "stepOverReverse": lambda c: self._safe(False, self.step_over_reverse),
            "stepReturn": lambda c: self._safe(False, self.step_return),
            "stepReturnReverse": lambda c: self._safe(False, self.step_return_reverse),
            "invokeBackendCommand": lambda c, s: self._string(self._safe("", self.invoke_backend_command, self._text(s))),
            "getInstructionOffset": lambda c: self._safe(0, self.get_instruction_offset),
            "getStackPointer": lambda c: self._safe(0, self.get_stack_pointer),
            "supportFeature": lambda c, f: self._safe(False, self.support_feature, f),
            "writeStdin": lambda c, s: self._safe(None, self.write_stdin, self._text(s)),
            "getProperty": lambda c, n: None,
            "setProperty": lambda c, n, v: False,
            "getAdapterSettings": self._get_settings,
            "freeProcessList": lambda c, p, n: self._release("processes", p),
            "freeThreadList": lambda c, p, n: self._release("threads", p),
            "freeBreakpointList": lambda c, p, n: self._release("breakpoints", p),
            "freeBreakpoint": lambda c, p: self._release("breakpoint_result", p),
            "freeRegisterList": lambda c, p, n: self._release("registers", p),
            "freeRegister": lambda c, p: self._release("register_result", p),
            "freeModuleList": lambda c, p, n: self._release("modules", p),
            "freeCallback": self._free,
        }
        for name, handler in handlers.items():
            default = None if types[name]._restype_ in (None, ctypes.c_void_p) else 0
            setattr(self._callbacks, name, types[name](partial(self._safe, default, handler)))

    @classmethod
    def register(cls):
        """Register a named adapter subclass, as with BinaryView and Architecture."""
        binaryninja._init_plugins()
        if not cls.name:
            raise ValueError("adapter 'name' is not defined")
        adapter_type = _ClassAdapterType(cls)
        cls.registered_adapter_type = adapter_type.register()
        return cls.registered_adapter_type

    @classmethod
    def is_valid_for_data(cls, view): return True
    @classmethod
    def can_execute(cls, view): return True
    @classmethod
    def can_connect(cls, view): return False

    @staticmethod
    def _text(value): return value.decode("utf-8") if value else ""
    @staticmethod
    def _string(value): return dbgcore.BNDebuggerAllocString(str(value).encode("utf-8"))

    @staticmethod
    def _safe(default, function, *args):
        try: return function(*args)
        except Exception:
            traceback.print_exc()
            return default

    def _array(self, key, ctype, rows, strings=()):
        if not rows: return None
        value = (ctype * len(rows))(*rows)
        address = ctypes.addressof(value)
        self._buffers[key, address] = (value, rows, strings)
        return address

    def _release(self, key, pointer):
        address = ctypes.cast(pointer, ctypes.c_void_p).value
        self._buffers.pop((key, address), None)

    def _retain_scalar(self, key, out, strings):
        self._buffers[key, ctypes.addressof(out.contents)] = strings

    def _fill_breakpoint(self, out, value):
        strings = (value.module.encode("utf-8"), value.condition.encode("utf-8"))
        out.contents.address = value.address
        out.contents.module = strings[0]
        out.contents.offset, out.contents.enabled = value.offset, value.enabled
        out.contents.condition = strings[1]
        out.contents.type, out.contents.size = value.type, value.size
        return strings

    def _fill_register(self, out, value):
        strings = (value.name.encode("utf-8"), value.hint.encode("utf-8"))
        out.contents.m_name = strings[0]
        out.contents.m_value[:] = int(value.value).to_bytes(64, "little")
        out.contents.m_width, out.contents.m_registerIndex = value.width, value.index
        out.contents.m_hint = strings[1]
        return strings

    def _get_processes(self, ctxt, count):
        values = self._safe([], self.get_process_list); count[0] = len(values); rows = []
        for v in values:
            row = dbgcore.BNDebugProcess(); row.m_pid = v.pid
            row.m_processName, row.m_commandLine = v.name, v.command_line; rows.append(row)
        return self._array("processes", dbgcore.BNDebugProcess, rows)

    def _get_threads(self, ctxt, count):
        values = self._safe([], self.get_thread_list); count[0] = len(values)
        return self._array("threads", dbgcore.BNDebugThread,
            [dbgcore.BNDebugThread(v.tid, v.rip, v.frozen) for v in values])

    def _get_active_thread(self, ctxt, out):
        value = self._safe(None, self.get_active_thread)
        if value is None: return False
        out.contents.m_tid, out.contents.m_rip, out.contents.m_isFrozen = value.tid, value.rip, value.frozen
        return True

    def _add_breakpoint(self, ctxt, address, out):
        value = self._safe(None, self.add_breakpoint, address)
        if value is None: return False
        self._retain_scalar("breakpoint_result", out, self._fill_breakpoint(out, value)); return True

    def _add_breakpoint_relative(self, ctxt, module, offset, out):
        value = self._safe(None, self.add_breakpoint_relative, self._text(module), offset)
        if value is None: return False
        self._retain_scalar("breakpoint_result", out, self._fill_breakpoint(out, value)); return True

    def _get_breakpoints(self, ctxt, count):
        values = self._safe([], self.get_breakpoint_list); count[0] = len(values); rows = []; strings = []
        for v in values:
            row = dbgcore.BNDebugBreakpoint(); strings.append(self._fill_breakpoint(ctypes.pointer(row), v)); rows.append(row)
        return self._array("breakpoints", dbgcore.BNDebugBreakpoint, rows, strings)

    def _get_registers(self, ctxt, count):
        values = list(self._safe({}, self.read_all_registers).values()); count[0] = len(values); rows = []; strings = []
        for v in values:
            row = dbgcore.BNDebugRegister(); strings.append(self._fill_register(ctypes.pointer(row), v)); rows.append(row)
        return self._array("registers", dbgcore.BNDebugRegister, rows, strings)

    def _get_register(self, ctxt, name, out):
        value = self._safe(None, self.read_register, self._text(name))
        if value is None: return False
        self._retain_scalar("register_result", out, self._fill_register(out, value)); return True

    def _read_memory(self, ctxt, address, size):
        data = self._safe(b"", self.read_memory, address, size)
        if not data: return None
        storage = ctypes.create_string_buffer(data)
        return ctypes.cast(bncore.BNCreateDataBuffer(storage, len(data)), ctypes.c_void_p).value

    def _write_memory(self, ctxt, address, buffer):
        buffer = ctypes.cast(buffer, ctypes.POINTER(bncore.BNDataBuffer))
        size = bncore.BNGetDataBufferLength(buffer)
        data = ctypes.string_at(bncore.BNGetDataBufferContents(buffer), size)
        return self._safe(False, self.write_memory, address, data)

    def _get_modules(self, ctxt, count):
        values = self._safe([], self.get_module_list); count[0] = len(values); rows = []
        for v in values:
            row = dbgcore.BNDebugModule(); row.m_name, row.m_short_name = v.name, v.short_name
            row.m_address, row.m_size, row.m_loaded = v.address, v.size, v.loaded; rows.append(row)
        return self._array("modules", dbgcore.BNDebugModule, rows)

    def _free(self, ctxt): self._instances.pop(id(self), None)

    def _get_settings(self, ctxt):
        settings = self._safe(None, self.get_adapter_settings)
        return ctypes.cast(bncore.BNNewSettingsReference(settings.handle), ctypes.c_void_p).value if settings else None

    def post_event(self, event):
        """Post a ``BNDebuggerEvent`` to the controller owning this adapter."""
        if self._handle:
            dbgcore.BNCustomDebugAdapterPostEvent(self._handle, ctypes.byref(event))

    def post_stopped(self, reason, thread_id=0, exit_code=0):
        """Notify the debugger that the target stopped."""
        event = dbgcore.BNDebuggerEvent()
        event.type = 10  # DebuggerEventType.AdapterStoppedEventType
        event.data.targetStoppedData.reason = reason
        event.data.targetStoppedData.lastActiveThread = thread_id
        event.data.targetStoppedData.exitCode = exit_code
        self.post_event(event)

    def init(self): return True
    def get_adapter_settings(self): return None
    def execute(self, path): raise NotImplementedError
    def execute_with_args(self, path, args, working_dir): return self.execute(path)
    def attach(self, pid): return False
    def connect(self, server, port): return False
    def connect_to_debug_server(self, server, port): return False
    def detach(self): return False
    def quit(self): return False
    def get_process_list(self): return []
    def get_active_pid(self): return 0
    def get_thread_list(self): return []
    def get_active_thread(self): return None
    def get_active_thread_id(self): return 0
    def set_active_thread(self, thread): return False
    def set_active_thread_id(self, tid): return False
    def suspend_thread(self, tid): return False
    def resume_thread(self, tid): return False
    def add_breakpoint(self, address): return None
    def add_breakpoint_relative(self, module, offset): return None
    def remove_breakpoint(self, address): return False
    def remove_breakpoint_relative(self, module, offset): return False
    def get_breakpoint_list(self): return []
    def read_all_registers(self): return {}
    def read_register(self, name): return None
    def write_register(self, name, value): return False
    def read_memory(self, address, size): return b""
    def write_memory(self, address, data): return False
    def get_module_list(self): return []
    def get_target_architecture(self): return ""
    def stop_reason(self): return 0
    def exit_code(self): return 0
    def break_into(self): return False
    def go(self): return False
    def go_reverse(self): return False
    def step_into(self): return False
    def step_into_reverse(self): return False
    def step_over(self): return False
    def step_over_reverse(self): return False
    def step_return(self): return False
    def step_return_reverse(self): return False
    def invoke_backend_command(self, command): return ""
    def get_instruction_offset(self): return 0
    def get_stack_pointer(self): return 0
    def support_feature(self, feature): return False
    def write_stdin(self, data): pass


class CustomDebugAdapterType(DebugAdapterType):
    """Factory and availability predicates for a custom adapter."""

    _instances = {}

    def __init__(self, name):
        super().__init__(None)
        self.name = name
        self._callbacks = dbgcore.BNCustomDebugAdapterTypeCallbacks(); types = dict(self._callbacks._fields_)
        self._callbacks.context = id(self)
        self._callbacks.create = types["create"](self._create)
        self._callbacks.isValidForData = types["isValidForData"](lambda c, d: self._predicate(self.is_valid_for_data, d))
        self._callbacks.canExecute = types["canExecute"](lambda c, d: self._predicate(self.can_execute, d))
        self._callbacks.canConnect = types["canConnect"](lambda c, d: self._predicate(self.can_connect, d))
        self._callbacks.freeCallback = types["freeCallback"](lambda c: self._instances.pop(id(self), None))

    @staticmethod
    def _view(handle):
        core_handle = ctypes.cast(handle, ctypes.POINTER(bncore.BNBinaryView))
        return binaryninja.BinaryView(handle=bncore.BNNewViewReference(core_handle))
    def _predicate(self, function, data):
        try: return function(self._view(data))
        except Exception: traceback.print_exc(); return False
    def _create(self, ctxt, data):
        try:
            adapter = self.create(self._view(data))
            if adapter is None: return None
            adapter._handle = dbgcore.BNCreateCustomDebugAdapter(data, ctypes.byref(adapter._callbacks))
            return ctypes.cast(adapter._handle, ctypes.c_void_p).value
        except Exception: traceback.print_exc(); return None
    def register(self):
        if self.handle:
            raise ValueError("Adapter type is already registered")
        self.handle = dbgcore.BNRegisterCustomDebugAdapterType(self.name, ctypes.byref(self._callbacks))
        if not self.handle:
            raise ValueError("Adapter type name must be nonempty and unique")
        self._instances[id(self)] = self
        return self
    def create(self, bv): raise NotImplementedError
    def is_valid_for_data(self, bv): return True
    def can_execute(self, bv): return True
    def can_connect(self, bv): return False


class _ClassAdapterType(CustomDebugAdapterType):
    def __init__(self, adapter_class):
        self.adapter_class = adapter_class
        super().__init__(adapter_class.name)

    def create(self, view): return self.adapter_class(view)
    def is_valid_for_data(self, view): return self.adapter_class.is_valid_for_data(view)
    def can_execute(self, view): return self.adapter_class.can_execute(view)
    def can_connect(self, view): return self.adapter_class.can_connect(view)
