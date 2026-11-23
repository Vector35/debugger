"""Controller integration for API-side adapters; no third-party emulator required."""
import ctypes
from concurrent.futures import ThreadPoolExecutor
import gc
import os
from pathlib import Path
import sys
import uuid
import weakref

import binaryninja as bn
import pytest
from debugger.customdebugadapter import (
    CustomDebugAdapter, CustomDebugAdapterType, DebugBreakpoint, DebugModule, DebugProcess,
    DebugRegister, DebugThread,
)
from debugger.debuggercontroller import DebuggerController
from debugger.debugadaptertype import DebugAdapterType
from debugger.debugger_enums import DebuggerEventType, DebugStopReason as Reason
from debugger import _debuggercore as core

_fixture_libraries = []


class PythonAdapter(CustomDebugAdapter):
    def __init__(self, bv):
        super().__init__()
        self.bv = bv
        self.pc = 0x1000
        self.value = 0
        self.memory = bytearray(b"\x90" * 0x1000)
        self.settings = bn.Settings("custom-adapter-test-" + uuid.uuid4().hex)
        self.settings.set_resource_id("custom-adapter-test")
        self.settings.register_group("launch", "Launch")
        assert self.settings.register_setting("launch.executablePath",
            '{"title":"Path","description":"Fixture path","type":"string","default":""}')

    def get_adapter_settings(self): return self.settings
    def execute(self, path): self.post_stopped(int(Reason.InitialBreakpoint), 1); return True
    def step_into(self):
        self.value, self.pc = 42, 0x1005
        self.post_stopped(int(Reason.SingleStep), 1)
        return True
    def go(self):
        self.value, self.pc = 43, 0x1007
        self.post_stopped(int(Reason.Breakpoint), 1)
        return True
    def quit(self):
        event = core.BNDebuggerEvent()
        event.type = int(DebuggerEventType.TargetExitedEventType)
        self.post_event(event)
        return True
    def get_target_architecture(self): return "x86_64"
    def get_active_pid(self): return 1
    def get_process_list(self): return [DebugProcess(1, "python-fixture")]
    def get_active_thread_id(self): return 1
    def get_active_thread(self): return DebugThread(1, self.pc)
    def get_thread_list(self): return [self.get_active_thread()]
    def get_instruction_offset(self): return self.pc
    def get_stack_pointer(self): return 0x1800
    def get_module_list(self): return [DebugModule("python-fixture", "python-fixture", 0x1000, 0x1000)]
    def read_all_registers(self):
        result = {name: DebugRegister(name, value, 8, i) for i, (name, value) in
            enumerate((("rax", self.value), ("rip", self.pc), ("rsp", 0x1800)))}
        result.update({f"long_register_name_{i}": DebugRegister(f"long_register_name_{i}", i, 8, i + 3) for i in range(32)})
        return result
    def read_register(self, name): return self.read_all_registers().get(name)
    def read_memory(self, address, size):
        if not 0x1000 <= address < 0x2000: return b""
        return bytes(self.memory[address - 0x1000:address - 0x1000 + size])
    def write_memory(self, address, data):
        if address < 0x1000 or address + len(data) > 0x2000: return False
        self.memory[address - 0x1000:address - 0x1000 + len(data)] = data
        return True


class PythonType(CustomDebugAdapterType):
    def __init__(self):
        self.last = None
        super().__init__("PYTHON_API_TEST_" + uuid.uuid4().hex)
    def create(self, bv):
        adapter = PythonAdapter(bv)
        self.last = weakref.ref(adapter)
        return adapter


@pytest.mark.parametrize("method,release,ctype,key", [
    ("_get_processes", "freeProcessList", core.BNDebugProcess, "processes"),
    ("_get_threads", "freeThreadList", core.BNDebugThread, "threads"),
    ("_get_breakpoints", "freeBreakpointList", core.BNDebugBreakpoint, "breakpoints"),
    ("_get_registers", "freeRegisterList", core.BNDebugRegister, "registers"),
    ("_get_modules", "freeModuleList", core.BNDebugModule, "modules"),
])
def test_callback_results_live_until_individual_release(method, release, ctype, key):
    bv = bn.BinaryView.new(b"\x90")
    adapter = PythonAdapter(bv)
    text = "callback-storage-" + "x" * 4096
    adapter.get_process_list = lambda: [DebugProcess(7, text, text)]
    adapter.get_breakpoint_list = lambda: [DebugBreakpoint(0x1000, module=text, condition=text)]
    adapter.get_module_list = lambda: [DebugModule(text, text, 0x1000, 0x1000)]
    count = ctypes.c_size_t()
    get = getattr(adapter, method)
    first = get(None, ctypes.pointer(count))
    first_count = count.value
    second = get(None, ctypes.pointer(count))
    second_count = count.value
    try:
        gc.collect()
        assert first != second
        assert (key, first) in adapter._buffers
        assert (key, second) in adapter._buffers
        if key == "processes":
            assert ctypes.cast(first, ctypes.POINTER(ctype))[0].m_processName == text
        elif key == "breakpoints":
            assert ctypes.cast(first, ctypes.POINTER(ctype))[0].module == text
        elif key == "registers":
            assert ctypes.cast(first, ctypes.POINTER(ctype))[0].m_name == "rax"
        elif key == "modules":
            assert ctypes.cast(first, ctypes.POINTER(ctype))[0].m_name == text
        getattr(adapter._callbacks, release)(None, ctypes.cast(first, ctypes.POINTER(ctype)), first_count)
        assert (key, first) not in adapter._buffers
        assert (key, second) in adapter._buffers
        getattr(adapter._callbacks, release)(None, ctypes.cast(second, ctypes.POINTER(ctype)), second_count)
        assert (key, second) not in adapter._buffers
    finally:
        adapter._free(None)
        bv.file.close()


@pytest.mark.parametrize("register", [True, False])
def test_scalar_strings_live_until_individual_release(register):
    bv = bn.BinaryView.new(b"\x90")
    adapter = PythonAdapter(bv)
    text = "scalar-storage-" + "y" * 4096
    adapter.read_register = lambda name: DebugRegister(name + text, 42, 8, hint=text)
    adapter.add_breakpoint = lambda address: DebugBreakpoint(address, module=text, condition=text)
    ctype = core.BNDebugRegister if register else core.BNDebugBreakpoint
    key = "register_result" if register else "breakpoint_result"
    first, second = ctype(), ctype()
    out1, out2 = ctypes.pointer(first), ctypes.pointer(second)
    try:
        if register:
            assert adapter._get_register(None, b"rax", out1)
            assert adapter._get_register(None, b"rip", out2)
        else:
            assert adapter._add_breakpoint(None, 0x1000, out1)
            assert adapter._add_breakpoint(None, 0x1001, out2)
        gc.collect()
        address1, address2 = ctypes.addressof(first), ctypes.addressof(second)
        assert (key, address1) in adapter._buffers
        assert (key, address2) in adapter._buffers
        assert (first.m_hint if register else first.module) == text
        release = adapter._callbacks.freeRegister if register else adapter._callbacks.freeBreakpoint
        release(None, out1)
        assert (key, address1) not in adapter._buffers
        assert (key, address2) in adapter._buffers
        release(None, out2)
        assert (key, address2) not in adapter._buffers
    finally:
        adapter._free(None)
        bv.file.close()


def test_concurrent_process_list_callbacks():
    adapter_type = PythonType().register()
    bv = bn.BinaryView.new(b"\x90")
    controller = DebuggerController(bv)
    controller.adapter_type = adapter_type.name
    controller.executable_path = "fixture-path"
    adapter = adapter_type.last()
    names = ["process-" + str(i) + "-" + "z" * 4096 for i in range(16)]
    def processes():
        gc.collect()
        return [DebugProcess(i + 1, name, name) for i, name in enumerate(names)]
    adapter.get_process_list = processes
    def read_many():
        for _ in range(16):
            result = controller.processes
            assert [p.name for p in result] == names
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for result in pool.map(lambda _: read_many(), range(4)):
                pass
        assert not adapter._buffers
    finally:
        dispose(controller, bv)



def exercise(controller):
    assert controller.launch_and_wait(5000) == Reason.InitialBreakpoint
    assert controller.read_memory(0x1000, 4) == b"\x90" * 4
    assert controller.step_into_and_wait(timeout=5000) == Reason.SingleStep
    assert controller.regs["rax"].value == 42
    assert controller.go_and_wait(5000) == Reason.Breakpoint
    assert controller.regs["rax"].value == 43
    assert controller.regs["rip"].value == 0x1007
    assert controller.write_memory(0x1800, b"adapter-api")
    assert controller.read_memory(0x1800, 11) == b"adapter-api"
    assert not controller.write_memory(0xDEAD0000, b"x")
    controller.quit_and_wait(5000)


def dispose(controller, bv):
    if controller.connected:
        controller.quit_and_wait(5000)
    controller.destroy()
    bv.file.close()


def test_class_registration_matches_binary_view_style():
    class ClassAdapter(PythonAdapter):
        name = "CLASS_API_TEST_" + uuid.uuid4().hex

        @classmethod
        def is_valid_for_data(cls, bv):
            return bv.file.filename == "class-adapter-view"

    adapter_type = ClassAdapter.register()
    assert ClassAdapter.registered_adapter_type is adapter_type
    assert isinstance(adapter_type, DebugAdapterType)
    registered = DebugAdapterType.get_by_name(ClassAdapter.name)
    assert registered is not None
    assert DebugAdapterType.get_by_name("missing_" + uuid.uuid4().hex) is None
    with pytest.raises(ValueError):
        ClassAdapter.register()

    bv = bn.BinaryView.new(b"\x90" * 8)
    bv.file.filename = "class-adapter-view"
    assert registered.can_execute(bv)
    assert ClassAdapter.name in DebugAdapterType.get_available_adapters(bv)
    controller = DebuggerController(bv)
    controller.adapter_type = ClassAdapter.name
    try:
        exercise(controller)
    finally:
        dispose(controller, bv)


def test_class_registration_requires_name():
    class UnnamedAdapter(CustomDebugAdapter):
        pass
    with pytest.raises(ValueError, match="name"):
        UnnamedAdapter.register()


def test_callback_conversion_exceptions_return_failure(capsys):
    bv = bn.BinaryView.new(b"\x90")
    adapter = PythonAdapter(bv)
    adapter.read_all_registers = lambda: {"bad": DebugRegister("bad", -1, 8)}
    count = ctypes.c_uint64()
    output = core.BNDebugRegister()
    try:
        assert adapter._callbacks.readAllRegisters(None, ctypes.byref(count)) is None
        assert not adapter._callbacks.readRegister(None, b"bad", ctypes.byref(output))
        assert "OverflowError" in capsys.readouterr().err
    finally:
        adapter._free(None)
        bv.file.close()


def test_cpp_adapter_callbacks_and_lifetime():
    suffix = ".dll" if sys.platform == "win32" else ".so"
    prefix = "" if sys.platform == "win32" else "lib"
    path = Path(os.environ.get("CPP_ADAPTER_FIXTURE", Path(__file__).resolve().parents[1] /
        "build" / "test" / (prefix + "custom_adapter_fixture" + suffix)))
    if not path.is_file():
        if "CPP_ADAPTER_FIXTURE" in os.environ:
            pytest.fail(f"Required C++ adapter fixture is missing: {path}")
        pytest.skip("Build with -DBUILD_CUSTOM_ADAPTER_TESTS=ON for the C++ fixture")
    library = ctypes.CDLL(str(path))
    _fixture_libraries.append(library)
    library.RegisterCppAdapterFixture.restype = ctypes.c_bool
    library.CppAdapterDestroyedCount.restype = ctypes.c_uint
    library.CppAdapterTypeDestroyedCount.restype = ctypes.c_uint
    library.CppAdapterEmptyNameRejected.restype = ctypes.c_bool
    types_before = library.CppAdapterTypeDestroyedCount()
    assert library.RegisterCppAdapterFixture()
    assert library.CppAdapterTypeDestroyedCount() == types_before
    assert not library.RegisterCppAdapterFixture()
    assert library.CppAdapterEmptyNameRejected()
    assert library.CppAdapterTypeDestroyedCount() == types_before + 2
    before = library.CppAdapterDestroyedCount()
    bv = bn.BinaryView.new(b"\x90" * 8)
    controller = DebuggerController(bv)
    controller.adapter_type = "CPP_API_TEST"
    try:
        exercise(controller)
        assert library.CppAdapterDestroyedCount() == before
    finally:
        dispose(controller, bv)
    del controller, bv
    gc.collect()
    assert library.CppAdapterDestroyedCount() == before + 1
