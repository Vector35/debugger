"""Fresh-process WinDbg/TTD checks; imported only by windbg_test.py's child process."""

import os
import json
import sys
from pathlib import Path

from binaryninja import Settings, SettingsScope, load
try:
    from debugger import DebuggerController, DebugStopReason
except ImportError:
    from binaryninja.debugger import DebuggerController, DebugStopReason


def position(value):
    return [value.sequence, value.step]


def check_queries(dbg, expected):
    access_flags = {"Read": 1, "Write": 2, "Execute": 4}
    for access, rows in expected["memory"].items():
        address = expected["execute_address"] if access == "e" else expected["data_address"]
        actual = dbg.get_ttd_memory_access_for_address(address, address + 1, access)
        assert len(actual) == len(rows), (access, actual, rows)
        for event, row in zip(actual, rows):
            for field in ("thread_id", "unique_thread_id", "size"):
                assert getattr(event, field) == row[field], (access, field)
            for field in ("address", "instruction_address", "value"):
                assert getattr(event, field) == int(row[field], 16), (access, field)
            assert event.memory_address == int(row["address"], 16)
            assert event.access_type == access_flags[row["access_type"]]
            assert position(event.time_start) == row["time_start"]
            assert position(event.time_end) == row["time_end"]
    calls = dbg.get_ttd_calls_for_symbols(hex(expected["call_address"]))
    assert len(calls) == len(expected["calls"])
    for event, row in zip(calls, expected["calls"]):
        for field in ("thread_id", "unique_thread_id"):
            assert getattr(event, field) == row[field], field
        for field in ("function_address", "return_address", "return_value"):
            assert getattr(event, field) == int(row[field], 16), field
        assert event.has_return_value
        assert [int(p, 0) for p in event.parameters] == [int(p, 16) for p in row["parameters"]]
        assert position(event.time_start) == row["time_start"]
        assert position(event.time_end) == row["time_end"]
    assert dbg.get_ttd_memory_access_for_address(0, 1, "rw") == []
    first_return = int(expected["calls"][0]["return_address"], 16)
    second_return = int(expected["calls"][1]["return_address"], 16)
    filtered = dbg.get_ttd_calls_for_symbols(hex(expected["call_address"]), first_return, second_return)
    assert filtered == calls[:1]
    assert dbg.get_ttd_calls_for_symbols(hex(expected["call_address"]), 1, 2) == []


def main(target, trace, expected_path):
    assert os.environ.get("BN_DBGENG_DLLS"), "BN_DBGENG_DLLS is not set"

    # Loading a view initializes native plugins and registers debugger settings.
    # Importing the Python bindings alone does not initialize the native plugin.
    # BN_DBGENG_DLLS is already inherited before either operation.
    bv = load(target)
    assert bv is not None, target
    # Prove that the environment override wins over the user-facing setting.
    settings = Settings()
    assert settings.contains("debugger.x64dbgEngPath"), "Debugger settings were not registered"
    assert settings.set_string("debugger.x64dbgEngPath", str(Path(target).parent / "not-windbg"))

    dbg = DebuggerController(bv)
    dbg.adapter_type = "DBGENG_TTD"
    # These are resource-scoped adapter Settings, not DebugAdapter properties.
    # DbgEngTTDAdapter::ExecuteWithArgsInternal reads this named Settings instance.
    adapter_settings = Settings("DbgEngTTDAdapterSettings")
    for key, value in (("launch.trace_path", trace), ("common.inputFile", target)):
        assert adapter_settings.contains(key), key
        assert adapter_settings.set_string(key, value, bv, SettingsScope.SettingsResourceScope), key
        assert adapter_settings.get_string(key, bv) == value, key
    try:
        reason = dbg.launch_and_wait()
        assert reason not in (DebugStopReason.ProcessExited, DebugStopReason.InternalError), reason
        initial = dbg.current_ttd_position
        assert initial is not None
        assert dbg.step_into_and_wait() == DebugStopReason.SingleStep
        stepped = dbg.current_ttd_position
        assert stepped is not None and stepped != initial
        assert dbg.step_into_reverse_and_wait() == DebugStopReason.SingleStep
        reversed_position = dbg.current_ttd_position
        assert reversed_position is not None
        check_queries(dbg, json.loads(Path(expected_path).read_text()))
        print(f"WINDBG_TTD_OK {initial} {stepped} {reversed_position}")
    finally:
        dbg.quit_and_wait()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
