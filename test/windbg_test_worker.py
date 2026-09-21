"""Fresh-process WinDbg/TTD checks; imported only by windbg_test.py's child process."""

import os
import sys
from pathlib import Path

from binaryninja import Settings, load
try:
    from debugger import DebuggerController, DebugStopReason
except ImportError:
    from binaryninja.debugger import DebuggerController, DebugStopReason


def main(target, trace):
    assert os.environ.get("BN_DBGENG_DLLS"), "BN_DBGENG_DLLS is not set"

    # Prove that the environment override wins over the user-facing setting.
    settings = Settings()
    assert settings.set_string("debugger.x64dbgEngPath", str(Path(target).parent / "not-windbg"))

    bv = load(target)
    dbg = DebuggerController(bv)
    dbg.adapter_type = "DBGENG_TTD"
    assert dbg.set_adapter_property("launch.trace_path", trace)
    assert dbg.set_adapter_property("common.inputFile", target)
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
        print(f"WINDBG_TTD_OK {initial} {stepped} {reversed_position}")
    finally:
        dbg.quit_and_wait()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
