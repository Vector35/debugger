#!/usr/bin/env python3
#
# Unit tests for the debugger's MCP tools (api/python/mcp_tools.py).
#
# These exercise the registered tools the way an MCP client would -- through
# ``mcp.Tool.by_name(name).invoke(arguments, view)`` -- against a real DebuggerController session,
# rather than mocking the controller. The tools are thin wrappers over DebuggerController, so a real
# session is both simpler to set up and more meaningful than the old RPC-server prototype's
# FakeBV/FakeDbg mocks.

import base64
import platform
import unittest

from binaryninja import load, mcp

from debugger_test import name_to_fpath

try:
    from debugger import DebuggerController, DebugStopReason
except ImportError:
    from binaryninja.debugger import DebuggerController, DebugStopReason


def invoke(name, arguments=None, view=None):
    tool = mcp.Tool.by_name(name)
    if tool is None:
        raise AssertionError(f"MCP tool '{name}' is not registered")
    return tool.invoke(arguments or {}, view)


class McpToolRegistrationTests(unittest.TestCase):
    def test_every_debugger_tool_is_registered(self):
        expected = {
            "debugger_launch", "debugger_attach", "debugger_connect", "debugger_detach",
            "debugger_quit", "debugger_restart", "debugger_go", "debugger_step_into",
            "debugger_step_over", "debugger_step_return", "debugger_run_to", "debugger_pause",
            "debugger_status", "debugger_registers_get", "debugger_register_set",
            "debugger_read_memory", "debugger_write_memory", "debugger_threads_list",
            "debugger_thread_select", "debugger_backtrace", "debugger_modules_list",
            "debugger_memory_map", "debugger_processes_list", "debugger_breakpoints_list",
            "debugger_breakpoint_set", "debugger_breakpoint_delete", "debugger_breakpoint_set_enabled",
            "debugger_breakpoint_condition_set",
            "debugger_write_stdin", "debugger_execute_backend_command", "debugger_property_get",
            "debugger_property_set",
        }
        names = {tool.name for tool in mcp.Tool.list()}
        missing = expected - names
        self.assertEqual(missing, set(), f"tools missing from the registry: {missing}")


class NoControllerTests(unittest.TestCase):
    """Inspection tools must not auto-create a controller for a view that was never debugged."""

    def setUp(self):
        self.bv = load(name_to_fpath('helloworld'))

    def tearDown(self):
        self.bv.file.close()

    def test_status_reports_no_session_without_creating_a_controller(self):
        result = invoke("debugger_status", view=self.bv)
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["connected"], False)

    def test_inspection_tools_report_no_controller(self):
        for name in ("debugger_registers_get", "debugger_read_memory", "debugger_threads_list",
                     "debugger_modules_list", "debugger_memory_map"):
            arguments = {"address": "0x0"} if name == "debugger_read_memory" else {}
            result = invoke(name, arguments, view=self.bv)
            self.assertTrue(result["isError"], f"{name} should error with no controller")
            self.assertEqual(result["structuredContent"]["errorCode"], "no_controller")

    def test_breakpoints_list_is_empty_without_a_controller(self):
        result = invoke("debugger_breakpoints_list", view=self.bv)
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["breakpoints"], [])


class BreakpointManagementTests(unittest.TestCase):
    """Breakpoints require the target to have been launched at least once to register, but then
    persist across quit -- so each test launches once up front and manages breakpoints from there."""

    def setUp(self):
        self.bv = load(name_to_fpath('helloworld'))
        self.address = self.bv.entry_point
        result = invoke("debugger_launch", view=self.bv)
        assert not result["isError"], result

    def tearDown(self):
        invoke("debugger_quit", view=self.bv)
        self.bv.file.close()

    def test_set_list_and_delete_a_software_breakpoint(self):
        result = invoke("debugger_breakpoint_set", {"address": hex(self.address)}, view=self.bv)
        self.assertFalse(result["isError"], result)

        listed = invoke("debugger_breakpoints_list", view=self.bv)
        addresses = [bp["address"] for bp in listed["structuredContent"]["breakpoints"]]
        self.assertIn(hex(self.address), addresses)

        result = invoke("debugger_breakpoint_delete", {"address": hex(self.address)}, view=self.bv)
        self.assertFalse(result["isError"], result)

        listed = invoke("debugger_breakpoints_list", view=self.bv)
        addresses = [bp["address"] for bp in listed["structuredContent"]["breakpoints"]]
        self.assertNotIn(hex(self.address), addresses)

    def test_delete_unknown_breakpoint_reports_unknown_breakpoint(self):
        result = invoke("debugger_breakpoint_delete", {"address": hex(self.address)}, view=self.bv)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["errorCode"], "unknown_breakpoint")

    def test_enable_and_disable_a_breakpoint(self):
        invoke("debugger_breakpoint_set", {"address": hex(self.address)}, view=self.bv)
        result = invoke(
            "debugger_breakpoint_set_enabled", {"address": hex(self.address), "enabled": False}, view=self.bv)
        self.assertFalse(result["isError"])
        self.assertFalse(result["structuredContent"]["enabled"])

        listed = invoke("debugger_breakpoints_list", view=self.bv)
        [entry] = [bp for bp in listed["structuredContent"]["breakpoints"] if bp["address"] == hex(self.address)]
        self.assertFalse(entry["enabled"])

        result = invoke(
            "debugger_breakpoint_set_enabled", {"address": hex(self.address), "enabled": True}, view=self.bv)
        self.assertFalse(result["isError"])
        self.assertTrue(result["structuredContent"]["enabled"])

    def test_set_enabled_on_unknown_breakpoint_reports_unknown_breakpoint(self):
        result = invoke("debugger_breakpoint_set_enabled", {"address": hex(self.address)}, view=self.bv)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["errorCode"], "unknown_breakpoint")

    def test_hardware_breakpoints_use_the_requested_kind_and_size(self):
        result = invoke(
            "debugger_breakpoint_set", {"address": hex(self.address), "kind": "write", "size": 4}, view=self.bv)
        self.assertFalse(result["isError"], result)
        listed = invoke("debugger_breakpoints_list", view=self.bv)
        [entry] = [bp for bp in listed["structuredContent"]["breakpoints"] if bp["address"] == hex(self.address)]
        self.assertEqual(entry["type"], "BNHardwareWriteBreakpoint")
        self.assertEqual(entry["size"], 4)

    def test_set_and_clear_a_condition(self):
        invoke("debugger_breakpoint_set", {"address": hex(self.address)}, view=self.bv)
        result = invoke(
            "debugger_breakpoint_condition_set", {"address": hex(self.address), "condition": "rax == 0"},
            view=self.bv)
        self.assertFalse(result["isError"], result)
        listed = invoke("debugger_breakpoints_list", view=self.bv)
        [entry] = [bp for bp in listed["structuredContent"]["breakpoints"] if bp["address"] == hex(self.address)]
        self.assertEqual(entry["condition"], "rax == 0")


class LiveSessionTests(unittest.TestCase):
    """Lifecycle, execution control, memory and register tools against a real launched target."""

    def setUp(self):
        self.bv = load(name_to_fpath('helloworld'))
        self.dbg = DebuggerController(self.bv)

    def tearDown(self):
        if self.dbg.connected:
            self.dbg.quit_and_wait()
        self.bv.file.close()

    def test_launch_step_and_quit_round_trip(self):
        result = invoke("debugger_launch", view=self.bv)
        self.assertFalse(result["isError"], result)
        self.assertTrue(result["structuredContent"]["connected"])

        result = invoke("debugger_status", view=self.bv)
        self.assertTrue(result["structuredContent"]["connected"])
        self.assertFalse(result["structuredContent"]["running"])

        result = invoke("debugger_step_into", view=self.bv)
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["stopReason"], DebugStopReason.SingleStep.name)

        result = invoke("debugger_go", view=self.bv)
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["stopReason"], DebugStopReason.ProcessExited.name)
        # The process exiting disconnects the target, so there's nothing left to quit.
        self.assertFalse(result["structuredContent"]["connected"])

        result = invoke("debugger_quit", view=self.bv)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["errorCode"], "target_not_connected")

    def test_launch_twice_reports_target_connected(self):
        invoke("debugger_launch", view=self.bv)
        result = invoke("debugger_launch", view=self.bv)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["errorCode"], "target_connected")

    def test_go_before_launch_reports_target_not_connected(self):
        result = invoke("debugger_go", view=self.bv)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["errorCode"], "target_not_connected")

    def test_registers_get_and_set_round_trip(self):
        invoke("debugger_launch", view=self.bv)
        reg_name = 'x0' if platform.machine() in ('arm64', 'aarch64') else 'rax'

        result = invoke("debugger_registers_get", {"name": reg_name}, view=self.bv)
        self.assertFalse(result["isError"], result)
        [reg] = result["structuredContent"]["registers"]
        self.assertEqual(reg["name"], reg_name)

        result = invoke("debugger_register_set", {"name": reg_name, "value": "0x1234"}, view=self.bv)
        self.assertFalse(result["isError"], result)
        self.assertEqual(int(result["structuredContent"]["value"], 16), 0x1234)

    def test_unknown_register_is_reported(self):
        invoke("debugger_launch", view=self.bv)
        result = invoke("debugger_registers_get", {"name": "not_a_register"}, view=self.bv)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["errorCode"], "unknown_register")

    def test_default_group_excludes_wide_vector_registers(self):
        invoke("debugger_launch", view=self.bv)
        pointer_bits = self.dbg.remote_arch.address_size * 8

        most = invoke("debugger_registers_get", view=self.bv)
        self.assertFalse(most["isError"], most)
        most_regs = most["structuredContent"]["registers"]
        self.assertTrue(all(reg["width"] <= pointer_bits for reg in most_regs))

        everything = invoke("debugger_registers_get", {"group": "all"}, view=self.bv)
        self.assertFalse(everything["isError"], everything)
        self.assertGreaterEqual(len(everything["structuredContent"]["registers"]), len(most_regs))

    def test_read_and_write_memory_round_trip(self):
        invoke("debugger_launch", view=self.bv)
        address = self.dbg.ip

        result = invoke("debugger_read_memory", {"address": hex(address), "size": 4}, view=self.bv)
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["encoding"], "hex")
        original = result["structuredContent"]["data"]
        self.assertEqual(len(bytes.fromhex(original)), 4)

        result = invoke("debugger_write_memory", {"address": hex(address), "data": "90909090"}, view=self.bv)
        self.assertFalse(result["isError"], result)

        result = invoke("debugger_read_memory", {"address": hex(address), "size": 4}, view=self.bv)
        self.assertEqual(result["structuredContent"]["data"], "90909090")

    def test_read_memory_base64_encoding(self):
        invoke("debugger_launch", view=self.bv)
        address = self.dbg.ip

        result = invoke(
            "debugger_read_memory", {"address": hex(address), "size": 4, "encoding": "base64"}, view=self.bv)
        self.assertFalse(result["isError"], result)
        self.assertEqual(result["structuredContent"]["encoding"], "base64")
        decoded = base64.b64decode(result["structuredContent"]["data"])
        self.assertEqual(len(decoded), 4)
        self.assertEqual(decoded, bytes(self.dbg.read_memory(address, 4)))


if __name__ == '__main__':
    unittest.main()
