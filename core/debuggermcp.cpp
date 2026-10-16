/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.3
*/

// Registers the debugger's tools with Binary Ninja's MCP server, as a core (C++) plugin rather
// than a Python one: Binary Ninja Free has no Python/API access at all, so a Python-registered
// tool never loads there. This file is part of the core plugin binary and is registered from
// CorePluginInit/DebuggerPluginInit (see debugger.cpp) under every license tier.

#include "debuggermcp.h"
#include "debuggercontroller.h"
#include "mcp.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

using namespace BinaryNinja;
using namespace BinaryNinja::MCP;
using namespace BinaryNinjaDebugger;

namespace {

struct Err
{
	static constexpr const char* NoController = "no_controller";
	static constexpr const char* TargetNotConnected = "target_not_connected";
	static constexpr const char* TargetConnected = "target_connected";
	static constexpr const char* TargetRunning = "target_running";
	static constexpr const char* ActionFailed = "action_failed";
	static constexpr const char* ReadFailed = "read_failed";
	static constexpr const char* WriteFailed = "write_failed";
	static constexpr const char* UnknownBreakpoint = "unknown_breakpoint";
	static constexpr const char* UnknownRegister = "unknown_register";
	static constexpr const char* UnknownThread = "unknown_thread";
};

using ControllerResult = bn::base::expected<DbgRef<DebuggerController>, ToolResult>;
using VoidResult = bn::base::expected<void, ToolResult>;

std::string Hex(uint64_t value)
{
	return fmt::format("0x{:x}", value);
}

std::string HexBig(const intx::uint512& value)
{
	return "0x" + intx::hex(value);
}

std::string Permissions(bool read, bool write, bool execute)
{
	std::string result = "---";
	result[0] = read ? 'r' : '-';
	result[1] = write ? 'w' : '-';
	result[2] = execute ? 'x' : '-';
	return result;
}

void AddHexMember(rapidjson::Value& obj, const char* name, uint64_t value, rapidjson::Document::AllocatorType& allocator)
{
	std::string hex = Hex(value);
	obj.AddMember(rapidjson::StringRef(name), rapidjson::Value(hex.c_str(), hex.size(), allocator), allocator);
}

void AddStrMember(rapidjson::Value& obj, const char* name, const std::string& value, rapidjson::Document::AllocatorType& allocator)
{
	obj.AddMember(rapidjson::StringRef(name), rapidjson::Value(value.c_str(), value.size(), allocator), allocator);
}

std::string BytesToHex(const uint8_t* data, size_t len)
{
	static const char digits[] = "0123456789abcdef";
	std::string result;
	result.reserve(len * 2);
	for (size_t i = 0; i < len; i++)
	{
		result.push_back(digits[data[i] >> 4]);
		result.push_back(digits[data[i] & 0xf]);
	}
	return result;
}

std::optional<std::vector<uint8_t>> HexToBytes(const std::string& hex)
{
	if (hex.size() % 2 != 0)
		return std::nullopt;

	auto nibble = [](char c) -> int {
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;
		if (c >= 'A' && c <= 'F')
			return c - 'A' + 10;
		return -1;
	};

	std::vector<uint8_t> result;
	result.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2)
	{
		int hi = nibble(hex[i]);
		int lo = nibble(hex[i + 1]);
		if (hi < 0 || lo < 0)
			return std::nullopt;
		result.push_back(uint8_t((hi << 4) | lo));
	}
	return result;
}

const char* BreakpointTypeName(DebugBreakpointType type)
{
	switch (type)
	{
	case HardwareExecuteBreakpoint:
		return "BNHardwareExecuteBreakpoint";
	case HardwareReadBreakpoint:
		return "BNHardwareReadBreakpoint";
	case HardwareWriteBreakpoint:
		return "BNHardwareWriteBreakpoint";
	case HardwareAccessBreakpoint:
		return "BNHardwareAccessBreakpoint";
	case SoftwareBreakpoint:
	default:
		return "BNSoftwareBreakpoint";
	}
}

std::optional<DebugBreakpointType> HardwareKindFromString(const std::string& kind)
{
	if (kind == "execute")
		return HardwareExecuteBreakpoint;
	if (kind == "read")
		return HardwareReadBreakpoint;
	if (kind == "write")
		return HardwareWriteBreakpoint;
	if (kind == "access")
		return HardwareAccessBreakpoint;
	return std::nullopt;
}

uint64_t BreakpointAbsoluteAddress(DebuggerController& dbg, const BreakpointEntry& bp)
{
	// DebuggerController::RelativeAddressToAbsolute is declared but never implemented; the real
	// implementation lives on the state's module tracker (see BNDebuggerGetBreakpoints in ffi.cpp).
	return bp.isRelative ? dbg.GetState()->GetModules()->RelativeAddressToAbsolute(bp.location) : bp.address;
}

ControllerResult RequireController(BinaryViewRef bv)
{
	if (!DebuggerController::ControllerExists(bv))
		return bn::base::unexpected(ToolResult::Error(Err::NoController, "The active binary view has no debug session"));
	return DebuggerController::GetController(bv);
}

ControllerResult RequireConnected(BinaryViewRef bv)
{
	ControllerResult dbg = RequireController(bv);
	if (!dbg)
		return dbg;
	if ((*dbg)->GetConnectionStatus() != DebugAdapterConnectedStatus)
		return bn::base::unexpected(ToolResult::Error(Err::TargetNotConnected, "The target is not connected"));
	return dbg;
}

ControllerResult RequirePaused(BinaryViewRef bv)
{
	ControllerResult dbg = RequireConnected(bv);
	if (!dbg)
		return dbg;
	if ((*dbg)->GetExecutionStatus() == DebugAdapterRunningStatus)
		return bn::base::unexpected(ToolResult::Error(Err::TargetRunning, "The target is running; pause it first"));
	return dbg;
}

bn::base::expected<DebugRegister, ToolResult> RequireExistingRegister(DebuggerController& dbg, const std::string& name)
{
	for (const DebugRegister& reg : dbg.GetAllRegisters())
	{
		if (reg.m_name == name)
			return reg;
	}
	return bn::base::unexpected(ToolResult::Error(Err::UnknownRegister, fmt::format("No register named '{}'", name)));
}

bn::base::expected<DebugThread, ToolResult> FindThread(DebuggerController& dbg, uint64_t tid)
{
	for (const DebugThread& thread : dbg.GetAllThreads())
	{
		if (thread.m_tid == tid)
			return thread;
	}
	return bn::base::unexpected(ToolResult::Error(Err::UnknownThread, fmt::format("No thread with tid {}", tid)));
}

VoidResult RequireMatchingBreakpoint(DebuggerController& dbg, uint64_t address, const std::string& kind, size_t size)
{
	std::optional<DebugBreakpointType> hardwareKind = HardwareKindFromString(kind);
	for (const BreakpointEntry& bp : dbg.GetState()->GetBreakpoints()->GetBreakpointList())
	{
		if (BreakpointAbsoluteAddress(dbg, bp) != address)
			continue;
		if (!hardwareKind)
		{
			if (bp.type == SoftwareBreakpoint)
				return {};
		}
		else if (bp.type == *hardwareKind && bp.size == size)
			return {};
	}
	return bn::base::unexpected(
		ToolResult::Error(Err::UnknownBreakpoint, fmt::format("No {} breakpoint at {}", kind, Hex(address))));
}

// Matches attach_test_runner.py's definition of a lifecycle call that never actually connected.
std::optional<ToolResult> RequireStarted(DebugStopReason reason, const char* verb)
{
	switch (reason)
	{
	case InternalError:
	case ProcessExited:
	case InvalidStatusOrOperation:
	case TimedOut:
		return ToolResult::Error(
			Err::ActionFailed, fmt::format("Failed to {} the target: {}", verb, DebuggerController::GetStopReasonString(reason)));
	default:
		return std::nullopt;
	}
}

void FillStatus(DebuggerController& dbg, rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator)
{
	bool connected = dbg.GetConnectionStatus() == DebugAdapterConnectedStatus;
	bool running = dbg.GetExecutionStatus() == DebugAdapterRunningStatus;
	obj.AddMember("connected", connected, allocator);
	obj.AddMember("running", running, allocator);
	if (connected)
	{
		obj.AddMember("activePid", (uint64_t)dbg.GetActivePID(), allocator);
		if (!running)
			AddHexMember(obj, "ip", dbg.GetCurrentIP(), allocator);
	}
	// A resume action's most common outcome is the target exiting, which disconnects it -- so
	// stopReason/exitCode must not be conditioned on still being connected.
	if (!running)
	{
		AddStrMember(obj, "stopReason", DebuggerController::GetStopReasonString(dbg.StopReason()), allocator);
		obj.AddMember("exitCode", (uint64_t)dbg.GetExitCode(), allocator);
	}
}

ToolResult StatusResult(DebuggerController& dbg)
{
	rapidjson::Document doc;
	doc.SetObject();
	FillStatus(dbg, doc, doc.GetAllocator());
	return ToolResult::Structured(doc);
}

rapidjson::Value BreakpointJson(
	DebuggerController& dbg, const BreakpointEntry& bp, rapidjson::Document::AllocatorType& allocator)
{
	rapidjson::Value obj(rapidjson::kObjectType);
	AddHexMember(obj, "address", BreakpointAbsoluteAddress(dbg, bp), allocator);
	AddStrMember(obj, "module", bp.location.module, allocator);
	AddHexMember(obj, "offset", bp.location.offset, allocator);
	obj.AddMember("enabled", bp.enabled, allocator);
	AddStrMember(obj, "condition", bp.condition, allocator);
	AddStrMember(obj, "type", BreakpointTypeName(bp.type), allocator);
	obj.AddMember("size", (uint64_t)bp.size, allocator);
	return obj;
}

rapidjson::Value RegisterJson(const DebugRegister& reg, rapidjson::Document::AllocatorType& allocator)
{
	rapidjson::Value obj(rapidjson::kObjectType);
	AddStrMember(obj, "name", reg.m_name, allocator);
	AddStrMember(obj, "value", HexBig(reg.m_value), allocator);
	obj.AddMember("width", (uint64_t)reg.m_width, allocator);
	AddStrMember(obj, "hint", reg.m_hint, allocator);
	return obj;
}

rapidjson::Value MetadataToJson(const Ref<Metadata>& md, rapidjson::Document::AllocatorType& allocator)
{
	if (!md)
		return rapidjson::Value(rapidjson::kNullType);
	if (md->IsBoolean())
		return rapidjson::Value(md->GetBoolean());
	if (md->IsUnsignedInteger())
		return rapidjson::Value(md->GetUnsignedInteger());
	if (md->IsSignedInteger())
		return rapidjson::Value(md->GetSignedInteger());
	if (md->IsDouble())
		return rapidjson::Value(md->GetDouble());
	if (md->IsString())
	{
		std::string value = md->GetString();
		return rapidjson::Value(value.c_str(), value.size(), allocator);
	}
	if (md->IsStringList())
	{
		rapidjson::Value arr(rapidjson::kArrayType);
		for (const std::string& item : md->GetStringList())
			arr.PushBack(rapidjson::Value(item.c_str(), item.size(), allocator), allocator);
		return arr;
	}
	return rapidjson::Value(rapidjson::kNullType);
}

// Only the scalar and string-list shapes adapter properties actually use; nullptr for anything else
// (nested objects, mixed-type arrays), which callers report as invalid_params.
Ref<Metadata> JsonToMetadata(const rapidjson::Value& value)
{
	if (value.IsBool())
		return new Metadata(value.GetBool());
	if (value.IsString())
		return new Metadata(std::string(value.GetString(), value.GetStringLength()));
	if (value.IsUint64())
		return new Metadata(value.GetUint64());
	if (value.IsInt64())
		return new Metadata(value.GetInt64());
	if (value.IsDouble())
		return new Metadata(value.GetDouble());
	if (value.IsArray())
	{
		std::vector<std::string> items;
		for (const auto& item : value.GetArray())
		{
			if (!item.IsString())
				return nullptr;
			items.emplace_back(item.GetString(), item.GetStringLength());
		}
		return new Metadata(items);
	}
	return nullptr;
}

std::optional<ToolResult> ApplyAdapterSettings(DebuggerController& dbg, BinaryViewRef bv, const rapidjson::Value& settings)
{
	Ref<Settings> adapterSettings = dbg.GetAdapterSettings();
	if (!adapterSettings)
		return ToolResult::Error(Err::ActionFailed, "The current adapter type has no settings");

	for (const auto& member : settings.GetObject())
	{
		std::string key(member.name.GetString(), member.name.GetStringLength());
		const rapidjson::Value& value = member.value;
		if (!adapterSettings->Contains(key))
			return ToolResult::Error("invalid_params", fmt::format("Unknown adapter setting '{}'", key));

		bool ok;
		if (value.IsBool())
			ok = adapterSettings->Set(key, value.GetBool(), bv, SettingsResourceScope);
		else if (value.IsInt64() || value.IsUint64())
			ok = adapterSettings->Set(key, (int64_t)value.GetInt64(), bv, SettingsResourceScope);
		else if (value.IsDouble())
			ok = adapterSettings->Set(key, value.GetDouble(), bv, SettingsResourceScope);
		else if (value.IsString())
			ok = adapterSettings->Set(key, std::string(value.GetString(), value.GetStringLength()), bv, SettingsResourceScope);
		else if (value.IsArray())
		{
			std::vector<std::string> items;
			for (const auto& item : value.GetArray())
			{
				if (item.IsString())
					items.emplace_back(item.GetString(), item.GetStringLength());
				else
				{
					rapidjson::StringBuffer buf;
					rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
					item.Accept(writer);
					items.emplace_back(buf.GetString(), buf.GetSize());
				}
			}
			ok = adapterSettings->Set(key, items, bv, SettingsResourceScope);
		}
		else
			return ToolResult::Error("invalid_params", fmt::format("Unsupported value type for adapter setting '{}'", key));

		if (!ok)
			return ToolResult::Error(Err::ActionFailed, fmt::format("Failed to set adapter setting '{}'", key));
	}
	return std::nullopt;
}

const std::vector<std::string> BreakpointKindChoices = {"software", "execute", "read", "write", "access"};

Choice BreakpointKindParam()
{
	return Choice("kind", "\"software\" for a normal breakpoint, or a hardware watchpoint kind.", BreakpointKindChoices);
}

Int BreakpointSizeParam()
{
	return Int("size", "Size in bytes for a hardware watchpoint (1, 2, 4, or 8). Ignored for \"software\".")
		.Minimum(1)
		.Maximum(8);
}

// JsonValue's schema argument IS its input schema (it carries no separate description), so the
// human description has to live inside the schema fragment itself.
const std::string SettingsSchema = R"({
	"type": "object",
	"additionalProperties": true,
	"description": "Adapter-specific settings to apply before the operation, as a JSON object (e.g. {\"launch.environmentVariables\": [\"FOO=bar\"]}). See debugger_adapter_settings_list for the current adapter's available keys."
})";

JsonValue SettingsParam()
{
	return JsonValue("settings", SettingsSchema).Optional();
}

// --------------------------------------------------------------------------------------------
// Lifecycle
// --------------------------------------------------------------------------------------------

void RegisterLifecycleTools()
{
	MakeTool({"debugger_launch_and_wait", "Launch Target", "Launch the active binary view's target under the debugger.",
		Scope::BinaryView, IdempotentHint})
		.Param(String("executable_path", "Path of the executable to launch. Defaults to the binary view's input file.").Optional())
		.Param(String("arguments", "Command line arguments to pass to the target.").Optional())
		.Param(String("working_directory", "Working directory for the target.").Optional())
		.Param(SettingsParam())
		.Register([](ToolCall& call, std::optional<std::string> executablePath, std::optional<std::string> arguments,
					  std::optional<std::string> workingDirectory, const rapidjson::Value* settings) {
			BinaryViewRef bv = call.GetBinaryView();
			DbgRef<DebuggerController> dbg = DebuggerController::GetController(bv);
			if (dbg->GetConnectionStatus() == DebugAdapterConnectedStatus)
				return ToolResult::Error(Err::TargetConnected, "The target is already connected");
			if (executablePath)
				dbg->GetState()->SetExecutablePath(*executablePath);
			if (arguments)
				dbg->GetState()->SetCommandLineArguments(*arguments);
			if (workingDirectory)
				dbg->GetState()->SetWorkingDirectory(*workingDirectory);
			if (settings)
			{
				if (auto error = ApplyAdapterSettings(*dbg, bv, *settings))
					return *error;
			}
			if (auto error = RequireStarted(dbg->LaunchAndWait(), "launch"))
				return *error;
			return StatusResult(*dbg);
		});

	MakeTool({"debugger_attach_and_wait", "Attach to Process", "Attach the debugger to a running process."})
		.Param(UInt("pid", "Process ID to attach to. Defaults to the last attached pid.").Optional())
		.Param(SettingsParam())
		.Register([](ToolCall& call, std::optional<uint64_t> pid, const rapidjson::Value* settings) {
			BinaryViewRef bv = call.GetBinaryView();
			DbgRef<DebuggerController> dbg = DebuggerController::GetController(bv);
			if (dbg->GetConnectionStatus() == DebugAdapterConnectedStatus)
				return ToolResult::Error(Err::TargetConnected, "The target is already connected");
			if (pid)
				dbg->GetState()->SetPIDAttach((int32_t)*pid);
			if (settings)
			{
				if (auto error = ApplyAdapterSettings(*dbg, bv, *settings))
					return *error;
			}
			if (auto error = RequireStarted(dbg->AttachAndWait(), "attach to"))
				return *error;
			return StatusResult(*dbg);
		});

	MakeTool({"debugger_connect_and_wait", "Connect to Remote Target", "Connect the debugger to a remote target (e.g. a GDB/LLDB server)."})
		.Param(String("host", "Remote host to connect to. Defaults to the last configured host.").Optional())
		.Param(UInt("port", "Remote port to connect to. Defaults to the last configured port.").Optional())
		.Param(SettingsParam())
		.Register([](ToolCall& call, std::optional<std::string> host, std::optional<uint64_t> port, const rapidjson::Value* settings) {
			BinaryViewRef bv = call.GetBinaryView();
			DbgRef<DebuggerController> dbg = DebuggerController::GetController(bv);
			if (dbg->GetConnectionStatus() == DebugAdapterConnectedStatus)
				return ToolResult::Error(Err::TargetConnected, "The target is already connected");
			if (host)
				dbg->GetState()->SetRemoteHost(*host);
			if (port)
				dbg->GetState()->SetRemotePort((uint32_t)*port);
			if (settings)
			{
				if (auto error = ApplyAdapterSettings(*dbg, bv, *settings))
					return *error;
			}
			if (auto error = RequireStarted(dbg->ConnectAndWait(), "connect to"))
				return *error;
			return StatusResult(*dbg);
		});

	MakeTool({"debugger_detach_and_wait", "Detach", "Detach the debugger from the target, leaving it running.",
		Scope::BinaryView, DestructiveHint})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->DetachAndWait();
			return StatusResult(**dbg);
		});

	MakeTool({"debugger_quit_and_wait", "Quit Target", "Terminate the target and end the debug session.",
		Scope::BinaryView, DestructiveHint})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->QuitAndWait();
			return StatusResult(**dbg);
		});

	MakeTool({"debugger_restart_and_wait", "Restart Target", "Restart the target under the debugger.",
		Scope::BinaryView, DestructiveHint})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->RestartAndWait();
			return StatusResult(**dbg);
		});
}

// --------------------------------------------------------------------------------------------
// Execution control
// --------------------------------------------------------------------------------------------

void RegisterExecutionControlTools()
{
	MakeTool({"debugger_go_and_wait", "Resume Target", "Resume the target until it stops again (a breakpoint, a signal, or exit)."})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->GoAndWait();
			return StatusResult(**dbg);
		});

	MakeTool({"debugger_step_into_and_wait", "Step Into", "Single-step the target, stepping into any call."})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->StepIntoAndWait();
			return StatusResult(**dbg);
		});

	MakeTool({"debugger_step_over_and_wait", "Step Over", "Single-step the target, stepping over any call."})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->StepOverAndWait();
			return StatusResult(**dbg);
		});

	MakeTool({"debugger_step_return_and_wait", "Step Return", "Run the target until the current function returns."})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->StepReturnAndWait();
			return StatusResult(**dbg);
		});

	MakeTool({"debugger_run_to_and_wait", "Run To Address", "Resume the target until it reaches the given address."})
		.Param(Address("address", "Address to run to."))
		.Register([](ToolCall& call, uint64_t address) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->RunToAndWait({address});
			return StatusResult(**dbg);
		});

	MakeTool({"debugger_pause_and_wait", "Pause Target", "Pause the running target.", Scope::BinaryView, IdempotentHint})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			if ((*dbg)->GetExecutionStatus() != DebugAdapterRunningStatus)
				return ToolResult::Error(Err::TargetNotConnected, "The target is not running");
			(*dbg)->PauseAndWait();
			return StatusResult(**dbg);
		});
}

// --------------------------------------------------------------------------------------------
// Inspection
// --------------------------------------------------------------------------------------------

void RegisterInspectionTools()
{
	MakeTool({"debugger_status", "Debugger Status", "Report whether the active binary view has a debug session and its current state.",
		Scope::BinaryView, ReadOnlyHint})
		.Register([](ToolCall& call) {
			BinaryViewRef bv = call.GetBinaryView();
			if (!DebuggerController::ControllerExists(bv))
			{
				rapidjson::Document doc;
				doc.SetObject();
				doc.AddMember("connected", false, doc.GetAllocator());
				doc.AddMember("running", false, doc.GetAllocator());
				return ToolResult::Structured(doc);
			}
			DbgRef<DebuggerController> dbg = DebuggerController::GetController(bv);
			return StatusResult(*dbg);
		});

	MakeTool({"debugger_adapter_settings_list", "List Adapter Settings",
		"List the current debug adapter's own settings (e.g. launch/attach/connect fields, or backend-specific "
		"options like a TTD trace path), available to pass to the settings parameter of debugger_launch_and_wait, "
		"debugger_attach_and_wait, or debugger_connect_and_wait.",
		Scope::BinaryView, ReadOnlyHint})
		.Register([](ToolCall& call) {
			DbgRef<DebuggerController> dbg = DebuggerController::GetController(call.GetBinaryView());
			Ref<Settings> adapterSettings = dbg->GetAdapterSettings();
			rapidjson::Document doc;
			doc.SetObject();
			rapidjson::Value settingsArr(rapidjson::kArrayType);
			if (adapterSettings)
			{
				for (const std::string& key : adapterSettings->Keys())
				{
					rapidjson::Value entry(rapidjson::kObjectType);
					AddStrMember(entry, "key", key, doc.GetAllocator());
					AddStrMember(entry, "title", adapterSettings->QueryProperty<std::string>(key, "title"), doc.GetAllocator());
					AddStrMember(entry, "type", adapterSettings->QueryProperty<std::string>(key, "type"), doc.GetAllocator());
					AddStrMember(
						entry, "description", adapterSettings->QueryProperty<std::string>(key, "description"), doc.GetAllocator());
					settingsArr.PushBack(entry, doc.GetAllocator());
				}
			}
			doc.AddMember("settings", settingsArr, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_registers_get", "Get Registers", "Read one or all registers of the target.", Scope::BinaryView, ReadOnlyHint})
		.Param(String("name", "Name of a single register to read. Takes priority over group.").Optional())
		.Param(Choice("group",
			"With no name, \"most\" (the default) returns general-purpose/pointer-sized registers (e.g. rax-r15, "
			"rip, rsp on x86_64); \"all\" additionally includes wide vector/FPU registers (e.g. xmm/ymm/zmm, NEON). "
			"Use name= to read one such register directly without requesting the whole \"all\" set.",
			{"most", "all"})
				  .Default("most"))
		.Register([](ToolCall& call, std::optional<std::string> name, std::string group) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			rapidjson::Document doc;
			doc.SetObject();
			rapidjson::Value regsArr(rapidjson::kArrayType);

			if (name)
			{
				auto reg = RequireExistingRegister(**dbg, *name);
				if (!reg)
					return reg.error();
				regsArr.PushBack(RegisterJson(*reg, doc.GetAllocator()), doc.GetAllocator());
			}
			else
			{
				std::vector<DebugRegister> regs = (*dbg)->GetAllRegisters();
				size_t pointerBits = 64;
				ArchitectureRef arch = (*dbg)->GetRemoteArchitecture();
				if (arch)
					pointerBits = arch->GetAddressSize() * 8;
				for (const DebugRegister& reg : regs)
				{
					if (group == "most" && reg.m_width > pointerBits)
						continue;
					regsArr.PushBack(RegisterJson(reg, doc.GetAllocator()), doc.GetAllocator());
				}
			}
			doc.AddMember("registers", regsArr, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_register_set", "Set Register", "Write a register of the target.", Scope::BinaryView, IdempotentHint})
		.Param(String("name", "Name of the register to write."))
		.Param(IntegerExpression("value", "New value for the register."))
		.Register([](ToolCall& call, std::string name, uint64_t value) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			auto reg = RequireExistingRegister(**dbg, name);
			if (!reg)
				return reg.error();
			if (!(*dbg)->SetRegisterValue(name, intx::uint512(value)))
				return ToolResult::Error(Err::ActionFailed, fmt::format("Failed to set register '{}'", name));

			rapidjson::Document doc;
			doc.SetObject();
			AddStrMember(doc, "name", name, doc.GetAllocator());
			AddStrMember(doc, "value", HexBig((*dbg)->GetRegisterValue(name)), doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_read_memory", "Read Memory", "Read memory from the target.", Scope::BinaryView, ReadOnlyHint})
		.Param(Address("address", "Address to read from."))
		.Param(Int("size", "Number of bytes to read (up to 64 KiB).").Minimum(1).Maximum(0x10000).Default(0x10))
		.Param(Choice("encoding",
			"\"hex\" (default; easier to pattern-match pointers/strings by eye) or \"base64\" (more compact for "
			"larger reads).",
			{"hex", "base64"})
				  .Default("hex"))
		.Register([](ToolCall& call, uint64_t address, int64_t size, std::string encoding) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			DataBuffer buffer = (*dbg)->ReadMemory(address, (size_t)size);
			if (buffer.GetLength() == 0)
				return ToolResult::Error(Err::ReadFailed, fmt::format("Failed to read memory at {}", Hex(address)));

			std::string data = encoding == "hex"
				? BytesToHex((const uint8_t*)buffer.GetData(), buffer.GetLength())
				: buffer.ToBase64();

			rapidjson::Document doc;
			doc.SetObject();
			AddHexMember(doc, "address", address, doc.GetAllocator());
			doc.AddMember("size", (uint64_t)buffer.GetLength(), doc.GetAllocator());
			AddStrMember(doc, "data", data, doc.GetAllocator());
			AddStrMember(doc, "encoding", encoding, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_write_memory", "Write Memory", "Write memory of the target.", Scope::BinaryView, DestructiveHint})
		.Param(Address("address", "Address to write to."))
		.Param(String("data", "Bytes to write, as a hex string (e.g. \"deadbeef\").").NonEmpty())
		.Register([](ToolCall& call, uint64_t address, std::string data) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			std::optional<std::vector<uint8_t>> raw = HexToBytes(data);
			if (!raw)
				return ToolResult::Error("invalid_params", "'data' must be a hex string");
			DataBuffer buffer(raw->data(), raw->size());
			if (!(*dbg)->WriteMemory(address, buffer))
				return ToolResult::Error(Err::WriteFailed, fmt::format("Failed to write memory at {}", Hex(address)));

			rapidjson::Document doc;
			doc.SetObject();
			AddHexMember(doc, "address", address, doc.GetAllocator());
			doc.AddMember("size", (uint64_t)raw->size(), doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_threads_list", "List Threads", "List the threads of the target.", Scope::BinaryView, ReadOnlyHint})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			rapidjson::Document doc;
			doc.SetObject();
			rapidjson::Value threadsArr(rapidjson::kArrayType);
			for (const DebugThread& thread : (*dbg)->GetAllThreads())
			{
				rapidjson::Value entry(rapidjson::kObjectType);
				entry.AddMember("tid", (uint64_t)thread.m_tid, doc.GetAllocator());
				AddHexMember(entry, "ip", thread.m_rip, doc.GetAllocator());
				threadsArr.PushBack(entry, doc.GetAllocator());
			}
			doc.AddMember("threads", threadsArr, doc.GetAllocator());
			doc.AddMember("activeTid", (uint64_t)(*dbg)->GetActiveThread().m_tid, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_thread_select", "Select Thread", "Select the active thread of the target.", Scope::BinaryView, IdempotentHint})
		.Param(UInt("tid", "Thread ID to make active."))
		.Register([](ToolCall& call, uint64_t tid) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			auto thread = FindThread(**dbg, tid);
			if (!thread)
				return thread.error();
			(*dbg)->SetActiveThread(*thread);

			rapidjson::Document doc;
			doc.SetObject();
			doc.AddMember("activeTid", (uint64_t)(*dbg)->GetActiveThread().m_tid, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_backtrace", "Get Backtrace", "Get the stack trace of a thread.", Scope::BinaryView, ReadOnlyHint})
		.Param(UInt("tid", "Thread ID to trace. Defaults to the active thread.").Optional())
		.Register([](ToolCall& call, std::optional<uint64_t> tid) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			uint64_t threadId;
			if (tid)
			{
				auto thread = FindThread(**dbg, *tid);
				if (!thread)
					return thread.error();
				threadId = *tid;
			}
			else
				threadId = (*dbg)->GetActiveThread().m_tid;

			rapidjson::Document doc;
			doc.SetObject();
			doc.AddMember("tid", threadId, doc.GetAllocator());
			rapidjson::Value framesArr(rapidjson::kArrayType);
			for (const DebugFrame& frame : (*dbg)->GetFramesOfThread(threadId))
			{
				rapidjson::Value entry(rapidjson::kObjectType);
				entry.AddMember("index", (uint64_t)frame.m_index, doc.GetAllocator());
				AddHexMember(entry, "pc", frame.m_pc, doc.GetAllocator());
				AddHexMember(entry, "sp", frame.m_sp, doc.GetAllocator());
				AddHexMember(entry, "fp", frame.m_fp, doc.GetAllocator());
				AddStrMember(entry, "module", frame.m_module, doc.GetAllocator());
				AddStrMember(entry, "functionName", frame.m_functionName, doc.GetAllocator());
				AddHexMember(entry, "functionStart", frame.m_functionStart, doc.GetAllocator());
				framesArr.PushBack(entry, doc.GetAllocator());
			}
			doc.AddMember("frames", framesArr, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_modules_list", "List Modules", "List the modules loaded in the target.", Scope::BinaryView, ReadOnlyHint})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			rapidjson::Document doc;
			doc.SetObject();
			rapidjson::Value modulesArr(rapidjson::kArrayType);
			for (const DebugModule& module : (*dbg)->GetAllModules())
			{
				rapidjson::Value entry(rapidjson::kObjectType);
				AddStrMember(entry, "name", module.m_name, doc.GetAllocator());
				AddStrMember(entry, "shortName", module.m_short_name, doc.GetAllocator());
				AddHexMember(entry, "address", module.m_address, doc.GetAllocator());
				entry.AddMember("size", (uint64_t)module.m_size, doc.GetAllocator());
				modulesArr.PushBack(entry, doc.GetAllocator());
			}
			doc.AddMember("modules", modulesArr, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_memory_map", "Get Memory Map", "List the mapped memory regions of the target.", Scope::BinaryView, ReadOnlyHint})
		.Register([](ToolCall& call) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			rapidjson::Document doc;
			doc.SetObject();
			rapidjson::Value regionsArr(rapidjson::kArrayType);
			for (const DebugMemoryRegion& region : (*dbg)->GetMemoryMap())
			{
				rapidjson::Value entry(rapidjson::kObjectType);
				AddHexMember(entry, "start", region.m_start, doc.GetAllocator());
				entry.AddMember("size", (uint64_t)region.m_size, doc.GetAllocator());
				AddStrMember(entry, "name", region.m_name, doc.GetAllocator());
				AddStrMember(entry, "permissions", Permissions(region.m_read, region.m_write, region.m_execute), doc.GetAllocator());
				entry.AddMember("shared", region.m_shared, doc.GetAllocator());
				regionsArr.PushBack(entry, doc.GetAllocator());
			}
			doc.AddMember("regions", regionsArr, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_processes_list", "List Processes", "List processes available to attach to.", Scope::BinaryView, ReadOnlyHint})
		.Param(String("query", "Case-insensitive substring filter over process names.").Optional())
		.Register([](ToolCall& call, std::optional<std::string> query) {
			DbgRef<DebuggerController> dbg = DebuggerController::GetController(call.GetBinaryView());
			std::string needle;
			if (query)
			{
				needle = *query;
				std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) { return std::tolower(c); });
			}

			rapidjson::Document doc;
			doc.SetObject();
			rapidjson::Value processesArr(rapidjson::kArrayType);
			for (const DebugProcess& process : dbg->GetProcessList())
			{
				if (query)
				{
					std::string name = process.m_processName;
					std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });
					if (name.find(needle) == std::string::npos)
						continue;
				}
				rapidjson::Value entry(rapidjson::kObjectType);
				entry.AddMember("pid", (uint64_t)process.m_pid, doc.GetAllocator());
				AddStrMember(entry, "name", process.m_processName, doc.GetAllocator());
				AddStrMember(entry, "commandLine", process.m_commandLine, doc.GetAllocator());
				processesArr.PushBack(entry, doc.GetAllocator());
			}
			doc.AddMember("processes", processesArr, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_breakpoints_list", "List Breakpoints", "List the configured breakpoints.", Scope::BinaryView, ReadOnlyHint})
		.Register([](ToolCall& call) {
			BinaryViewRef bv = call.GetBinaryView();
			rapidjson::Document doc;
			doc.SetObject();
			rapidjson::Value breakpointsArr(rapidjson::kArrayType);
			if (DebuggerController::ControllerExists(bv))
			{
				DbgRef<DebuggerController> dbg = DebuggerController::GetController(bv);
				for (const BreakpointEntry& bp : dbg->GetState()->GetBreakpoints()->GetBreakpointList())
					breakpointsArr.PushBack(BreakpointJson(*dbg, bp, doc.GetAllocator()), doc.GetAllocator());
			}
			doc.AddMember("breakpoints", breakpointsArr, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});
}

// --------------------------------------------------------------------------------------------
// Breakpoints
// --------------------------------------------------------------------------------------------

void RegisterBreakpointTools()
{
	MakeTool({"debugger_breakpoint_set", "Set Breakpoint",
		"Set a breakpoint at an address.\n\nThe target must have been launched, attached to, or connected to at "
		"least once; a breakpoint set before that silently fails to register."})
		.Param(Address("address", "Address to set the breakpoint at."))
		.Param(BreakpointKindParam().Default("software"))
		.Param(BreakpointSizeParam().Default(1))
		.Register([](ToolCall& call, uint64_t address, std::string kind, int64_t size) {
			DbgRef<DebuggerController> dbg = DebuggerController::GetController(call.GetBinaryView());
			std::optional<DebugBreakpointType> hardwareKind = HardwareKindFromString(kind);
			// Neither AddBreakpoint (no return) nor AddHardwareBreakpoint (returns true even on failure)
			// reliably reports whether a breakpoint actually registered, so success is verified independently.
			if (!hardwareKind)
				dbg->AddBreakpoint(address);
			else
				dbg->AddHardwareBreakpoint(address, *hardwareKind, (size_t)size);
			if (!dbg->GetState()->GetBreakpoints()->ContainsAbsolute(address))
				return ToolResult::Error(Err::ActionFailed,
					fmt::format("Failed to set a {} breakpoint at {}; launch, attach, or connect at least once first",
						kind, Hex(address)));

			rapidjson::Document doc;
			doc.SetObject();
			AddHexMember(doc, "address", address, doc.GetAllocator());
			AddStrMember(doc, "kind", kind, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_breakpoint_delete", "Delete Breakpoint", "Delete a breakpoint at an address.",
		Scope::BinaryView, IdempotentHint})
		.Param(Address("address", "Address of the breakpoint to delete."))
		.Param(BreakpointKindParam().Default("software"))
		.Param(BreakpointSizeParam().Default(1))
		.Register([](ToolCall& call, uint64_t address, std::string kind, int64_t size) {
			ControllerResult dbg = RequireController(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			std::optional<DebugBreakpointType> hardwareKind = HardwareKindFromString(kind);
			if (!hardwareKind)
			{
				if (!(*dbg)->GetState()->GetBreakpoints()->ContainsAbsolute(address))
					return ToolResult::Error(Err::UnknownBreakpoint, fmt::format("No breakpoint at {}", Hex(address)));
				(*dbg)->DeleteBreakpoint(address);
			}
			else if (!(*dbg)->RemoveHardwareBreakpoint(address, *hardwareKind, (size_t)size))
				return ToolResult::Error(Err::UnknownBreakpoint, fmt::format("No {} breakpoint at {}", kind, Hex(address)));

			rapidjson::Document doc;
			doc.SetObject();
			AddHexMember(doc, "address", address, doc.GetAllocator());
			AddStrMember(doc, "kind", kind, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_breakpoint_set_enabled", "Enable/Disable Breakpoint",
		"Enable or disable a breakpoint without deleting it.", Scope::BinaryView, IdempotentHint})
		.Param(Address("address", "Address of the breakpoint."))
		.Param(BreakpointKindParam().Default("software"))
		.Param(BreakpointSizeParam().Default(1))
		.Param(Bool("enabled", "True to enable the breakpoint, False to disable it.").Default(true))
		.Register([](ToolCall& call, uint64_t address, std::string kind, int64_t size, bool enabled) {
			ControllerResult dbg = RequireController(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			if (auto error = RequireMatchingBreakpoint(**dbg, address, kind, (size_t)size); !error)
				return error.error();

			std::optional<DebugBreakpointType> hardwareKind = HardwareKindFromString(kind);
			if (!hardwareKind)
			{
				if (enabled)
					(*dbg)->EnableBreakpoint(address);
				else
					(*dbg)->DisableBreakpoint(address);
			}
			else if (enabled)
				(*dbg)->EnableHardwareBreakpoint(address, *hardwareKind, (size_t)size);
			else
				(*dbg)->DisableHardwareBreakpoint(address, *hardwareKind, (size_t)size);

			rapidjson::Document doc;
			doc.SetObject();
			AddHexMember(doc, "address", address, doc.GetAllocator());
			AddStrMember(doc, "kind", kind, doc.GetAllocator());
			doc.AddMember("enabled", enabled, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_breakpoint_condition_set", "Set Breakpoint Condition",
		"Set or clear a breakpoint's condition expression.", Scope::BinaryView, IdempotentHint})
		.Param(Address("address", "Address of the breakpoint."))
		.Param(BreakpointKindParam().Default("software"))
		.Param(BreakpointSizeParam().Default(1))
		.Param(String("condition",
			"Expression evaluated when the breakpoint is hit; the debugger only stops if it is non-zero. Pass an "
			"empty string to clear the condition.")
				  .Default(""))
		.Register([](ToolCall& call, uint64_t address, std::string kind, int64_t size, std::string condition) {
			ControllerResult dbg = RequireController(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			if (auto error = RequireMatchingBreakpoint(**dbg, address, kind, (size_t)size); !error)
				return error.error();
			if (!(*dbg)->SetBreakpointCondition(address, condition))
				return ToolResult::Error(Err::ActionFailed, fmt::format("Failed to set the condition at {}", Hex(address)));

			rapidjson::Document doc;
			doc.SetObject();
			AddHexMember(doc, "address", address, doc.GetAllocator());
			AddStrMember(doc, "kind", kind, doc.GetAllocator());
			AddStrMember(doc, "condition", condition, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});
}

// --------------------------------------------------------------------------------------------
// Misc
// --------------------------------------------------------------------------------------------

void RegisterMiscTools()
{
	MakeTool({"debugger_write_stdin", "Write to Stdin", "Write to the target's standard input."})
		.Param(String("data", "Text to write."))
		.Register([](ToolCall& call, std::string data) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();
			(*dbg)->WriteStdIn(data);

			rapidjson::Document doc;
			doc.SetObject();
			doc.AddMember("written", (uint64_t)data.size(), doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_execute_backend_command", "Execute Backend Command",
		"Execute a backend-specific debugger command (e.g. a GDB/LLDB command) and return its output."})
		.Param(String("command", "Command text to execute.").NonEmpty())
		.Register([](ToolCall& call, std::string command) {
			ControllerResult dbg = RequirePaused(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			rapidjson::Document doc;
			doc.SetObject();
			AddStrMember(doc, "output", (*dbg)->InvokeBackendCommand(command), doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_property_get", "Get Adapter Property", "Read an adapter-specific property of the target.",
		Scope::BinaryView, ReadOnlyHint})
		.Param(String("name", "Name of the property to read.").NonEmpty())
		.Register([](ToolCall& call, std::string name) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			rapidjson::Document doc;
			doc.SetObject();
			AddStrMember(doc, "name", name, doc.GetAllocator());
			Ref<Metadata> value = (*dbg)->GetAdapterProperty(name);
			doc.AddMember("value", MetadataToJson(value, doc.GetAllocator()), doc.GetAllocator());
			return ToolResult::Structured(doc);
		});

	MakeTool({"debugger_property_set", "Set Adapter Property", "Set an adapter-specific property of the target."})
		.Param(String("name", "Name of the property to set.").NonEmpty())
		.Param(JsonValue("value", "{}"))
		.Register([](ToolCall& call, std::string name, const rapidjson::Value* value) {
			ControllerResult dbg = RequireConnected(call.GetBinaryView());
			if (!dbg)
				return dbg.error();

			Ref<Metadata> metadata = JsonToMetadata(*value);
			if (!metadata)
				return ToolResult::Error("invalid_params", "Unsupported value type for adapter property");
			if (!(*dbg)->SetAdapterProperty(name, metadata))
				return ToolResult::Error(Err::ActionFailed, fmt::format("Failed to set property '{}'", name));

			rapidjson::Document doc;
			doc.SetObject();
			AddStrMember(doc, "name", name, doc.GetAllocator());
			rapidjson::Value valueCopy;
			valueCopy.CopyFrom(*value, doc.GetAllocator());
			doc.AddMember("value", valueCopy, doc.GetAllocator());
			return ToolResult::Structured(doc);
		});
}

}  // namespace

namespace BinaryNinjaDebugger {
void RegisterDebuggerMcpTools()
{
	RegisterLifecycleTools();
	RegisterExecutionControlTools();
	RegisterInspectionTools();
	RegisterBreakpointTools();
	RegisterMiscTools();
}
};  // namespace BinaryNinjaDebugger
