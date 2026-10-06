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
limitations under the License.
*/

#include "windowsnativeadapter.h"
#include <delayimp.h>
#include <filesystem>

// dbghelp.dll is delay-loaded. We use a notification hook to try loading it from the
// configured DbgEng path first, falling back to the system version if that fails.
// This avoids conflicts with the DbgEng adapter which needs specific versions of these DLLs.

static std::string GetDbgHelpPathFromSettings()
{
	// Try to get the path from settings - same logic as DbgEngAdapter::GetDbgEngPath
	auto settings = BinaryNinja::Settings::Instance();
	std::string path = settings->Get<std::string>("debugger.x64dbgEngPath");

	std::error_code ec;
	if (!path.empty())
	{
		auto dbgHelpPath = std::filesystem::path(path) / "dbghelp.dll";
		if (std::filesystem::exists(dbgHelpPath, ec))
			return dbgHelpPath.string();
	}

	// Check the bundled dbgeng folder
	std::string pluginRoot;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		pluginRoot = BinaryNinja::GetUserPluginDirectory();
	else
		pluginRoot = BinaryNinja::GetBundledPluginDirectory();

	auto bundledPath = std::filesystem::path(pluginRoot) / "dbgeng" / "amd64" / "dbghelp.dll";
	if (std::filesystem::exists(bundledPath, ec))
		return bundledPath.string();

	return "";
}

static FARPROC WINAPI DelayLoadNotifyHook(unsigned dliNotify, PDelayLoadInfo pdli)
{
	if (dliNotify == dliNotePreLoadLibrary)
	{
		// Check if this is dbghelp.dll being loaded
		if (pdli->szDll && _stricmp(pdli->szDll, "dbghelp.dll") == 0)
		{
			// Try to load from our preferred path first
			std::string customPath = GetDbgHelpPathFromSettings();
			if (!customPath.empty())
			{
				HMODULE hModule = LoadLibraryA(customPath.c_str());
				if (hModule)
				{
					BinaryNinja::LogDebug("Delay-loaded dbghelp.dll from: %s", customPath.c_str());
					return reinterpret_cast<FARPROC>(hModule);
				}
				BinaryNinja::LogDebug("Failed to load dbghelp.dll from %s, falling back to system", customPath.c_str());
			}
			// Return NULL to let the system load it from the default search path
		}
	}
	return NULL;
}

// Register our delay load hook
const PfnDliHook __pfnDliNotifyHook2 = DelayLoadNotifyHook;

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

namespace {
	DebugStopReason FromEngine(WindowsDebugging::DebugStopReason value)
	{
		switch (value)
		{
		case WindowsDebugging::UnknownReason: return UnknownReason;
		case WindowsDebugging::InitialBreakpoint: return InitialBreakpoint;
		case WindowsDebugging::ProcessExited: return ProcessExited;
		case WindowsDebugging::AccessViolation: return AccessViolation;
		case WindowsDebugging::SingleStep: return SingleStep;
		case WindowsDebugging::Calculation: return Calculation;
		case WindowsDebugging::Breakpoint: return Breakpoint;
		case WindowsDebugging::IllegalInstruction: return IllegalInstruction;
		default: return UnknownReason;
		}
	}

	DebugBreakpointType FromEngine(WindowsDebugging::DebugBreakpointType value)
	{
		switch (value)
		{
		case WindowsDebugging::SoftwareBreakpoint: return SoftwareBreakpoint;
		case WindowsDebugging::HardwareExecuteBreakpoint: return HardwareExecuteBreakpoint;
		case WindowsDebugging::HardwareReadBreakpoint: return HardwareReadBreakpoint;
		case WindowsDebugging::HardwareWriteBreakpoint: return HardwareWriteBreakpoint;
		case WindowsDebugging::HardwareAccessBreakpoint: return HardwareAccessBreakpoint;
		default: return SoftwareBreakpoint;
		}
	}

	WindowsDebugging::DebugBreakpointType ToEngine(DebugBreakpointType value)
	{
		switch (value)
		{
		case SoftwareBreakpoint: return WindowsDebugging::SoftwareBreakpoint;
		case HardwareExecuteBreakpoint: return WindowsDebugging::HardwareExecuteBreakpoint;
		case HardwareReadBreakpoint: return WindowsDebugging::HardwareReadBreakpoint;
		case HardwareWriteBreakpoint: return WindowsDebugging::HardwareWriteBreakpoint;
		case HardwareAccessBreakpoint: return WindowsDebugging::HardwareAccessBreakpoint;
		default: return WindowsDebugging::SoftwareBreakpoint;
		}
	}

	DebugProcess FromEngine(const WindowsDebugging::DebugProcess& value)
	{
		DebugProcess result;
		result.m_pid = value.m_pid;
		result.m_processName = value.m_processName;
		result.m_commandLine = value.m_commandLine;
		return result;
	}

	DebugThread FromEngine(const WindowsDebugging::DebugThread& value)
	{
		DebugThread result;
		result.m_tid = value.m_tid;
		result.m_rip = value.m_rip;
		result.m_isFrozen = value.m_isFrozen;
		return result;
	}

	DebugBreakpoint FromEngine(const WindowsDebugging::DebugBreakpoint& value)
	{
		DebugBreakpoint result;
		result.m_address = value.m_address;
		result.m_id = value.m_id;
		result.m_is_active = value.m_is_active;
		result.m_type = FromEngine(value.m_type);
		return result;
	}

	DebugRegister FromEngine(const WindowsDebugging::DebugRegister& value)
	{
		DebugRegister result;
		result.m_name = value.m_name;
		result.m_value = value.m_value;
		result.m_width = value.m_width;
		result.m_registerIndex = value.m_registerIndex;
		return result;
	}

	DebugModule FromEngine(const WindowsDebugging::DebugModule& value)
	{
		DebugModule result;
		result.m_name = value.m_name;
		result.m_short_name = value.m_short_name;
		result.m_address = value.m_address;
		result.m_size = value.m_size;
		result.m_loaded = value.m_loaded;
		result.m_caseInsensitive = value.m_caseInsensitive;
		return result;
	}

	DebugMemoryRegion FromEngine(const WindowsDebugging::DebugMemoryRegion& value)
	{
		DebugMemoryRegion result;
		result.m_start = value.m_start;
		result.m_size = value.m_size;
		result.m_name = value.m_name;
		result.m_read = value.m_read;
		result.m_write = value.m_write;
		result.m_execute = value.m_execute;
		result.m_shared = value.m_shared;
		return result;
	}

	DebugFrame FromEngine(const WindowsDebugging::DebugFrame& value)
	{
		DebugFrame result;
		result.m_index = value.m_index;
		result.m_pc = value.m_pc;
		result.m_sp = value.m_sp;
		result.m_fp = value.m_fp;
		result.m_functionName = value.m_functionName;
		result.m_functionStart = value.m_functionStart;
		result.m_module = value.m_module;
		return result;
	}

	DebugSymbol FromEngine(const WindowsDebugging::DebugSymbol& value)
	{
		DebugSymbol result;
		result.m_name = value.m_name;
		result.m_fullName = value.m_fullName;
		result.m_rawName = value.m_rawName;
		result.m_address = value.m_address;
		result.m_size = value.m_size;
		result.m_isFunction = value.m_isFunction;
		return result;
	}

	template<typename T> auto FromEngine(const std::vector<T>& values)
	{
		std::vector<decltype(FromEngine(T{}))> result;
		result.reserve(values.size());
		for (const auto& value : values) result.push_back(FromEngine(value));
		return result;
	}

	WindowsDebugging::ModuleNameAndOffset ToEngine(const ModuleNameAndOffset& value)
	{ return {value.module, value.offset}; }
}

WindowsNativeAdapter::WindowsNativeAdapter(BinaryView* data) : DebugAdapter(data)
{
	GenerateDefaultAdapterSettings(data);
	m_engine.SetBreakpointResetPolicy(WindowsDebugging::BreakpointResetPolicy::Preserve);
	m_engine.SetLogCallback([](bool error, const std::string& message) {
		if (error) LogError("%s", message.c_str());
		else LogWarn("%s", message.c_str());
	});
	m_engine.SetEventCallback([this](const WindowsDebugging::EngineEvent& source) {
		DebuggerEvent event;
		switch (source.type)
		{
		case WindowsDebugging::EngineEventType::LaunchFailure:
			event.type = LaunchFailureEventType;
			event.data.errorData.error = source.error;
			event.data.errorData.shortError = source.shortError;
			break;
		case WindowsDebugging::EngineEventType::TargetExited:
			event.type = TargetExitedEventType;
			event.data.exitData.exitCode = source.exitCode;
			break;
		case WindowsDebugging::EngineEventType::TargetStopped:
			event.type = AdapterStoppedEventType;
			event.data.targetStoppedData.reason = FromEngine(source.stopReason);
			event.data.targetStoppedData.lastActiveThread = source.lastActiveThread;
			event.data.targetStoppedData.exitCode = 0;
			event.data.targetStoppedData.data = nullptr;
			break;
		case WindowsDebugging::EngineEventType::Resumed:
			event.type = ResumeEventType;
			break;
		case WindowsDebugging::EngineEventType::StepIntoComplete:
			event.type = StepIntoEventType;
			break;
		}
		PostDebuggerEvent(event);
	});
	ConfigureEngine();
}

WindowsNativeAdapter::~WindowsNativeAdapter() = default;

void WindowsNativeAdapter::ConfigureEngine()
{
	BNSettingsScope scope = SettingsResourceScope;
	m_engine.SetVerboseLogging(GetAdapterSettings()->Get<bool>("common.verboseLogging", GetData(), &scope));
	auto settings = Settings::Instance();
	m_engine.SetStopAtSystemEntryPoint(settings->Get<bool>("debugger.stopAtSystemEntryPoint"));
	m_engine.SetEntryPointOffset(settings->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction
		? std::optional<uint64_t>(m_entryPoint - m_start) : std::nullopt);
	m_engine.SetCaseInsensitiveModuleNames(settings->Get<bool>("debugger.caseInsensitiveModuleName"));
}

bool WindowsNativeAdapter::Init() { return true; }

bool WindowsNativeAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return ExecuteWithArgs(path, "", "", configs);
}

bool WindowsNativeAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	ConfigureEngine();
	BNSettingsScope scope = SettingsResourceScope;
	auto settings = GetAdapterSettings();
	auto data = GetData();
	auto executable = settings->Get<std::string>("launch.executablePath", data, &scope);
	scope = SettingsResourceScope;
	auto directory = settings->Get<std::string>("launch.workingDirectory", data, &scope);
	scope = SettingsResourceScope;
	auto arguments = settings->Get<std::string>("launch.commandLineArguments", data, &scope);
	return m_engine.ExecuteWithArgs(executable, arguments, directory);
}

bool WindowsNativeAdapter::Attach(std::uint32_t pid)
{
	ConfigureEngine();
	return m_engine.Attach(pid);
}

bool WindowsNativeAdapter::Connect(const std::string&, std::uint32_t) { return false; }
std::string WindowsNativeAdapter::InvokeBackendCommand(const std::string&) { return ""; }

bool WindowsNativeAdapter::Detach()
{
	return m_engine.Detach();
}

bool WindowsNativeAdapter::Quit()
{
	return m_engine.Quit();
}

std::vector<DebugProcess> WindowsNativeAdapter::GetProcessList()
{
	return FromEngine(m_engine.GetProcessList());
}

std::vector<DebugThread> WindowsNativeAdapter::GetThreadList()
{
	return FromEngine(m_engine.GetThreadList());
}

DebugThread WindowsNativeAdapter::GetActiveThread() const
{
	return FromEngine(m_engine.GetActiveThread());
}

std::uint32_t WindowsNativeAdapter::GetActiveThreadId() const
{
	return m_engine.GetActiveThreadId();
}

bool WindowsNativeAdapter::SetActiveThread(const DebugThread& thread)
{
	return m_engine.SetActiveThread(WindowsDebugging::DebugThread(thread.m_tid, thread.m_rip));
}

bool WindowsNativeAdapter::SetActiveThreadId(std::uint32_t tid)
{
	return m_engine.SetActiveThreadId(tid);
}

DebugBreakpoint WindowsNativeAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags)
{
	return FromEngine(m_engine.AddBreakpoint(address, breakpoint_flags));
}

DebugBreakpoint WindowsNativeAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	return FromEngine(m_engine.AddBreakpoint(ToEngine(address), breakpoint_type));
}

bool WindowsNativeAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	return m_engine.RemoveBreakpoint(WindowsDebugging::DebugBreakpoint(breakpoint.m_address, breakpoint.m_id, breakpoint.m_is_active, ToEngine(breakpoint.m_type)));
}

bool WindowsNativeAdapter::RemoveBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	return m_engine.RemoveBreakpoint(ToEngine(breakpoint));
}

std::vector<DebugBreakpoint> WindowsNativeAdapter::GetBreakpointList() const
{
	return FromEngine(m_engine.GetBreakpointList());
}

bool WindowsNativeAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	return m_engine.AddHardwareBreakpoint(address, ToEngine(type), size);
}

bool WindowsNativeAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	return m_engine.RemoveHardwareBreakpoint(address, ToEngine(type), size);
}

bool WindowsNativeAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	return m_engine.AddHardwareBreakpoint(ToEngine(location), ToEngine(type), size);
}

bool WindowsNativeAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	return m_engine.RemoveHardwareBreakpoint(ToEngine(location), ToEngine(type), size);
}

std::unordered_map<std::string, DebugRegister> WindowsNativeAdapter::ReadAllRegisters()
{
	std::unordered_map<std::string, DebugRegister> result;
	for (const auto& [name, value] : m_engine.ReadAllRegisters()) result.emplace(name, FromEngine(value));
	return result;
}

DebugRegister WindowsNativeAdapter::ReadRegister(const std::string& reg)
{
	return FromEngine(m_engine.ReadRegister(reg));
}

bool WindowsNativeAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
	return m_engine.WriteRegister(reg, static_cast<uint64_t>(value));
}

DataBuffer WindowsNativeAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	auto bytes = m_engine.ReadMemory(address, size);
	return DataBuffer(bytes.data(), bytes.size());
}

bool WindowsNativeAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	const auto* bytes = static_cast<const uint8_t*>(buffer.GetData());
	std::vector<uint8_t> data;
	if (buffer.GetLength()) data.assign(bytes, bytes + buffer.GetLength());
	return m_engine.WriteMemory(address, data);
}

std::vector<DebugModule> WindowsNativeAdapter::GetModuleList()
{
	return FromEngine(m_engine.GetModuleList());
}

std::vector<DebugMemoryRegion> WindowsNativeAdapter::GetMemoryMap()
{
	return FromEngine(m_engine.GetMemoryMap());
}

std::vector<DebugSymbol> WindowsNativeAdapter::GetSymbolsForModule(const DebugModule& module)
{
	WindowsDebugging::DebugModule source(module.m_name, module.m_short_name, module.m_address, module.m_size, module.m_loaded);
	return FromEngine(m_engine.GetSymbolsForModule(source));
}

std::string WindowsNativeAdapter::GetTargetArchitecture()
{
	return m_engine.GetTargetArchitecture();
}

DebugStopReason WindowsNativeAdapter::StopReason()
{
	return FromEngine(m_engine.StopReason());
}

uint64_t WindowsNativeAdapter::ExitCode()
{
	return m_engine.ExitCode();
}

bool WindowsNativeAdapter::BreakInto()
{
	return m_engine.BreakInto();
}

bool WindowsNativeAdapter::Go()
{
	return m_engine.Go();
}

bool WindowsNativeAdapter::StepInto()
{
	return m_engine.StepInto();
}

bool WindowsNativeAdapter::StepOver()
{
	return m_engine.StepOver();
}

bool WindowsNativeAdapter::StepReturn()
{
	return m_engine.StepReturn();
}

uint64_t WindowsNativeAdapter::GetInstructionOffset()
{
	return m_engine.GetInstructionOffset();
}

uint64_t WindowsNativeAdapter::GetStackPointer()
{
	return m_engine.GetStackPointer();
}

std::uint32_t WindowsNativeAdapter::GetActivePID()
{
	return m_engine.GetActivePID();
}

bool WindowsNativeAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	switch (feature)
	{
	case DebugAdapterSupportStepOver: return m_engine.SupportFeature(WindowsDebugging::DebugAdapterSupportStepOver);
	case DebugAdapterSupportStepReturn: return m_engine.SupportFeature(WindowsDebugging::DebugAdapterSupportStepReturn);
	case DebugAdapterSupportModules: return m_engine.SupportFeature(WindowsDebugging::DebugAdapterSupportModules);
	case DebugAdapterSupportThreads: return m_engine.SupportFeature(WindowsDebugging::DebugAdapterSupportThreads);
	case DebugAdapterSupportSymbols: return m_engine.SupportFeature(WindowsDebugging::DebugAdapterSupportSymbols);
	default: return false;
	}
}

std::vector<DebugFrame> WindowsNativeAdapter::GetFramesOfThread(uint32_t tid)
{
	return FromEngine(m_engine.GetFramesOfThread(tid));
}

bool WindowsNativeAdapter::SuspendThread(std::uint32_t tid)
{
	return m_engine.SuspendThread(tid);
}

bool WindowsNativeAdapter::ResumeThread(std::uint32_t tid)
{
	return m_engine.ResumeThread(tid);
}

// Adapter Type implementation
WindowsNativeAdapterType::WindowsNativeAdapterType() : DebugAdapterType("WINDOWS_NATIVE")
{
}


DebugAdapter* WindowsNativeAdapterType::Create(BinaryNinja::BinaryView* data)
{
	return new WindowsNativeAdapter(data);
}


bool WindowsNativeAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool WindowsNativeAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
	return true;
#endif
	return false;
}


bool WindowsNativeAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	// Windows native adapter doesn't support remote connections
	return false;
}


Ref<Settings> WindowsNativeAdapter::GetAdapterSettings()
{
	return WindowsNativeAdapterType::GetAdapterSettings();
}


Ref<Settings> WindowsNativeAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = WindowsNativeAdapterType::RegisterAdapterSettings();
	return settings;
}


Ref<Settings> WindowsNativeAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("WindowsNativeAdapterSettings");
	settings->SetResourceId("windows_native_adapter_settings");

	settings->RegisterGroup("launch", "Launch");
	settings->RegisterGroup("attach", "Attach");
	settings->RegisterGroup("common", "Common");

	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Path of the input file for the debugger to find the base address",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");

	settings->RegisterSetting("common.verboseLogging",
		R"({
			"title" : "Verbose Logging",
			"type" : "boolean",
			"default" : false,
			"description" : "Enable verbose debug logging output for the Windows Native adapter",
			"readOnly" : false
			})");

	settings->RegisterSetting("launch.executablePath",
		R"({
			"title" : "Executable Path",
			"type" : "string",
			"default" : "",
			"description" : "Path of the executable to launch.",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");
	settings->RegisterSetting("launch.workingDirectory",
			R"({
			"title" : "Working Directory",
			"type" : "string",
			"default" : "",
			"description" : "Working directory to launch the target in.",
			"readOnly" : false,
			"uiSelectionAction" : "directory"
			})");
	settings->RegisterSetting("launch.commandLineArguments",
			R"({
			"title" : "Command Line Arguments",
			"type" : "string",
			"default" : "",
			"description" : "Command line arguments to pass to the target",
			"readOnly" : false
			})");

	settings->RegisterSetting("attach.pid",
		R"({
			"title" : "PID to attach to",
			"type" : "number",
			"default" : 0,
			"minValue" : 0,
			"maxValue" : 4294967295,
			"description" : "PID of the process to attach to",
			"readOnly" : false
			})");

	return settings;
}


void WindowsNativeAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto executablePath = adapterSettings->Get<std::string>("launch.executablePath", data, &scope);
	// If the value is not loaded from the database, we need to populate it with a default value
	if (scope != SettingsResourceScope)
	{
		executablePath = data->GetFile()->GetOriginalFilename();
		adapterSettings->Set("launch.executablePath", executablePath, data, SettingsResourceScope);
	}

	scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);

	scope = SettingsResourceScope;
	auto workingDirectory = adapterSettings->Get<std::string>("launch.workingDirectory", data, &scope);
	if (scope != SettingsResourceScope)
	{
		try
		{
			workingDirectory = std::filesystem::path(executablePath).parent_path().string();
		}
		catch (const std::exception&)
		{
			LogWarn("Cannot get the default working directory for the input file.");
		}
		adapterSettings->Set("launch.workingDirectory", workingDirectory, data, SettingsResourceScope);
	}
}


void BinaryNinjaDebugger::InitWindowsNativeAdapterType()
{
	static WindowsNativeAdapterType adapterType;
	DebugAdapterType::Register(&adapterType);
}
