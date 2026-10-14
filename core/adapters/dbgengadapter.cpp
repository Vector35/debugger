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

#include <filesystem>
#include "dbgengadapter.h"

using namespace BinaryNinjaDebugger;
using namespace std;

namespace {
	DebugStopReason FromEngine(DbgEngStopReason value)
	{
		switch (value)
		{
		case DbgEngStopReason::UnknownReason:
			return UnknownReason;
		case DbgEngStopReason::ProcessExited:
			return ProcessExited;
		case DbgEngStopReason::AccessViolation:
			return AccessViolation;
		case DbgEngStopReason::SingleStep:
			return SingleStep;
		case DbgEngStopReason::Calculation:
			return Calculation;
		case DbgEngStopReason::Breakpoint:
			return Breakpoint;
		default:
			return UnknownReason;
		}
	}
}

static bool IsValidDbgEngPaths(const std::string& path)
{
	if (path.empty())
		return false;

	std::error_code ec;
	auto enginePath = filesystem::path(path);
	if (!filesystem::exists(enginePath, ec))
		return false;

	if (!filesystem::exists(enginePath / "dbgeng.dll", ec))
		return false;

	if (!filesystem::exists(enginePath / "dbghelp.dll", ec))
		return false;

	if (!filesystem::exists(enginePath / "dbgmodel.dll", ec))
		return false;

	if (!filesystem::exists(enginePath / "dbgcore.dll", ec))
		return false;

	if (!filesystem::exists(enginePath / "dbgsrv.exe", ec))
		return false;

	return true;
}

std::string DbgEngAdapter::GetDbgEngPath(const std::string& arch)
{
	std::string path;
	if (arch == "amd64")
		path = Settings::Instance()->Get<string>("debugger.x64dbgEngPath");
	else
		path = Settings::Instance()->Get<string>("debugger.x86dbgEngPath");

	if (!path.empty())
	{
		// If the user has specified the path in the setting, then check it for validity. If it is valid, then use it;
		// if it is invalid, fail the operation -- do not fallback to the default one
		if (IsValidDbgEngPaths(path))
			return path;
		else
			return "";
	}

	std::string pluginRoot;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		pluginRoot = GetUserPluginDirectory();
	else
		pluginRoot = GetBundledPluginDirectory();

	// If the user does not specify a path (the default case), find the one from the plugins/dbgeng/arch
    auto debuggerRoot = filesystem::path(pluginRoot)  / "dbgeng" / arch;
    if (IsValidDbgEngPaths(debuggerRoot.string()))
        return debuggerRoot.string();

	return "";
}


bool DbgEngAdapter::LoadDngEngLibraries()
{
	SetDbgEngLogCallback([](DbgEngLogLevel level, const std::string& message) {
		switch (level)
		{
		case DbgEngLogLevel::Debug:
			BinaryNinja::LogDebug("%s", message.c_str());
			break;
		case DbgEngLogLevel::Info:
			BinaryNinja::LogInfo("%s", message.c_str());
			break;
		case DbgEngLogLevel::Warn:
			BinaryNinja::LogWarn("%s", message.c_str());
			break;
		case DbgEngLogLevel::Error:
			BinaryNinja::LogError("%s", message.c_str());
			break;
		}
	});

	auto enginePath = GetDbgEngPath("amd64");
	if (enginePath.empty())
	{
		LogWarn("The debugger cannot find the path for the DbgEng DLLs. "
			"If you have set debugger.x64dbgEngPath, check if it valid");
		return false;
	}

	auto settings = Settings::Instance();
	auto strictCheckPath = settings->Get<bool>("debugger.checkDbgEngDLLPath");
	auto forceUnload = settings->Get<bool>("debugger.tryUnloadWrongDbgEngDLL");

	return DbgEngEngine::LoadLibraries(enginePath, strictCheckPath, forceUnload);
}


DbgEngAdapter::DbgEngAdapter(BinaryView* data) : DbgEngAdapter(data, std::make_unique<DbgEngEngine>()) {}


DbgEngAdapter::DbgEngAdapter(BinaryView* data, std::unique_ptr<DbgEngEngine> engine) :
	DebugAdapter(data), m_engine(std::move(engine))
{
	auto metadata = data->QueryMetadata("PDB_FILENAME");
	if (metadata && metadata->IsString())
		m_engine->SetPdbFileName(metadata->GetString());

	m_engine->SetOriginalImageBase(m_originalImageBase);
	GenerateDefaultAdapterSettings(data);
	m_engine->SetEventCallback([this](const DbgEngEvent& source) {
		DebuggerEvent event;
		switch (source.type)
		{
		case DbgEngEventType::LaunchFailure:
			event.type = LaunchFailureEventType;
			event.data.errorData.error = source.error;
			event.data.errorData.shortError = source.shortError;
			break;
		case DbgEngEventType::TargetExited:
			event.type = TargetExitedEventType;
			event.data.exitData.exitCode = source.exitCode;
			break;
		case DbgEngEventType::TargetStopped:
			event.type = AdapterStoppedEventType;
			event.data.targetStoppedData.reason = FromEngine(source.stopReason);
			break;
		case DbgEngEventType::Resumed:
			event.type = ResumeEventType;
			break;
		case DbgEngEventType::StepIntoComplete:
			event.type = StepIntoEventType;
			break;
		case DbgEngEventType::BackendMessage:
			event.type = BackendMessageEventType;
			event.data.messageData.message = source.message;
			break;
		}
		PostDebuggerEvent(event);
	});
	m_engine->SetInputFileCallback([this]() { return ReadInputFile(); });
}


std::string DbgEngAdapter::ReadInputFile()
{
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	return adapterSettings->Get<std::string>("common.inputFile", data, &scope);
}


bool DbgEngAdapter::Init()
{
	return true;
}


bool DbgEngAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return this->ExecuteWithArgs(path, "", "", {});
}


void DbgEngAdapter::ConfigureEngine()
{
	m_engine->SetDbgSrvEnginePath(GetDbgEngPath(m_defaultArchitecture == "x86" ? "x86" : "amd64"));
	auto settings = Settings::Instance();
	m_engine->SetStopAtSystemEntryPoint(settings->Get<bool>("debugger.stopAtSystemEntryPoint"));
	m_engine->SetEntryPointOffset(settings->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction
		? std::optional<uint64_t>(m_entryPoint - m_start) : std::nullopt);
	m_engine->SetOutputStateOnStop(settings->Get<bool>("debugger.dbgEngOutputStateOnStop"));
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	m_engine->SetRunAsAdministrator(adapterSettings->Contains("common.runAsAdministrator")
		&& adapterSettings->Get<bool>("common.runAsAdministrator", data, &scope));
}


bool DbgEngAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
	const LaunchConfigurations& configs)
{
	ConfigureEngine();
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto executablePath = adapterSettings->Get<std::string>("launch.executablePath", data, &scope);
	scope = SettingsResourceScope;
	auto workingDirectory = adapterSettings->Get<std::string>("launch.workingDirectory", data, &scope);
	scope = SettingsResourceScope;
	auto commandLineArgs = adapterSettings->Get<std::string>("launch.commandLineArguments", data, &scope);
	scope = SettingsResourceScope;
	auto envVariables = adapterSettings->Get<vector<string>>("launch.environmentVariables", data, &scope);
	m_engine->SetEnvironmentVariables(envVariables);
	return m_engine->ExecuteWithArgs(executablePath, commandLineArgs, workingDirectory);
}


bool DbgEngAdapter::Attach(std::uint32_t pid)
{
	ConfigureEngine();
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto attachPID = adapterSettings->Get<uint64_t>("attach.pid", data, &scope);

	return m_engine->Attach((std::uint32_t)attachPID);
}


bool DbgEngAdapter::Connect(const std::string& server, std::uint32_t port)
{
	return m_engine->Connect(server, port);
}


bool DbgEngAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port)
{
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto ipAddress = adapterSettings->Get<std::string>("debugServer.ipAddress", data, &scope);
	scope = SettingsResourceScope;
	auto serverPort = adapterSettings->Get<uint64_t>("debugServer.port", data, &scope);

	return m_engine->ConnectToDebugServer(ipAddress, (std::uint32_t)serverPort);
}


bool DbgEngAdapter::DisconnectDebugServer()
{
	return m_engine->DisconnectDebugServer();
}


bool DbgEngAdapter::Detach()
{
	return m_engine->Detach();
}


bool DbgEngAdapter::Quit()
{
	return m_engine->Quit();
}


std::vector<DebugProcess> DbgEngAdapter::GetProcessList()
{
	return m_engine->GetProcessList();
}


std::vector<DebugThread> DbgEngAdapter::GetThreadList()
{
	return m_engine->GetThreadList();
}


DebugThread DbgEngAdapter::GetActiveThread() const
{
	return m_engine->GetActiveThread();
}


std::uint32_t DbgEngAdapter::GetActiveThreadId() const
{
	return m_engine->GetActiveThreadId();
}


bool DbgEngAdapter::SetActiveThread(const DebugThread& thread)
{
	return m_engine->SetActiveThread(thread);
}


bool DbgEngAdapter::SetActiveThreadId(std::uint32_t tid)
{
	return m_engine->SetActiveThreadId(tid);
}


DebugBreakpoint DbgEngAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags)
{
	return m_engine->AddBreakpoint(address, breakpoint_flags);
}


DebugBreakpoint DbgEngAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	return m_engine->AddBreakpoint(address, breakpoint_type);
}


bool DbgEngAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	return m_engine->RemoveBreakpoint(breakpoint);
}


bool DbgEngAdapter::RemoveBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	return m_engine->RemoveBreakpoint(breakpoint);
}


std::vector<DebugBreakpoint> DbgEngAdapter::GetBreakpointList() const
{
	return m_engine->GetBreakpointList();
}


bool DbgEngAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	return m_engine->AddHardwareBreakpoint(address, type, size);
}


bool DbgEngAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	return m_engine->RemoveHardwareBreakpoint(address, type, size);
}


bool DbgEngAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	return m_engine->AddHardwareBreakpoint(location, type, size);
}


bool DbgEngAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	return m_engine->RemoveHardwareBreakpoint(location, type, size);
}


std::unordered_map<std::string, DebugRegister> DbgEngAdapter::ReadAllRegisters()
{
	return m_engine->ReadAllRegisters();
}


DebugRegister DbgEngAdapter::ReadRegister(const std::string& reg)
{
	return m_engine->ReadRegister(reg);
}


bool DbgEngAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
	return m_engine->WriteRegister(reg, value);
}


DataBuffer DbgEngAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	auto bytes = m_engine->ReadMemory(address, size);
	return bytes.empty() ? DataBuffer() : DataBuffer(bytes.data(), bytes.size());
}


bool DbgEngAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	return m_engine->WriteMemory(address,
		std::vector<uint8_t>((const uint8_t*)buffer.GetData(), (const uint8_t*)buffer.GetData() + buffer.GetLength()));
}


std::vector<DebugModule> DbgEngAdapter::GetModuleList()
{
	return m_engine->GetModuleList();
}


std::vector<DebugMemoryRegion> DbgEngAdapter::GetMemoryMap()
{
	return m_engine->GetMemoryMap();
}


std::vector<DebugSymbol> DbgEngAdapter::GetSymbolsForModule(const DebugModule& module)
{
	return m_engine->GetSymbolsForModule(module);
}


std::string DbgEngAdapter::GetTargetArchitecture()
{
	return m_engine->GetTargetArchitecture();
}


DebugStopReason DbgEngAdapter::StopReason()
{
	return FromEngine(m_engine->StopReason());
}


uint64_t DbgEngAdapter::ExitCode()
{
	return m_engine->ExitCode();
}


bool DbgEngAdapter::BreakInto()
{
	return m_engine->BreakInto();
}


bool DbgEngAdapter::Go()
{
	return m_engine->Go();
}


bool DbgEngAdapter::StepInto()
{
	return m_engine->StepInto();
}


bool DbgEngAdapter::StepOver()
{
	return m_engine->StepOver();
}


bool DbgEngAdapter::StepReturn()
{
	return m_engine->StepReturn();
}


std::string DbgEngAdapter::InvokeBackendCommand(const std::string& command)
{
	return m_engine->InvokeBackendCommand(command);
}


uint64_t DbgEngAdapter::GetInstructionOffset()
{
	return m_engine->GetInstructionOffset();
}


uint64_t DbgEngAdapter::GetStackPointer()
{
	return m_engine->GetStackPointer();
}


std::uint32_t DbgEngAdapter::GetActivePID()
{
	return m_engine->GetActivePID();
}


bool DbgEngAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	return m_engine->SupportFeature(feature);
}


std::vector<DebugFrame> DbgEngAdapter::GetFramesOfThread(uint32_t tid)
{
	return m_engine->GetFramesOfThread(tid);
}


bool DbgEngAdapter::SuspendThread(std::uint32_t tid)
{
	return m_engine->SuspendThread(tid);
}


bool DbgEngAdapter::ResumeThread(std::uint32_t tid)
{
	return m_engine->ResumeThread(tid);
}


LocalDbgEngAdapterType::LocalDbgEngAdapterType() : DebugAdapterType("DBGENG") {}


DebugAdapter* LocalDbgEngAdapterType::Create(BinaryNinja::BinaryView* data)
{
	// TODO: someone should free this.
	return new DbgEngAdapter(data);
}


bool LocalDbgEngAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool LocalDbgEngAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	return true;
}


bool LocalDbgEngAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
	return true;
#endif
	return false;
}


Ref<Settings> DbgEngAdapter::GetAdapterSettings()
{
	return LocalDbgEngAdapterType::GetAdapterSettings();
}


Ref<Settings> LocalDbgEngAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = LocalDbgEngAdapterType::RegisterAdapterSettings();
	return settings;
}


Ref<Settings> LocalDbgEngAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("DbgEngAdapterSettings");
	settings->SetResourceId("dbgeng_adapter_settings");
	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Input file to use to find the base address of the binary view",
			"readOnly" : false,
			"uiSelectionAction" : "file"
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
	settings->RegisterSetting("launch.environmentVariables",
		R"({
			"title" : "Environment Variables",
			"type" : "array",
			"sorted" : false,
			"default" : [],
			"description" : "Environment Variables for the target. Provide the list of in the form of [\"var1=val1\", \"var2=val2\"]",
			"readOnly" : false
			})");

	settings->RegisterSetting("debugServer.ipAddress",
			R"({
			"title" : "IP Address",
			"type" : "string",
			"default" : "127.0.0.1",
			"description" : "IP address of the debug server to connect to",
			"readOnly" : false
			})");
	settings->RegisterSetting("debugServer.port",
			R"({
			"title" : "Port",
			"type" : "number",
			"default" : 31337,
			"minValue" : 0,
			"maxValue" : 65535,
			"description" : "Port of the debug server to connect to",
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

	settings->RegisterSetting("common.runAsAdministrator",
		R"({
			"title" : "Run as Administrator",
			"type" : "boolean",
			"default" : false,
			"description" : "Launch the debug server (dbgsrv.exe) with administrator privileges. Required when debugging processes that run with elevated privileges.",
			"readOnly" : false
			})");

	return settings;
}


void DbgEngAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
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
		// This mitigates https://github.com/Vector35/debugger/issues/469. However, it is NOT a proper fix since the
		// debugger still will not be able to launch the target properly. We will need to deal with the charset issue
		// to get this really fixed.
		try
		{
			workingDirectory = filesystem::path(executablePath).parent_path().string();
		}
		catch (const exception&)
		{
			LogWarn("Cannot get the default working directory for the input file. "
					"There might be special characters in the file path. "
					"The debugger may not be able to launch the target correctly. "
					"You can try changing the file path to ASCII allow.");
		}
		adapterSettings->Set("launch.workingDirectory", workingDirectory, data, SettingsResourceScope);
	}
}


void BinaryNinjaDebugger::InitDbgEngAdapterType()
{
	static LocalDbgEngAdapterType localType;
	DebugAdapterType::Register(&localType);
}
