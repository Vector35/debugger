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

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <csignal>
#include <cstring>
#include <optional>
#include "ptraceadapter.h"

namespace BinaryNinjaDebugger {

	static std::optional<std::vector<std::string>> ParseCommandLineArguments(const std::string& commandLine)
	{
		enum class Quote { None, Single, Double };
		Quote quote = Quote::None;
		bool escaped = false;
		bool argumentStarted = false;
		std::string argument;
		std::vector<std::string> arguments;

		for (char ch : commandLine)
		{
			if (escaped)
			{
				argument += ch;
				argumentStarted = true;
				escaped = false;
				continue;
			}

			if (ch == '\\' && quote != Quote::Single)
			{
				escaped = true;
				argumentStarted = true;
				continue;
			}
			if (ch == '\'' && quote != Quote::Double)
			{
				quote = quote == Quote::Single ? Quote::None : Quote::Single;
				argumentStarted = true;
				continue;
			}
			if (ch == '"' && quote != Quote::Single)
			{
				quote = quote == Quote::Double ? Quote::None : Quote::Double;
				argumentStarted = true;
				continue;
			}
			if (std::isspace(static_cast<unsigned char>(ch)) && quote == Quote::None)
			{
				if (argumentStarted)
				{
					arguments.push_back(argument);
					argument.clear();
					argumentStarted = false;
				}
				continue;
			}

			argument += ch;
			argumentStarted = true;
		}

		if (escaped || quote != Quote::None)
			return std::nullopt;
		if (argumentStarted)
			arguments.push_back(argument);
		return arguments;
	}


	static DebugRegister RegisterFromBytes(const PtraceRegister& reg, const std::vector<uint8_t>& data, size_t index)
	{
		uint8_t buffer[64] = {};
		memcpy(buffer, data.data() + reg.offset, std::min(reg.size, sizeof(buffer)));
		return DebugRegister(reg.name, intx::le::load<intx::uint512>(buffer), reg.size * 8, index);
	}


	static bool RegisterInBounds(const PtraceRegister& reg, const std::vector<uint8_t>& data)
	{
		return reg.offset + reg.size <= data.size();
	}


	static bool HwTypeFromBreakpointType(DebugBreakpointType type, PtraceHwType& result)
	{
		switch (type)
		{
		case HardwareExecuteBreakpoint:
			result = PtraceHwType::Execute;
			return true;
		case HardwareReadBreakpoint:
			result = PtraceHwType::Read;
			return true;
		case HardwareWriteBreakpoint:
			result = PtraceHwType::Write;
			return true;
		case HardwareAccessBreakpoint:
			result = PtraceHwType::Access;
			return true;
		default:
			return false;
		}
	}


	static DebugStopReason StopReasonFromEvent(const PtraceEngine::Event& event)
	{
		if (event.interrupted)
			return UnknownReason;
		if (event.breakpoint || event.hardware)
			return Breakpoint;
		if (event.signal == SIGTRAP)
			return event.singleStep ? SingleStep : Breakpoint;
		return SignalToDebugStopReason(event.signal);
	}


	static bool IsSupportedArchitecture(BinaryView* data)
	{
		if (!data)
			return false;

		auto arch = data->GetDefaultArchitecture();
		if (!arch)
			return false;

		auto name = arch->GetName();
		return name == "x86" || name == "x86_64";
	}


	bool PtraceAdapter::ResolveModuleAddress(const ModuleNameAndOffset& location, uint64_t& address)
	{
		if (location.module.empty())
		{
			address = location.offset;
			return true;
		}
		if (!m_engine)
			return false;

		// The base of a module is where its first mapping starts
		uint64_t base = UINT64_MAX;
		for (const auto& map : m_engine->GetMaps())
		{
			if (!map.path.empty() && DebugModule::IsSameBaseModule(map.path, location.module))
				base = std::min(base, map.start);
		}
		if (base == UINT64_MAX)
			return false;

		address = base + location.offset;
		return true;
	}


	PtraceAdapter::PtraceAdapter(BinaryView* data) : DebugAdapter(data)
	{
		m_targetActive = false;
		GenerateDefaultAdapterSettings(data);
	}


	PtraceAdapter::~PtraceAdapter()
	{
		m_engine.reset();
	}


	bool PtraceAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
	{
		return ExecuteWithArgs(path, "", "", configs);
	}


	bool PtraceAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
		const std::string& workingDir, const LaunchConfigurations& configs)
	{
		auto adapterSettings = GetAdapterSettings();
		auto data = GetData();
		BNSettingsScope scope = SettingsResourceScope;
		auto executablePath = adapterSettings->Get<std::string>("launch.executablePath", data, &scope);
		scope = SettingsResourceScope;
		m_inputFile = adapterSettings->Get<std::string>("common.inputFile", data, &scope);
		scope = SettingsResourceScope;
		auto workingDirectory = adapterSettings->Get<std::string>("launch.workingDirectory", data, &scope);
		scope = SettingsResourceScope;
		auto commandLineArgs = adapterSettings->Get<std::string>("launch.commandLineArguments", data, &scope);
		scope = SettingsResourceScope;
		auto disableAslr = adapterSettings->Get<bool>("launch.disableAslr", data, &scope);

		if (executablePath.empty())
			executablePath = path;
		if (workingDirectory.empty())
			workingDirectory = workingDir;
		if (commandLineArgs.empty())
			commandLineArgs = args;
		if (m_inputFile.empty())
			m_inputFile = executablePath;

		auto launchFailure = [this](const std::string& error) {
			DebuggerEvent event;
			event.type = LaunchFailureEventType;
			event.data.errorData.shortError = "Failed to launch target";
			event.data.errorData.error = fmt::format("PTRACE: {}", error);
			PostDebuggerEvent(event);
			return false;
		};

		if (executablePath.empty())
			return launchFailure("no executable path specified");

		auto parsedArguments = ParseCommandLineArguments(commandLineArgs);
		if (!parsedArguments)
			return launchFailure("invalid command line arguments");

		PtraceEngine::LaunchOptions options;
		options.path = executablePath;
		options.args = *parsedArguments;
		options.workingDir = workingDirectory;
		options.disableAslr = disableAslr;

		m_engine.reset();
		m_stopAtSystemEntry = Settings::Instance()->Get<bool>("debugger.stopAtSystemEntryPoint");
		m_firstStop = true;
		m_targetActive = true;
		m_engine = std::make_unique<PtraceEngine>([this](const PtraceEngine::Event& event) { HandleEngineEvent(event); });

		std::string error;
		if (!m_engine->Launch(options, error))
		{
			m_targetActive = false;
			return launchFailure(error);
		}
		return true;
	}


	void PtraceAdapter::HandleEngineEvent(const PtraceEngine::Event& event)
	{
		DebuggerEvent dbgevt;
		switch (event.type)
		{
		case PtraceEngine::StoppedEvent:
			m_activeThreadId = event.tid;
			m_lastStopReason = StopReasonFromEvent(event);
			if (m_firstStop)
			{
				m_firstStop = false;
				m_arch = m_engine->GetArch();
				if (!m_arch)
					LogWarn("PtraceAdapter: unsupported target architecture");

				if (Settings::Instance()->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction)
					AddBreakpoint(ModuleNameAndOffset(m_inputFile, m_entryPoint - m_start), 0);
				if (!m_stopAtSystemEntry)
				{
					ApplyBreakpoints();
					m_engine->Resume(false, 0);
					break;
				}
			}
			ApplyBreakpoints();
			dbgevt.type = AdapterStoppedEventType;
			dbgevt.data.targetStoppedData.reason = m_lastStopReason;
			dbgevt.data.targetStoppedData.lastActiveThread = event.tid;
			PostDebuggerEvent(dbgevt);
			break;
		case PtraceEngine::ExitedEvent:
			m_targetActive = false;
			ClearBreakpoints();
			m_lastStopReason = ProcessExited;
			m_exitCode = event.signal ? 128 + event.signal : event.exitCode;
			dbgevt.type = TargetExitedEventType;
			dbgevt.data.exitData.exitCode = m_exitCode;
			PostDebuggerEvent(dbgevt);
			break;
		case PtraceEngine::DetachedEvent:
			m_targetActive = false;
			ClearBreakpoints();
			dbgevt.type = DetachedEventType;
			PostDebuggerEvent(dbgevt);
			break;
		case PtraceEngine::OutputEvent:
			dbgevt.type = StdoutMessageEventType;
			dbgevt.data.messageData.message = event.data;
			PostDebuggerEvent(dbgevt);
			break;
		}
	}


	bool PtraceAdapter::Attach(std::uint32_t pid)
	{
		LogWarn("PtraceAdapter::Attach not implemented");
		return false;
	}


	bool PtraceAdapter::Connect(const std::string& server, std::uint32_t port)
	{
		return false;
	}


	bool PtraceAdapter::Detach()
	{
		return m_engine && m_engine->Detach();
	}


	bool PtraceAdapter::Quit()
	{
		return m_engine && m_engine->Kill();
	}


	std::vector<DebugProcess> PtraceAdapter::GetProcessList()
	{
		return {};
	}


	std::uint32_t PtraceAdapter::GetActivePID()
	{
		return m_engine ? m_engine->GetPid() : 0;
	}


	std::vector<DebugThread> PtraceAdapter::GetThreadList()
	{
		std::vector<DebugThread> threads;
		if (!m_engine)
			return threads;

		auto arch = m_arch.load();
		for (uint32_t tid : m_engine->GetThreads())
		{
			DebugThread thread(tid);
			if (arch && !m_engine->IsRunning())
			{
				auto pc = arch->Find(arch->pc);
				std::vector<uint8_t> data;
				if (pc && m_engine->GetRegisterSet(tid, pc->regset, data) && RegisterInBounds(*pc, data))
					thread.m_rip = (uintptr_t)RegisterFromBytes(*pc, data, 0).m_value;
			}
			threads.push_back(thread);
		}
		return threads;
	}


	DebugThread PtraceAdapter::GetActiveThread() const
	{
		return DebugThread(m_activeThreadId);
	}


	uint32_t PtraceAdapter::GetActiveThreadId() const
	{
		return m_activeThreadId;
	}


	bool PtraceAdapter::SetActiveThread(const DebugThread& thread)
	{
		return SetActiveThreadId(thread.m_tid);
	}


	bool PtraceAdapter::SetActiveThreadId(std::uint32_t tid)
	{
		if (!m_engine)
			return false;

		auto threads = m_engine->GetThreads();
		if (std::find(threads.begin(), threads.end(), tid) == threads.end())
			return false;

		m_activeThreadId = tid;
		return true;
	}


	bool PtraceAdapter::SuspendThread(std::uint32_t tid)
	{
		return false;
	}


	bool PtraceAdapter::ResumeThread(std::uint32_t tid)
	{
		return false;
	}


	std::vector<DebugFrame> PtraceAdapter::GetFramesOfThread(uint32_t tid)
	{
		return {};
	}


	DebugBreakpoint PtraceAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
	{
		if (!m_engine || !m_targetActive)
			return DebugBreakpoint();

		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(),
			[address](const DebugBreakpoint& bp) { return bp.m_address == address; });
		if (it != m_breakpoints.end())
			return *it;

		if (!m_engine->AddBreakpoint(address))
		{
			LogWarn("PtraceAdapter: failed to set a breakpoint at 0x%" PRIx64, (uint64_t)address);
			return DebugBreakpoint();
		}

		m_breakpoints.emplace_back(address, m_nextBreakpointId++, true);
		return m_breakpoints.back();
	}


	DebugBreakpoint PtraceAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		uint64_t resolved;
		if (m_targetActive && ResolveModuleAddress(address, resolved))
			return AddBreakpoint(resolved, breakpoint_type);

		// The module is not loaded yet, so this waits for it
		if (std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end())
			m_pendingBreakpoints.push_back(address);
		return DebugBreakpoint();
	}


	bool PtraceAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(),
			[&breakpoint](const DebugBreakpoint& bp) { return bp.m_address == breakpoint.m_address; });
		if (!m_engine || it == m_breakpoints.end() || !m_engine->RemoveBreakpoint(breakpoint.m_address))
			return false;

		m_breakpoints.erase(it);
		return true;
	}


	bool PtraceAdapter::RemoveBreakpoint(const ModuleNameAndOffset& address)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto pending = std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address);
		if (pending != m_pendingBreakpoints.end())
		{
			m_pendingBreakpoints.erase(pending);
			return true;
		}

		uint64_t resolved;
		return m_targetActive && ResolveModuleAddress(address, resolved) && RemoveBreakpoint(DebugBreakpoint(resolved));
	}


	std::vector<DebugBreakpoint> PtraceAdapter::GetBreakpointList() const
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		return m_breakpoints;
	}


	// Hardware breakpoint and watchpoint support
	bool PtraceAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
	{
		PtraceHwType hwType;
		if (!m_engine || !m_targetActive || !HwTypeFromBreakpointType(type, hwType))
			return false;

		return m_engine->AddHardwareBreakpoint(address, hwType, size);
	}


	bool PtraceAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
	{
		PtraceHwType hwType;
		if (!m_engine || !m_targetActive || !HwTypeFromBreakpointType(type, hwType))
			return false;

		return m_engine->RemoveHardwareBreakpoint(address, hwType, size);
	}


	bool PtraceAdapter::AddHardwareBreakpoint(
		const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		uint64_t resolved;
		if (m_targetActive && ResolveModuleAddress(location, resolved))
			return AddHardwareBreakpoint(resolved, type, size);

		PendingHardwareBreakpoint pending(location, type, size);
		if (std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
			== m_pendingHardwareBreakpoints.end())
			m_pendingHardwareBreakpoints.push_back(pending);
		return true;
	}


	bool PtraceAdapter::RemoveHardwareBreakpoint(
		const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		PendingHardwareBreakpoint pending(location, type, size);
		auto it = std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending);
		if (it != m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.erase(it);
			return true;
		}

		uint64_t resolved;
		return m_targetActive && ResolveModuleAddress(location, resolved)
			&& RemoveHardwareBreakpoint(resolved, type, size);
	}


	std::unordered_map<std::string, DebugRegister> PtraceAdapter::ReadAllRegisters()
	{
		std::unordered_map<std::string, DebugRegister> result;
		auto arch = m_arch.load();
		if (!m_engine || !arch)
			return result;

		std::unordered_map<int, std::vector<uint8_t>> regsets;
		for (int regset : arch->regsets)
		{
			std::vector<uint8_t> data;
			if (m_engine->GetRegisterSet(m_activeThreadId, regset, data))
				regsets[regset] = std::move(data);
		}

		for (size_t i = 0; i < arch->registers.size(); i++)
		{
			const auto& reg = arch->registers[i];
			auto it = regsets.find(reg.regset);
			if (it != regsets.end() && RegisterInBounds(reg, it->second))
				result[reg.name] = RegisterFromBytes(reg, it->second, i);
		}
		return result;
	}


	DebugRegister PtraceAdapter::ReadRegister(const std::string& reg)
	{
		auto arch = m_arch.load();
		if (!m_engine || !arch)
			return DebugRegister();

		auto info = arch->Find(reg);
		std::vector<uint8_t> data;
		if (!info || !m_engine->GetRegisterSet(m_activeThreadId, info->regset, data) || !RegisterInBounds(*info, data))
			return DebugRegister();

		return RegisterFromBytes(*info, data, info - arch->registers.data());
	}


	bool PtraceAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
	{
		auto arch = m_arch.load();
		if (!m_engine || !arch)
			return false;

		auto info = arch->Find(reg);
		std::vector<uint8_t> data;
		if (!info || !m_engine->GetRegisterSet(m_activeThreadId, info->regset, data) || !RegisterInBounds(*info, data))
			return false;

		uint8_t buffer[64];
		intx::le::store(buffer, value);
		memcpy(data.data() + info->offset, buffer, std::min(info->size, sizeof(buffer)));
		return m_engine->SetRegisterSet(m_activeThreadId, info->regset, data);
	}


	uint64_t PtraceAdapter::ReadArchRegister(const std::string& name)
	{
		return (uint64_t)ReadRegister(name).m_value;
	}


	DataBuffer PtraceAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
	{
		DataBuffer result;
		if (!m_engine || size == 0)
			return result;

		std::vector<uint8_t> buffer(size);
		if (m_engine->ReadMemory(address, buffer.data(), size))
			result.Append(buffer.data(), size);
		return result;
	}


	bool PtraceAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
	{
		return m_engine && m_engine->WriteMemory(address, buffer.GetData(), buffer.GetLength());
	}


	std::vector<DebugModule> PtraceAdapter::GetModuleList()
	{
		return {};
	}


	std::vector<DebugMemoryRegion> PtraceAdapter::GetMemoryMap()
	{
		return {};
	}


	std::vector<DebugSymbol> PtraceAdapter::GetSymbolsForModule(const DebugModule& module)
	{
		return {};
	}


	std::string PtraceAdapter::GetTargetArchitecture()
	{
		auto arch = m_arch.load();
		return arch ? arch->name : "";
	}


	DebugStopReason PtraceAdapter::StopReason()
	{
		return m_lastStopReason;
	}


	uint64_t PtraceAdapter::ExitCode()
	{
		return m_exitCode;
	}


	bool PtraceAdapter::BreakInto()
	{
		return m_engine && m_engine->Interrupt();
	}


	bool PtraceAdapter::Go()
	{
		if (!m_engine || !m_engine->Resume(false, 0))
			return false;

		DebuggerEvent event;
		event.type = ResumeEventType;
		PostDebuggerEvent(event);
		return true;
	}


	bool PtraceAdapter::StepInto()
	{
		if (!m_engine || !m_engine->Resume(true, m_activeThreadId))
			return false;

		DebuggerEvent event;
		event.type = StepIntoEventType;
		PostDebuggerEvent(event);
		return true;
	}


	bool PtraceAdapter::StepOver()
	{
		return false;
	}


	bool PtraceAdapter::StepReturn()
	{
		return false;
	}


	std::string PtraceAdapter::InvokeBackendCommand(const std::string& command)
	{
		return "";
	}


	uint64_t PtraceAdapter::GetInstructionOffset()
	{
		auto arch = m_arch.load();
		return arch ? ReadArchRegister(arch->pc) : 0;
	}


	uint64_t PtraceAdapter::GetStackPointer()
	{
		auto arch = m_arch.load();
		return arch ? ReadArchRegister(arch->sp) : 0;
	}


	bool PtraceAdapter::SupportFeature(DebugAdapterCapacity feature)
	{
		switch (feature)
		{
		case DebugAdapterSupportThreads:
			return true;
		default:
			return false;
		}
	}


	void PtraceAdapter::EventListener() {}


	void PtraceAdapter::WriteStdin(const std::string& msg)
	{
		if (m_engine)
			m_engine->WriteInput(msg);
	}


	void PtraceAdapter::FixActiveThread() {}


	Ref<Metadata> PtraceAdapter::GetProperty(const std::string& name)
	{
		return nullptr;
	}


	bool PtraceAdapter::SetProperty(const std::string& name, const Ref<Metadata>& value)
	{
		return false;
	}


	void PtraceAdapter::ApplyBreakpoints()
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		if (!m_engine || !m_targetActive)
			return;

		// Only what has been applied leaves the list, so the rest waits for a module that is not loaded yet
		for (auto it = m_pendingBreakpoints.begin(); it != m_pendingBreakpoints.end();)
		{
			uint64_t address;
			if (ResolveModuleAddress(*it, address) && AddBreakpoint(address, 0).m_address != 0)
				it = m_pendingBreakpoints.erase(it);
			else
				it++;
		}

		for (auto it = m_pendingHardwareBreakpoints.begin(); it != m_pendingHardwareBreakpoints.end();)
		{
			uint64_t address = it->address;
			bool resolved = !it->isRelative || ResolveModuleAddress(it->location, address);
			if (resolved && AddHardwareBreakpoint(address, it->type, it->size))
				it = m_pendingHardwareBreakpoints.erase(it);
			else
				it++;
		}
	}


	void PtraceAdapter::ClearBreakpoints()
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		m_breakpoints.clear();
	}


	void PtraceAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
	{
		auto adapterSettings = GetAdapterSettings();
		BNSettingsScope scope = SettingsResourceScope;
		adapterSettings->Get<std::string>("common.inputFile", data, &scope);
		if (scope != SettingsResourceScope)
			adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);

		scope = SettingsResourceScope;
		adapterSettings->Get<std::string>("launch.executablePath", data, &scope);
		if (scope != SettingsResourceScope)
			adapterSettings->Set(
				"launch.executablePath", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
	}


	Ref<Settings> PtraceAdapter::GetAdapterSettings()
	{
		return PtraceAdapterType::GetAdapterSettings();
	}


	PtraceAdapterType::PtraceAdapterType() : DebugAdapterType("PTRACE") {}


	DebugAdapter* PtraceAdapterType::Create(BinaryNinja::BinaryView* data)
	{
		return new PtraceAdapter(data);
	}


	bool PtraceAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
	{
		return IsSupportedArchitecture(data);
	}


	bool PtraceAdapterType::CanConnect(BinaryNinja::BinaryView* data)
	{
		return false;
	}


	bool PtraceAdapterType::CanExecute(BinaryNinja::BinaryView* data)
	{
		return data && data->GetTypeName() == "ELF";
	}


	Ref<Settings> PtraceAdapterType::RegisterAdapterSettings()
	{
		Ref<Settings> settings = Settings::Instance("PtraceAdapterSettings");
		settings->SetResourceId("ptrace_adapter_settings");
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
			"description" : "Path of the executable to launch for local debugging.",
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
			"description" : "Command line arguments to pass to the target.",
			"readOnly" : false
			})");
		settings->RegisterSetting("launch.disableAslr",
			R"({
			"title" : "Disable ASLR",
			"type" : "boolean",
			"default" : true,
			"description" : "Disable address space layout randomization for the target.",
			"readOnly" : false
			})");

		return settings;
	}


	Ref<Settings> PtraceAdapterType::GetAdapterSettings()
	{
		static Ref<Settings> settings = PtraceAdapterType::RegisterAdapterSettings();
		return settings;
	}


	void InitPtraceAdapterType()
	{
		static PtraceAdapterType ptraceType;
		DebugAdapterType::Register(&ptraceType);
	}

}  // namespace BinaryNinjaDebugger
