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
#include <filesystem>
#include <csignal>
#include <cstring>
#include <optional>
#include "ptraceadapter.h"
#include "lowlevelilinstruction.h"

namespace BinaryNinjaDebugger {

	static std::optional<std::vector<std::string>> ParseCommandLineArguments(const std::string& commandLine)
	{
		enum class Quote
		{
			None,
			Single,
			Double
		};
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
		m_stepper.reset();
		m_engine.reset();
	}


	bool PtraceAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
	{
		return ExecuteWithArgs(path, "", "", configs);
	}


	bool PtraceAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
		const LaunchConfigurations& configs)
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

		m_stepper.reset();
		m_engine.reset();
		ResetTargetState();
		m_stopAtSystemEntry = Settings::Instance()->Get<bool>("debugger.stopAtSystemEntryPoint");
		m_firstStop = true;
		m_targetActive = true;
		m_engine = std::make_unique<PtraceEngine>([this](const PtraceEngine::Event& event) {
			HandleEngineEvent(event);
		});
		m_stepper = std::make_unique<PtraceStepper>(
			*m_engine, [this](uint64_t address) { return AcquireBreakpoint(address); },
			[this](uint64_t address) { return ReleaseBreakpoint(address); });

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
			m_stopGeneration++;
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
				SetUpLoaderBreakpoint();
				if (!m_stopAtSystemEntry)
				{
					ApplyBreakpoints();
					m_engine->Resume(false, 0);
					break;
				}
			}
			// A library was loaded or unloaded, which may be where a pending breakpoint goes
			if (event.breakpoint && m_loaderBreakpoint && m_arch.load()
				&& ReadArchRegister(m_arch.load()->pc) == m_loaderBreakpoint)
			{
				ApplyBreakpoints();
				m_engine->Resume(false, 0);
				break;
			}

			if (m_stepper && m_stepper->IsActive())
			{
				auto arch = m_arch.load();
				uint64_t pc = arch ? ReadArchRegister(arch->pc) : 0;
				uint64_t sp = arch ? ReadArchRegister(arch->sp) : 0;
				auto result = m_stepper->OnStop(event, pc, sp, IsUserBreakpoint(pc));
				if (result == PtraceStepper::Result::Consumed)
					break;
				if (result == PtraceStepper::Result::Finished)
					m_lastStopReason = SingleStep;
			}

			ApplyBreakpoints();
			dbgevt.type = AdapterStoppedEventType;
			dbgevt.data.targetStoppedData.reason = m_lastStopReason;
			dbgevt.data.targetStoppedData.lastActiveThread = event.tid;
			PostDebuggerEvent(dbgevt);
			break;
		case PtraceEngine::ExitedEvent:
			m_stopGeneration++;
			m_targetActive = false;
			if (m_stepper)
				m_stepper->Cancel();
			ClearBreakpoints();
			m_lastStopReason = ProcessExited;
			m_exitCode = event.signal ? 128 + event.signal : event.exitCode;
			dbgevt.type = TargetExitedEventType;
			dbgevt.data.exitData.exitCode = m_exitCode;
			PostDebuggerEvent(dbgevt);
			break;
		case PtraceEngine::DetachedEvent:
			m_targetActive = false;
			if (m_stepper)
				m_stepper->Cancel();
			ClearBreakpoints();
			dbgevt.type = DetachedEventType;
			PostDebuggerEvent(dbgevt);
			break;
		case PtraceEngine::TaskEvent:
			// The engine runs these itself
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
		std::vector<DebugProcess> processes;
		for (const auto& process : ListProcesses())
			processes.push_back(DebugProcess(process.pid, process.name, process.commandLine));
		return processes;
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


	bool PtraceAdapter::ReadRegisterOf(uint32_t tid, const std::string& name, uint64_t& value)
	{
		auto arch = m_arch.load();
		auto info = arch ? arch->Find(name) : nullptr;
		std::vector<uint8_t> data;
		if (!m_engine || !info || !m_engine->GetRegisterSet(tid, info->regset, data) || !RegisterInBounds(*info, data))
			return false;

		value = (uint64_t)RegisterFromBytes(*info, data, 0).m_value;
		return true;
	}


	std::vector<DebugFrame> PtraceAdapter::GetFramesOfThread(uint32_t tid)
	{
		std::vector<DebugFrame> frames;
		auto arch = m_arch.load();
		auto pcInfo = arch ? arch->Find(arch->pc) : nullptr;
		uint64_t pc, sp, fp = 0;
		if (!m_engine || !pcInfo || m_engine->IsRunning() || !ReadRegisterOf(tid, arch->pc, pc)
			|| !ReadRegisterOf(tid, arch->sp, sp))
			return frames;
		// Without a frame pointer register there is only the one frame
		if (!arch->fp.empty())
			ReadRegisterOf(tid, arch->fp, fp);

		std::vector<std::pair<uint64_t, uint64_t>> executable;
		for (const auto& map : m_engine->GetMaps())
		{
			if (map.execute)
				executable.emplace_back(map.start, map.end);
		}
		std::sort(executable.begin(), executable.end());

		size_t wordSize = pcInfo->size;
		auto isExecutable = [&executable](uint64_t address) {
			auto it = std::upper_bound(executable.begin(), executable.end(), std::make_pair(address, UINT64_MAX));
			return it != executable.begin() && address < std::prev(it)->second;
		};
		auto readWord = [this, wordSize](uint64_t address, uint64_t& value) {
			value = 0;
			return m_engine->ReadMemory(address, &value, wordSize);
		};

		auto modules = GetModules();
		size_t index = 0;
		for (const auto& record : UnwindFramePointers(pc, sp, fp, wordSize, readWord, isExecutable))
		{
			std::string functionName;
			uint64_t functionStart = 0;
			std::string moduleName = "<unknown>";
			for (const auto& module : modules)
			{
				if (record.pc < module.base || record.pc >= module.base + module.size)
					continue;

				moduleName = module.shortName;
				auto elf = GetElf(module.path);
				uint64_t bias = module.base - (elf ? elf->linkBase : 0);
				if (auto symbol = elf ? FindElfSymbol(*elf, record.pc - bias) : nullptr)
				{
					functionName = symbol->name;
					functionStart = symbol->address + bias;
				}
				break;
			}

			frames.push_back(
				DebugFrame(index++, record.pc, record.sp, record.fp, functionName, functionStart, moduleName));
		}
		return frames;
	}


	DebugBreakpoint PtraceAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
	{
		if (!m_engine || !m_targetActive)
			return DebugBreakpoint();

		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [address](const DebugBreakpoint& bp) {
			return bp.m_address == address;
		});
		if (it != m_breakpoints.end())
			return *it;

		if (!AcquireBreakpoint(address))
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
		auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [&breakpoint](const DebugBreakpoint& bp) {
			return bp.m_address == breakpoint.m_address;
		});
		if (!m_engine || it == m_breakpoints.end() || !ReleaseBreakpoint(breakpoint.m_address))
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


	std::vector<PtraceModuleInfo> PtraceAdapter::GetModules()
	{
		if (!m_engine)
			return {};

		std::lock_guard<std::mutex> lock(m_moduleMutex);
		uint64_t generation = m_stopGeneration;
		if (m_moduleGeneration != generation)
		{
			m_modules = BuildModules(m_engine->GetMaps(), [this](uint64_t address) {
				uint8_t magic[4];
				return m_engine->ReadMemory(address, magic, sizeof(magic))
					&& memcmp(magic,
						   "\x7f"
						   "ELF",
						   4)
					== 0;
			});
			m_moduleGeneration = generation;
		}
		return m_modules;
	}


	std::shared_ptr<ElfInfo> PtraceAdapter::GetElf(const std::string& path)
	{
		std::lock_guard<std::mutex> lock(m_moduleMutex);
		auto it = m_elfCache.find(path);
		if (it != m_elfCache.end())
			return it->second;

		// A file that cannot be read is remembered as well, so that it is not tried for every frame
		auto elf = std::make_shared<ElfInfo>();
		if (!ReadElfFile(path, *elf))
			elf = nullptr;
		m_elfCache[path] = elf;
		return elf;
	}


	void PtraceAdapter::ResetTargetState()
	{
		std::lock_guard<std::mutex> lock(m_moduleMutex);
		m_elfCache.clear();
		m_modules.clear();
		m_moduleGeneration = UINT64_MAX;
		m_loaderBreakpoint = 0;
	}


	// The dynamic loader calls _dl_debug_state every time it changes the list of libraries. Stopping there is how
	// a breakpoint in a library gets placed before the library runs, and how libraries that are loaded later are found.
	void PtraceAdapter::SetUpLoaderBreakpoint()
	{
		if (!m_engine)
			return;

		std::error_code error;
		auto exe = std::filesystem::read_symlink("/proc/" + std::to_string(m_engine->GetPid()) + "/exe", error);
		auto elf = error ? nullptr : GetElf(exe.string());
		if (!elf || elf->interpreter.empty())
			return;

		for (const auto& module : GetModules())
		{
			if (!DebugModule::IsSameBaseModule(module.path, elf->interpreter))
				continue;

			auto loader = GetElf(module.path);
			if (!loader)
				return;

			for (const auto& symbol : loader->symbols)
			{
				if (symbol.name != "_dl_debug_state")
					continue;

				uint64_t address = symbol.address + module.base - loader->linkBase;
				if (AcquireBreakpoint(address))
					m_loaderBreakpoint = address;
				return;
			}
			return;
		}
	}


	std::vector<DebugModule> PtraceAdapter::GetModuleList()
	{
		std::vector<DebugModule> modules;
		for (const auto& module : GetModules())
			modules.push_back(DebugModule(module.path, module.shortName, module.base, module.size, true));
		return modules;
	}


	std::vector<DebugMemoryRegion> PtraceAdapter::GetMemoryMap()
	{
		std::vector<DebugMemoryRegion> regions;
		if (!m_engine)
			return regions;

		for (const auto& map : m_engine->GetMaps())
		{
			if (map.end > map.start)
				regions.push_back(DebugMemoryRegion(
					map.start, map.end - map.start, map.path, map.read, map.write, map.execute, map.shared));
		}
		return regions;
	}


	std::vector<DebugSymbol> PtraceAdapter::GetSymbolsForModule(const DebugModule& module)
	{
		std::vector<DebugSymbol> symbols;
		const PtraceModuleInfo* match = nullptr;
		auto modules = GetModules();
		for (const auto& candidate : modules)
		{
			// Prefer the module at the same address, since two modules can have the same name
			if (candidate.base == module.m_address)
			{
				match = &candidate;
				break;
			}
			if (!match && module.IsSameBaseModule(candidate.path))
				match = &candidate;
		}

		auto elf = match ? GetElf(match->path) : nullptr;
		if (!elf)
			return symbols;

		uint64_t bias = match->base - elf->linkBase;
		symbols.reserve(elf->symbols.size());
		for (const auto& symbol : elf->symbols)
		{
			symbols.push_back(DebugSymbol(symbol.name, match->shortName + "!" + symbol.name, symbol.name,
				symbol.address + bias, symbol.size, symbol.isFunction));
		}
		return symbols;
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
		if (m_stepper)
			m_stepper->Cancel();
		m_stopGeneration++;
		if (!m_engine || !m_engine->Resume(false, 0))
			return false;

		DebuggerEvent event;
		event.type = ResumeEventType;
		PostDebuggerEvent(event);
		return true;
	}


	bool PtraceAdapter::StepInto()
	{
		if (m_stepper)
			m_stepper->Cancel();
		m_stopGeneration++;
		if (!m_engine || !m_engine->Resume(true, m_activeThreadId))
			return false;

		DebuggerEvent event;
		event.type = StepIntoEventType;
		PostDebuggerEvent(event);
		return true;
	}


	// The controller calls these with the adapter lock held, and working out what to do needs the analysis of
	// Binary Ninja, which must not be called under that lock. So the work is done on the thread of the events, and the
	// controller waits for the stop as it does for any other step.
	bool PtraceAdapter::StepOver()
	{
		if (!m_engine || !m_stepper || m_engine->IsRunning())
			return false;

		m_stepper->Cancel();
		m_stopGeneration++;
		uint32_t tid = m_activeThreadId;
		m_engine->PostTask([this, tid] { DoStepOver(tid); });

		DebuggerEvent event;
		event.type = StepOverEventType;
		PostDebuggerEvent(event);
		return true;
	}


	bool PtraceAdapter::StepReturn()
	{
		if (!m_engine || !m_stepper || m_engine->IsRunning())
			return false;

		m_stepper->Cancel();
		m_stopGeneration++;
		uint32_t tid = m_activeThreadId;
		m_engine->PostTask([this, tid] { DoStepReturn(tid); });

		DebuggerEvent event;
		event.type = StepOverEventType;
		PostDebuggerEvent(event);
		return true;
	}


	// The controller is waiting for a stop, so a step that cannot be done still has to end in one
	void PtraceAdapter::FailStep(const std::string& message)
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = "Step failed";
		event.data.errorData.error = fmt::format("PTRACE: {}", message);
		PostDebuggerEvent(event);

		m_lastStopReason = UnknownReason;
		DebuggerEvent stopped;
		stopped.type = AdapterStoppedEventType;
		stopped.data.targetStoppedData.reason = UnknownReason;
		stopped.data.targetStoppedData.lastActiveThread = m_activeThreadId;
		PostDebuggerEvent(stopped);
	}


	size_t PtraceAdapter::GetCallLength(uint64_t pc)
	{
		auto data = GetData();
		auto arch = data ? data->GetDefaultArchitecture() : nullptr;
		if (!arch)
			return 0;

		DataBuffer buffer = ReadMemory(pc, arch->GetMaxInstructionLength());
		size_t bytesRead = buffer.GetLength();
		if (bytesRead == 0)
			return 0;

		Ref<LowLevelILFunction> il = new LowLevelILFunction(arch, nullptr);
		il->SetCurrentAddress(arch, pc);
		arch->GetInstructionLowLevelIL((const uint8_t*)buffer.GetData(), pc, bytesRead, *il);
		if (il->GetInstructionCount() == 0 || (*il)[0].operation != LLIL_CALL)
			return 0;

		InstructionInfo info;
		if (!arch->GetInstructionInfo((const uint8_t*)buffer.GetData(), pc, bytesRead, info))
			return 0;
		return info.length;
	}


	std::vector<uint64_t> PtraceAdapter::GetReturnSites(uint64_t pc)
	{
		std::vector<uint64_t> sites;
		auto data = GetData();
		auto functions = data ? data->GetAnalysisFunctionsContainingAddress(pc) : std::vector<Ref<Function>>();
		if (functions.empty() || !functions[0])
			return sites;

		auto il = functions[0]->GetLowLevelIL();
		if (!il)
			return sites;

		for (size_t i = 0; i < il->GetInstructionCount(); i++)
		{
			auto instruction = il->GetInstruction(i);
			if (instruction.operation == LLIL_RET || instruction.operation == LLIL_TAILCALL)
				sites.push_back(instruction.address);
		}
		return sites;
	}


	void PtraceAdapter::DoStepOver(uint32_t tid)
	{
		auto arch = m_arch.load();
		auto pcInfo = arch ? arch->Find(arch->pc) : nullptr;
		uint64_t pc, sp;
		if (!pcInfo || !ReadRegisterOf(tid, arch->pc, pc) || !ReadRegisterOf(tid, arch->sp, sp))
		{
			FailStep("could not read the registers of the thread");
			return;
		}

		if (!m_stepper->StepOver(tid, pc, sp, GetCallLength(pc), pcInfo->size))
			FailStep("could not step over the instruction");
	}


	void PtraceAdapter::DoStepReturn(uint32_t tid)
	{
		auto arch = m_arch.load();
		uint64_t pc, sp;
		if (!arch || !ReadRegisterOf(tid, arch->pc, pc) || !ReadRegisterOf(tid, arch->sp, sp))
		{
			FailStep("could not read the registers of the thread");
			return;
		}

		// Without an analysis of the function, its caller is found from the frame pointers
		auto sites = GetReturnSites(pc);
		uint64_t returnAddress = 0, returnSp = 0;
		if (sites.empty())
		{
			auto frames = GetFramesOfThread(tid);
			if (frames.size() >= 2)
			{
				returnAddress = frames[1].m_pc;
				returnSp = frames[1].m_sp;
			}
		}

		// A return instruction has the stack pointer of the function or above it, on every ABI that keeps the return
		// address on the stack, as well as on those that do not once the epilogue has run
		if (!m_stepper->StepReturn(tid, pc, sp, sites, returnAddress, returnSp))
			FailStep("could not find where the function returns");
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
		case DebugAdapterSupportStepOver:
		case DebugAdapterSupportStepReturn:
		case DebugAdapterSupportThreads:
		case DebugAdapterSupportModules:
		case DebugAdapterSupportSymbols:
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
		m_engineBreakpointRefs.clear();
	}


	bool PtraceAdapter::AcquireBreakpoint(uint64_t address)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		if (!m_engine)
			return false;

		int& count = m_engineBreakpointRefs[address];
		if (count == 0 && !m_engine->AddBreakpoint(address))
		{
			m_engineBreakpointRefs.erase(address);
			return false;
		}
		count++;
		return true;
	}


	bool PtraceAdapter::ReleaseBreakpoint(uint64_t address)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto it = m_engineBreakpointRefs.find(address);
		if (!m_engine || it == m_engineBreakpointRefs.end())
			return false;

		if (--it->second > 0)
			return true;

		m_engineBreakpointRefs.erase(it);
		return m_engine->RemoveBreakpoint(address);
	}


	bool PtraceAdapter::IsUserBreakpoint(uint64_t address)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		return std::any_of(m_breakpoints.begin(), m_breakpoints.end(), [address](const DebugBreakpoint& bp) {
			return bp.m_address == address;
		});
	}


	void PtraceAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
	{
		auto adapterSettings = GetAdapterSettings();
		BNSettingsScope scope = SettingsResourceScope;
		adapterSettings->Get<std::string>("common.inputFile", data, &scope);
		if (scope != SettingsResourceScope)
			adapterSettings->Set(
				"common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);

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
