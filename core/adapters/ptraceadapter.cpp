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
#include <sstream>
#include "ptraceadapter.h"
#include "ptracesignal.h"
#include "lowlevelilinstruction.h"
#include "../debuggercontroller.h"

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
		// ExcSyscall is the closest reason there is. It is the one of the Mach exception for a system call.
		if (event.syscall)
			return ExcSyscall;
		// Stopped at the handler of a signal, so it is the signal that is the reason
		if (event.signalHandler)
			return StopReasonFromLinuxSignal(event.signalHandler);
		if (event.trapOrigin == PtraceEngine::TrapOrigin::Target)
			return StopReasonFromLinuxSignal(event.signal);
		if (event.breakpoint || event.hardware)
			return Breakpoint;
		if (event.signal == SIGTRAP)
			return event.singleStep ? SingleStep : Breakpoint;
		return StopReasonFromLinuxSignal(event.signal);
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

		scope = SettingsResourceScope;
		for (const auto& text : adapterSettings->Get<std::vector<std::string>>("launch.redirectFileDescriptors", data, &scope))
		{
			if (text.empty())
				continue;

			PtraceEngine::FdRedirect redirect;
			std::string parseError;
			if (!ParseFdRedirect(text, redirect, parseError))
				return launchFailure(parseError);
			options.redirects.push_back(std::move(redirect));
		}

		CreateEngine(false);
		std::string error;
		if (!m_engine->Launch(options, error))
		{
			m_targetActive = false;
			return launchFailure(error);
		}
		return true;
	}


	void PtraceAdapter::CreateEngine(bool attached)
	{
		m_stepper.reset();
		m_engine.reset();
		ResetTargetState();
		m_attached = attached;
		m_stopAtSystemEntry = Settings::Instance()->Get<bool>("debugger.stopAtSystemEntryPoint");
		m_firstStop = true;
		m_targetActive = true;
		m_engine = std::make_unique<PtraceEngine>([this](const PtraceEngine::Event& event) {
			HandleEngineEvent(event);
		});
		SyncEngineSettings();
		m_stepper = std::make_unique<PtraceStepper>(
			*m_engine, [this](uint64_t address) { return AcquireBreakpoint(address); },
			[this](uint64_t address) { return ReleaseBreakpoint(address); });
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
			if (event.exec)
			{
				HandleExec(event);
				break;
			}
			if (m_firstStop)
			{
				m_firstStop = false;
				m_arch = m_engine->GetArch();
				if (!m_arch)
					LogWarn("PtraceAdapter: unsupported target architecture");

				// An attached target is long past its entry point, and it stops where it is
				if (!m_attached && Settings::Instance()->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction)
					AddBreakpoint(ModuleNameAndOffset(m_inputFile, m_entryPoint - m_start), 0);
				SetUpLoaderBreakpoint();
				if (m_attached)
					m_lastStopReason = InitialBreakpoint;
				else if (!m_stopAtSystemEntry)
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
			if (event.signalHandler)
			{
				auto arch = m_arch.load();
				DebuggerEvent message;
				message.type = BackendMessageEventType;
				message.data.messageData.message = fmt::format(
					"PTRACE: signal {} ({}) was delivered to thread {}, which is stopped at the start of its handler, "
					"0x{:x}\n",
					event.signalHandler, strsignal(event.signalHandler), event.tid,
					arch ? ReadArchRegister(arch->pc) : 0);
				PostDebuggerEvent(message);
			}
			if (event.syscall)
			{
				PtraceEngine::SyscallInfo info;
				DebuggerEvent message;
				message.type = BackendMessageEventType;
				if (m_engine->GetSyscallInfo(event.tid, info))
					message.data.messageData.message = "PTRACE: " + DescribeSyscallStop(event.tid, info) + "\n";
				else
					message.data.messageData.message = fmt::format(
						"PTRACE: thread {} is stopped at a system call, but its details could not be read, which needs "
						"Linux 5.3\n",
						event.tid);
				PostDebuggerEvent(message);
			}
			dbgevt.type = AdapterStoppedEventType;
			dbgevt.data.targetStoppedData.reason = m_lastStopReason;
			dbgevt.data.targetStoppedData.lastActiveThread = event.tid;
			PostDebuggerEvent(dbgevt);
			break;
		case PtraceEngine::ExitedEvent:
			m_stopGeneration++;
			m_targetActive = false;
			ForgetKnownBreakpoints();
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
			ForgetKnownBreakpoints();
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
		if (pid == 0)
		{
			DebuggerEvent event;
			event.type = LaunchFailureEventType;
			event.data.errorData.shortError = "Failed to attach to target";
			event.data.errorData.error = "PTRACE: no process id to attach to";
			PostDebuggerEvent(event);
			return false;
		}

		auto adapterSettings = GetAdapterSettings();
		auto data = GetData();
		BNSettingsScope scope = SettingsResourceScope;
		m_inputFile = adapterSettings->Get<std::string>("common.inputFile", data, &scope);
		if (m_inputFile.empty())
		{
			std::error_code error;
			auto exe = std::filesystem::read_symlink("/proc/" + std::to_string(pid) + "/exe", error);
			if (!error)
				m_inputFile = exe.string();
		}

		CreateEngine(true);
		std::string error;
		if (!m_engine->Attach(pid, error))
		{
			m_targetActive = false;
			DebuggerEvent event;
			event.type = LaunchFailureEventType;
			event.data.errorData.shortError = "Failed to attach to target";
			event.data.errorData.error = fmt::format("PTRACE: {}", error);
			PostDebuggerEvent(event);
			return false;
		}
		return true;
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

		RememberBreakpoint(address);
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
		if (std::none_of(m_knownBreakpoints.begin(), m_knownBreakpoints.end(),
				[&address](const KnownBreakpoint& known) { return known.location == address; }))
			m_knownBreakpoints.push_back({address, "", 0});
		return DebugBreakpoint();
	}


	bool PtraceAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto it = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [&breakpoint](const DebugBreakpoint& bp) {
			return bp.m_address == breakpoint.m_address;
		});
		if (!m_engine || it == m_breakpoints.end())
			return false;

		ModuleNameAndOffset location;
		bool known = ToModuleOffset(breakpoint.m_address, location);
		if (!ReleaseBreakpoint(breakpoint.m_address))
			return false;

		m_breakpoints.erase(it);
		std::erase_if(m_knownBreakpoints, [&](const KnownBreakpoint& k) {
			return k.appliedAddress == breakpoint.m_address || (known && k.location == location);
		});
		return true;
	}


	bool PtraceAdapter::RemoveBreakpoint(const ModuleNameAndOffset& address)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto known = std::find_if(m_knownBreakpoints.begin(), m_knownBreakpoints.end(),
			[&address](const KnownBreakpoint& k) { return k.location == address; });
		if (known != m_knownBreakpoints.end() && known->appliedAddress)
		{
			uint64_t appliedAddress = known->appliedAddress;
			auto breakpoint = std::find_if(m_breakpoints.begin(), m_breakpoints.end(),
				[appliedAddress](const DebugBreakpoint& bp) { return bp.m_address == appliedAddress; });
			if (breakpoint != m_breakpoints.end())
			{
				if (!ReleaseBreakpoint(appliedAddress))
					return false;
				m_breakpoints.erase(breakpoint);
			}
		}

		if (known == m_knownBreakpoints.end())
			return false;
		m_knownBreakpoints.erase(known);
		m_pendingBreakpoints.erase(std::remove(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address),
			m_pendingBreakpoints.end());
		return true;
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

		if (!m_engine->AddHardwareBreakpoint(address, hwType, size))
			return false;

		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		ModuleNameAndOffset location;
		if (ToModuleOffset(address, location))
		{
			PendingHardwareBreakpoint known(location, type, size);
			known.address = address;
			auto existing = std::find(m_knownHardwareBreakpoints.begin(), m_knownHardwareBreakpoints.end(), known);
			if (existing == m_knownHardwareBreakpoints.end())
				m_knownHardwareBreakpoints.push_back(known);
			else
				existing->address = address;
		}
		return true;
	}


	bool PtraceAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
	{
		PtraceHwType hwType;
		if (!m_engine || !m_targetActive || !HwTypeFromBreakpointType(type, hwType))
			return false;

		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		ModuleNameAndOffset location;
		bool known = ToModuleOffset(address, location);
		if (!m_engine->RemoveHardwareBreakpoint(address, hwType, size))
			return false;

		std::erase_if(m_knownHardwareBreakpoints, [&](const PendingHardwareBreakpoint& entry) {
			return entry.address == address
				|| (known && entry.isRelative && entry.location == location && entry.type == type && entry.size == size);
		});
		return true;
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
		if (std::find(m_knownHardwareBreakpoints.begin(), m_knownHardwareBreakpoints.end(), pending)
			== m_knownHardwareBreakpoints.end())
			m_knownHardwareBreakpoints.push_back(pending);
		return true;
	}


	bool PtraceAdapter::RemoveHardwareBreakpoint(
		const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		PendingHardwareBreakpoint pending(location, type, size);
		auto known = std::find(m_knownHardwareBreakpoints.begin(), m_knownHardwareBreakpoints.end(), pending);
		if (known == m_knownHardwareBreakpoints.end())
			return false;
		if (known->address && !RemoveHardwareBreakpoint(known->address, type, size))
			return false;
		m_knownHardwareBreakpoints.erase(
			std::remove(m_knownHardwareBreakpoints.begin(), m_knownHardwareBreakpoints.end(), pending),
			m_knownHardwareBreakpoints.end());
		m_pendingHardwareBreakpoints.erase(
			std::remove(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending),
			m_pendingHardwareBreakpoints.end());
		return true;
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

		std::lock_guard<std::mutex> syscallLock(m_syscallMutex);
		m_syscallEntries.clear();
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
		SyncEngineSettings();
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
		SyncEngineSettings();
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

		SyncEngineSettings();
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

		SyncEngineSettings();
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


	// The view analyzes one module, the input file. Its functions are only where that module is, so what the analysis
	// knows says nothing about an address outside of it, such as in another program after an exec.
	bool PtraceAdapter::IsInAnalyzedModule(uint64_t address)
	{
		for (const auto& module : GetModules())
		{
			if (DebugModule::IsSameBaseModule(module.path, m_inputFile) && address >= module.base
				&& address < module.base + module.size)
				return true;
		}
		return false;
	}


	bool PtraceAdapter::AnalyzedModuleLoaded()
	{
		for (const auto& module : GetModules())
		{
			if (DebugModule::IsSameBaseModule(module.path, m_inputFile))
				return true;
		}
		return false;
	}


	std::vector<uint64_t> PtraceAdapter::GetReturnSites(uint64_t pc)
	{
		std::vector<uint64_t> sites;
		if (!IsInAnalyzedModule(pc))
			return sites;

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


	static const char* BackendCommandHelp =
		"PTRACE backend commands:\n"
		"  syscall           continue until a thread is at the entry or the exit of a system call. The call is made.\n"
		"  sysemu            continue until a thread is at the entry of a system call, which is not made. Put the result\n"
		"                    in the return register of the target, and resume it with the usual buttons.\n"
		"  syscall-info      describe the system call that the active thread is stopped at\n"
		"  syscall-set F V   change the stop, on Linux 6.16 or newer: F is nr or arg0 to arg5 at an entry, or ret at an\n"
		"                    exit, and V is a number\n";


	std::string PtraceAdapter::InvokeBackendCommand(const std::string& command)
	{
		std::istringstream stream(command);
		std::vector<std::string> words;
		for (std::string word; stream >> word;)
			words.push_back(word);

		if (words.empty() || words[0] == "help" || words[0] == "?")
			return BackendCommandHelp;
		if (words[0] == "syscall" && words.size() == 1)
			return ContinueToSyscall(PtraceEngine::SyscallMode::Trace);
		if (words[0] == "sysemu" && words.size() == 1)
			return ContinueToSyscall(PtraceEngine::SyscallMode::Emulate);
		if (words[0] == "syscall-info" && words.size() == 1)
			return DescribeCurrentSyscall();
		if (words[0] == "syscall-set" && words.size() == 3)
			return SetSyscallField(words[1], words[2]);

		return fmt::format("PTRACE: unknown command \"{}\"\n{}", command, BackendCommandHelp);
	}


	std::string PtraceAdapter::DescribeSyscallStop(uint32_t tid, const PtraceEngine::SyscallInfo& info)
	{
		std::lock_guard<std::mutex> lock(m_syscallMutex);
		switch (info.op)
		{
		case PtraceEngine::SyscallInfo::Entry:
		case PtraceEngine::SyscallInfo::Seccomp:
			m_syscallEntries[tid] = info;
			return fmt::format("thread {} is entering {}", tid, DescribeSyscall(info));
		case PtraceEngine::SyscallInfo::Exit:
		{
			// The exit only has the result, so the call comes from the entry
			auto entry = m_syscallEntries.find(tid);
			std::string call = entry != m_syscallEntries.end() ? DescribeSyscall(entry->second) + " " : "";
			m_syscallEntries.erase(tid);
			return fmt::format("thread {} left {}{}", tid, call, DescribeSyscall(info));
		}
		default:
			return fmt::format("thread {}: {}", tid, DescribeSyscall(info));
		}
	}


	std::string PtraceAdapter::ContinueToSyscall(PtraceEngine::SyscallMode mode)
	{
		if (!m_engine || !m_targetActive)
			return "PTRACE: there is no target\n";
		if (m_engine->IsRunning())
			return "PTRACE: the target is running\n";
		auto arch = m_arch.load();
		if (mode == PtraceEngine::SyscallMode::Emulate && (!arch || !arch->sysemu))
			return "PTRACE: this architecture has no PTRACE_SYSEMU\n";

		SyncEngineSettings();
		if (m_stepper)
			m_stepper->Cancel();
		m_stopGeneration++;

		// The controller did not ask for this, so it has to be told that the target runs. That comes before the resume,
		// because a stop that comes quickly must not be the first of the two that the controller hears of.
		DebuggerEvent resumed;
		resumed.type = ResumeEventType;
		PostDebuggerEvent(resumed);

		if (m_engine->ResumeToSyscall(mode))
			return mode == PtraceEngine::SyscallMode::Trace
				? "PTRACE: running to the entry or the exit of the next system call\n"
				: "PTRACE: running to the entry of the next system call, which will not be made\n";

		DebuggerEvent stopped;
		stopped.type = AdapterStoppedEventType;
		stopped.data.targetStoppedData.reason = m_lastStopReason;
		stopped.data.targetStoppedData.lastActiveThread = m_activeThreadId;
		PostDebuggerEvent(stopped);
		return "PTRACE: the target could not be resumed\n";
	}


	std::string PtraceAdapter::DescribeCurrentSyscall()
	{
		if (!m_engine || !m_targetActive)
			return "PTRACE: there is no target\n";

		PtraceEngine::SyscallInfo info;
		if (m_engine->IsRunning() || !m_engine->GetSyscallInfo(m_activeThreadId, info))
			return "PTRACE: the system call information could not be read. The target has to be stopped, on Linux 5.3 or "
				   "newer.\n";

		std::string text = DescribeSyscall(info, true);
		if (info.op == PtraceEngine::SyscallInfo::Exit)
		{
			std::lock_guard<std::mutex> lock(m_syscallMutex);
			auto entry = m_syscallEntries.find(m_activeThreadId);
			if (entry != m_syscallEntries.end())
				text += "\nentered as " + DescribeSyscall(entry->second);
		}
		return "PTRACE: " + text + "\n";
	}


	std::string PtraceAdapter::SetSyscallField(const std::string& field, const std::string& value)
	{
		if (!m_engine || !m_targetActive || m_engine->IsRunning())
			return "PTRACE: the target has to be stopped\n";

		PtraceEngine::SyscallInfo info;
		if (!m_engine->GetSyscallInfo(m_activeThreadId, info)
			|| (info.op == PtraceEngine::SyscallInfo::None))
			return "PTRACE: the active thread is not stopped at a system call\n";

		char* end = nullptr;
		bool isEntry = info.op != PtraceEngine::SyscallInfo::Exit;
		if (field == "ret")
		{
			if (isEntry)
				return "PTRACE: ret can only be set at an exit\n";
			info.returnValue = strtoll(value.c_str(), &end, 0);
			// The kernel puts a value from -4095 to -1 in the register for an error
			info.isError = info.returnValue < 0 && info.returnValue >= -4095;
		}
		else if (field == "nr" || (field.size() == 4 && field.rfind("arg", 0) == 0 && field[3] >= '0' && field[3] <= '5'))
		{
			if (!isEntry)
				return fmt::format("PTRACE: {} can only be set at an entry\n", field);
			uint64_t number = strtoull(value.c_str(), &end, 0);
			if (field == "nr")
				info.number = number;
			else
				info.args[field[3] - '0'] = number;
		}
		else
		{
			return fmt::format("PTRACE: unknown field \"{}\", the fields are nr, arg0 to arg5 and ret\n", field);
		}

		if (value.empty() || !end || *end != '\0')
			return fmt::format("PTRACE: \"{}\" is not a number\n", value);
		if (!m_engine->SetSyscallInfo(m_activeThreadId, info))
			return "PTRACE: the kernel did not take the change. It needs Linux 6.16.\n";
		return "PTRACE: changed. " + DescribeCurrentSyscall();
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
		// The system call that the active thread is stopped at, for scripts
		if (name != "syscall" || !m_engine || !m_targetActive || m_engine->IsRunning())
			return nullptr;

		PtraceEngine::SyscallInfo info;
		if (!m_engine->GetSyscallInfo(m_activeThreadId, info))
			return nullptr;

		static const char* const ops[] = {"none", "entry", "exit", "seccomp"};
		std::map<std::string, Ref<Metadata>> values;
		values["op"] = new Metadata(std::string(ops[info.op]));
		values["arch"] = new Metadata((uint64_t)info.arch);
		values["pc"] = new Metadata(info.instructionPointer);
		values["sp"] = new Metadata(info.stackPointer);
		if (info.op == PtraceEngine::SyscallInfo::Entry || info.op == PtraceEngine::SyscallInfo::Seccomp)
		{
			const char* syscallName = SyscallName(info.arch, info.number);
			values["number"] = new Metadata(info.number);
			values["name"] = new Metadata(std::string(syscallName ? syscallName : ""));
			values["args"] = new Metadata(std::vector<uint64_t>(info.args, info.args + 6));
		}
		if (info.op == PtraceEngine::SyscallInfo::Exit)
		{
			values["return"] = new Metadata(info.returnValue);
			values["is_error"] = new Metadata(info.isError);
		}
		return new Metadata(values);
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

		// The logical module-relative breakpoint remains authoritative after it has been applied. A loader rendezvous
		// may mean that its mapping disappeared, was replaced at the same address, or moved to another base.
		for (size_t index = 0; index < m_knownBreakpoints.size(); index++)
		{
			auto location = m_knownBreakpoints[index].location;
			uint64_t oldAddress = m_knownBreakpoints[index].appliedAddress;
			uint64_t address = 0;
			bool resolved = ResolveModuleAddress(location, address);

			if (oldAddress && (!resolved || oldAddress != address))
			{
				auto applied = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [oldAddress](const DebugBreakpoint& bp) {
					return bp.m_address == oldAddress;
				});
				if (applied != m_breakpoints.end())
				{
					if (!ReleaseBreakpoint(oldAddress, false))
						continue;
					m_breakpoints.erase(applied);
				}
				m_knownBreakpoints[index].appliedAddress = 0;
			}

			if (!resolved)
				continue;

			auto applied = std::find_if(m_breakpoints.begin(), m_breakpoints.end(), [address](const DebugBreakpoint& bp) {
				return bp.m_address == address;
			});
			if (applied != m_breakpoints.end())
			{
				if (m_engine->AddBreakpoint(address))
					m_knownBreakpoints[index].appliedAddress = address;
			}
			else if (AddBreakpoint(address, 0).m_address != 0)
			{
				// RememberBreakpoint, called by AddBreakpoint, records this address on the same logical entry.
				m_knownBreakpoints[index].appliedAddress = address;
			}
		}

		m_pendingBreakpoints.clear();
		for (const auto& known : m_knownBreakpoints)
		{
			if (!known.appliedAddress)
				m_pendingBreakpoints.push_back(known.location);
		}

		// Breakpoints outside a module have no logical location to reconcile, but an idempotent add still repairs a
		// replacement mapping at the same absolute address.
		for (const auto& breakpoint : m_breakpoints)
		{
			bool logical = std::any_of(m_knownBreakpoints.begin(), m_knownBreakpoints.end(),
				[&breakpoint](const KnownBreakpoint& known) { return known.appliedAddress == breakpoint.m_address; });
			if (!logical)
				m_engine->AddBreakpoint(breakpoint.m_address);
		}

		for (auto& known : m_knownHardwareBreakpoints)
		{
			uint64_t address = 0;
			bool resolved = ResolveModuleAddress(known.location, address);
			PtraceHwType hwType;
			if (!HwTypeFromBreakpointType(known.type, hwType))
				continue;

			if (known.address && (!resolved || known.address != address))
			{
				if (!m_engine->RemoveHardwareBreakpoint(known.address, hwType, known.size))
					continue;
				known.address = 0;
			}
			if (resolved && !known.address && m_engine->AddHardwareBreakpoint(address, hwType, known.size))
				known.address = address;
		}
		m_pendingHardwareBreakpoints.clear();
		for (const auto& known : m_knownHardwareBreakpoints)
		{
			if (!known.address)
				m_pendingHardwareBreakpoints.push_back(known);
		}
	}


	// The target has started another program. The engine has already thrown away everything that belonged to the old
	// one, so this does the same for what the adapter keeps, and sets the new program up the way the first stop set up
	// the first.
	void PtraceAdapter::HandleExec(const PtraceEngine::Event& event)
	{
		// A step that the exec cut short is over, and the stop is the end of it
		bool wasStepping = event.singleStep || (m_stepper && m_stepper->IsActive());
		if (m_stepper)
			m_stepper->Cancel();
		ClearBreakpoints();
		ResetTargetState();

		m_arch = m_engine->GetArch();
		if (!m_arch)
			LogWarn("PtraceAdapter: unsupported target architecture");

		{
			std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
			m_pendingBreakpoints.clear();
			for (auto& known : m_knownBreakpoints)
			{
				known.appliedAddress = 0;
				m_pendingBreakpoints.push_back(known.location);
			}
			for (auto& known : m_knownHardwareBreakpoints)
				known.address = 0;
			m_pendingHardwareBreakpoints = m_knownHardwareBreakpoints;
		}

		std::error_code error;
		auto program = std::filesystem::read_symlink("/proc/" + std::to_string(m_engine->GetPid()) + "/exe", error);
		DebuggerEvent message;
		message.type = BackendMessageEventType;
		message.data.messageData.message = fmt::format("PTRACE: the process started {}\n", program.string());
		PostDebuggerEvent(message);

		SetUpLoaderBreakpoint();
		ApplyBreakpoints();
		std::string resolved = ResolveBreakpointsByName(program.string());
		resolved += RefreshSymbolsAfterExec(program.string());
		m_lastStopReason = UnknownReason;
		ReportAfterExec(resolved);

		BNSettingsScope scope = SettingsResourceScope;
		bool stopOnExec = GetAdapterSettings()->Get<bool>("common.stopOnExec", GetData(), &scope);
		if (!stopOnExec && !wasStepping)
		{
			m_engine->Resume(false, 0);
			return;
		}

		DebuggerEvent stopped;
		stopped.type = AdapterStoppedEventType;
		stopped.data.targetStoppedData.reason = UnknownReason;
		stopped.data.targetStoppedData.lastActiveThread = event.tid;
		PostDebuggerEvent(stopped);
	}


	// Says what the exec has left as it was, since the view still analyzes the program that the target started with
	void PtraceAdapter::ReportAfterExec(const std::string& resolved)
	{
		std::string text = resolved;
		if (!AnalyzedModuleLoaded())
			text += fmt::format(
				"PTRACE: this view analyzes {}, which the target is no longer running. Its analysis does not "
				"apply to the new program, and stepping out of a function follows the frame pointers "
				"instead.\n",
				DebugModule::GetPathBaseName(m_inputFile));

		{
			std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
			if (!m_pendingBreakpoints.empty())
			{
				text += fmt::format("PTRACE: {} breakpoint(s) are inactive, because their module is not loaded:",
					m_pendingBreakpoints.size());
				size_t shown = 0;
				for (const auto& location : m_pendingBreakpoints)
				{
					if (shown++ == 5)
					{
						text += fmt::format(" and {} more", m_pendingBreakpoints.size() - 5);
						break;
					}
					text += fmt::format(" {}+0x{:x}", DebugModule::GetPathBaseName(location.module), location.offset);
				}
				text += "\n";

				// Say how the ones at the start of a function can be found in the new program
				bool namedOnes = std::any_of(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(),
					[this](const ModuleNameAndOffset& location) {
						return std::any_of(m_knownBreakpoints.begin(), m_knownBreakpoints.end(),
							[&location](const KnownBreakpoint& k) {
								return k.location == location && !k.function.empty();
							});
					});
				if (namedOnes && !ResolveByNameEnabled())
					text +=
						"PTRACE: the ones at the start of a function can be found by its name in the new program, with "
						"the "
						"common.resolveBreakpointsByNameOnExec setting.\n";
			}
		}

		if (text.empty())
			return;

		DebuggerEvent message;
		message.type = BackendMessageEventType;
		message.data.messageData.message = text;
		PostDebuggerEvent(message);
	}


	// A breakpoint is known by the module that it is in, and its offset there, which stays true when the address does
	// not
	bool PtraceAdapter::FindModule(uint64_t address, PtraceModuleInfo& module)
	{
		for (const auto& candidate : GetModules())
		{
			if (address >= candidate.base && address < candidate.base + candidate.size)
			{
				module = candidate;
				return true;
			}
		}
		return false;
	}


	bool PtraceAdapter::ToModuleOffset(uint64_t address, ModuleNameAndOffset& location)
	{
		PtraceModuleInfo module;
		if (!FindModule(address, module))
			return false;

		location = ModuleNameAndOffset(module.path, address - module.base);
		return true;
	}


	// Keeps a breakpoint by its module and offset, and by the function that it is at the start of
	void PtraceAdapter::RememberBreakpoint(uint64_t address)
	{
		PtraceModuleInfo module;
		if (!FindModule(address, module))
			return;

		std::string function;
		if (auto elf = GetElf(module.path))
		{
			uint64_t bias = module.base - elf->linkBase;
			auto symbol = FindElfSymbol(*elf, address - bias);
			if (symbol && symbol->isFunction && symbol->address + bias == address)
				function = symbol->name;
		}

		ModuleNameAndOffset location(module.path, address - module.base);
		auto it = std::find_if(m_knownBreakpoints.begin(), m_knownBreakpoints.end(),
			[&location](const KnownBreakpoint& known) { return known.location == location; });
		if (it == m_knownBreakpoints.end())
			m_knownBreakpoints.push_back({location, function, address});
		else if (it->function.empty())
			it->function = function;
		it = std::find_if(m_knownBreakpoints.begin(), m_knownBreakpoints.end(),
			[&location](const KnownBreakpoint& known) { return known.location == location; });
		if (it != m_knownBreakpoints.end())
			it->appliedAddress = address;
	}


	bool PtraceAdapter::ResolveByNameEnabled()
	{
		BNSettingsScope scope = SettingsResourceScope;
		return GetAdapterSettings()->Get<bool>("common.resolveBreakpointsByNameOnExec", GetData(), &scope);
	}


	// The symbols that were loaded into the view are at the addresses of the old program. A module that is still there
	// is loaded again, since it may have moved, and one that is gone is taken out. The controller is used through what
	// it offers for this, with modules made from what the adapter sees now, because its own list of modules is only
	// brought up to date at the next stop. This runs with none of the adapter's locks held, since it reaches into
	// Binary Ninja.
	std::string PtraceAdapter::RefreshSymbolsAfterExec(const std::string& program)
	{
		auto controller = GetController();
		if (!controller)
			return "";

		auto modules = GetModules();
		auto toDebugModule = [](const PtraceModuleInfo& module) {
			return DebugModule(module.path, module.shortName, module.base, module.size, true);
		};

		size_t reloaded = 0, removed = 0;
		bool programDone = false;
		for (const auto& name : controller->GetModulesWithLoadedSymbols())
		{
			auto it = std::find_if(modules.begin(), modules.end(), [&name](const PtraceModuleInfo& module) {
				return DebugModule::IsSameBaseModule(module.path, name);
			});
			if (it == modules.end())
			{
				controller->RemoveSymbolsForModule(name);
				removed++;
				continue;
			}

			controller->LoadSymbolsForModule(toDebugModule(*it));
			reloaded++;
			programDone = programDone || it->path == program;
		}

		bool loadedProgram = false;
		BNSettingsScope scope = SettingsResourceScope;
		if (!programDone && GetAdapterSettings()->Get<bool>("common.loadSymbolsAfterExec", GetData(), &scope))
		{
			for (const auto& module : modules)
			{
				if (module.path == program)
				{
					loadedProgram = controller->LoadSymbolsForModule(toDebugModule(module)) > 0;
					break;
				}
			}
		}

		if (!reloaded && !removed && !loadedProgram)
			return "";

		std::string text = "PTRACE: symbols in the view:";
		if (removed)
			text += fmt::format(" {} module(s) that are gone were taken out;", removed);
		if (reloaded)
			text += fmt::format(" {} that are still there were loaded again;", reloaded);
		if (loadedProgram)
			text += fmt::format(" the symbols of {} were loaded;", DebugModule::GetPathBaseName(program));
		text.back() = '\n';
		return text;
	}


	// GDB looks a breakpoint up again by its name when the target starts another program. A breakpoint here is a module
	// and an offset, which mean nothing in another program, so the ones at the start of a function are looked up by
	// that function's name in the main executable of the new program, when that is asked for.
	std::string PtraceAdapter::ResolveBreakpointsByName(const std::string& program)
	{
		if (!ResolveByNameEnabled())
			return "";

		PtraceModuleInfo main;
		bool found = false;
		for (const auto& module : GetModules())
		{
			if (module.path == program)
			{
				main = module;
				found = true;
				break;
			}
		}
		auto elf = found ? GetElf(program) : nullptr;
		if (!elf)
			return "";

		uint64_t bias = main.base - elf->linkBase;
		std::string text;
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		// Adding a breakpoint changes these lists, so it is done from a copy
		for (const auto& location : std::vector<ModuleNameAndOffset>(m_pendingBreakpoints))
		{
			auto known = std::find_if(m_knownBreakpoints.begin(), m_knownBreakpoints.end(),
				[&location](const KnownBreakpoint& k) { return k.location == location; });
			if (known == m_knownBreakpoints.end() || known->function.empty())
				continue;

			std::string function = known->function;
			bool ambiguous;
			auto symbol = FindElfFunctionByName(*elf, function, &ambiguous);
			if (!symbol)
			{
				if (ambiguous)
					text += fmt::format("PTRACE: {} is more than one function in {}, so its breakpoint is not moved\n",
						function, DebugModule::GetPathBaseName(program));
				continue;
			}

			uint64_t address = symbol->address + bias;
			if (!AddBreakpoint(address, 0).m_address)
				continue;

			// It belongs to the new program now, and the old place is forgotten
			text += fmt::format("PTRACE: the breakpoint at {}+0x{:x} ({}) is now at {}+0x{:x}\n",
				DebugModule::GetPathBaseName(location.module), location.offset, function,
				DebugModule::GetPathBaseName(program), address - main.base);
			std::erase_if(m_knownBreakpoints, [&location](const KnownBreakpoint& k) { return k.location == location; });
			m_pendingBreakpoints.erase(std::remove(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), location),
				m_pendingBreakpoints.end());
		}
		return text;
	}


	// The setting can be changed while the target is stopped, so the engine is told again before every resume
	void PtraceAdapter::SyncEngineSettings()
	{
		if (!m_engine)
			return;

		BNSettingsScope scope = SettingsResourceScope;
		m_engine->SetDebugSignalHandlers(
			GetAdapterSettings()->Get<bool>("common.debugSignalHandlers", GetData(), &scope));
	}


	void PtraceAdapter::ForgetKnownBreakpoints()
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		m_knownBreakpoints.clear();
		m_knownHardwareBreakpoints.clear();
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


	bool PtraceAdapter::ReleaseBreakpoint(uint64_t address, bool restore)
	{
		std::lock_guard<std::recursive_mutex> lock(m_breakpointMutex);
		auto it = m_engineBreakpointRefs.find(address);
		if (!m_engine || it == m_engineBreakpointRefs.end())
			return false;

		if (it->second > 1)
		{
			it->second--;
			return true;
		}

		bool removed = restore ? m_engine->RemoveBreakpoint(address) : m_engine->DiscardBreakpoint(address);
		if (removed)
			m_engineBreakpointRefs.erase(it);
		return removed;
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
		settings->RegisterSetting("common.debugSignalHandlers",
			R"({
			"title" : "Debug Signal Handlers",
			"type" : "boolean",
			"default" : false,
			"description" : "When the target is sent a signal that it has a handler for, stop at the first instruction of the handler. This includes the signals that would not stop the target otherwise, such as SIGCHLD, SIGALRM and SIGWINCH. Signals without a handler are not affected, and neither is stepping. A change takes effect the next time the target is resumed.",
			"readOnly" : false
			})");
		settings->RegisterSetting("common.loadSymbolsAfterExec",
			R"({
			"title" : "Load Symbols After Exec",
			"type" : "boolean",
			"default" : false,
			"description" : "When the target starts another program, load the symbols of that program into the view. The symbols that were already loaded into the view are always brought up to date after an exec: the ones for modules that are gone are removed, and the others are loaded again.",
			"readOnly" : false
			})");
		settings->RegisterSetting("common.resolveBreakpointsByNameOnExec",
			R"({
			"title" : "Find Breakpoints By Function Name After Exec",
			"type" : "boolean",
			"default" : false,
			"description" : "When the target starts another program, look up the breakpoints that are at the start of a function by the name of that function in the main executable of the new program, the way GDB does. Otherwise a breakpoint belongs to its module, and stays inactive while that module is not loaded. Only a name that is exactly one function in the new program is used, and only breakpoints at the very start of a function.",
			"readOnly" : false
			})");
		settings->RegisterSetting("common.stopOnExec",
			R"({
			"title" : "Stop On Exec",
			"type" : "boolean",
			"default" : false,
			"description" : "Stop the target when it starts another program with exec. Otherwise the target carries on with the new program, and the debugger says so in its messages.",
			"readOnly" : false
			})");
		settings->RegisterSetting("launch.redirectFileDescriptors",
			R"({
			"title" : "Redirect File Descriptors",
			"type" : "array",
			"sorted" : false,
			"default" : [],
			"description" : "Sets file descriptors of the target before it starts, written the way a shell writes them, and applied in order. The forms are: [\"0<input.txt\"] to read descriptor 0 from a file, [\"1>out.txt\"] to write it to a file, [\"1>>out.txt\"] to append to it, [\"3<>data.bin\"] to open it for reading and writing, [\"2>&1\"] to make descriptor 2 a copy of descriptor 1, and [\"4>&-\"] to close it. Without a number it is 0 for < and 1 for the others. Files are created when they do not exist, and a relative path is relative to the working directory. Without a redirect, descriptors 0, 1 and 2 are the terminal of the debugger. A descriptor that is redirected to a file no longer reaches the terminal, and input written to the target no longer reaches it if descriptor 0 is redirected. This has no effect when attaching to a process.",
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
