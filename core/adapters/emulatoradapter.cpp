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

#include "emulatoradapter.h"
#include <fmt/format.h>

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;


// ─── EmulatorAdapter ─────────────────────────────────────────────────────────

EmulatorAdapter::EmulatorAdapter(BinaryView* data) :
	DebugAdapter(data)
{
	m_view = data;
	m_arch = data->GetDefaultArchitecture();

	// Snapshot segment info now, before the debugger memory overlay is installed by
	// CreateDebuggerBinaryView(). Once the overlay is in place, m_view's segments include
	// giant debugger-owned regions that cover the entire address space, so we can no longer
	// distinguish the original binary segments.
	for (auto& seg : data->GetSegments())
	{
		m_originalSegments.push_back(
			{seg->GetStart(), seg->GetDataOffset(), seg->GetDataLength(), (size_t)seg->GetLength()});
	}

	GenerateDefaultAdapterSettings(data);
}


EmulatorAdapter::~EmulatorAdapter()
{
}


void EmulatorAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("emulator.entryPoint", data, &scope);

	// Only populate if not already saved in the database
	if (scope != SettingsResourceScope)
	{
		uint64_t entryAddr = 0;

		// Try "main" / "_main" first
		auto mainSyms = data->GetSymbolsByName("main");
		if (mainSyms.empty())
			mainSyms = data->GetSymbolsByName("_main");
		for (auto& sym : mainSyms)
		{
			if (sym->GetType() == FunctionSymbol)
			{
				entryAddr = sym->GetAddress();
				break;
			}
		}

		// Fall back to binary entry point
		if (entryAddr == 0)
			entryAddr = data->GetEntryPoint();

		// Fall back to first function
		if (entryAddr == 0)
		{
			auto funcs = data->GetAnalysisFunctionList();
			if (!funcs.empty())
				entryAddr = funcs[0]->GetStart();
		}

		if (entryAddr != 0)
			adapterSettings->Set("emulator.entryPoint", fmt::format("{:x}", entryAddr), data, SettingsResourceScope);
	}

	// Populate default stack pointer
	scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("emulator.stackPointer", data, &scope);
	if (scope != SettingsResourceScope)
	{
		// Choose a reasonable default based on address size
		size_t addrSize = data->GetAddressSize();
		uint64_t defaultSp;
		if (addrSize >= 8)
			defaultSp = 0x7fff0000;  // 64-bit: mid-range user space
		else
			defaultSp = 0x7fff0000;  // 32-bit: typical stack region

		adapterSettings->Set("emulator.stackPointer", fmt::format("{:x}", defaultSp), data, SettingsResourceScope);
	}
}


// ─── Helpers ─────────────────────────────────────────────────────────────────

DebugStopReason EmulatorAdapter::MapStopReason(BNILEmulatorStopReason reason)
{
	switch (reason)
	{
	case ILEmulatorBreakpoint:
		return Breakpoint;
	case ILEmulatorHalt:
		return ProcessExited;
	case ILEmulatorInstructionLimit:
		return SingleStep;
	case ILEmulatorError:
	case ILEmulatorUnimplemented:
		// Map to a stop reason that triggers NotifyStopped so the UI shows
		// where the emulator stopped, like an exception in a real debugger.
		return IllegalInstruction;
	case ILEmulatorUserRequestedStop:
		return UserRequestedBreak;
	case ILEmulatorRunning:
		return SingleStep;
	default:
		return UnknownReason;
	}
}


void EmulatorAdapter::PostStopEvent(DebugStopReason reason)
{
	DebuggerEvent event;
	event.type = AdapterStoppedEventType;
	event.data.targetStoppedData.reason = reason;
	event.data.targetStoppedData.lastActiveThread = 1;
	event.data.targetStoppedData.exitCode = 0;
	event.data.targetStoppedData.data = nullptr;
	PostDebuggerEvent(event);
}


// ─── Lifecycle ───────────────────────────────────────────────────────────────

bool EmulatorAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return ExecuteWithArgs(path, "", "", configs);
}


Ref<Settings> EmulatorAdapter::GetAdapterSettings()
{
	return EmulatorAdapterType::GetAdapterSettings();
}


bool EmulatorAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	m_emulator = new LLILEmulator(m_view);

	// Read the entry point from adapter settings (pre-populated by GenerateDefaultAdapterSettings)
	auto adapterSettings = GetAdapterSettings();
	std::string entryPointStr = adapterSettings->Get<std::string>("emulator.entryPoint", m_view);

	if (entryPointStr.empty())
	{
		LogError("BNIL Emulator: no entry point configured");
		return false;
	}

	uint64_t entryAddr = 0;
	std::string parseError;
	if (!BinaryView::ParseExpression(m_view, entryPointStr, entryAddr, 0, parseError))
	{
		LogError("BNIL Emulator: failed to parse entry point '%s': %s",
			entryPointStr.c_str(), parseError.c_str());
		return false;
	}

	if (!m_emulator->SetEntryPoint(entryAddr))
	{
		LogError("BNIL Emulator: failed to set entry point at 0x%" PRIx64, entryAddr);
		return false;
	}

	// Map the original binary segments into the emulator's memory.
	// We use the segment snapshot captured in the constructor (before the debugger memory
	// overlay was installed) and read backing data from the Raw view at file offsets.
	std::string baseName = DebugModule::GetPathBaseName(m_view->GetFile()->GetOriginalFilename());
	auto rawView = m_view->GetFile()->GetViewOfType("Raw");
	for (auto& seg : m_originalSegments)
	{
		std::string segName = baseName;
		if (seg.dataLen > 0 && rawView)
		{
			std::vector<uint8_t> buf(seg.dataLen);
			size_t bytesRead = rawView->Read(buf.data(), seg.dataOffset, seg.dataLen);
			if (bytesRead > 0)
				m_emulator->MapMemory(seg.virtualAddr, buf.data(), bytesRead, segName);

			// Zero-fill the rest of the segment beyond data (BSS-like)
			if (seg.segLen > seg.dataLen)
				m_emulator->MapMemory(seg.virtualAddr + seg.dataLen, seg.segLen - seg.dataLen, segName);
		}
		else if (seg.segLen > 0)
		{
			m_emulator->MapMemory(seg.virtualAddr, seg.segLen, segName);
		}
	}

	// Map stack memory (1MB zero-filled region below the stack pointer)
	static constexpr size_t STACK_SIZE = 0x100000;  // 1MB

	// Set initial stack pointer and map stack memory
	std::string spStr = adapterSettings->Get<std::string>("emulator.stackPointer", m_view);
	if (!spStr.empty() && m_arch)
	{
		uint64_t spValue = 0;
		std::string spError;
		if (BinaryView::ParseExpression(m_view, spStr, spValue, 0, spError))
		{
			uint32_t spReg = m_arch->GetStackPointerRegister();
			m_emulator->SetRegister(spReg, spValue);

			// Map stack region: [sp - STACK_SIZE, sp + page_size)
			uint64_t stackBase = spValue - STACK_SIZE;
			m_emulator->MapMemory(stackBase, STACK_SIZE + 0x1000, "stack");
		}
	}

	// No call hook — let the emulator enter callees via EnterFunction naturally.

	// Apply emulator settings
	bool nopExternals = adapterSettings->Get<bool>("emulator.nopUnknownExternals", m_view);
	m_emulator->SetNopUnknownExternals(nopExternals);

	// Wire stdout to Target Console
	m_emulator->SetStdoutCallback([this](LLILEmulator*, const std::string& data) {
		DebuggerEvent event;
		event.type = StdoutMessageEventType;
		event.data.messageData.message = data;
		PostDebuggerEvent(event);
	});

	// Wire stdin from Target Console buffer
	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinBuffer.clear();
		m_stdinClosed = false;
	}
	m_emulator->SetStdinCallback([this](LLILEmulator*, char* buf, size_t maxLen) -> size_t {
		std::unique_lock<std::mutex> lock(m_stdinMutex);
		m_stdinCV.wait(lock, [this]() { return !m_stdinBuffer.empty() || m_stdinClosed; });
		if (m_stdinClosed && m_stdinBuffer.empty())
			return 0;
		size_t n = std::min(maxLen, m_stdinBuffer.size());
		memcpy(buf, m_stdinBuffer.data(), n);
		m_stdinBuffer.erase(0, n);
		return n;
	});

	// Re-apply any breakpoints that were set before this launch (e.g., on a second launch).
	for (auto& bp : m_breakpoints)
		m_emulator->AddBreakpoint(bp.m_address);

	// Load saved state file if specified
	std::string stateFile = adapterSettings->Get<std::string>("emulator.stateFile", m_view);
	if (!stateFile.empty())
	{
		FILE* f = fopen(stateFile.c_str(), "r");
		if (f)
		{
			fseek(f, 0, SEEK_END);
			long size = ftell(f);
			fseek(f, 0, SEEK_SET);
			std::string json(size, '\0');
			fread(json.data(), 1, size, f);
			fclose(f);
			if (!m_emulator->LoadState(json))
				LogWarn("Failed to load emulator state from: %s", stateFile.c_str());
		}
		else
		{
			LogWarn("Could not open state file: %s", stateFile.c_str());
		}
	}

	m_running = true;
	m_exitCode = 0;

	// Post initial stop event
	PostStopEvent(InitialBreakpoint);
	return true;
}


bool EmulatorAdapter::Attach(std::uint32_t pid)
{
	return false;
}


bool EmulatorAdapter::Connect(const std::string& server, std::uint32_t port)
{
	return false;
}


bool EmulatorAdapter::Detach()
{
	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinClosed = true;
		m_stdinCV.notify_all();
	}

	m_emulator = nullptr;
	m_running = false;

	DebuggerEvent event;
	event.type = DetachedEventType;
	PostDebuggerEvent(event);
	return true;
}


bool EmulatorAdapter::Quit()
{
	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinClosed = true;
		m_stdinCV.notify_all();
	}

	m_emulator = nullptr;
	m_running = false;

	DebuggerEvent event;
	event.type = TargetExitedEventType;
	event.data.exitData.exitCode = m_exitCode;
	PostDebuggerEvent(event);
	return true;
}


// ─── Process / Thread ────────────────────────────────────────────────────────

std::vector<DebugProcess> EmulatorAdapter::GetProcessList()
{
	return {DebugProcess(1, "emulator")};
}


std::uint32_t EmulatorAdapter::GetActivePID()
{
	return 1;
}


std::vector<DebugThread> EmulatorAdapter::GetThreadList()
{
	uint64_t addr = m_emulator ? m_emulator->GetCurrentAddress() : 0;
	return {DebugThread(1, addr)};
}


DebugThread EmulatorAdapter::GetActiveThread() const
{
	uint64_t addr = m_emulator ? m_emulator->GetCurrentAddress() : 0;
	return DebugThread(1, addr);
}


std::uint32_t EmulatorAdapter::GetActiveThreadId() const
{
	return 1;
}


bool EmulatorAdapter::SetActiveThread(const DebugThread& thread)
{
	return true;
}


bool EmulatorAdapter::SetActiveThreadId(std::uint32_t tid)
{
	return true;
}


bool EmulatorAdapter::SuspendThread(std::uint32_t tid)
{
	return false;
}


bool EmulatorAdapter::ResumeThread(std::uint32_t tid)
{
	return false;
}


std::vector<DebugFrame> EmulatorAdapter::GetFramesOfThread(std::uint32_t tid)
{
	if (!m_emulator)
		return {};

	auto callStack = m_emulator->GetCallStack();
	if (callStack.empty())
		return {};

	std::string moduleName = DebugModule::GetPathBaseName(m_view->GetFile()->GetOriginalFilename());
	uint64_t sp = 0;
	if (m_arch)
	{
		uint32_t spReg = m_arch->GetStackPointerRegister();
		sp = static_cast<uint64_t>(m_emulator->GetRegister(spReg));
	}

	std::vector<DebugFrame> frames;
	for (size_t i = 0; i < callStack.size(); i++)
	{
		auto& entry = callStack[i];
		// For frame 0, returnAddress is actually the current PC
		uint64_t pc = entry.returnAddress;
		uint64_t funcStart = entry.functionAddress;

		// Leave the function name empty on purpose: DebuggerThreads::SymbolizeFrames fills it
		// in from BN analysis *after* the adapter lock is released. Resolving it here would call
		// into BN core while holding the adapter lock (GetFramesOfThread runs under it), inverting
		// the adapter-lock / analysis-lock order and deadlocking against the UI. See
		// DebuggerThreads::Update and its "Never hold the adapter lock across [SymbolizeFrames]" note.
		frames.push_back(DebugFrame(i, pc, sp, 0, "", funcStart, moduleName));
	}

	return frames;
}


// ─── Breakpoints ─────────────────────────────────────────────────────────────

DebugBreakpoint EmulatorAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
	if (m_emulator)
		m_emulator->AddBreakpoint(address);

	DebugBreakpoint bp(address, m_nextBreakpointId++, true);
	m_breakpoints.push_back(bp);
	return bp;
}


DebugBreakpoint EmulatorAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	return {};
}


bool EmulatorAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	if (m_emulator)
		m_emulator->RemoveBreakpoint(breakpoint.m_address);

	m_breakpoints.erase(
		std::remove_if(m_breakpoints.begin(), m_breakpoints.end(),
			[&](const DebugBreakpoint& bp) { return bp.m_address == breakpoint.m_address; }),
		m_breakpoints.end());
	return true;
}


std::vector<DebugBreakpoint> EmulatorAdapter::GetBreakpointList() const
{
	return m_breakpoints;
}


bool EmulatorAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	return false;
}


bool EmulatorAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	return false;
}


bool EmulatorAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	return false;
}


bool EmulatorAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	return false;
}


// ─── Registers ───────────────────────────────────────────────────────────────

std::unordered_map<std::string, DebugRegister> EmulatorAdapter::ReadAllRegisters()
{
	std::unordered_map<std::string, DebugRegister> result;
	if (!m_emulator || !m_arch)
		return result;

	auto regs = m_arch->GetFullWidthRegisters();
	size_t regIndex = 0;
	for (uint32_t reg : regs)
	{
		std::string name = m_arch->GetRegisterName(reg);
		BNRegisterInfo info = m_arch->GetRegisterInfo(reg);
		auto value = m_emulator->GetRegister(reg);
		size_t widthBits = info.size * 8;

		result[name] = DebugRegister(name, value, widthBits, regIndex++);
	}

	// Include temp registers (only non-empty when the current function uses them)
	auto temps = m_emulator->GetAllTempRegisters();
	for (auto& [index, value] : temps)
	{
		std::string name = fmt::format("temp{}", index);
		// Temp registers don't have architecture info; report as address-sized
		size_t widthBits = m_arch->GetAddressSize() * 8;
		result[name] = DebugRegister(name, value, widthBits, regIndex++);
	}

	return result;
}


DebugRegister EmulatorAdapter::ReadRegister(const std::string& reg)
{
	if (!m_emulator || !m_arch)
		return {};

	// Check for temp register (e.g., "temp0", "temp2")
	if (reg.rfind("temp", 0) == 0)
	{
		uint32_t index = std::stoul(reg.substr(4));
		auto value = m_emulator->GetTempRegister(index);
		size_t widthBits = m_arch->GetAddressSize() * 8;
		return DebugRegister(reg, value, widthBits, 0);
	}

	// Look up register ID by name
	auto allRegs = m_arch->GetAllRegisters();
	for (uint32_t regId : allRegs)
	{
		if (m_arch->GetRegisterName(regId) == reg)
		{
			BNRegisterInfo info = m_arch->GetRegisterInfo(regId);
			auto value = m_emulator->GetRegister(regId);
			return DebugRegister(reg, value, info.size * 8, regId);
		}
	}
	return {};
}


bool EmulatorAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
	if (!m_emulator || !m_arch)
		return false;

	// Check for temp register
	if (reg.rfind("temp", 0) == 0)
	{
		uint32_t index = std::stoul(reg.substr(4));
		m_emulator->SetTempRegister(index, value);
		return true;
	}

	auto allRegs = m_arch->GetAllRegisters();
	for (uint32_t regId : allRegs)
	{
		if (m_arch->GetRegisterName(regId) == reg)
		{
			m_emulator->SetRegister(regId, value);
			return true;
		}
	}
	return false;
}


// ─── Memory ──────────────────────────────────────────────────────────────────

DataBuffer EmulatorAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	if (!m_emulator)
		return DataBuffer();

	std::vector<uint8_t> tmp(size);
	size_t bytesRead = m_emulator->ReadMemory(tmp.data(), address, size);
	return DataBuffer(tmp.data(), bytesRead);
}


bool EmulatorAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	if (!m_emulator)
		return false;

	size_t written = m_emulator->WriteMemory(address, buffer.GetData(), buffer.GetLength());
	return written == buffer.GetLength();
}


// ─── Modules ─────────────────────────────────────────────────────────────────

std::vector<DebugModule> EmulatorAdapter::GetModuleList()
{
	if (!m_emulator)
		return {};

	auto regions = m_emulator->GetMappedRegions();
	std::vector<DebugModule> modules;

	for (size_t i = 0; i < regions.size(); i++)
	{
		auto& region = regions[i];
		std::string name = region.name.empty()
			? fmt::format("region_0x{:x}", region.start)
			: region.name;

		modules.push_back(DebugModule(name, name, region.start, region.size, true));
	}

	return modules;
}


// ─── Architecture ────────────────────────────────────────────────────────────

std::string EmulatorAdapter::GetTargetArchitecture()
{
	if (m_arch)
		return m_arch->GetName();
	return "";
}


// ─── Execution control ──────────────────────────────────────────────────────

DebugStopReason EmulatorAdapter::StopReason()
{
	if (!m_emulator)
		return UnknownReason;
	return MapStopReason(m_emulator->GetStopReason());
}


uint64_t EmulatorAdapter::ExitCode()
{
	return m_exitCode;
}


bool EmulatorAdapter::BreakInto()
{
	if (!m_emulator)
		return false;

	// Request the emulator to stop at the next instruction check.
	m_emulator->RequestStop();

	// Also unblock any pending stdin read so the emulator thread can
	// reach the next stop-check point.
	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinClosed = true;
		m_stdinCV.notify_all();
	}

	return true;
}


// The emulator uses the Halt stop reason for two distinct situations:
//
// 1. "Step completed normally" — StepN()/StepOver() finished executing the requested
//    number of instructions. The stop reason is set to Halt with an EMPTY message.
//    This is just a sentinel; the emulator is still alive and can continue.
//
// 2. "Emulation is truly done" — top-level LLIL_RET ("return"), ran off end of IL,
//    or pre-instruction hook stopped execution. The stop reason is Halt with a
//    NON-EMPTY message describing why.
//
// Go() always calls HandleStopReason() because Run() only returns Halt when emulation
// is truly done. StepInto()/StepOver() check the message to distinguish the two cases.

void EmulatorAdapter::HandleStopReason(BNILEmulatorStopReason reason)
{
	auto stopMsg = m_emulator->GetStopMessage();

	if (reason == ILEmulatorHalt)
	{
		// Emulation finished — treat like process exit.
		if (stopMsg.empty())
			LogInfo("BNIL Emulator: halted");
		else
			LogInfo("BNIL Emulator: halted (%s)", stopMsg.c_str());

		m_running = false;
		DebuggerEvent event;
		event.type = TargetExitedEventType;
		event.data.exitData.exitCode = 0;
		PostDebuggerEvent(event);
		return;
	}

	if (!stopMsg.empty())
		LogWarn("BNIL Emulator: stopped (%s)", stopMsg.c_str());

	PostStopEvent(MapStopReason(reason));
}


bool EmulatorAdapter::Go()
{
	if (!m_emulator)
		return false;

	// Reset stdin state in case BreakInto closed it
	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinClosed = false;
	}

	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	auto reason = m_emulator->Run();
	HandleStopReason(reason);
	return true;
}


bool EmulatorAdapter::StepInto()
{
	if (!m_emulator)
		return false;

	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinClosed = false;
	}

	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	auto reason = m_emulator->Step();
	if (reason == ILEmulatorHalt && m_emulator->GetStopMessage().empty())
		PostStopEvent(SingleStep);
	else
		HandleStopReason(reason);
	return true;
}


bool EmulatorAdapter::StepOver()
{
	if (!m_emulator)
		return false;

	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinClosed = false;
	}

	DebuggerEvent dbgevt;
	dbgevt.type = ResumeEventType;
	PostDebuggerEvent(dbgevt);

	auto reason = m_emulator->StepOver();
	if (reason == ILEmulatorHalt && m_emulator->GetStopMessage().empty())
		PostStopEvent(SingleStep);
	else
		HandleStopReason(reason);
	return true;
}


// ─── State ───────────────────────────────────────────────────────────────────

uint64_t EmulatorAdapter::GetInstructionOffset()
{
	if (!m_emulator)
		return 0;
	return m_emulator->GetCurrentAddress();
}


uint64_t EmulatorAdapter::GetStackPointer()
{
	if (!m_emulator || !m_arch)
		return 0;

	uint32_t spReg = m_arch->GetStackPointerRegister();
	return static_cast<uint64_t>(m_emulator->GetRegister(spReg));
}


std::string EmulatorAdapter::InvokeBackendCommand(const std::string& command)
{
	if (command == "eof")
	{
		std::lock_guard<std::mutex> lock(m_stdinMutex);
		m_stdinClosed = true;
		m_stdinCV.notify_all();
		return "stdin closed (EOF)\n";
	}
	return "";
}


bool EmulatorAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	switch (feature)
	{
	case DebugAdapterSupportStepOver:
	case DebugAdapterSupportModules:
		return true;
	default:
		return false;
	}
}


void EmulatorAdapter::WriteStdin(const std::string& msg)
{
	std::lock_guard<std::mutex> lock(m_stdinMutex);
	m_stdinBuffer += msg;
	m_stdinCV.notify_one();
}


bool EmulatorAdapter::DumpTargetState(const std::string& filePath)
{
	if (!m_emulator)
		return false;

	std::string json = m_emulator->SaveState();
	if (json.empty())
		return false;

	FILE* f = fopen(filePath.c_str(), "w");
	if (!f)
		return false;

	fwrite(json.data(), 1, json.size(), f);
	fclose(f);
	return true;
}


// ─── EmulatorAdapterType ─────────────────────────────────────────────────────

EmulatorAdapterType::EmulatorAdapterType() : DebugAdapterType("BNIL Emulator")
{
}


DebugAdapter* EmulatorAdapterType::Create(BinaryView* data)
{
	return new EmulatorAdapter(data);
}


bool EmulatorAdapterType::IsValidForData(BinaryView* data)
{
	// Valid for any view that has an architecture and at least one function
	if (!data->GetDefaultArchitecture())
		return false;
	auto funcs = data->GetAnalysisFunctionList();
	return !funcs.empty();
}


bool EmulatorAdapterType::CanExecute(BinaryView* data)
{
	return true;
}


bool EmulatorAdapterType::CanConnect(BinaryView* data)
{
	return false;
}


Ref<Settings> EmulatorAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}


Ref<Settings> EmulatorAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("BNILEmulatorAdapterSettings");
	settings->SetResourceId("bnil_emulator_adapter_settings");

	settings->RegisterGroup("emulator", "Emulator");

	settings->RegisterSetting("emulator.entryPoint",
		R"({
			"title" : "Entry Point",
			"type" : "string",
			"default" : "",
			"description" : "Address to start emulation from. Supports hex addresses, symbol names, and expressions.",
			"readOnly" : false
		})");

	settings->RegisterSetting("emulator.stackPointer",
		R"({
			"title" : "Stack Pointer",
			"type" : "string",
			"default" : "",
			"description" : "Initial stack pointer value (hex). A reasonable default is provided automatically.",
			"readOnly" : false
		})");

	settings->RegisterSetting("emulator.nopUnknownExternals",
		R"({
			"title" : "NOP Unknown External Calls",
			"type" : "boolean",
			"default" : false,
			"description" : "Treat calls to external functions without built-in stubs as no-ops that return 0.",
			"readOnly" : false
		})");

	settings->RegisterSetting("emulator.stateFile",
		R"({
			"title" : "State File",
			"type" : "string",
			"default" : "",
			"description" : "Path to a saved emulator state file (JSON). If set, the emulator loads this state on launch instead of starting fresh.",
			"readOnly" : false,
			"uiSelectionAction" : "file"
		})");

	return settings;
}


// ─── Registration ────────────────────────────────────────────────────────────

void BinaryNinjaDebugger::InitEmulatorAdapterType()
{
	static EmulatorAdapterType emulatorType;
	DebugAdapterType::Register(&emulatorType);
}
