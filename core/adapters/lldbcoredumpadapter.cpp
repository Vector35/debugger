/*
Copyright 2020-2025 Vector 35 Inc.

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

#include <inttypes.h>
#include <filesystem>
#include "lldbcoredumpadapter.h"
#include "thread"

using namespace lldb;
using namespace BinaryNinjaDebugger;
using namespace std;

static std::string lldbArchNameForBinaryNinjaArchName(std::string name)
{
	if (name == "x86")
		return "x86";
	if (name == "x86_64")
		return "x86_64";
	else if (name == "aarch64")
		return "arm64";
	else if (name == "armv7")
		return "arm";
	else if (name == "ppc")
		return "powerpc";
	else if (name == "ppc64")
		return "powerpc64";

	return "";
}

LldbCoreDumpAdapter::LldbCoreDumpAdapter(BinaryView* data) : DebugAdapter(data)
{
	SBDebugger::Initialize();
	m_debugger = SBDebugger::Create();
	if (!m_debugger.IsValid())
		LogWarn("Invalid debugger");

	// Set auto-confirm to true so operations that ask for confirmation will proceed automatically.
	// Otherwise, the confirmation prompt will be sent to the terminal that BN is launched from, which is a very
	// confusing behavior.
	InvokeBackendCommand("settings set auto-confirm true");
	m_debugger.SetAsync(false);

	GenerateDefaultAdapterSettings(data);
}


LldbCoreDumpAdapter::~LldbCoreDumpAdapter()
{
	m_process.Destroy();
	SBDebugger::Destroy(m_debugger);
}


LldbCoreDumpAdapterType::LldbCoreDumpAdapterType() : DebugAdapterType("LLDB Core Dump") {}


DebugAdapter* LldbCoreDumpAdapterType::Create(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
	// Since we have applied delay load on liblldb.dll, we must explicitly specify the directory the liblldb.dll is in
	// and load it by ourselves. This is because the delay load only search for the directory that the binaryninja.exe
	// is in, and it does not search for the directory where the user/default plugin is in, which is exactly where
	// the liblldb.dll is located.
	// As a note, the reason for us to apply delay load on liblldb.dll is that if we load it early, it will also load
	// the system's default dbgeng dlls, which does not work for our dbgeng adapter.
	std::string lldbDir;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		lldbDir = GetUserPluginDirectory();
	else
		lldbDir = GetBundledPluginDirectory();

	auto lldbPath = lldbDir + '\\' + "liblldb.dll";
	auto module = LoadLibraryA(lldbPath.c_str());
	if (module == NULL)
		throw std::runtime_error(std::string("fail to load ") + lldbPath);
#endif

	// TODO: someone should free this.
	return new LldbCoreDumpAdapter(data);
}


bool LldbCoreDumpAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	//	it does not matter what the BinaryViewType is -- as long as we can connect to it, it is fine.
	return true;
}


bool LldbCoreDumpAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	//	We can connect to remote lldb on any host system
	//  TODO: we need to create a new API to get available adapters, rather the
	//  DebugAdapterType::GetAvailableAdapters(), which returns true when either the CanConnect() and CanExecute()
	//  returns true.
	return true;
}


bool LldbCoreDumpAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
	if (data->GetTypeName() == "PE")
		return false;

	return true;
}


Ref<Settings> LldbCoreDumpAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("LLDBAdapterSettings");
	settings->SetResourceId("lldb_adapter_settings");
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

	return settings;
}


Ref<Settings> LldbCoreDumpAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = LldbCoreDumpAdapterType::RegisterAdapterSettings();
	return settings;
}


void BinaryNinjaDebugger::InitLldbCoreDumpAdapterType()
{
	static LldbCoreDumpAdapterType lldbType;
	DebugAdapterType::Register(&lldbType);
}


bool LldbCoreDumpAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return ExecuteWithArgs(path, "", "", configs);
}


bool LldbCoreDumpAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
	const LaunchConfigurations& configs)
{
	m_debugger.SetAsync(true);

	// We must start the event listener before calling CreateTarget, since CreateTarget will send out the initial
	// batch of module load events.
	std::thread thread([&]() { EventListener(); });
	thread.detach();

	SBError err;

	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto executablePath = adapterSettings->Get<std::string>("launch.executablePath", data, &scope);
	scope = SettingsResourceScope;
	auto inputFile = adapterSettings->Get<std::string>("common.inputFile", data, &scope);

	CreateTarget(inputFile);

	if (!m_target.IsValid())
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.shortError = "LLDB failed to create target.";
		event.data.errorData.error =
			fmt::format("LLDB Failed to create target with \"{}\"", err.GetCString() ? err.GetCString() : "");
		PostDebuggerEvent(event);
		return false;
	}

	SBError error;
	m_process = m_target.LoadCore(path.c_str(), error);
	if (error.Fail())
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.shortError = fmt::format("LLDB failed to load the core.");
		event.data.errorData.error =
			fmt::format("LLDB failed to load the core with \"{}\"", err.GetCString() ? err.GetCString() : "");
		PostDebuggerEvent(event);
		return false;
	}

	DebuggerEvent dbgevt;
	dbgevt.type = AdapterStoppedEventType;
	dbgevt.data.targetStoppedData.reason = InitialBreakpoint;
	PostDebuggerEvent(dbgevt);

	return true;
}


bool LldbCoreDumpAdapter::Attach(std::uint32_t pid)
{
	return false;
}


bool LldbCoreDumpAdapter::CreateTarget(const std::string &file)
{
	// We try different ways to create a target until one of them works...
	auto archName = lldbArchNameForBinaryNinjaArchName(m_defaultArchitecture);
	std::string triple = "";
	if (!archName.empty())
		triple = archName + "-unknown-none";

	m_target = m_debugger.CreateTargetWithFileAndArch(file.c_str(), archName.c_str());
	if (m_target.IsValid())
		return true;

	m_target = m_debugger.CreateTargetWithFileAndArch(file.c_str(), "");
	if (m_target.IsValid())
		return true;

	SBError err;
	m_target = m_debugger.CreateTarget(file.c_str(), triple.c_str(), "", true, err);
	if (m_target.IsValid())
		return true;

	m_target = m_debugger.CreateTarget(file.c_str(), "", "", true, err);
	if (m_target.IsValid())
		return true;

	m_target = m_debugger.CreateTarget("", "", "", true, err);
	if (m_target.IsValid())
		return true;

	return false;
}



bool LldbCoreDumpAdapter::Connect(const std::string& server, std::uint32_t port)
{
	return false;
}


bool LldbCoreDumpAdapter::Detach()
{
	std::unique_lock<std::mutex> lock(m_quitingMutex);
	SBError error = m_process.Detach();
	if (error.Success())
		return true;

	return false;
}


bool LldbCoreDumpAdapter::Quit()
{
	std::unique_lock<std::mutex> lock(m_quitingMutex);
	bool ok = m_debugger.DeleteTarget(m_target);

	DebuggerEvent dbgevt;
	dbgevt.type = TargetExitedEventType;
	dbgevt.data.exitData.exitCode = 0;
	PostDebuggerEvent(dbgevt);

	return ok;
}


std::vector<DebugProcess> LldbCoreDumpAdapter::GetProcessList()
{
	return {};
}


std::vector<DebugThread> LldbCoreDumpAdapter::GetThreadList()
{
	size_t threadCount = m_process.GetNumThreads();
	std::vector<DebugThread> result;
	for (size_t i = 0; i < threadCount; i++)
	{
		SBThread thread = m_process.GetThreadAtIndex(i);
		if (!thread.IsValid())
			continue;
		auto tid = thread.GetThreadID();
		uint64_t pc = 0;

		size_t frameCount = thread.GetNumFrames();
		if (frameCount > 0)
		{
			SBFrame frame = thread.GetFrameAtIndex(0);
			if (frame.IsValid())
				pc = frame.GetPC();
		}
		result.emplace_back(tid, pc);
	}
	return result;
}


DebugThread LldbCoreDumpAdapter::GetActiveThread() const
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return DebugThread {};

	auto tid = thread.GetThreadID();

	uint64_t pc = 0;
	size_t frameCount = thread.GetNumFrames();
	if (frameCount > 0)
	{
		SBFrame frame = thread.GetFrameAtIndex(0);
		if (frame.IsValid())
			pc = frame.GetPC();
	}

	return DebugThread(tid, pc);
}


uint32_t LldbCoreDumpAdapter::GetActiveThreadId() const
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return 0;

	auto tid = thread.GetThreadID();
	// TODO: we should probably change the return value to uint64_t
	return tid;
}


bool LldbCoreDumpAdapter::SetActiveThread(const DebugThread& thread)
{
	return SetActiveThreadId(thread.m_tid);
}


bool LldbCoreDumpAdapter::SetActiveThreadId(std::uint32_t tid)
{
	return m_process.SetSelectedThreadByID(tid);
}


bool LldbCoreDumpAdapter::SuspendThread(std::uint32_t tid)
{
	return false;
}

bool LldbCoreDumpAdapter::ResumeThread(std::uint32_t tid)
{
	return false;
}


std::vector<DebugFrame> LldbCoreDumpAdapter::GetFramesOfThread(uint32_t tid)
{
	size_t threadCount = m_process.GetNumThreads();
	std::vector<DebugFrame> result;
	result.reserve(threadCount);
	for (size_t i = 0; i < threadCount; i++)
	{
		SBThread thread = m_process.GetThreadAtIndex(i);
		if (!thread.IsValid())
			continue;
		if (tid == thread.GetThreadID())
		{
			size_t frameCount = thread.GetNumFrames();
			for (size_t j = 0; j < frameCount; j++)
			{
				SBFrame frame = thread.GetFrameAtIndex(j);
				if (!frame.IsValid())
					continue;
				SBModule module = frame.GetModule();
				SBFileSpec fileSpec = module.GetFileSpec();
				std::string modulePath;
				if (fileSpec.GetFilename())
					modulePath = fileSpec.GetFilename();

				uint64_t startAddress = 0;
				SBFunction function = frame.GetFunction();
				if (function.IsValid())
				{
					startAddress = function.GetStartAddress().GetLoadAddress(m_target);
				}
				else
				{
					SBSymbol symbol = frame.GetSymbol();
					if (symbol.IsValid())
						startAddress = symbol.GetStartAddress().GetLoadAddress(m_target);
				}

				std::string frameFunctionName;
				if (frame.GetFunctionName())
					frameFunctionName = std::string(frame.GetFunctionName());
				DebugFrame f(
					j, frame.GetPC(), frame.GetSP(), frame.GetFP(), frameFunctionName, startAddress, modulePath);
				result.push_back(f);
			}
			return result;
		}
	}
	return result;
}


DebugBreakpoint LldbCoreDumpAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
	return {};
}


DebugBreakpoint LldbCoreDumpAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	return {};
}


bool LldbCoreDumpAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	return true;
}


bool LldbCoreDumpAdapter::RemoveBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	return true;
}


// TODO: this should be deprecated
std::vector<DebugBreakpoint> LldbCoreDumpAdapter::GetBreakpointList() const
{
	return std::vector<DebugBreakpoint>();
}


std::unordered_map<std::string, DebugRegister> LldbCoreDumpAdapter::ReadAllRegisters()
{
	std::unordered_map<std::string, DebugRegister> result;

	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return result;

	size_t frameCount = thread.GetNumFrames();
	if (frameCount == 0)
		return result;

	SBFrame frame = thread.GetFrameAtIndex(0);
	if (!frame.IsValid())
		return result;

	size_t regIndex = 0;
	SBValueList regGroups = frame.GetRegisters();
	size_t numGroups = regGroups.GetSize();
	for (size_t i = 0; i < numGroups; i++)
	{
		SBValue regGroupInfo = regGroups.GetValueAtIndex(i);
		if (!regGroupInfo.IsValid())
			continue;

		size_t numRegs = regGroupInfo.GetNumChildren();
		for (size_t j = 0; j < numRegs; j++)
		{
			SBValue reg = regGroupInfo.GetChildAtIndex(j);
			// TODO: register width and internal index
			// Right now we basically rely on LLDB to always return the registers in the same order

			// SBValue::GetName() sometimes returns NULL on the second call. So we must get its value only once and save
			// it. Calling it twice causes problem.
			const char* regNameStr = reg.GetName();
			if (reg.IsValid() && (regNameStr != nullptr))
			{
				std::string regName(regNameStr);
				if (!regName.empty())
					result[regName] = DebugRegister(regName, reg.GetValueAsUnsigned(), reg.GetByteSize() * 8, regIndex++);
			}
		}
	}
	return result;
}


DebugRegister LldbCoreDumpAdapter::ReadRegister(const std::string& name)
{
	DebugRegister result {};

	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return result;

	size_t frameCount = thread.GetNumFrames();
	if (frameCount == 0)
		return result;

	SBFrame frame = thread.GetFrameAtIndex(0);
	if (!frame.IsValid())
		return result;

	SBValueList regGroups = frame.GetRegisters();
	size_t numGroups = regGroups.GetSize();
	for (size_t i = 0; i < numGroups; i++)
	{
		SBValue regGroupInfo = regGroups.GetValueAtIndex(i);
		size_t numRegs = regGroupInfo.GetNumChildren();
		for (size_t j = 0; j < numRegs; j++)
		{
			SBValue reg = regGroupInfo.GetChildAtIndex(j);
			if (name == reg.GetName())
				// TODO: register width and internal index
				return DebugRegister(name, reg.GetValueAsUnsigned(), 0, 0);
		}
	}
	return result;
}


bool LldbCoreDumpAdapter::WriteRegister(const std::string& name, intx::uint512 value)
{
	return false;
}


DataBuffer LldbCoreDumpAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	if (!m_quitingMutex.try_lock())
		return DataBuffer{};

	auto buffer = new uint8_t[size];
	SBError error;
	size_t bytesRead = m_process.ReadMemory(address, buffer, size, error);
	DataBuffer result;
	if (bytesRead > 0 && error.Success())
	{
		result.Append(buffer, bytesRead);
	}
	delete[] buffer;
	m_quitingMutex.unlock();
	return result;
}


bool LldbCoreDumpAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	return false;
}


static uint64_t GetModuleHighestAddress(SBModule& module, SBTarget& target)
{
	uint64_t largestAddress = 0;
	const size_t numSections = module.GetNumSections();
	for (size_t i = 0; i < numSections; i++)
	{
		SBSection section = module.GetSectionAtIndex(i);
		uint64_t start = section.GetLoadAddress(target);
		size_t size = section.GetByteSize();
		uint64_t end = start + size;
		if (end > largestAddress)
			largestAddress = end;
	}
	return largestAddress;
}


std::vector<DebugModule> LldbCoreDumpAdapter::GetModuleList()
{
	std::vector<DebugModule> result;
	size_t numModules = m_target.GetNumModules();
	for (size_t i = 0; i < numModules; i++)
	{
		SBModule module = m_target.GetModuleAtIndex(i);
		if (!module.IsValid())
			continue;

		DebugModule m;
		SBFileSpec fileSpec = module.GetFileSpec();
		char path[1024];
		size_t len = fileSpec.GetPath(path, 1024);
		m.m_name = std::string(path, len);
		m.m_short_name = fileSpec.GetFilename();
		SBAddress headerAddress = module.GetObjectFileHeaderAddress();
		m.m_address = headerAddress.GetLoadAddress(m_target);
		m.m_size = GetModuleHighestAddress(module, m_target) - m.m_address;
		m.m_loaded = true;
		result.push_back(m);
	}
	return result;
}


std::string LldbCoreDumpAdapter::GetTargetArchitecture()
{
	SBPlatform platform = m_target.GetPlatform();
	//	"arm64-apple-macosx" ==> "arm64"
	std::string triple(platform.GetTriple());
	auto position = triple.find('-');
	if (position == std::string::npos)
		return "";

	return triple.substr(0, position);
}


static DebugStopReason GetWindowsStopReasonFromExceptionDescription(const std::string exceptionString)
{
	//	example:
	//	exception string: Exception 0xc0000094 encountered at address 0x7ff7d2ec10dc
	//  0xc0000094 == EXCEPTION_INT_DIVIDE_BY_ZERO

#ifdef WIN32
	uint32_t exceptionCode = 0;
	if (auto pos = exceptionString.find(' '); pos != std::string::npos)
	{
		std::string exceptionCodeStr = exceptionString.substr(pos + 1);
		if (pos = exceptionCodeStr.find(' '); pos != std::string::npos)
		{
			exceptionCodeStr = exceptionCodeStr.substr(0, pos);
			exceptionCode = strtoull(exceptionCodeStr.c_str(), nullptr, 16);
		}
	}

	if (exceptionCode == 0)
		return DebugStopReason::UnknownReason;

	switch ((DWORD)exceptionCode)
	{
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		return DebugStopReason::Calculation;
	case EXCEPTION_ACCESS_VIOLATION:
		return DebugStopReason::AccessViolation;
	case EXCEPTION_SINGLE_STEP:
		return DebugStopReason::SingleStep;
	case EXCEPTION_BREAKPOINT:
		return DebugStopReason::Breakpoint;
	default:
		break;
	}
#endif

	return DebugStopReason::UnknownReason;
}


static DebugStopReason GetUnixStopReasonFromExceptionDescription(const std::string exceptionString)
{
	// Right now, the only we to distinguish different kind of exceptions is to parse this.
	// The API fails to give the correct exception code (as well as the associated address).
	//  Examples:
	//	EXC_BAD_ACCESS (code=2, address=0x16fdff57c)
	//	EXC_ARITHMETIC (code=EXC_I386_DIV, subcode=0x0)
	//  The description is generated in StopInfoMachException::GetDescription()

	//	static std::unordered_map<std::uint64_t, DebugStopReason> metype_lookup =
	//	{
	//		{1, DebugStopReason::AccessViolation},
	//		{2, DebugStopReason::IllegalInstruction},
	//		{3, DebugStopReason::Calculation},
	//		{4, DebugStopReason::ExcEmulation},
	//		{5, DebugStopReason::ExcSoftware},
	//		{6, DebugStopReason::Breakpoint},
	//		{7, DebugStopReason::ExcSyscall},
	//		{8, DebugStopReason::ExcMachSyscall},
	//		{9, DebugStopReason::ExcRpcAlert},
	//		{10, DebugStopReason::ExcCrash}
	//	};

	static std::unordered_map<std::string, DebugStopReason> mestring_lookup = {
		{"EXC_BAD_ACCESS", DebugStopReason::AccessViolation},
		{"EXC_BAD_INSTRUCTION", DebugStopReason::IllegalInstruction}, {"EXC_ARITHMETIC", DebugStopReason::Calculation},
		{"EXC_EMULATION", DebugStopReason::ExcEmulation}, {"EXC_SOFTWARE", DebugStopReason::ExcSoftware},
		{"EXC_BREAKPOINT", DebugStopReason::Breakpoint}, {"EXC_SYSCALL", DebugStopReason::ExcSyscall},
		{"EXC_MACH_SYSCALL", DebugStopReason::ExcMachSyscall}, {"EXC_RPC_ALERT", DebugStopReason::ExcRpcAlert},
		{"EXC_CRASH", DebugStopReason::ExcCrash}};

	if (auto pos = exceptionString.find(' '); pos != std::string::npos)
	{
		std::string exceptionMame = exceptionString.substr(0, pos);
		auto iter = mestring_lookup.find(exceptionMame);
		if (iter != mestring_lookup.end())
			return iter->second;
	}

	return DebugStopReason::UnknownReason;
}


static DebugStopReason GetStopReasonFromLinuxSignal(uint64_t signal)
{
	static std::unordered_map<std::uint64_t, DebugStopReason> signal_lookup = {
		{1, DebugStopReason::SignalHup},
		{2, DebugStopReason::SignalInt},
		{3, DebugStopReason::SignalQuit},
		{4, DebugStopReason::IllegalInstruction},
		{5, DebugStopReason::SingleStep},
		{6, DebugStopReason::SignalAbrt},
		{7, DebugStopReason::SignalEmt},
		{8, DebugStopReason::SignalFpe},
		{9, DebugStopReason::SignalKill},
		{10, DebugStopReason::SignalBus},
		{11, DebugStopReason::SignalSegv},
		{12, DebugStopReason::SignalSys},
		{13, DebugStopReason::SignalPipe},
		{14, DebugStopReason::SignalAlrm},
		{15, DebugStopReason::SignalTerm},
		{16, DebugStopReason::SignalUrg},
		{17, DebugStopReason::SignalStop},
		{18, DebugStopReason::SignalTstp},
		{19, DebugStopReason::SignalCont},
		{20, DebugStopReason::SignalChld},
		{21, DebugStopReason::SignalTtin},
		{22, DebugStopReason::SignalTtou},
		{23, DebugStopReason::SignalIo},
		{24, DebugStopReason::SignalXcpu},
		{25, DebugStopReason::SignalXfsz},
		{26, DebugStopReason::SignalVtalrm},
		{27, DebugStopReason::SignalProf},
		{28, DebugStopReason::SignalWinch},
		{29, DebugStopReason::SignalInfo},
		{30, DebugStopReason::SignalUsr1},
		{31, DebugStopReason::SignalUsr2},
	};

	if (signal_lookup.find(signal) != signal_lookup.end())
	{
		return signal_lookup[signal];
	}

	return DebugStopReason::UnknownReason;
}


DebugStopReason LldbCoreDumpAdapter::StopReason()
{
	StateType state = m_process.GetState();
	if (state == lldb::eStateExited)
	{
		LogWarn("target exited");
		return DebugStopReason::ProcessExited;
	}

	if (state == lldb::eStateStopped)
	{
		// Check all threads to find a valid stop reason
		DebugStopReason reason = UnknownReason;
		size_t numThreads = m_process.GetNumThreads();
		for (size_t i = 0; i < numThreads; i++)
		{
			SBThread thread = m_process.GetThreadAtIndex(i);
			lldb::StopReason threadReason = thread.GetStopReason();
			if (threadReason == lldb::eStopReasonBreakpoint)
			{
				reason = DebugStopReason::Breakpoint;
			}
			else if (threadReason == lldb::eStopReasonSignal)
			{
				size_t dataCount = thread.GetStopReasonDataCount();
				if (dataCount > 0)
				{
					uint64_t signal = thread.GetStopReasonDataAtIndex(0);
					reason = GetStopReasonFromLinuxSignal(signal);
				}
			}
			else if (threadReason == lldb::eStopReasonException)
			{
				char buffer[1024];
				thread.GetStopDescription(buffer, 1024);
				std::string exceptionString(buffer);
				std::string triple = m_target.GetTriple();
				if (triple.find("windows") != std::string::npos)
				{
					reason = GetWindowsStopReasonFromExceptionDescription(exceptionString);
				}
				else
				{
					reason = GetUnixStopReasonFromExceptionDescription(exceptionString);
				}
			}
			else if (threadReason == lldb::eStopReasonPlanComplete)
			{
				// The last planned operation completed, nothing unexpected happened
				// Directly return DebugStopReason::SingleStep here. Because stepping (into/over) is the only way
				// that a lldb::eStopReasonPlanComplete could be triggered. The situation might change in the future
				reason = DebugStopReason::SingleStep;
			}

			if (reason != DebugStopReason::UnknownReason)
				return reason;
		}
	}
	return DebugStopReason::UnknownReason;
}


uint64_t LldbCoreDumpAdapter::ExitCode()
{
	if (m_process.GetState() != lldb::eStateExited)
		return -1;

	return m_process.GetExitStatus();
}


bool LldbCoreDumpAdapter::BreakInto()
{
	if ((m_process.GetState() != lldb::eStateRunning) && (m_process.GetState() != lldb::eStateStepping))
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = "pause failed";
		event.data.errorData.error = fmt::format("LLDB: pause failed, process state is not running");
		PostDebuggerEvent(event);
		return false;
	}

	//	Since we are in Sync mode, if we call m_process.Stop(), it will hang
	m_process.SendAsyncInterrupt();
	return true;
}


bool LldbCoreDumpAdapter::Go()
{
	return false;
}


bool LldbCoreDumpAdapter::StepInto()
{
	return false;
}


bool LldbCoreDumpAdapter::StepOver()
{
	return false;
}


bool LldbCoreDumpAdapter::StepReturn()
{
	return false;
}


std::string LldbCoreDumpAdapter::InvokeBackendCommand(const std::string& command)
{
	// Since the `kill` command can cause the target to quit, we must guard this function with the mutex as well
	std::unique_lock<std::mutex> lock(m_quitingMutex);

	SBCommandInterpreter interpreter = m_debugger.GetCommandInterpreter();
	SBCommandReturnObject commandResult;
	interpreter.HandleCommand(command.c_str(), commandResult);

	std::string result;
	if (commandResult.GetOutputSize() > 0)
		result += commandResult.GetOutput();

	if (commandResult.GetErrorSize() > 0)
		result += commandResult.GetError();

	return result;
}


uint64_t LldbCoreDumpAdapter::GetInstructionOffset()
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return 0;

	uint64_t pc = 0;
	size_t frameCount = thread.GetNumFrames();
	if (frameCount > 0)
	{
		SBFrame frame = thread.GetFrameAtIndex(0);
		if (frame.IsValid())
			pc = frame.GetPC();
	}

	return pc;
}


uint64_t LldbCoreDumpAdapter::GetStackPointer()
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return 0;

	uint64_t sp = 0;
	size_t frameCount = thread.GetNumFrames();
	if (frameCount > 0)
	{
		SBFrame frame = thread.GetFrameAtIndex(0);
		if (frame.IsValid())
			sp = frame.GetSP();
	}

	return sp;
}


bool LldbCoreDumpAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	switch (feature)
	{
		case DebugAdapterSupportStepOver:
			return true;
		case DebugAdapterSupportModules:
			return true;
		case DebugAdapterSupportThreads:
			return true;
		case DebugAdapterSupportTTD:
			return false;
		default:
			return false;
	}
}


static bool ThreadHasValidStopReason(SBThread thread)
{
	if (!thread.IsValid())
		return false;

	auto reason = thread.GetStopReason();
	if ((reason == eStopReasonInvalid) || (reason == eStopReasonNone) || (reason == eStopReasonThreadExiting))
		return false;

	return true;
}


void LldbCoreDumpAdapter::FixActiveThread()
{
	// If there are no more than one thread, we are done
	size_t threadCount = m_process.GetNumThreads();
	if (threadCount < 2)
		return;

	// If the active thread has a valid stop reason, we are done
	auto activeThread = m_process.GetSelectedThread();
	if (ThreadHasValidStopReason(activeThread))
		return;

	// Find the first thread that has a valid reason, and set it as the active thread
	for (size_t i = 0; i < threadCount; i++)
	{
		SBThread thread = m_process.GetThreadAtIndex(i);
		if (ThreadHasValidStopReason(thread))
		{
			if (m_process.SetSelectedThread(thread))
			{
				LogDebug("Active thread is overriden from 0x%" PRIx64 " to 0x%" PRIX64, activeThread.GetThreadID(),
					thread.GetThreadID());
				break;
			}
		}
	}
}


void LldbCoreDumpAdapter::EventListener()
{
	auto listener = m_debugger.GetListener();

	bool done = false;
	while (!done)
	{
		SBEvent event;
		if (!listener.WaitForEvent(1, event))
			continue;

		uint32_t event_type = event.GetType();
		if (lldb::SBProcess::EventIsProcessEvent(event))
		{
			SBProcess process = lldb::SBProcess::GetProcessFromEvent(event);
			if (event_type & lldb::SBProcess::eBroadcastBitStateChanged)
			{
				// This can solve the problem that if the user resumes/steps the target from the console,
				// the UI is not updated. However, in order to receive the eBroadcastBitStateChanged notification,
				// We need to turn on async mode, which requires other changes as well.

				StateType state = SBProcess::GetStateFromEvent(event);
				switch (state)
				{
				case lldb::eStateRunning:
				{
					DebuggerEvent dbgevt;
					dbgevt.type = ResumeEventType;
					PostDebuggerEvent(dbgevt);
					break;
				}
				// LLDB seems to always report eStateRunning instead of eStateStepping
				case lldb::eStateStepping:
				{
					DebuggerEvent dbgevt;
					dbgevt.type = StepIntoEventType;
					PostDebuggerEvent(dbgevt);
					break;
				}
				case lldb::eStateStopped:
				{
					FixActiveThread();
					DebuggerEvent dbgevt;
					dbgevt.type = AdapterStoppedEventType;
					// LLDB sometimes fails to update the process status when it is already sending eStateStopped event.
					// When we restart the process, the target will appear to have exited
					auto reason = StopReason();
					if (reason == ProcessExited)
						reason = UnknownReason;
					dbgevt.data.targetStoppedData.reason = reason;
					PostDebuggerEvent(dbgevt);
					break;
				}
				case lldb::eStateExited:
				{
					done = true;
					DebuggerEvent dbgevt;
					dbgevt.type = TargetExitedEventType;
					dbgevt.data.exitData.exitCode = ExitCode();
					PostDebuggerEvent(dbgevt);
					break;
				}
				case lldb::eStateDetached:
				{
					done = true;
					DebuggerEvent dbgevt;
					dbgevt.type = DetachedEventType;
					PostDebuggerEvent(dbgevt);
					break;
				}
				default:
					break;
				}
			}
			else if ((event_type & lldb::SBProcess::eBroadcastBitSTDOUT)
				|| (event_type & lldb::SBProcess::eBroadcastBitSTDERR))
			{
				char buffer[1024];
				size_t count = 0;
				std::string output {};
				// TODO: we should differentiate stdout and stderr
				while ((count = process.GetSTDOUT(buffer, 1024)) > 0)
					output += std::string(buffer, count);

				DebuggerEvent event;
				event.type = StdoutMessageEventType;
				event.data.messageData.message = output;
				PostDebuggerEvent(event);

				output.clear();
				while ((count = process.GetSTDERR(buffer, 1024)) > 0)
					output += std::string(buffer, count);

				event.type = StdoutMessageEventType;
				event.data.messageData.message = output;
				PostDebuggerEvent(event);
			}
		}
		else if (lldb::SBTarget::EventIsTargetEvent(event))
		{
			SBTarget target = lldb::SBTarget::GetTargetFromEvent(event);
			if (event_type & lldb::SBTarget::eBroadcastBitModulesLoaded)
			{
				[[maybe_unused]] size_t numModules = SBTarget::GetNumModulesFromEvent(event);
			}
		}
		else if (lldb::SBBreakpoint::EventIsBreakpointEvent(event))
		{
			if (event_type & lldb::SBTarget::eBroadcastBitBreakpointChanged)
			{
				auto bpEventType = lldb::SBBreakpoint::GetBreakpointEventTypeFromEvent(event);
				auto bp = lldb::SBBreakpoint::GetBreakpointFromEvent(event);
				for (size_t i = 0; i < bp.GetNumLocations(); i++)
				{
					if (bpEventType == lldb::eBreakpointEventTypeAdded)
					{
						auto location = bp.GetLocationAtIndex(i);
						auto address = location.GetAddress();
						auto module = address.GetModule();
						if (module.IsValid())
						{
							SBAddress headerAddress = module.GetObjectFileHeaderAddress();
							uint64_t moduleBase = headerAddress.GetLoadAddress(m_target);
							uint64_t bpAddress = location.GetAddress().GetLoadAddress(m_target);
							auto fileSpec = module.GetFileSpec();
							char path[1024];
							size_t bytes = fileSpec.GetPath(path, sizeof(path));
							DebuggerEvent evt;
							evt.type = RelativeBreakpointAddedEvent;
							evt.data.relativeAddress.module = std::string(path, bytes);
							evt.data.relativeAddress.offset = bpAddress - moduleBase;
							PostDebuggerEvent(evt);
						}
						else
						{
							DebuggerEvent evt;
							evt.type = AbsoluteBreakpointAddedEvent;
							evt.data.absoluteAddress = location.GetAddress().GetLoadAddress(m_target);
							PostDebuggerEvent(evt);
						}
					}
					else if (bpEventType == lldb::eBreakpointEventTypeRemoved)
					{
						auto location = bp.GetLocationAtIndex(i);
						auto address = location.GetAddress();
						auto module = address.GetModule();
						if (module.IsValid())
						{
							SBAddress headerAddress = module.GetObjectFileHeaderAddress();
							uint64_t moduleBase = headerAddress.GetLoadAddress(m_target);
							uint64_t bpAddress = location.GetAddress().GetLoadAddress(m_target);
							auto fileSpec = module.GetFileSpec();
							char path[1024];
							size_t bytes = fileSpec.GetPath(path, sizeof(path));
							DebuggerEvent evt;
							evt.type = RelativeBreakpointRemovedEvent;
							evt.data.relativeAddress.module = std::string(path, bytes);
							evt.data.relativeAddress.offset = bpAddress - moduleBase;
							PostDebuggerEvent(evt);
						}
						else
						{
							DebuggerEvent evt;
							evt.type = AbsoluteBreakpointRemovedEvent;
							evt.data.absoluteAddress = location.GetAddress().GetLoadAddress(m_target);
							PostDebuggerEvent(evt);
						}
					}
				}
			}
		}
		else if (lldb::SBCommandInterpreter::EventIsCommandInterpreterEvent(event))
		{
			LogDebug("command line interpreter event");
		}
		else if (lldb::SBThread::EventIsThreadEvent(event))
		{
			LogDebug("thread events");
		}
		else if (lldb::SBWatchpoint::EventIsWatchpointEvent(event))
		{
			LogDebug("watchpoint event");
		}
		else if (lldb::SBProcess::EventIsStructuredDataEvent(event))
		{
			LogDebug("structured data event");
		}
	}

	listener.Clear();
}


void LldbCoreDumpAdapter::WriteStdin(const std::string& msg)
{
	m_process.PutSTDIN(msg.c_str(), msg.length());
}


Ref<Metadata> LldbCoreDumpAdapter::GetProperty(const std::string& name)
{
	return nullptr;
}


bool LldbCoreDumpAdapter::SetProperty(const std::string& name, const Ref<Metadata>& value)
{
	return false;
}


bool LldbCoreDumpAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port)
{
	return false;
}


bool LldbCoreDumpAdapter::DisconnectDebugServer()
{
	return false;
}


Ref<Settings> LldbCoreDumpAdapter::GetAdapterSettings()
{
	return LldbCoreDumpAdapterType::GetAdapterSettings();
}


void LldbCoreDumpAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
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
}


std::uint32_t LldbCoreDumpAdapter::GetActivePID()
{
	if (!m_process.IsValid())
		return 0;

	return m_process.GetProcessID();
}
