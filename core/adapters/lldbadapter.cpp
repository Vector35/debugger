/*
Copyright 2020-2022 Vector 35 Inc.

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
#include "lldbadapter.h"
#include "thread"

using namespace lldb;
using namespace BinaryNinjaDebugger;

std::string lldbArchNameForBinaryNinjaArchName(std::string name)
{
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

LldbAdapter::LldbAdapter(BinaryView* data) : DebugAdapter(data)
{
	m_targetActive = false;
	SBDebugger::Initialize();
	m_debugger = SBDebugger::Create();
	if (!m_debugger.IsValid())
		LogWarn("Invalid debugger");

	// Set auto-confirm to true so operations that ask for confirmation will proceed automatically.
	// Otherwise, the confirmation prompt will be sent to the terminal that BN is launched from, which is a very
	// confusing behavior.
	InvokeBackendCommand("settings set auto-confirm true");
	m_debugger.SetAsync(false);
}


LldbAdapter::~LldbAdapter() {}


LldbAdapterType::LldbAdapterType() : DebugAdapterType("LLDB") {}


DebugAdapter* LldbAdapterType::Create(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
	// Since we have applied delay load on liblldb.dll, we must explicitly specify the directory the liblldb.dll is in
	// and load it by ourselves. This is because the delay load only search for the directory that the binaryninja.exe
	// is in, and it does not search for the directory where the user/default plugin is in, which is exactly where
	// the liblldb.dll is located.
	// As a note, the reason for us to apply delay load on liblldb.dll is that if we load it early, it will also load
	// the system's default dbgeng dlls, which does not work for our dbgeng adapter.
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		SetDllDirectoryA(GetUserPluginDirectory().c_str());
	else
		SetDllDirectoryA(GetBundledPluginDirectory().c_str());

	auto module = LoadLibraryA("liblldb.dll");
	if (module == NULL)
		throw std::runtime_error("fail to load liblldb");
#endif

	// TODO: someone should free this.
	return new LldbAdapter(data);
}


bool LldbAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	//	it does not matter what the BinaryViewType is -- as long as we can connect to it, it is fine.
	return true;
}


bool LldbAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	//	We can connect to remote lldb on any host system
	//  TODO: we need to create a new API to get available adapters, rather the
	//  DebugAdapterType::GetAvailableAdapters(), which returns true when either the CanConnect() and CanExecute()
	//  returns true.
	return false;
}


bool LldbAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
	if (data->GetTypeName() == "PE" && data->GetDefaultArchitecture()->GetName() == "x86")
		return false;

	return true;
}


void BinaryNinjaDebugger::InitLldbAdapterType()
{
	static LldbAdapterType lldbType;
	DebugAdapterType::Register(&lldbType);
}


void LldbAdapter::ApplyBreakpoints()
{
	for (const auto& bp : m_pendingBreakpoints)
	{
		AddBreakpoint(bp);
	}
	// Clear the pending breakpoint list so that when the adapter launch/attach/connect to the target for the next time,
	// it always gets a clean list of breakpoints from the controller.
	m_pendingBreakpoints.clear();
}


bool LldbAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return ExecuteWithArgs(path, "", "", configs);
}


bool LldbAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
	const LaunchConfigurations& configs)
{
	auto n = std::thread::hardware_concurrency();
	if (n <= 2)
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = "Not enough CPU threads to launch the target.";
		event.data.errorData.error = fmt::format(
			"This CPU can only run {} threads. "
			"on Linux, the debugger is known to malfunction when the CPU cannot "
			"run at least 4 threads. We will fix this ASAP.",
			n);
		PostDebuggerEvent(event);
		return false;
	}

	m_debugger.SetAsync(false);

	SBError err;

	// *Attempt* to create a functional target triple for the binary.
	// This allows attaching to fat binaries. If the triple is empty, it will still attach on thin binaries.
	auto archName = lldbArchNameForBinaryNinjaArchName(m_defaultArchitecture);
	std::string triple = "";
	if (!archName.empty())
		triple = archName + "-unknown-none";

	m_target = m_debugger.CreateTarget(path.c_str(), triple.c_str(), "", true, err);

	if (!m_target.IsValid())
	{
		// It is likely lldb did not like our target triple.
		if (err.GetCString() && std::string(err.GetCString()).find("is not compatible with") != std::string::npos)
		{
			// Last-ditch effort. If it is a thin binary, we will be able to attach without passing a triple.
			m_target = m_debugger.CreateTarget(path.c_str(), "", "", true, err);
		}
	}

	if (!m_target.IsValid())
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = "LLDB failed to create target.";
		event.data.errorData.error =
			fmt::format("LLDB Failed to create target with \"{}\"", err.GetCString() ? err.GetCString() : "");
		PostDebuggerEvent(event);
		return false;
	}

	m_targetActive = true;
	// Breakpoints are added to this adapter right after the adapter gets created. However, at that time, the target is
	// not created yet, so there is no way the adapter could apply the breakpoints to the target. Instead, the adapter
	// stores all the breakpoints in m_pendingBreakpoints, and applies them when launching/connecting/attaching to the
	// target.
	ApplyBreakpoints();

	std::thread thread([&]() { EventListener(); });
	thread.detach();

	if (Settings::Instance()->Get<bool>("debugger.stopAtEntryPoint"))
		AddBreakpoint(ModuleNameAndOffset(path, m_entryPoint - m_start));

	std::string launchCommand = "process launch";
	if (Settings::Instance()->Get<bool>("debugger.stopAtSystemEntryPoint"))
		launchCommand += " --stop-at-entry";

	if (configs.requestTerminalEmulator)
		launchCommand += " --tty";

	if (!workingDir.empty())
		launchCommand += fmt::format(" --working-dir \"{}\"", workingDir);

	if (!args.empty())
		launchCommand += (" -- " + args);

	auto result = InvokeBackendCommand(launchCommand);
	DebuggerEvent evt;
	evt.type = BackendMessageEventType;
	evt.data.messageData.message = result;
	PostDebuggerEvent(evt);

	m_process = m_target.GetProcess();
	if (!m_process.IsValid() || (m_process.GetState() != StateType::eStateStopped) || (result.rfind("error: ", 0) == 0))
	{
		auto it = result.find_last_not_of('\n');
		result.erase(it + 1);
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = fmt::format("LLDB failed to launch target.");
		event.data.errorData.error = fmt::format("LLDB Failed to launch target with \"{}\"", result.c_str());
		PostDebuggerEvent(event);
		return false;
	}
	m_debugger.SetAsync(true);
	return true;
}


bool LldbAdapter::Attach(std::uint32_t pid)
{
	m_debugger.SetAsync(false);

	SBError err;

	// *Attempt* to create a functional target triple for the binary.
	// This allows attaching to fat binaries. If the triple is empty, it will still attach on thin binaries.
	auto archName = lldbArchNameForBinaryNinjaArchName(m_defaultArchitecture);
	std::string triple = "";
	if (!archName.empty())
		triple = archName + "-unknown-none";

	m_target = m_debugger.CreateTarget(m_originalFileName.c_str(), triple.c_str(), "", true, err);

	if (!m_target.IsValid())
	{
		// It is likely lldb did not like our target triple.
		if (err.GetCString() && std::string(err.GetCString()).find("is not compatible with") != std::string::npos)
		{
			// Last-ditch effort. If it is a thin binary, we will be able to attach without passing a triple.
			m_target = m_debugger.CreateTarget(m_originalFileName.c_str(), "", "", true, err);
		}
	}

	if (!m_target.IsValid())
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = fmt::format("LLDB failed to attach to target.");
		event.data.errorData.error =
			fmt::format("LLDB failed to attach to target with \"{}\"", err.GetCString() ? err.GetCString() : "");
		PostDebuggerEvent(event);
		return false;
	}

	m_targetActive = true;
	ApplyBreakpoints();

	std::thread thread([&]() { EventListener(); });
	thread.detach();

	SBAttachInfo info(pid);
	m_process = m_target.Attach(info, err);
	if (!m_process.IsValid() || (m_process.GetState() != StateType::eStateStopped) || err.Fail())
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = fmt::format("LLDB failed to attach to target.");
		event.data.errorData.error =
			fmt::format("LLDB Failed to attach to target with \"{}\"", err.GetCString() ? err.GetCString() : "");
		PostDebuggerEvent(event);
		return false;
	}
	m_debugger.SetAsync(true);
	return true;
}


bool LldbAdapter::Connect(const std::string& server, std::uint32_t port)
{
	m_debugger.SetAsync(false);

	SBError err;

	// *Attempt* to create a functional target triple for the binary.
	// This allows attaching to fat binaries. If the triple is empty, it will still attach on thin binaries.
	auto archName = lldbArchNameForBinaryNinjaArchName(m_defaultArchitecture);
	std::string triple = "";
	if (!archName.empty())
		triple = archName + "-unknown-none";

	m_target = m_debugger.CreateTarget(m_originalFileName.c_str(), triple.c_str(), "", true, err);

	if (!m_target.IsValid())
	{
		// It is likely lldb did not like our target triple.
		if (err.GetCString() && std::string(err.GetCString()).find("is not compatible with") != std::string::npos)
		{
			// Last-ditch effort. If it is a thin binary, we will be able to attach without passing a triple.
			m_target = m_debugger.CreateTarget(m_originalFileName.c_str(), "", "", true, err);
		}
	}

	if (!m_target.IsValid())
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = fmt::format("LLDB failed to connect to target.");
		event.data.errorData.error =
			fmt::format("LLDB failed to connect to target with \"{}\"", err.GetCString() ? err.GetCString() : "");
		PostDebuggerEvent(event);
		return false;
	}

	m_targetActive = true;
	ApplyBreakpoints();

	std::thread thread([&]() { EventListener(); });
	thread.detach();

	if (Settings::Instance()->Get<bool>("debugger.stopAtEntryPoint"))
		AddBreakpoint(ModuleNameAndOffset(m_originalFileName, m_entryPoint - m_start));

	std::string url = fmt::format("connect://{}:{}", server, port);
	SBListener listener;
	const char* plugin = nullptr;
	if (!m_processPlugin.empty() && m_processPlugin != "debugserver/lldb")
		plugin = m_processPlugin.c_str();
	m_process = m_target.ConnectRemote(listener, url.c_str(), plugin, err);
	if (!m_process.IsValid() || (m_process.GetState() != StateType::eStateStopped) || err.Fail())
	{
		DebuggerEvent event;
		event.type = ErrorEventType;
		event.data.errorData.shortError = fmt::format("LLDB failed to connect to target.");
		event.data.errorData.error =
			fmt::format("LLDB Failed to connect to target with \"{}\"", err.GetCString() ? err.GetCString() : "");
		PostDebuggerEvent(event);
		return false;
	}
	m_debugger.SetAsync(true);
	return true;
}


void LldbAdapter::Detach()
{
	// TODO: return if the operation succeeds
	SBError error = m_process.Detach();
}


void LldbAdapter::Quit()
{
	// TODO: return if the operation succeeds
	SBError error = m_process.Kill();
}


std::vector<DebugProcess> LldbAdapter::GetProcessList()
{
	std::vector<DebugProcess> debug_processes {};

	std::istringstream processList(InvokeBackendCommand("platform process list"));
	std::string line;

	while (getline(processList, line, '\n'))
	{
		uint32_t pid{};

		// skip header lines and lines that have len <= 56
		if (line.rfind("matching processes were found on") != std::string::npos
			|| line.rfind("PID    PARENT USER") != std::string::npos
			|| line.rfind("====== ======") != std::string::npos
			|| line.size() <= 56)
		{
			continue;
		}

		if (sscanf(line.c_str(), "%d", &pid) == 0)
			continue;

		// example output lines:
		//	1268   944                                              csrss.exe
		//  37635  9677   xusheng    arm64-apple-*                  Code Helper (Renderer)
		// 
		// we've 56 bytes until process name which is calculated like this:
		// (6 + 1) + (6 + 1) + (10 + 1) + (30 + 1)

		std::string processName(std::next(line.begin(), 56), line.end());

		debug_processes.emplace_back(pid, processName);
	}

	return debug_processes;
}


std::vector<DebugThread> LldbAdapter::GetThreadList()
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


DebugThread LldbAdapter::GetActiveThread() const
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


uint32_t LldbAdapter::GetActiveThreadId() const
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return 0;

	auto tid = thread.GetThreadID();
	// TODO: we should probably change the return value to uint64_t
	return tid;
}


bool LldbAdapter::SetActiveThread(const DebugThread& thread)
{
	return SetActiveThreadId(thread.m_tid);
}


bool LldbAdapter::SetActiveThreadId(std::uint32_t tid)
{
	return m_process.SetSelectedThreadByID(tid);
}


std::vector<DebugFrame> LldbAdapter::GetFramesOfThread(uint32_t tid)
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


DebugBreakpoint LldbAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
	SBBreakpoint bp = m_target.BreakpointCreateByAddress(address);
	if (!bp.IsValid())
		return DebugBreakpoint {};

	return DebugBreakpoint(address, bp.GetID(), bp.IsEnabled());
}


DebugBreakpoint LldbAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	if (!m_targetActive)
	{
		if (std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end())
			m_pendingBreakpoints.push_back(address);
	}
	else
	{
		uint64_t addr = address.offset + m_start;
		std::string entryBreakpointCommand = fmt::format("b -s \"{}\" -a 0x{:x}", address.module, addr);
		auto ret = InvokeBackendCommand(entryBreakpointCommand);
		DebuggerEvent evt;
		evt.type = BackendMessageEventType;
		evt.data.messageData.message = ret;
		PostDebuggerEvent(evt);
	}

	return DebugBreakpoint {};
}


bool LldbAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	// This is what gets called when we delete a breakpoint from the controller. Because the adapter would have no
	// convenient way of mapping a ModuleNameAndOffset to an actual address, so the controller uses the address of the
	// breakpoint to carry out deletion.

	// Only the address is valid. We cannot use the .m_id info.
	bool ok = false;
	uint64_t address = breakpoint.m_address;
	for (size_t i = 0; i < m_target.GetNumBreakpoints(); i++)
	{
		auto bp = m_target.GetBreakpointAtIndex(i);
		for (size_t j = 0; j < bp.GetNumLocations(); j++)
		{
			auto location = bp.GetLocationAtIndex(j);
			auto bpAddress = location.GetAddress().GetLoadAddress(m_target);
			if (address == bpAddress)
			{
				ok |= m_target.BreakpointDelete(bp.GetID());
				break;
			}
		}
	}
	return ok;
}


bool LldbAdapter::RemoveBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	// This function is actually never called, because the adapter handles the cache of the breakpoints when the target
	// is inactive. When the target is active, the `LldbAdapter::RemoveBreakpoint(const DebugBreakpoint & breakpoint)`
	// above is called.
	auto it = std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), breakpoint);
	if (it != m_pendingBreakpoints.end())
		m_pendingBreakpoints.erase(it);
	return true;
}


// TODO: this should be deprecated
std::vector<DebugBreakpoint> LldbAdapter::GetBreakpointList() const
{
	return std::vector<DebugBreakpoint>();
}


std::unordered_map<std::string, DebugRegister> LldbAdapter::ReadAllRegisters()
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
			if (reg.IsValid() && reg.GetName())
				result[reg.GetName()] = DebugRegister(reg.GetName(), reg.GetValueAsUnsigned(), 0, regIndex++);
		}
	}
	return result;
}


DebugRegister LldbAdapter::ReadRegister(const std::string& name)
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


bool LldbAdapter::WriteRegister(const std::string& name, std::uintptr_t value)
{
	//	SBThread thread = m_process.GetSelectedThread();
	//	if (!thread.IsValid())
	//		return false;
	//
	//	size_t frameCount = thread.GetNumFrames();
	//	if (frameCount == 0)
	//		return false;
	//
	//	SBFrame frame = thread.GetFrameAtIndex(0);
	//	if (!frame.IsValid())
	//		return false;
	//
	//	SBValue reg = frame.FindRegister(name.c_str());
	//	if (!reg.IsValid())
	//		return false;
	//
	//	SBError error;
	//	bool ok = reg.SetValueFromCString(fmt::format("{}", value).c_str(), error);
	//	return ok && error.Success();

	//	An LLDB bug forces the use of a command rather than the above code via API. When one tries to update the pc
	//  value using the API, the GetInstructionOffset() function will still return the old value, making the current
	//  instruction highlight inaccurate.
	auto command = fmt::format("reg write {} 0x{:x}", name, value);
	auto result = InvokeBackendCommand(command);
	if ((result.rfind("error: ", 0) == 0))
		return false;

	return true;
}


DataBuffer LldbAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	auto buffer = new uint8_t[size];
	SBError error;
	size_t bytesRead = m_process.ReadMemory(address, buffer, size, error);
	DataBuffer result;
	if (bytesRead > 0 && error.Success())
	{
		result.Append(buffer, bytesRead);
	}
	delete[] buffer;
	return result;
}


bool LldbAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	SBError error;
	size_t bytesWritten = m_process.WriteMemory(address, buffer.GetData(), buffer.GetLength(), error);
	if ((bytesWritten == buffer.GetLength()) && error.Success())
		return true;

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


std::vector<DebugModule> LldbAdapter::GetModuleList()
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


std::string LldbAdapter::GetTargetArchitecture()
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


DebugStopReason LldbAdapter::StopReason()
{
	StateType state = m_process.GetState();
	if (state == lldb::eStateExited)
		return DebugStopReason::ProcessExited;

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


uint64_t LldbAdapter::ExitCode()
{
	if (m_process.GetState() != lldb::eStateExited)
		return -1;

	return m_process.GetExitStatus();
}


bool LldbAdapter::BreakInto()
{
	//	Since we are in Sync mode, if we call m_process.Stop(), it will hang
	m_process.SendAsyncInterrupt();
	return true;
}


DebugStopReason LldbAdapter::Go()
{
#ifndef WIN32
	SBError error = m_process.Continue();
	if (!error.Success())
		return DebugStopReason::InternalError;
#else
	InvokeBackendCommand("c");
#endif
	return StopReason();
}


DebugStopReason LldbAdapter::StepInto()
{
#ifndef WIN32
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return DebugStopReason::InternalError;

	SBError error;
	thread.StepInstruction(false, error);
	if (!error.Success())
		return DebugStopReason::InternalError;
#else
	InvokeBackendCommand("si");
#endif
	return StopReason();
}


DebugStopReason LldbAdapter::StepOver()
{
#ifndef WIN32
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return DebugStopReason::InternalError;

	SBError error;
	thread.StepInstruction(true, error);
	if (!error.Success())
		return DebugStopReason::InternalError;
#else
	InvokeBackendCommand("ni");
#endif
	return StopReason();
}


DebugStopReason LldbAdapter::StepReturn()
{
	//	The following method, calling StepOutOfFrame(), will receive an unexpected lldb::eStateRunning event when the
	//	operation failed, e.g., due to inability to place the breakpoint at the return address. This seems to be a LLDB
	//	bug. For now, we just run the `finish` command instead.

	//#ifndef WIN32
	//	SBThread thread = m_process.GetSelectedThread();
	//	if (!thread.IsValid())
	//		return DebugStopReason::InternalError;
	//
	//	size_t frameCount = thread.GetNumFrames();
	//	if (frameCount > 0)
	//	{
	//		SBFrame frame = thread.GetFrameAtIndex(0);
	//		SBError error;
	//		thread.StepOutOfFrame(frame, error);
	//		if (error.Fail())
	//			return DebugStopReason::InternalError;
	//	}
	//#else
	InvokeBackendCommand("finish");
	//#endif
	return StopReason();
}


std::string LldbAdapter::InvokeBackendCommand(const std::string& command)
{
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


uintptr_t LldbAdapter::GetInstructionOffset()
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


uint64_t LldbAdapter::GetStackPointer()
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


bool LldbAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	return false;
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


void LldbAdapter::FixActiveThread()
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


void LldbAdapter::EventListener()
{
	SBEvent event;
	SBListener listener = SBListener("listener");
	listener.StartListeningForEventClass(m_debugger, SBProcess::GetBroadcasterClassName(),
		lldb::SBProcess::eBroadcastBitStateChanged |
		lldb::SBProcess::eBroadcastBitSTDERR |
		lldb::SBProcess::eBroadcastBitSTDOUT);

	listener.StartListeningForEventClass(m_debugger, SBTarget::GetBroadcasterClassName(),
		lldb::SBTarget::eBroadcastBitBreakpointChanged |
		lldb::SBTarget::eBroadcastBitModulesLoaded |
		lldb::SBTarget::eBroadcastBitModulesUnloaded);

	listener.StartListeningForEventClass(m_debugger, SBCommandInterpreter::GetBroadcasterClass(),
		lldb::SBCommandInterpreter::eBroadcastBitAsynchronousErrorData |
		lldb::SBCommandInterpreter::eBroadcastBitAsynchronousOutputData);

	bool done = false;
	while (!done)
	{
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
					dbgevt.data.targetStoppedData.reason = StopReason();
					PostDebuggerEvent(dbgevt);
					break;
				}
				case lldb::eStateExited:
				{
					done = true;
					m_targetActive = false;
					DebuggerEvent dbgevt;
					dbgevt.type = TargetExitedEventType;
					dbgevt.data.exitData.exitCode = ExitCode();
					PostDebuggerEvent(dbgevt);
					break;
				}
				case lldb::eStateDetached:
				{
					done = true;
					m_targetActive = false;
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

	listener.StopListeningForEventClass(m_debugger, SBProcess::GetBroadcasterClassName(),
		lldb::SBProcess::eBroadcastBitStateChanged |
		lldb::SBProcess::eBroadcastBitSTDERR |
		lldb::SBProcess::eBroadcastBitSTDOUT);

	listener.StopListeningForEventClass(m_debugger, SBTarget::GetBroadcasterClassName(),
		lldb::SBTarget::eBroadcastBitBreakpointChanged |
		lldb::SBTarget::eBroadcastBitModulesLoaded |
		lldb::SBTarget::eBroadcastBitModulesUnloaded);

	listener.StopListeningForEventClass(m_debugger, SBCommandInterpreter::GetBroadcasterClass(),
		lldb::SBCommandInterpreter::eBroadcastBitAsynchronousErrorData |
		lldb::SBCommandInterpreter::eBroadcastBitAsynchronousOutputData);
}


void LldbAdapter::WriteStdin(const std::string& msg)
{
	m_process.PutSTDIN(msg.c_str(), msg.length());
}


Ref<Metadata> LldbAdapter::GetProperty(const std::string& name)
{
	if (name == "current_platform")
	{
		auto platform = m_debugger.GetSelectedPlatform();
		return new Metadata(std::string(platform.GetName()));
	}
	else if (name == "platforms")
	{
		std::vector<std::string> platforms;
		for (size_t i = 0; i < m_debugger.GetNumAvailablePlatforms(); i++)
		{
			auto platform = m_debugger.GetAvailablePlatformInfoAtIndex(i);
			auto nameData = platform.GetValueForKey("name");
			char name[1024];
			nameData.GetStringValue(name, 1024);
			platforms.emplace_back(name);
		}
		return new Metadata(platforms);
	}
	else if (name == "process_plugins")
	{
		std::vector<std::string> plugins;
		plugins.emplace_back("gdb-remote");
		plugins.emplace_back("debugserver/lldb");
		return new Metadata(plugins);
	}
	else if (name == "current_process_plugin")
	{
		return new Metadata(m_processPlugin);
	}
	return nullptr;
}


bool LldbAdapter::SetProperty(const std::string& name, const Ref<Metadata>& value)
{
	if (name == "current_platform")
	{
		if (value->IsString())
		{
			auto platform = value->GetString();
			if (!platform.empty())
			{
				auto error = m_debugger.SetCurrentPlatform(platform.c_str());
				if (error.Success())
					return true;
			}
		}
	}
	else if (name == "current_process_plugin")
	{
		if (value->IsString())
		{
			m_processPlugin = value->GetString();
			return true;
		}
	}
	return false;
}


bool LldbAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port)
{
	auto platform = m_debugger.GetSelectedPlatform();
	auto connectionString = fmt::format("connect://{}:{}", server, port);
	SBPlatformConnectOptions options(connectionString.c_str());
	auto error = platform.ConnectRemote(options);
	return error.Success();
}


bool LldbAdapter::DisconnectDebugServer()
{
	auto platform = m_debugger.GetSelectedPlatform();
	platform.DisconnectRemote();
	// Since connecting to a debug server will set the platform remote-xxxx, we must reset it to host
	// Otherwise, launching the target (on the host) would not work after disconnecting from a debug server.
	[[maybe_unused]] auto error = m_debugger.SetCurrentPlatform("host");
	return true;
}
