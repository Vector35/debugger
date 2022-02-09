#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

DebuggerController* DebuggerController::GetController(BinaryNinja::BinaryView* data)
{
	BNDebuggerController* controller = BNGetDebuggerController(data);
	if (!controller)
		return nullptr;

	return new DebuggerController(controller);
}


DebuggerController::DebuggerController(BNDebuggerController* controller)
{
	m_object = controller;
}


Ref<BinaryView> DebuggerController::GetLiveView()
{
	BNBinaryView* view = BNDebuggerGetLiveView(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


Ref<BinaryView> DebuggerController::GetData()
{
	BNBinaryView* view = BNDebuggerGetData(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


Ref<Architecture> DebuggerController::GetRemoteArchitecture()
{
	return BNDebuggerGetRemoteArchitecture(m_object);
}


bool DebuggerController::IsConnected()
{
	return BNDebuggerIsConnected(m_object);
}


bool DebuggerController::IsRunning()
{
	return BNDebuggerIsRunning(m_object);
}


uint64_t DebuggerController::StackPointer()
{
	return BNDebuggerGetStackPointer(m_object);
}


DataBuffer DebuggerController::ReadMemory(std::uintptr_t address, std::size_t size)
{
    return BNDebuggerReadMemory(m_object, address, size);
}


bool DebuggerController::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	return BNDebuggerWriteMemory(m_object, address, buffer);
}


std::vector<DebugThread> DebuggerController::GetThreads()
{
	size_t count;
	BNDebugThread* threads = BNDebuggerGetThreads(m_object, &count);

	vector<DebugThread> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugThread thread;
		thread.m_rip = threads[i].m_rip;
		thread.m_tid = threads[i].m_tid;
		result.push_back(thread);
	}
	BNDebuggerFreeThreads(threads, count);

	return result;
}


DebugThread DebuggerController::GetActiveThread()
{
	BNDebugThread thread = BNDebuggerGetActiveThread(m_object);
	DebugThread result;
	result.m_tid = thread.m_tid;
	result.m_rip = thread.m_rip;
	return result;
}


void DebuggerController::SetActiveThread(const DebugThread& thread)
{
	BNDebugThread activeThread;
	activeThread.m_rip = thread.m_rip;
	activeThread.m_tid = thread.m_tid;
	BNDebuggerSetActiveThread(m_object, activeThread);
}


std::vector<DebugModule> DebuggerController::GetModules()
{
	size_t count;
	BNDebugModule* modules = BNDebuggerGetModules(m_object, &count);

	vector<DebugModule> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugModule module;
		module.m_address = modules[i].m_address;
		module.m_name = modules[i].m_name;
		module.m_short_name = modules[i].m_short_name;
		module.m_size = modules[i].m_size;
		module.m_loaded = modules[i].m_loaded;
		result.push_back(module);
	}
	BNDebuggerFreeModules(modules, count);

	return result;
}


std::vector<DebugRegister> DebuggerController::GetRegisters()
{
	size_t count;
	BNDebugRegister* registers = BNDebuggerGetRegisters(m_object, &count);

	vector<DebugRegister> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugRegister reg;
		reg.m_name = registers[i].m_name;
		reg.m_value = registers[i].m_value;
		reg.m_width = registers[i].m_width;
		reg.m_registerIndex = registers[i].m_registerIndex;
		reg.m_hint = registers[i].m_hint;
		result.push_back(reg);
	}
	BNDebuggerFreeRegisters(registers, count);

	return result;
}


bool DebuggerController::SetRegisterValue(const std::string &name, uint64_t value)
{
	return BNDebuggerSetRegisterValue(m_object, name.c_str(), name.size(), value);
}


BNDebugStopReason DebuggerController::Go()
{
	return BNDebuggerGo(m_object);
}


bool DebuggerController::Launch()
{
	return BNDebuggerLaunch(m_object);
}


bool DebuggerController::Execute()
{
	return BNDebuggerExecute(m_object);
}


void DebuggerController::Restart()
{
	BNDebuggerRestart(m_object);
}


void DebuggerController::Quit()
{
	BNDebuggerQuit(m_object);
}


void DebuggerController::Connect()
{
	BNDebuggerConnect(m_object);
}


void DebuggerController::Detach()
{
	BNDebuggerDetach(m_object);
}


void DebuggerController::Pause()
{
	BNDebuggerPause(m_object);
}


// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
void DebuggerController::LaunchOrConnect()
{
	BNDebuggerLaunchOrConnect(m_object);
}


BNDebugStopReason DebuggerController::StepInto(BNFunctionGraphType il)
{
	return BNDebuggerStepInto(m_object, il);
}


BNDebugStopReason DebuggerController::StepOver(BNFunctionGraphType il)
{
	return BNDebuggerStepOver(m_object, il);
}


BNDebugStopReason DebuggerController::StepReturn()
{
	return BNDebuggerStepOver(m_object);
}


BNDebugStopReason DebuggerController::StepTo(const std::vector<uint64_t> &remoteAddresses)
{
	return BNDebuggerStepTo(m_object, remoteAddresses.data(), remoteAddresses.size());
}


std::string DebuggerController::GetAdapterType()
{
	char* adapter = BNDebuggerGetAdapterType(m_object);
	if (!adapter)
		return "";

	std::string result = adapter;
	BNFreeString(adapter);

	return result;
}


void DebuggerController::SetAdapterType(const std::string &adapter)
{
	BNDebuggerSetAdapterType(m_object, adapter.c_str());
}


DebugAdapterConnectionStatus DebuggerController::GetConnectionStatus()
{
	return BNDebuggerGetConnectionStatus(m_object);
}


DebugAdapterTargetStatus DebuggerController::GetTargetStatus()
{
	return BNDebuggerGetTargetStatus(m_object);
}


std::string DebuggerController::GetRemoteHost()
{
	char* host = BNDebuggerGetRemoteHost(m_object);
	if (!host)
		return "";

	std::string result = host;
	BNFreeString(host);
	return result;
}


uint32_t DebuggerController::GetRemotePort()
{
	return BNDebuggerGetRemotePort(m_object);
}


std::string DebuggerController::GetExecutablePath()
{
	char* path = BNDebuggerGetExecutablePath(m_object);
	if (!path)
		return "";

	std::string result = path;
	BNFreeString(path);
	return result;
}


bool DebuggerController::GetRequestTerminalEmulator()
{
	return BNDebuggerGetRequestTerminalEmulator(m_object);
}


std::string DebuggerController::GetCommandLineArguments()
{
	char* args = BNDebuggerGetCommandLineArguments(m_object);
	if (!args)
		return "";

	std::string result = args;
	BNFreeString(args);
	return result;
}


void DebuggerController::SetExecutablePath(const std::string& path)
{
	BNDebuggerSetExecutablePath(m_object, path.c_str());
}


void DebuggerController::SetCommandLineArguments(const std::string& arguments)
{
	BNDebuggerSetCommandLineArguments(m_object, arguments.c_str());
}


void DebuggerController::SetRemoteHost(const std::string& host)
{
	BNDebuggerSetRemoteHost(m_object, host.c_str());
}


void DebuggerController::SetRemotePort(uint32_t port)
{
	BNDebuggerSetRemotePort(m_object, port);
}


void DebuggerController::SetRequestTerminalEmulator(bool requested)
{
	BNDebuggerSetRequestTerminalEmulator(m_object, requested);
}


std::vector<DebugBreakpoint> DebuggerController::GetBreakpoints()
{
	size_t count;
	BNDebugBreakpoint* breakpoints = BNDebuggerGetBreakpoints(m_object, &count);

	std::vector<DebugBreakpoint> result;
	result.resize(count);

	for (size_t i = 0; i < count; i++)
	{
		DebugBreakpoint bp;
		bp.module = breakpoints[i].module;
		bp.offset = breakpoints[i].offset;
		bp.address = breakpoints[i].address;
		bp.enabled = breakpoints[i].enabled;
	}

	BNDebuggerFreeBreakpoints(breakpoints, count);
	return result;
}


void DebuggerController::DeleteBreakpoint(uint64_t address)
{
	BNDebuggerDeleteAbsoluteBreakpoint(m_object, address);
}


void DebuggerController::DeleteBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	BNDebuggerDeleteRelativeBreakpoint(m_object, breakpoint.module.c_str(), breakpoint.offset);
}


void DebuggerController::AddBreakpoint(uint64_t address)
{
	BNDebuggerAddAbsoluteBreakpoint(m_object, address);
}


void DebuggerController::AddBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	BNDebuggerAddRelativeBreakpoint(m_object, breakpoint.module.c_str(), breakpoint.offset);
}


bool DebuggerController::ContainsBreakpoint(uint64_t address)
{
	return BNDebuggerContainsAbsoluteBreakpoint(m_object, address);
}


bool DebuggerController::ContainsBreakpoint(const ModuleNameAndOffset &breakpoint)
{
	return BNDebuggerContainsRelativeBreakpoint(m_object, breakpoint.module.c_str(), breakpoint.offset);
}


uint64_t DebuggerController::RelativeAddressToAbsolute(const ModuleNameAndOffset& address)
{
	return BNDebuggerRelativeAddressToAbsolute(m_object, address.module.c_str(), address.offset);
}


ModuleNameAndOffset DebuggerController::AbsoluteAddressToRelative(uint64_t address)
{
	BNModuleNameAndOffset addr = BNDebuggerAbsoluteAddressToRelative(m_object, address);
	ModuleNameAndOffset result;
	result.module = addr.module;
	result.offset = addr.offset;
	BNFreeString(addr.module);
	return result;
}


uint64_t DebuggerController::IP()
{
	return BNDebuggerGetIP(m_object);
}


uint64_t DebuggerController::GetLastIP()
{
	return BNDebuggerGetLastIP(m_object);
}
