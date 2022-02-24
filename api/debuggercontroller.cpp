#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

DebuggerController* DebuggerController::GetController(Ref<BinaryNinja::BinaryView> data)
{
	BNDebuggerController* controller = BNGetDebuggerController(data->GetObject());
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
	BNArchitecture* arch = BNDebuggerGetRemoteArchitecture(m_object);
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
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
    return DataBuffer(BNDebuggerReadMemory(m_object, address, size));
}


bool DebuggerController::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	return BNDebuggerWriteMemory(m_object, address, buffer.GetBufferObject());
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


uint64_t DebuggerController::GetRegisterValue(const std::string &name)
{
	return BNDebuggerGetRegisterValue(m_object, name.c_str());
}


bool DebuggerController::SetRegisterValue(const std::string &name, uint64_t value)
{
	return BNDebuggerSetRegisterValue(m_object, name.c_str(), value);
}


DebugStopReason DebuggerController::Go()
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


bool DebuggerController::Attach(uint32_t pid)
{
	return BNDebuggerAttach(m_object, pid);
}


DebugStopReason DebuggerController::StepInto(BNFunctionGraphType il)
{
	return BNDebuggerStepInto(m_object, il);
}


DebugStopReason DebuggerController::StepOver(BNFunctionGraphType il)
{
	return BNDebuggerStepOver(m_object, il);
}


DebugStopReason DebuggerController::StepReturn()
{
	return BNDebuggerStepReturn(m_object);
}


DebugStopReason DebuggerController::StepTo(uint64_t remoteAddresses)
{
	return StepTo({remoteAddresses});
}


DebugStopReason DebuggerController::StepTo(const std::vector<uint64_t> &remoteAddresses)
{
	return BNDebuggerStepTo(m_object, remoteAddresses.data(), remoteAddresses.size());
}


std::string DebuggerController::GetAdapterType()
{
	char* adapter = BNDebuggerGetAdapterType(m_object);
	if (!adapter)
		return "";

	std::string result = adapter;
	BNDebuggerFreeString(adapter);

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
	BNDebuggerFreeString(host);
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
	BNDebuggerFreeString(path);
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
	BNDebuggerFreeString(args);
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
		result[i] = bp;
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
	BNDebuggerFreeString(addr.module);
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


size_t DebuggerController::RegisterEventCallback(std::function<void(const DebuggerEvent &event)> callback)
{
	DebuggerEventCallbackObject* object = new DebuggerEventCallbackObject;
	object->action = callback;
	return BNDebuggerRegisterEventCallback(GetObject(), DebuggerEventCallback, object);
}


void DebuggerController::DebuggerEventCallback(void* ctxt, BNDebuggerEvent* event)
{
	DebuggerEventCallbackObject* object = (DebuggerEventCallbackObject*)ctxt;
	DebuggerEvent evt;
	evt.type = event->type;
	evt.data.targetStoppedData.reason = event->data.targetStoppedData.reason;
	evt.data.targetStoppedData.exitCode = event->data.targetStoppedData.exitCode;
	evt.data.targetStoppedData.lastActiveThread = event->data.targetStoppedData.lastActiveThread;
	evt.data.targetStoppedData.data = event->data.targetStoppedData.data;

	evt.data.errorData.error = string(event->data.errorData.error);
	BNDebuggerFreeString(event->data.errorData.error);
	evt.data.errorData.data = event->data.errorData.data;

	evt.data.exitData.exitCode = event->data.exitData.exitCode;

	evt.data.relativeAddress.module = string(event->data.relativeAddress.module);
	BNDebuggerFreeString(event->data.relativeAddress.module);
	evt.data.relativeAddress.offset = event->data.relativeAddress.offset;

	evt.data.absoluteAddress = event->data.absoluteAddress;

	evt.data.messageData.message = string (event->data.messageData.message);
	BNDebuggerFreeString(event->data.messageData.message);

	object->action(evt);
}


void DebuggerController::RemoveEventCallback(size_t index)
{
	BNDebuggerRemoveEventCallback(m_object, index);
}
