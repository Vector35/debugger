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

#include "debuggerapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

DbgRef<DebuggerController> DebuggerController::GetController(Ref<BinaryNinja::BinaryView> data)
{
	if (!data)
		return nullptr;

	BNDebuggerController* controller = BNGetDebuggerController(data->GetObject());
	if (!controller)
		return nullptr;

	return new DebuggerController(controller);
}


DbgRef<DebuggerController> DebuggerController::GetController(Ref<BinaryNinja::FileMetadata> file)
{
	if (!file)
		return nullptr;

	BNDebuggerController* controller = BNGetDebuggerControllerFromFile(file->GetObject());
	if (!controller)
		return nullptr;

	return new DebuggerController(controller);
}


DebuggerController::DebuggerController(BNDebuggerController* controller)
{
	m_object = controller;
}


DebuggerController::~DebuggerController()
{
	// Free all callback objects
	for (auto& [index, object] : m_callbackObjects)
	{
		delete object;
	}

	m_callbackObjects.clear();
}


bool DebuggerController::ControllerExists(Ref<BinaryNinja::BinaryView> data)
{
	return BNDebuggerControllerExists(data->GetObject());
}


bool DebuggerController::ControllerExists(Ref<BinaryNinja::FileMetadata> file)
{
	return BNDebuggerControllerExistsFromFile(file->GetObject());
}


void DebuggerController::Destroy()
{
	BNDebuggerDestroyController(m_object);
}


Ref<BinaryView> DebuggerController::GetData()
{
	BNBinaryView* view = BNDebuggerGetData(m_object);
	if (!view)
		return nullptr;
	return new BinaryView(view);
}


void DebuggerController::SetData(const Ref<BinaryView>& data)
{
	BNDebuggerSetData(m_object, BNNewViewReference(data->GetObject()));
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


bool DebuggerController::IsConnectedToDebugServer()
{
	return BNDebuggerIsConnectedToDebugServer(m_object);
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

std::vector<DebugProcess> DebuggerController::GetProcessList()
{
	size_t count;
	BNDebugProcess* processes = BNDebuggerGetProcessList(m_object, &count);

	vector<DebugProcess> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugProcess process;
		process.m_pid = processes[i].m_pid;
		process.m_processName = processes[i].m_processName;
		result.push_back(process);
	}
	BNDebuggerFreeProcessList(processes, count);

	return result;
}


std::uint32_t DebuggerController::GetActivePID()
{
	return BNDebuggerGetActivePID(m_object);
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
		thread.m_isFrozen = threads[i].m_isFrozen;
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


bool DebuggerController::SuspendThread(std::uint32_t tid)
{
	return BNDebuggerSuspendThread(m_object, tid);
}


bool DebuggerController::ResumeThread(std::uint32_t tid)
{
	return BNDebuggerResumeThread(m_object, tid);
}


std::vector<DebugFrame> DebuggerController::GetFramesOfThread(uint32_t tid)
{
	size_t count;
	BNDebugFrame* frames = BNDebuggerGetFramesOfThread(m_object, tid, &count);

	std::vector<DebugFrame> result;
	result.reserve(count);

	for (size_t i = 0; i < count; i++)
	{
		DebugFrame frame;
		frame.m_index = frames[i].m_index;
		frame.m_pc = frames[i].m_pc;
		frame.m_sp = frames[i].m_sp;
		frame.m_fp = frames[i].m_fp;
		frame.m_functionName = frames[i].m_functionName;
		frame.m_functionStart = frames[i].m_functionStart;
		frame.m_module = frames[i].m_module;
		result.push_back(frame);
	}
	BNDebuggerFreeFrames(frames, count);

	return result;
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
		reg.m_value = intx::le::load<intx::uint512>(registers[i].m_value);
		reg.m_width = registers[i].m_width;
		reg.m_registerIndex = registers[i].m_registerIndex;
		reg.m_hint = registers[i].m_hint;
		result.push_back(reg);
	}
	BNDebuggerFreeRegisters(registers, count);

	return result;
}


intx::uint512 DebuggerController::GetRegisterValue(const std::string& name)
{
	uint8_t buffer[64] = {0};
	BNDebuggerGetRegisterValue(m_object, name.c_str(), buffer);
	return intx::le::load<intx::uint512>(buffer);
}


bool DebuggerController::SetRegisterValue(const std::string& name, const intx::uint512& value)
{
	uint8_t valueBytes[64] = {0};
	intx::le::store(valueBytes, value);
	return BNDebuggerSetRegisterValue(m_object, name.c_str(), valueBytes);
}


bool DebuggerController::Go()
{
	return BNDebuggerGo(m_object);
}

bool DebuggerController::GoReverse()
{
	return BNDebuggerGoReverse(m_object);
}


DebugStopReason DebuggerController::GoAndWait()
{
	return BNDebuggerGoAndWait(m_object);
}


DebugStopReason DebuggerController::GoReverseAndWait()
{
	return BNDebuggerGoReverseAndWait(m_object);
}


bool DebuggerController::Launch()
{
	return BNDebuggerLaunch(m_object);
}


DebugStopReason DebuggerController::LaunchAndWait()
{
	return BNDebuggerLaunchAndWait(m_object);
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


void DebuggerController::QuitAndWait()
{
	BNDebuggerQuitAndWait(m_object);
}


bool DebuggerController::Connect()
{
	return BNDebuggerConnect(m_object);
}


DebugStopReason DebuggerController::ConnectAndWait()
{
	return BNDebuggerConnectAndWait(m_object);
}


bool DebuggerController::ConnectToDebugServer()
{
	return BNDebuggerConnectToDebugServer(m_object);
}


bool DebuggerController::DisconnectDebugServer()
{
	return BNDebuggerDisconnectDebugServer(m_object);
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


bool DebuggerController::Attach()
{
	return BNDebuggerAttach(m_object);
}


DebugStopReason DebuggerController::AttachAndWait()
{
	return BNDebuggerAttachAndWait(m_object);
}



bool DebuggerController::StepInto(BNFunctionGraphType il)
{
	return BNDebuggerStepInto(m_object, il);
}


bool DebuggerController::StepIntoReverse(BNFunctionGraphType il)
{
	return BNDebuggerStepIntoReverse(m_object, il);
}


bool DebuggerController::StepOver(BNFunctionGraphType il)
{
	return BNDebuggerStepOver(m_object, il);
}


bool DebuggerController::StepOverReverse(BNFunctionGraphType il)
{
	return BNDebuggerStepOverReverse(m_object, il);
}


bool DebuggerController::StepReturn()
{
	return BNDebuggerStepReturn(m_object);
}


bool DebuggerController::StepReturnReverse()
{
	return BNDebuggerStepReturnReverse(m_object);
}


bool DebuggerController::RunTo(uint64_t remoteAddresses)
{
	return RunTo(std::vector<uint64_t> {remoteAddresses});
}


bool DebuggerController::RunTo(const std::vector<uint64_t>& remoteAddresses)
{
	return BNDebuggerRunTo(m_object, remoteAddresses.data(), remoteAddresses.size());
}


bool DebuggerController::RunToReverse(uint64_t remoteAddresses)
{
	return RunToReverse(std::vector<uint64_t> {remoteAddresses});
}


bool DebuggerController::RunToReverse(const std::vector<uint64_t>& remoteAddresses)
{
	return BNDebuggerRunToReverse(m_object, remoteAddresses.data(), remoteAddresses.size());
}


DebugStopReason DebuggerController::StepIntoAndWait(BNFunctionGraphType il)
{
	return BNDebuggerStepIntoAndWait(m_object, il);
}


DebugStopReason DebuggerController::StepIntoReverseAndWait(BNFunctionGraphType il)
{
	return BNDebuggerStepIntoReverseAndWait(m_object, il);
}


DebugStopReason DebuggerController::StepOverAndWait(BNFunctionGraphType il)
{
	return BNDebuggerStepOverAndWait(m_object, il);
}


DebugStopReason DebuggerController::StepOverReverseAndWait(BNFunctionGraphType il)
{
	return BNDebuggerStepOverReverseAndWait(m_object, il);
}


DebugStopReason DebuggerController::StepReturnAndWait()
{
	return BNDebuggerStepReturnAndWait(m_object);
}

DebugStopReason DebuggerController::StepReturnReverseAndWait()
{
	return BNDebuggerStepReturnReverseAndWait(m_object);
}


DebugStopReason DebuggerController::RunToAndWait(uint64_t remoteAddresses)
{
	return RunToAndWait(std::vector<uint64_t> {remoteAddresses});
}


DebugStopReason DebuggerController::RunToAndWait(const std::vector<uint64_t>& remoteAddresses)
{
	return BNDebuggerRunToAndWait(m_object, remoteAddresses.data(), remoteAddresses.size());
}


DebugStopReason DebuggerController::RunToReverseAndWait(uint64_t remoteAddresses)
{
	return RunToReverseAndWait(std::vector<uint64_t> {remoteAddresses});
}


DebugStopReason DebuggerController::RunToReverseAndWait(const std::vector<uint64_t>& remoteAddresses)
{
	return BNDebuggerRunToReverseAndWait(m_object, remoteAddresses.data(), remoteAddresses.size());
}


DebugStopReason DebuggerController::PauseAndWait()
{
	return BNDebuggerPauseAndWait(m_object);
}


DebugStopReason DebuggerController::RestartAndWait()
{
	return BNDebuggerRestartAndWait(m_object);
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


void DebuggerController::SetAdapterType(const std::string& adapter)
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


int32_t DebuggerController::GetPIDAttach()
{
	return BNDebuggerGetPIDAttach(m_object);
}


std::string DebuggerController::GetInputFile()
{
	char* path = BNDebuggerGetInputFile(m_object);
	if (!path)
		return "";

	std::string result = path;
	BNDebuggerFreeString(path);
	return result;
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


std::string DebuggerController::GetWorkingDirectory()
{
	char* path = BNDebuggerGetWorkingDirectory(m_object);
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


void DebuggerController::SetInputFile(const std::string& path)
{
	BNDebuggerSetInputFile(m_object, path.c_str());
}


void DebuggerController::SetExecutablePath(const std::string& path)
{
	BNDebuggerSetExecutablePath(m_object, path.c_str());
}


void DebuggerController::SetWorkingDirectory(const std::string& path)
{
	BNDebuggerSetWorkingDirectory(m_object, path.c_str());
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


void DebuggerController::SetPIDAttach(int32_t port)
{
	BNDebuggerSetPIDAttach(m_object, port);
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


void DebuggerController::EnableBreakpoint(uint64_t address)
{
	BNDebuggerEnableAbsoluteBreakpoint(m_object, address);
}


void DebuggerController::EnableBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	BNDebuggerEnableRelativeBreakpoint(m_object, breakpoint.module.c_str(), breakpoint.offset);
}


void DebuggerController::DisableBreakpoint(uint64_t address)
{
	BNDebuggerDisableAbsoluteBreakpoint(m_object, address);
}


void DebuggerController::DisableBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	BNDebuggerDisableRelativeBreakpoint(m_object, breakpoint.module.c_str(), breakpoint.offset);
}


bool DebuggerController::ContainsBreakpoint(uint64_t address)
{
	return BNDebuggerContainsAbsoluteBreakpoint(m_object, address);
}


bool DebuggerController::ContainsBreakpoint(const ModuleNameAndOffset& breakpoint)
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


bool DebuggerController::SetIP(uint64_t address)
{
	return BNDebuggerSetIP(m_object, address);
}


uint32_t DebuggerController::GetExitCode()
{
	return BNDebuggerGetExitCode(m_object);
}


size_t DebuggerController::RegisterEventCallback(
	std::function<void(const DebuggerEvent& event)> callback, const std::string& name)
{
	DebuggerEventCallbackObject* object = new DebuggerEventCallbackObject;
	object->action = callback;

	size_t index = BNDebuggerRegisterEventCallback(GetObject(), DebuggerEventCallback, name.c_str(), object);

	// Store the callback object in the map
	m_callbackObjects[index] = object;

	return index;
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
	evt.data.errorData.shortError = string(event->data.errorData.shortError);
	evt.data.errorData.data = event->data.errorData.data;

	evt.data.exitData.exitCode = event->data.exitData.exitCode;

	evt.data.relativeAddress.module = string(event->data.relativeAddress.module);
	evt.data.relativeAddress.offset = event->data.relativeAddress.offset;

	evt.data.absoluteAddress = event->data.absoluteAddress;

	evt.data.messageData.message = string(event->data.messageData.message);

	object->action(evt);
}


void DebuggerController::RemoveEventCallback(size_t index)
{
	// Remove the event callback using the BN API
	BNDebuggerRemoveEventCallback(m_object, index);

	// Free the callback object from the map
	auto it = m_callbackObjects.find(index);
	if (it != m_callbackObjects.end())
	{
		delete it->second; // Free the dynamically allocated memory
		m_callbackObjects.erase(it); // Remove the entry from the map
	}
}


void DebuggerController::SetDebuggerUICallbacks(DebuggerUICallbacks* cb)
{
	BNDebuggerSetDebuggerUICallbacks(m_object, cb->GetCallbacks(), cb);
}


void DebuggerController::WriteStdin(const std::string& msg)
{
	BNDebuggerWriteStdin(m_object, msg.c_str(), msg.length());
}


std::string DebuggerController::InvokeBackendCommand(const std::string& command)
{
	char* output = BNDebuggerInvokeBackendCommand(m_object, command.c_str());
	std::string result = std::string(output);
	BNDebuggerFreeString(output);
	return result;
}


std::string DebuggerController::GetDebugStopReasonString(DebugStopReason reason)
{
	char* str = BNDebuggerGetStopReasonString(reason);
	std::string result = std::string(str);
	BNDebuggerFreeString(str);
	return result;
}


DebugStopReason DebuggerController::StopReason()
{
	return BNDebuggerGetStopReason(m_object);
}


Ref<Metadata> DebuggerController::GetAdapterProperty(const std::string& name)
{
	BNMetadata* value = BNDebuggerGetAdapterProperty(m_object, name.c_str());
	if (!value)
		return nullptr;
	return new Metadata(value);
}


bool DebuggerController::SetAdapterProperty(const std::string& name, const BinaryNinja::Ref<Metadata>& value)
{
	return BNDebuggerSetAdapterProperty(m_object, name.c_str(), value->m_object);
}


bool DebuggerController::ActivateDebugAdapter()
{
	return BNDebuggerActivateDebugAdapter(m_object);
}


std::string DebuggerController::GetAddressInformation(intx::uint512 address)
{
	uint8_t buffer[64];
	intx::le::store(buffer, address);
	char* info = BNDebuggerGetAddressInformation(m_object, buffer);
	std::string result = std::string(info);
	BNDebuggerFreeString(info);
	return result;
}


bool DebuggerController::IsFirstLaunch()
{
	return BNDebuggerIsFirstLaunch(m_object);
}


bool DebuggerController::IsFirstConnect()
{
	return BNDebuggerIsFirstConnect(m_object);
}


bool DebuggerController::IsFirstConnectToDebugServer()
{
	return BNDebuggerIsFirstConnectToDebugServer(m_object);
}


bool DebuggerController::IsFirstAttach()
{
	return BNDebuggerIsFirstAttach(m_object);
}


bool DebuggerController::IsTTD()
{
	return BNDebuggerIsTTD(m_object);
}


std::vector<TTDMemoryEvent> DebuggerController::GetTTDMemoryAccessForAddress(uint64_t address, uint64_t size, TTDMemoryAccessType accessType)
{
	std::vector<TTDMemoryEvent> result;
	
	BNDebuggerTTDMemoryAccessType type = static_cast<BNDebuggerTTDMemoryAccessType>(accessType);
	
	size_t count = 0;
	BNDebuggerTTDMemoryEvent* events = BNDebuggerGetTTDMemoryAccessForAddress(m_object, address, size, type, &count);
	
	if (events && count > 0)
	{
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			TTDMemoryEvent event;
			event.eventType = events[i].eventType ? std::string(events[i].eventType) : "";
			event.threadId = events[i].threadId;
			event.uniqueThreadId = events[i].uniqueThreadId;
			event.timeStart.sequence = events[i].timeStart.sequence;
			event.timeStart.step = events[i].timeStart.step;
			event.timeEnd.sequence = events[i].timeEnd.sequence;
			event.timeEnd.step = events[i].timeEnd.step;
			event.accessType = static_cast<TTDMemoryAccessType>(events[i].accessType);
			event.address = events[i].address;
			event.size = events[i].size;
			event.memoryAddress = events[i].memoryAddress;
			event.instructionAddress = events[i].instructionAddress;
			event.value = events[i].value;
			result.push_back(event);
		}
		BNDebuggerFreeTTDMemoryEvents(events, count);
	}
	
	return result;
}

TTDPosition DebuggerController::GetCurrentTTDPosition()
{
	BNDebuggerTTDPosition pos = BNDebuggerGetCurrentTTDPosition(m_object);
	return TTDPosition(pos.sequence, pos.step);
}

bool DebuggerController::SetTTDPosition(const TTDPosition& position)
{
	BNDebuggerTTDPosition pos = {position.sequence, position.step};
	return BNDebuggerSetTTDPosition(m_object, pos);
}

std::vector<TTDCallEvent> DebuggerController::GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress)
{
	std::vector<TTDCallEvent> result;
	
	size_t count = 0;
	BNDebuggerTTDCallEvent* events = BNDebuggerGetTTDCallsForSymbols(m_object, 
		symbols.c_str(), startReturnAddress, endReturnAddress, &count);
	
	if (events && count > 0)
	{
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			TTDCallEvent event;
			event.eventType = events[i].eventType ? std::string(events[i].eventType) : "";
			event.threadId = events[i].threadId;
			event.uniqueThreadId = events[i].uniqueThreadId;
			event.function = events[i].function ? std::string(events[i].function) : "";
			event.functionAddress = events[i].functionAddress;
			event.returnAddress = events[i].returnAddress;
			event.returnValue = events[i].returnValue;
			event.hasReturnValue = events[i].hasReturnValue;
			event.timeStart.sequence = events[i].timeStart.sequence;
			event.timeStart.step = events[i].timeStart.step;
			event.timeEnd.sequence = events[i].timeEnd.sequence;
			event.timeEnd.step = events[i].timeEnd.step;
			
			// Convert parameters array
			if (events[i].parameters && events[i].parameterCount > 0)
			{
				event.parameters.reserve(events[i].parameterCount);
				for (size_t j = 0; j < events[i].parameterCount; j++)
				{
					if (events[i].parameters[j])
					{
						event.parameters.push_back(std::string(events[i].parameters[j]));
					}
					else
					{
						event.parameters.push_back("");
					}
				}
			}
			
			result.push_back(event);
		}
		BNDebuggerFreeTTDCallEvents(events, count);
	}
	
	return result;
}


std::vector<TTDEvent> DebuggerController::GetTTDEvents(TTDEventType eventType)
{
	std::vector<TTDEvent> result;
	
	size_t count = 0;
	BNDebuggerTTDEvent* events = BNDebuggerGetTTDEvents(m_object, 
		static_cast<BNDebuggerTTDEventType>(eventType), &count);
	
	if (events && count > 0)
	{
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			TTDEvent event;
			event.type = static_cast<TTDEventType>(events[i].type);
			event.position.sequence = events[i].position.sequence;
			event.position.step = events[i].position.step;
			
			// Copy optional module details
			if (events[i].module)
			{
				TTDModule module;
				module.name = events[i].module->name ? std::string(events[i].module->name) : "";
				module.address = events[i].module->address;
				module.size = events[i].module->size;
				module.checksum = events[i].module->checksum;
				module.timestamp = events[i].module->timestamp;
				event.module = module;
			}
			
			// Copy optional thread details
			if (events[i].thread)
			{
				TTDThread thread;
				thread.uniqueId = events[i].thread->uniqueId;
				thread.id = events[i].thread->id;
				thread.lifetimeStart.sequence = events[i].thread->lifetimeStart.sequence;
				thread.lifetimeStart.step = events[i].thread->lifetimeStart.step;
				thread.lifetimeEnd.sequence = events[i].thread->lifetimeEnd.sequence;
				thread.lifetimeEnd.step = events[i].thread->lifetimeEnd.step;
				thread.activeTimeStart.sequence = events[i].thread->activeTimeStart.sequence;
				thread.activeTimeStart.step = events[i].thread->activeTimeStart.step;
				thread.activeTimeEnd.sequence = events[i].thread->activeTimeEnd.sequence;
				thread.activeTimeEnd.step = events[i].thread->activeTimeEnd.step;
				event.thread = thread;
			}
			
			// Copy optional exception details
			if (events[i].exception)
			{
				TTDException exception;
				exception.type = static_cast<TTDExceptionType>(events[i].exception->type);
				exception.programCounter = events[i].exception->programCounter;
				exception.code = events[i].exception->code;
				exception.flags = events[i].exception->flags;
				exception.recordAddress = events[i].exception->recordAddress;
				exception.position.sequence = events[i].exception->position.sequence;
				exception.position.step = events[i].exception->position.step;
				event.exception = exception;
			}
			
			result.push_back(event);
		}
		BNDebuggerFreeTTDEvents(events, count);
	}
	
	return result;
}


std::vector<TTDEvent> DebuggerController::GetAllTTDEvents()
{
	std::vector<TTDEvent> result;
	
	size_t count = 0;
	BNDebuggerTTDEvent* events = BNDebuggerGetAllTTDEvents(m_object, &count);
	
	if (events && count > 0)
	{
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			TTDEvent event;
			event.type = static_cast<TTDEventType>(events[i].type);
			event.position.sequence = events[i].position.sequence;
			event.position.step = events[i].position.step;
			
			// Copy optional module details
			if (events[i].module)
			{
				TTDModule module;
				module.name = events[i].module->name ? std::string(events[i].module->name) : "";
				module.address = events[i].module->address;
				module.size = events[i].module->size;
				module.checksum = events[i].module->checksum;
				module.timestamp = events[i].module->timestamp;
				event.module = module;
			}
			
			// Copy optional thread details
			if (events[i].thread)
			{
				TTDThread thread;
				thread.uniqueId = events[i].thread->uniqueId;
				thread.id = events[i].thread->id;
				thread.lifetimeStart.sequence = events[i].thread->lifetimeStart.sequence;
				thread.lifetimeStart.step = events[i].thread->lifetimeStart.step;
				thread.lifetimeEnd.sequence = events[i].thread->lifetimeEnd.sequence;
				thread.lifetimeEnd.step = events[i].thread->lifetimeEnd.step;
				thread.activeTimeStart.sequence = events[i].thread->activeTimeStart.sequence;
				thread.activeTimeStart.step = events[i].thread->activeTimeStart.step;
				thread.activeTimeEnd.sequence = events[i].thread->activeTimeEnd.sequence;
				thread.activeTimeEnd.step = events[i].thread->activeTimeEnd.step;
				event.thread = thread;
			}
			
			// Copy optional exception details
			if (events[i].exception)
			{
				TTDException exception;
				exception.type = static_cast<TTDExceptionType>(events[i].exception->type);
				exception.programCounter = events[i].exception->programCounter;
				exception.code = events[i].exception->code;
				exception.flags = events[i].exception->flags;
				exception.recordAddress = events[i].exception->recordAddress;
				exception.position.sequence = events[i].exception->position.sequence;
				exception.position.step = events[i].exception->position.step;
				event.exception = exception;
			}
			
			result.push_back(event);
		}
		BNDebuggerFreeTTDEvents(events, count);
	}
	
	return result;
}


bool DebuggerController::IsInstructionExecuted(uint64_t address)
{
	return BNDebuggerIsInstructionExecuted(m_object, address);
}


bool DebuggerController::RunCodeCoverageAnalysis(uint64_t startAddress, uint64_t endAddress)
{
	return BNDebuggerRunCodeCoverageAnalysisRange(m_object, startAddress, endAddress);
}


size_t DebuggerController::GetExecutedInstructionCount() const
{
	return BNDebuggerGetExecutedInstructionCount(m_object);
}


bool DebuggerController::SaveCodeCoverageToFile(const std::string& filePath) const
{
	return BNDebuggerSaveCodeCoverageToFile(m_object, filePath.c_str());
}


bool DebuggerController::LoadCodeCoverageFromFile(const std::string& filePath)
{
	return BNDebuggerLoadCodeCoverageFromFile(m_object, filePath.c_str());
}


void DebuggerController::PostDebuggerEvent(const DebuggerEvent &event)
{
	BNDebuggerEvent* evt = new BNDebuggerEvent;

	evt->type = event.type;
	evt->data.targetStoppedData.reason = event.data.targetStoppedData.reason;
	evt->data.targetStoppedData.exitCode = event.data.targetStoppedData.exitCode;
	evt->data.targetStoppedData.lastActiveThread = event.data.targetStoppedData.lastActiveThread;
	evt->data.targetStoppedData.data = event.data.targetStoppedData.data;

	evt->data.errorData.error = BNDebuggerAllocString(event.data.errorData.error.c_str());
	evt->data.errorData.shortError = BNDebuggerAllocString(event.data.errorData.shortError.c_str());
	evt->data.errorData.data = event.data.errorData.data;

	evt->data.exitData.exitCode = event.data.exitData.exitCode;

	evt->data.relativeAddress.module = BNDebuggerAllocString(event.data.relativeAddress.module.c_str());
	evt->data.relativeAddress.offset = event.data.relativeAddress.offset;

	evt->data.absoluteAddress = event.data.absoluteAddress;

	evt->data.messageData.message = BNDebuggerAllocString(event.data.messageData.message.c_str());

	BNDebuggerPostDebuggerEvent(m_object, evt);

	BNDebuggerFreeString(evt->data.errorData.error);
	BNDebuggerFreeString(evt->data.errorData.shortError);
	BNDebuggerFreeString(evt->data.relativeAddress.module);
	BNDebuggerFreeString(evt->data.messageData.message);
	delete evt;
}


bool DebuggerController::RemoveDebuggerMemoryRegion()
{
	return BNDebuggerRemoveMemoryRegion(m_object);
}


bool DebuggerController::ReAddDebuggerMemoryRegion()
{
	return BNDebuggerReAddMemoryRegion(m_object);
}


uint64_t DebuggerController::GetViewFileSegmentsStart()
{
	return BNDebuggerGetViewFileSegmentsStart(m_object);
}


bool DebuggerController::ComputeExprValue(const Ref<LowLevelILFunction>& func,
	const BinaryNinja::LowLevelILInstruction &expr, intx::uint512 &value)
{
	uint8_t buffer[64] = {0};
	if (!BNDebuggerComputeLLILExprValue(m_object, func->GetObject(), expr.exprIndex, buffer))
		return false;
	value = intx::le::load<intx::uint512>(buffer);
	return true;
}


bool DebuggerController::ComputeExprValue(const Ref<MediumLevelILFunction>& func,
	const BinaryNinja::MediumLevelILInstruction &expr, intx::uint512 &value)
{
	uint8_t buffer[64] = {0};
	if (!BNDebuggerComputeMLILExprValue(m_object, func->GetObject(), expr.exprIndex, buffer))
		return false;
	value = intx::le::load<intx::uint512>(buffer);
	return true;
}


bool DebuggerController::ComputeExprValue(const Ref<HighLevelILFunction>& func,
	const BinaryNinja::HighLevelILInstruction &expr, intx::uint512 &value)
{
	uint8_t buffer[64] = {0};
	if (!BNDebuggerComputeHLILExprValue(m_object, func->GetObject(), expr.exprIndex, buffer))
		return false;
	value = intx::le::load<intx::uint512>(buffer);
	return true;
}


bool DebuggerController::GetVariableValue(BinaryNinja::Variable &var, uint64_t address, size_t size,
	intx::uint512 &value)
{
	uint8_t buffer[64] = {0};
	if (!BNDebuggerGetVariableValue(m_object, &var, address, size, buffer))
		return false;
	value = intx::le::load<intx::uint512>(buffer);
	return true;
}


Ref<Settings> DebuggerController::GetAdapterSettings()
{
	auto settings =  BNDebuggerGetAdapterSettings(m_object);
	if (!settings)
		return nullptr;

	return new Settings(settings);
}


bool DebuggerController::FunctionExistsInOldView(uint64_t address)
{
	return BNDebuggerFunctionExistsInOldView(m_object, address);
}
