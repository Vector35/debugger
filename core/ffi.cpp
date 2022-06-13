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

#include "binaryninjaapi.h"
#include "debuggercontroller.h"
#include "debuggercommon.h"
#include "../api/ffi.h"

using namespace BinaryNinjaDebugger;


// Macro-like function to convert an non-referenced object to the external API reference
template <typename T>
static auto* API_OBJECT_STATIC(T* obj)
{
	if (obj == nullptr)
		return nullptr;
	return obj->GetAPIObject();
}

template <typename T>
static auto* API_OBJECT_STATIC(const BinaryNinja::Ref<T>& obj)
{
	if (!obj)
		return (decltype(obj->m_object))nullptr;
	obj->AddRef();
	return obj->GetObject();
}

// From refcountobject.h
template <typename T>
static auto* API_OBJECT_REF(T* obj)
{
	if (obj == nullptr)
		return (decltype(obj->m_object))nullptr;
	obj->AddRef();
	return obj->m_object;
}

template <typename T>
static auto* API_OBJECT_REF(const BinaryNinja::Ref<T>& obj)
{
	if (!obj)
		return (decltype(obj->m_object))nullptr;
	obj->AddRef();
	return obj->m_object;
}

template <class T>
static T* API_OBJECT_NEW_REF(T* obj)
{
	if (obj)
		obj->object->AddRef();
	return obj;
}

template <class T>
static void API_OBJECT_FREE(T* obj)
{
	if (obj)
		obj->object->ReleaseAPIRef();
}


char* BNDebuggerAllocString(const char* contents)
{
	return BNAllocString(contents);
}


void BNDebuggerFreeString(char* str)
{
	BNFreeString(str);
}


char** BNDebuggerAllocStringList(const char** contents, size_t size)
{
	return BNAllocStringList(contents, size);
}


void BNDebuggerFreeStringList(char** strs, size_t count)
{
	BNFreeStringList(strs, count);
}



BNDebuggerController* BNGetDebuggerController(BNBinaryView* data)
{
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return DebuggerController::GetController(view)->GetAPIObject();
}


void BNDebuggerDestroyController(BNDebuggerController* controller)
{
	controller->object->Destroy();
}


BNBinaryView* BNDebuggerGetLiveView(BNDebuggerController* controller)
{
	return API_OBJECT_REF(controller->object->GetLiveView());
}


BNBinaryView* BNDebuggerGetData(BNDebuggerController* controller)
{
	return API_OBJECT_REF(controller->object->GetData());
}


BNArchitecture* BNDebuggerGetRemoteArchitecture(BNDebuggerController* controller)
{
	return API_OBJECT_STATIC(controller->object->GetRemoteArchitecture());
}


bool BNDebuggerIsConnected(BNDebuggerController* controller)
{
	return controller->object->GetState()->IsConnected();
}


bool BNDebuggerIsConnectedToDebugServer(BNDebuggerController* controller)
{
    return controller->object->GetState()->IsConnectedToDebugServer();
}


bool BNDebuggerIsRunning(BNDebuggerController* controller)
{
	return controller->object->GetState()->IsRunning();
}


uint64_t BNDebuggerGetStackPointer(BNDebuggerController* controller)
{
	return controller->object->GetState()->StackPointer();
}


BNDataBuffer* BNDebuggerReadMemory(BNDebuggerController* controller, uint64_t address, size_t size)
{
	DataBuffer* data = new DataBuffer(controller->object->ReadMemory(address, size));
	return data->GetBufferObject();
}


bool BNDebuggerWriteMemory(BNDebuggerController* controller, uint64_t address, BNDataBuffer* buffer)
{
	// Hacky way of getting a BinaryNinj::DataBuffer out of a BNDataBuffer, without causing a segfault
	DataBuffer buf;
	BNAppendDataBuffer(buf.GetBufferObject(), buffer);
	return controller->object->WriteMemory(address, buf);
}


BNDebugThread* BNDebuggerGetThreads(BNDebuggerController* controller, size_t* size)
{
	std::vector<DebugThread> threads = controller->object->GetAllThreads();

	*size = threads.size();
	BNDebugThread* results = new BNDebugThread[threads.size()];

	for (size_t i = 0; i < threads.size(); i++)
	{
		results[i].m_tid = threads[i].m_tid;
		results[i].m_rip = threads[i].m_rip;
	}

	return results;
}


void BNDebuggerFreeThreads(BNDebugThread* threads, size_t count)
{
	delete[] threads;
}


BNDebugThread BNDebuggerGetActiveThread(BNDebuggerController* controller)
{
	DebugThread thread = controller->object->GetActiveThread();
	BNDebugThread result;
	result.m_tid = thread.m_tid;
	result.m_rip = thread.m_rip;
	return result;
}


void BNDebuggerSetActiveThread(BNDebuggerController* controller, BNDebugThread thread)
{
	DebugThread activeThread;
	activeThread.m_rip = thread.m_rip;
	activeThread.m_tid = thread.m_tid;

	controller->object->SetActiveThread(activeThread);
}


BNDebugFrame* BNDebuggerGetFramesOfThread(BNDebuggerController* controller, uint32_t tid, size_t* count)
{
	std::vector<DebugFrame> frames = controller->object->GetFramesOfThread(tid);
	*count = frames.size();

	BNDebugFrame* results = new BNDebugFrame[frames.size()];

	for (size_t i = 0; i < frames.size(); i++)
	{
		results[i].m_index = frames[i].m_index;
		results[i].m_pc = frames[i].m_pc;
		results[i].m_sp = frames[i].m_sp;
		results[i].m_fp = frames[i].m_fp;
		results[i].m_functionName = BNDebuggerAllocString(frames[i].m_functionName.c_str());
		results[i].m_functionStart = frames[i].m_functionStart;
		results[i].m_module = BNDebuggerAllocString(frames[i].m_module.c_str());
	}

	return results;
}


void BNDebuggerFreeFrames(BNDebugFrame* frames, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(frames[i].m_functionName);
		BNDebuggerFreeString(frames[i].m_module);
	}

	delete []frames;
}


BNDebugModule* BNDebuggerGetModules(BNDebuggerController* controller, size_t* size)
{
	std::vector<DebugModule> modules = controller->object->GetAllModules();

	*size = modules.size();
	BNDebugModule* results = new BNDebugModule[modules.size()];

	for (size_t i = 0; i < modules.size(); i++)
	{
		results[i].m_address = modules[i].m_address;
		results[i].m_name = BNDebuggerAllocString(modules[i].m_name.c_str());
		results[i].m_short_name = BNDebuggerAllocString(modules[i].m_short_name.c_str());
		results[i].m_size = modules[i].m_size;
		results[i].m_loaded = modules[i].m_loaded;
	}

	return results;
}


void BNDebuggerFreeModules(BNDebugModule* modules, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(modules[i].m_name);
		BNDebuggerFreeString(modules[i].m_short_name);
	}
	delete[] modules;
}


BNDebugRegister* BNDebuggerGetRegisters(BNDebuggerController* controller, size_t* size)
{
	std::vector<DebugRegister> registers = controller->object->GetAllRegisters();

	*size = registers.size();
	BNDebugRegister* results = new BNDebugRegister[registers.size()];

	for (size_t i = 0; i < registers.size(); i++)
	{
		results[i].m_name = BNDebuggerAllocString(registers[i].m_name.c_str());
		results[i].m_value = registers[i].m_value;
		results[i].m_width = registers[i].m_width;
		results[i].m_registerIndex = registers[i].m_registerIndex;
		results[i].m_hint = BNDebuggerAllocString(registers[i].m_hint.c_str());
	}

	return results;
}


void BNDebuggerFreeRegisters(BNDebugRegister* registers, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(registers[i].m_name);
		BNDebuggerFreeString(registers[i].m_hint);
	}
	delete[] registers;
}


bool BNDebuggerSetRegisterValue(BNDebuggerController* controller, const char* name, uint64_t value)
{
	return controller->object->SetRegisterValue(std::string(name), value);
}


uint64_t BNDebuggerGetRegisterValue(BNDebuggerController* controller, const char* name)
{
	return controller->object->GetRegisterValue(std::string(name));
}


// target control
bool BNDebuggerLaunch(BNDebuggerController* controller)
{
	return controller->object->Launch();
}


bool BNDebuggerExecute(BNDebuggerController* controller)
{
	return controller->object->Execute();
}


// TODO: Maybe this should return bool?
void BNDebuggerRestart(BNDebuggerController* controller)
{
	controller->object->Restart();
}


void BNDebuggerQuit(BNDebuggerController* controller)
{
	controller->object->Quit();
}


void BNDebuggerConnect(BNDebuggerController* controller)
{
	controller->object->Connect();
}


bool BNDebuggerConnectToDebugServer(BNDebuggerController* controller)
{
    return controller->object->ConnectToDebugServer();
}


bool BNDebuggerDisconnectDebugServer(BNDebuggerController* controller)
{
    return controller->object->DisconnectDebugServer();
}


void BNDebuggerDetach(BNDebuggerController* controller)
{
	controller->object->Detach();
}


void BNDebuggerPause(BNDebuggerController* controller)
{
	controller->object->Pause();
}


// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
void BNDebuggerLaunchOrConnect(BNDebuggerController* controller)
{
	controller->object->LaunchOrConnect();
}


bool BNDebuggerAttach(BNDebuggerController* controller, uint32_t pid)
{
	return controller->object->Attach(pid);
}


bool BNDebuggerGo(BNDebuggerController* controller)
{
	return controller->object->Go();
}


bool BNDebuggerStepInto(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepInto(il);
}


bool BNDebuggerStepOver(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepOver(il);
}


bool BNDebuggerStepReturn(BNDebuggerController* controller)
{
	return controller->object->StepReturn();
}


bool BNDebuggerRunTo(BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count)
{
	std::vector<uint64_t> addresses;
	addresses.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		addresses.push_back(remoteAddresses[i]);
	}
	return controller->object->RunTo(addresses);
}


BNDebugStopReason BNDebuggerGoAndWait(BNDebuggerController* controller)
{
	return controller->object->GoAndWait();
}


BNDebugStopReason BNDebuggerStepIntoAndWait(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepIntoAndWait(il);
}


BNDebugStopReason BNDebuggerStepOverAndWait(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepOverAndWait(il);
}


BNDebugStopReason BNDebuggerStepReturnAndWait(BNDebuggerController* controller)
{
	return controller->object->StepReturnAndWait();
}


BNDebugStopReason BNDebuggerRunToAndWait(BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count)
{
	std::vector<uint64_t> addresses;
	addresses.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		addresses.push_back(remoteAddresses[i]);
	}
	return controller->object->RunToAndWait(addresses);
}


DebugStopReason BNDebuggerPauseAndWait(BNDebuggerController* controller)
{
	return controller->object->PauseAndWait();
}


char* BNDebuggerGetAdapterType(BNDebuggerController* controller)
{
	if (!controller->object->GetState())
		return nullptr;

	return BNDebuggerAllocString(controller->object->GetState()->GetAdapterType().c_str());
}


void BNDebuggerSetAdapterType(BNDebuggerController* controller, const char* adapter)
{
	controller->object->GetState()->SetAdapterType(adapter);
}


BNDebugAdapterType* BNGetDebugAdapterTypeByName(const char* name)
{
	return DebugAdapterType::GetByName(name)->GetAPIObject();
}


bool BNDebugAdapterTypeCanExecute(BNDebugAdapterType* adapter, BNBinaryView* data)
{
	return adapter->object->CanExecute(new BinaryView(data));
}


bool BNDebugAdapterTypeCanConnect(BNDebugAdapterType* adapter, BNBinaryView* data)
{
	return adapter->object->CanConnect(new BinaryView(data));
}


BNDebugAdapterConnectionStatus BNDebuggerGetConnectionStatus(BNDebuggerController* controller)
{
	return controller->object->GetConnectionStatus();
}


BNDebugAdapterTargetStatus BNDebuggerGetTargetStatus(BNDebuggerController* controller)
{
	return controller->object->GetExecutionStatus();
}


char** BNGetAvailableDebugAdapterTypes(BNBinaryView* data, size_t* count)
{
	std::vector<std::string> adapters = DebugAdapterType::GetAvailableAdapters(new BinaryView(data));
	*count = adapters.size();

	std::vector<const char*> cstrings;
	cstrings.reserve(adapters.size());
	for (auto& str: adapters)
	{
		cstrings.push_back(str.c_str());
	}
	*count = adapters.size();
	return BNDebuggerAllocStringList(cstrings.data(), *count);
}


char* BNDebuggerGetRemoteHost(BNDebuggerController* controller)
{
	return BNDebuggerAllocString(controller->object->GetState()->GetRemoteHost().c_str());
}


uint32_t BNDebuggerGetRemotePort(BNDebuggerController* controller)
{
	return controller->object->GetState()->GetRemotePort();
}


char* BNDebuggerGetExecutablePath(BNDebuggerController* controller)
{
	return BNDebuggerAllocString(controller->object->GetState()->GetExecutablePath().c_str());
}


char* BNDebuggerGetWorkingDirectory(BNDebuggerController* controller)
{
	return BNDebuggerAllocString(controller->object->GetState()->GetWorkingDirectory().c_str());
}


bool BNDebuggerGetRequestTerminalEmulator(BNDebuggerController* controller)
{
	return controller->object->GetState()->GetRequestTerminalEmulator();
}


char* BNDebuggerGetCommandLineArguments(BNDebuggerController* controller)
{
	return BNDebuggerAllocString(controller->object->GetState()->GetCommandLineArguments().c_str());
}


void BNDebuggerSetRemoteHost(BNDebuggerController* controller, const char* host)
{
	controller->object->GetState()->SetRemoteHost(host);
}


void BNDebuggerSetRemotePort(BNDebuggerController* controller, uint32_t port)
{
	controller->object->GetState()->SetRemotePort(port);
}


void BNDebuggerSetExecutablePath(BNDebuggerController* controller, const char* path)
{
	controller->object->GetState()->SetExecutablePath(path);
}


void BNDebuggerSetWorkingDirectory(BNDebuggerController* controller, const char* path)
{
	controller->object->GetState()->SetWorkingDirectory(path);
}


void BNDebuggerSetRequestTerminalEmulator(BNDebuggerController* controller, bool requestEmulator)
{
	controller->object->GetState()->SetRequestTerminalEmulator(requestEmulator);
}


void BNDebuggerSetCommandLineArguments(BNDebuggerController* controller, const char* args)
{
	controller->object->GetState()->SetCommandLineArguments(args);
}


// TODO: the structures to hold information about the breakpoints are different in the API and the core, so we need to
// convert it here. Better unify them later.
BNDebugBreakpoint* BNDebuggerGetBreakpoints(BNDebuggerController* controller, size_t* count)
{
	DebuggerState* state = controller->object->GetState();
	std::vector<ModuleNameAndOffset> breakpoints = state->GetBreakpoints()->GetBreakpointList();
	*count = breakpoints.size();

//	std::vector<DebugBreakpoint> remoteList;
//	if (state->IsConnected() && state->GetAdapter())
//		remoteList = state->GetAdapter()->GetBreakpointList();

	BNDebugBreakpoint* result = new BNDebugBreakpoint[breakpoints.size()];
	for (size_t i = 0; i < breakpoints.size(); i++)
	{
		uint64_t remoteAddress = state->GetModules()->RelativeAddressToAbsolute(breakpoints[i]);
		bool enabled = false;
//		for (const DebugBreakpoint& bp: remoteList)
//		{
//			if (bp.m_address == remoteAddress)
//			{
//				enabled = true;
//				break;
//			}
//		}
		result[i].module = BNDebuggerAllocString(breakpoints[i].module.c_str());
		result[i].offset = breakpoints[i].offset;
		result[i].address = remoteAddress;
		result[i].enabled = enabled;
	}
	return result;
}


void BNDebuggerFreeBreakpoints(BNDebugBreakpoint* breakpoints, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(breakpoints[i].module);
	}
	delete[] breakpoints;
}


void BNDebuggerDeleteAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address)
{
	controller->object->DeleteBreakpoint(address);
}


void BNDebuggerDeleteRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset)
{
	controller->object->DeleteBreakpoint(ModuleNameAndOffset(module, offset));
}


void BNDebuggerAddAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address)
{
	controller->object->AddBreakpoint(address);
}


void BNDebuggerAddRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset)
{
	controller->object->AddBreakpoint(ModuleNameAndOffset(module, offset));
}


uint64_t BNDebuggerGetIP(BNDebuggerController* controller)
{
	return controller->object->GetCurrentIP();
}


uint64_t BNDebuggerGetLastIP(BNDebuggerController* controller)
{
	return controller->object->GetLastIP();
}


bool BNDebuggerContainsAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address)
{
	DebuggerState* state = controller->object->GetState();
	if (!state)
		return false;

	DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
	if (!breakpoints)
		return false;

	return breakpoints->ContainsAbsolute(address);
}


bool BNDebuggerContainsRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset)
{
	DebuggerState* state = controller->object->GetState();
	if (!state)
		return false;

	DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
	if (!breakpoints)
		return false;

	return breakpoints->ContainsOffset(ModuleNameAndOffset(module, offset));
}


uint64_t BNDebuggerRelativeAddressToAbsolute(BNDebuggerController* controller, const char* module, uint64_t offset)
{
	DebuggerState* state = controller->object->GetState();
	if (!state)
		return 0;

	DebuggerModules* modules = state->GetModules();
	if (!modules)
		return 0;

	return modules->RelativeAddressToAbsolute(ModuleNameAndOffset(module, offset));
}


BNModuleNameAndOffset BNDebuggerAbsoluteAddressToRelative(BNDebuggerController* controller, uint64_t address)
{
	BNModuleNameAndOffset result;
	result.offset = 0;
	result.module = nullptr;

	DebuggerState* state = controller->object->GetState();
	if (!state)
		return result;

	DebuggerModules* modules = state->GetModules();
	if (!modules)
		return result;

	ModuleNameAndOffset addr = modules->AbsoluteAddressToRelative(address);
	result.module = BNDebuggerAllocString(addr.module.c_str());
	result.offset = addr.offset;
	return result;
}


bool BNDebuggerIsSameBaseModule(const char* module1, const char* module2)
{
	return DebugModule::IsSameBaseModule(module1, module2);
}


size_t BNDebuggerRegisterEventCallback(BNDebuggerController* controller,
									   void (*callback)(void* ctx, BNDebuggerEvent* event),
									   void* ctx)
{
	return controller->object->RegisterEventCallback([=](const DebuggerEvent& event){
		BNDebuggerEvent* evt = new BNDebuggerEvent;

		evt->type = event.type;
		evt->data.targetStoppedData.reason = event.data.targetStoppedData.reason;
		evt->data.targetStoppedData.exitCode = event.data.targetStoppedData.exitCode;
		evt->data.targetStoppedData.lastActiveThread = event.data.targetStoppedData.lastActiveThread;
		evt->data.targetStoppedData.data = event.data.targetStoppedData.data;

		evt->data.errorData.error = BNDebuggerAllocString(event.data.errorData.error.c_str());
		evt->data.errorData.data = event.data.errorData.data;

		evt->data.exitData.exitCode = event.data.exitData.exitCode;

		evt->data.relativeAddress.module = BNDebuggerAllocString(event.data.relativeAddress.module.c_str());
		evt->data.relativeAddress.offset = event.data.relativeAddress.offset;

		evt->data.absoluteAddress = event.data.absoluteAddress;

		evt->data.messageData.message = BNDebuggerAllocString(event.data.messageData.message.c_str());

		callback(ctx, evt);
		delete evt;
	});
}


void BNDebuggerRemoveEventCallback(BNDebuggerController* controller, size_t index)
{
	controller->object->RemoveEventCallback(index);
}


uint32_t BNDebuggerGetExitCode(BNDebuggerController* controller)
{
	return controller->object->GetExitCode();
}


void BNDebuggerWriteStdin(BNDebuggerController* controller, const char* data, size_t len)
{
	controller->object->WriteStdIn(std::string(data, len));
}


DEBUGGER_FFI_API char* BNDebuggerInvokeBackendCommand(BNDebuggerController* controller, const char* cmd)
{
	std::string output = controller->object->InvokeBackendCommand(std::string(cmd));
	char* result = BNDebuggerAllocString(output.c_str());
	return result;
}


DEBUGGER_FFI_API char* BNDebuggerGetStopReasonString(BNDebugStopReason reason)
{
	std::string str = DebuggerController::GetStopReasonString(reason);
	return BNDebuggerAllocString(str.c_str());
}


DEBUGGER_FFI_API DebugStopReason BNDebuggerGetStopReason(BNDebuggerController* controller)
{
	return controller->object->StopReason();
}
