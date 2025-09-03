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

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "debuggercontroller.h"
#include "debuggercommon.h"
#include "../api/ffi.h"
#include <map>

using namespace BinaryNinjaDebugger;


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
	if (!data)
		return nullptr;

	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	DebuggerController* controller = DebuggerController::GetController(view);
	if (!controller)
		return nullptr;

	return DBG_API_OBJECT_REF(controller);
}


void BNDebuggerDestroyController(BNDebuggerController* controller)
{
	controller->object->Destroy();
}


bool BNDebuggerControllerExists(BNBinaryView* data)
{
	if (!data)
		return false;

	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return DebuggerController::ControllerExists(view);
}


BNDebuggerController* BNGetDebuggerControllerFromFile(BNFileMetadata* file)
{
	if (!file)
		return nullptr;

	Ref<FileMetadata> fileObject = new FileMetadata(BNNewFileReference(file));
	DebuggerController* controller = DebuggerController::GetController(fileObject);
	if (!controller)
		return nullptr;

	return DBG_API_OBJECT_REF(controller);
}


bool BNDebuggerControllerExistsFromFile(BNFileMetadata* file)
{
	if (!file)
		return false;

	Ref<FileMetadata> fileObject = new FileMetadata(BNNewFileReference(file));
	return DebuggerController::ControllerExists(fileObject);
}


BNBinaryView* BNDebuggerGetData(BNDebuggerController* controller)
{
	BinaryViewRef result = controller->object->GetData();
	if (result)
		return BNNewViewReference(result->GetObject());
	return nullptr;
}


void BNDebuggerSetData(BNDebuggerController* controller, BNBinaryView* data)
{
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	controller->object->SetData(view);
}


BNArchitecture* BNDebuggerGetRemoteArchitecture(BNDebuggerController* controller)
{
	ArchitectureRef result = controller->object->GetRemoteArchitecture();
	if (result)
		return result->GetObject();
	return nullptr;
}


bool BNDebuggerIsConnected(BNDebuggerController* controller)
{
	return controller->object->GetState()->IsConnected();
}


bool BNDebuggerIsConnectedToDebugServer(BNDebuggerController* controller)
{
	return controller->object->IsConnectedToDebugServer();
}


bool BNDebuggerIsRunning(BNDebuggerController* controller)
{
	return controller->object->GetState()->IsRunning();
}


BNDebuggerController* BNDebuggerNewControllerReference(BNDebuggerController* controller)
{
	return DBG_API_OBJECT_NEW_REF(controller);
}


void BNDebuggerFreeController(BNDebuggerController* view)
{
	DBG_API_OBJECT_FREE(view);
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


BNDebugProcess* BNDebuggerGetProcessList(BNDebuggerController* controller, size_t* size)
{
	std::vector<DebugProcess> processes = controller->object->GetProcessList();

	*size = processes.size();
	BNDebugProcess* results = new BNDebugProcess[processes.size()];

	for (size_t i = 0; i < processes.size(); i++)
	{
		results[i].m_pid = processes[i].m_pid;
		results[i].m_processName = BNDebuggerAllocString(processes[i].m_processName.c_str());
	}

	return results;
}


void BNDebuggerFreeProcessList(BNDebugProcess* processes, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(processes[i].m_processName);
	}

	delete[] processes;
}


uint32_t BNDebuggerGetActivePID(BNDebuggerController* controller)
{
	return controller->object->GetActivePID();
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
		results[i].m_isFrozen = threads[i].m_isFrozen;
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


bool BNDebuggerSuspendThread(BNDebuggerController* controller, uint32_t tid)
{
	return controller->object->SuspendThread(tid);
}


bool BNDebuggerResumeThread(BNDebuggerController* controller, uint32_t tid)
{
	return controller->object->ResumeThread(tid);
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

	delete[] frames;
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
		intx::le::store(results[i].m_value, registers[i].m_value);
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


bool BNDebuggerSetRegisterValue(BNDebuggerController* controller, const char* name, const uint8_t* value)
{
	uint8_t buffer[64];
	memcpy(buffer, value, 64);
	return controller->object->SetRegisterValue(std::string(name), intx::le::load<intx::uint512>(buffer));
}


void BNDebuggerGetRegisterValue(BNDebuggerController* controller, const char* name, uint8_t* buffer)
{
	auto value = controller->object->GetRegisterValue(std::string(name));
	uint8_t temp[64] = {};
	intx::le::store(temp, value);
	memcpy(buffer, temp, 64);
}


// target control
bool BNDebuggerLaunch(BNDebuggerController* controller)
{
	return controller->object->Launch();
}


BNDebugStopReason BNDebuggerLaunchAndWait(BNDebuggerController* controller)
{
	return controller->object->LaunchAndWait();
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


void BNDebuggerQuitAndWait(BNDebuggerController* controller)
{
	controller->object->QuitAndWait();
}


bool BNDebuggerConnect(BNDebuggerController* controller)
{
	return controller->object->Connect();
}


BNDebugStopReason BNDebuggerConnectAndWait(BNDebuggerController* controller)
{
	return controller->object->ConnectAndWait();
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


bool BNDebuggerAttach(BNDebuggerController* controller)
{
	return controller->object->Attach();
}


BNDebugStopReason BNDebuggerAttachAndWait(BNDebuggerController* controller)
{
	return controller->object->AttachAndWait();
}


bool BNDebuggerGo(BNDebuggerController* controller)
{
	return controller->object->Go();
}


bool BNDebuggerGoReverse(BNDebuggerController* controller)
{
	return controller->object->GoReverse();
}


bool BNDebuggerStepInto(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepInto(il);
}

bool BNDebuggerStepIntoReverse(BNDebuggerController* controller, BNFunctionGraphType il)
 {
 	return controller->object->StepIntoReverse(il);
 }


bool BNDebuggerStepOver(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepOver(il);
}


bool BNDebuggerStepOverReverse(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepOverReverse(il);
}


bool BNDebuggerStepReturn(BNDebuggerController* controller)
{
	return controller->object->StepReturn();
}


bool BNDebuggerStepReturnReverse(BNDebuggerController* controller)
{
	return controller->object->StepReturnReverse();
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


bool BNDebuggerRunToReverse(BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count)
{
	std::vector<uint64_t> addresses;
	addresses.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		addresses.push_back(remoteAddresses[i]);
	}
	return controller->object->RunToReverse(addresses);
}


BNDebugStopReason BNDebuggerGoAndWait(BNDebuggerController* controller)
{
	return controller->object->GoAndWait();
}


BNDebugStopReason BNDebuggerGoReverseAndWait(BNDebuggerController* controller)
{
	return controller->object->GoReverseAndWait();
}


BNDebugStopReason BNDebuggerStepIntoAndWait(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepIntoAndWait(il);
}


BNDebugStopReason BNDebuggerStepIntoReverseAndWait(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepIntoReverseAndWait(il);
}


BNDebugStopReason BNDebuggerStepOverAndWait(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepOverAndWait(il);
}

BNDebugStopReason BNDebuggerStepOverReverseAndWait(BNDebuggerController* controller, BNFunctionGraphType il)
{
	return controller->object->StepOverReverseAndWait(il);
}


BNDebugStopReason BNDebuggerStepReturnAndWait(BNDebuggerController* controller)
{
	return controller->object->StepReturnAndWait();
}


BNDebugStopReason BNDebuggerStepReturnReverseAndWait(BNDebuggerController* controller)
{
	return controller->object->StepReturnReverseAndWait();
}


BNDebugStopReason BNDebuggerRunToAndWait(
	BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count)
{
	std::vector<uint64_t> addresses;
	addresses.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		addresses.push_back(remoteAddresses[i]);
	}
	return controller->object->RunToAndWait(addresses);
}


BNDebugStopReason BNDebuggerRunToReverseAndWait(
	BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count)
{
	std::vector<uint64_t> addresses;
	addresses.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		addresses.push_back(remoteAddresses[i]);
	}
	return controller->object->RunToReverseAndWait(addresses);
}


DebugStopReason BNDebuggerPauseAndWait(BNDebuggerController* controller)
{
	return controller->object->PauseAndWait();
}


DebugStopReason BNDebuggerRestartAndWait(BNDebuggerController* controller)
{
	return controller->object->RestartAndWait();
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
	DebugAdapterType* type = DebugAdapterType::GetByName(name);
 	if (!type)
		return nullptr;

	return type->GetAPIObject();
}


bool BNDebugAdapterTypeCanExecute(BNDebugAdapterType* adapter, BNBinaryView* data)
{
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return adapter->object->CanExecute(view);
}


bool BNDebugAdapterTypeCanConnect(BNDebugAdapterType* adapter, BNBinaryView* data)
{
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	return adapter->object->CanConnect(view);
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
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	std::vector<std::string> adapters = DebugAdapterType::GetAvailableAdapters(view);
	*count = adapters.size();

	std::vector<const char*> cstrings;
	cstrings.reserve(adapters.size());
	for (auto& str : adapters)
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


int32_t BNDebuggerGetPIDAttach(BNDebuggerController* controller)
{
	return controller->object->GetState()->GetPIDAttach();
}


char* BNDebuggerGetInputFile(BNDebuggerController* controller)
{
	return BNDebuggerAllocString(controller->object->GetState()->GetInputFile().c_str());
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


void BNDebuggerSetPIDAttach(BNDebuggerController* controller, int32_t pid)
{
	controller->object->GetState()->SetPIDAttach(pid);
}


void BNDebuggerSetInputFile(BNDebuggerController* controller, const char* path)
{
	controller->object->GetState()->SetInputFile(path);
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

	//std::vector<DebugBreakpoint> remoteList;
	//if (state->IsConnected() && state->GetAdapter())
	//	remoteList = state->GetAdapter()->GetBreakpointList();

	BNDebugBreakpoint* result = new BNDebugBreakpoint[breakpoints.size()];
	for (size_t i = 0; i < breakpoints.size(); i++)
	{
		uint64_t remoteAddress = state->GetModules()->RelativeAddressToAbsolute(breakpoints[i]);
		bool enabled = state->GetBreakpoints()->IsEnabledOffset(breakpoints[i]);
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


void BNDebuggerEnableAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address)
{
	controller->object->EnableBreakpoint(address);
}


void BNDebuggerEnableRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset)
{
	controller->object->EnableBreakpoint(ModuleNameAndOffset(module, offset));
}


void BNDebuggerDisableAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address)
{
	controller->object->DisableBreakpoint(address);
}


void BNDebuggerDisableRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset)
{
	controller->object->DisableBreakpoint(ModuleNameAndOffset(module, offset));
}


uint64_t BNDebuggerGetIP(BNDebuggerController* controller)
{
	return controller->object->GetCurrentIP();
}


uint64_t BNDebuggerGetLastIP(BNDebuggerController* controller)
{
	return controller->object->GetLastIP();
}


bool BNDebuggerSetIP(BNDebuggerController* controller, uint64_t address)
{
	return controller->object->SetIP(address);
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


size_t BNDebuggerRegisterEventCallback(
	BNDebuggerController* controller, void (*callback)(void* ctx, BNDebuggerEvent* event), const char* name, void* ctx)
{
	return controller->object->RegisterEventCallback(
		[=](const DebuggerEvent& event) {
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

			callback(ctx, evt);

			BNDebuggerFreeString(evt->data.errorData.error);
			BNDebuggerFreeString(evt->data.errorData.shortError);
			BNDebuggerFreeString(evt->data.relativeAddress.module);
			BNDebuggerFreeString(evt->data.messageData.message);
			delete evt;
		},
		name);
}


void BNDebuggerRemoveEventCallback(BNDebuggerController* controller, size_t index)
{
	controller->object->RemoveEventCallback(index);
}


uint32_t BNDebuggerGetExitCode(BNDebuggerController* controller)
{
	return controller->object->GetExitCode();
}


void BNDebuggerSetDebuggerUICallbacks(BNDebuggerController* controller, BNDebuggerUICallbacks* cb, void* ctxt)
{
	controller->object->SetDebuggerUICallbacks(cb, ctxt);
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


DEBUGGER_FFI_API BNMetadata* BNDebuggerGetAdapterProperty(BNDebuggerController* controller, const char* name)
{
	Ref<Metadata> result = controller->object->GetAdapterProperty(name);
	if (result)
		return BNNewMetadataReference(result->GetObject());
	return nullptr;
}


DEBUGGER_FFI_API bool BNDebuggerSetAdapterProperty(
	BNDebuggerController* controller, const char* name, BNMetadata* value)
{
	return controller->object->SetAdapterProperty(name, new Metadata(BNNewMetadataReference(value)));
}


bool BNDebuggerActivateDebugAdapter(BNDebuggerController* controller)
{
	return controller->object->ActivateDebugAdapter();
}


char* BNDebuggerGetAddressInformation(BNDebuggerController* controller, uint8_t* buffer)
{
	uint8_t temp[64] = {};
	memcpy(temp, buffer, 64);
	auto value = intx::le::load<intx::uint512>(temp);
	return BNDebuggerAllocString(controller->object->GetAddressInformation(value).c_str());
}


bool BNDebuggerIsFirstLaunch(BNDebuggerController* controller)
{
	return controller->object->IsFirstLaunch();
}


bool BNDebuggerIsFirstConnect(BNDebuggerController* controller)
{
	return controller->object->IsFirstConnect();
}


bool BNDebuggerIsFirstConnectToDebugServer(BNDebuggerController* controller)
{
	return controller->object->IsFirstConnectToDebugServer();
}


bool BNDebuggerIsFirstAttach(BNDebuggerController* controller)
{
	return controller->object->IsFirstAttach();
}


bool BNDebuggerIsTTD(BNDebuggerController* controller)
{
	return controller->object->IsTTD();
}


BNDebuggerTTDMemoryEvent* BNDebuggerGetTTDMemoryAccessForAddress(BNDebuggerController* controller,
	uint64_t address, uint64_t size, BNDebuggerTTDMemoryAccessType accessType, size_t* count)
{
	if (!count)
		return nullptr;
		
	*count = 0;
	
	TTDMemoryAccessType type = static_cast<TTDMemoryAccessType>(accessType);
	auto events = controller->object->GetTTDMemoryAccessForAddress(address, size, type);
	if (events.empty())
		return nullptr;
		
	*count = events.size();
	auto result = new BNDebuggerTTDMemoryEvent[events.size()];
	
	for (size_t i = 0; i < events.size(); i++)
	{
		result[i].eventType = BNAllocString(events[i].eventType.c_str());
		result[i].threadId = events[i].threadId;
		result[i].uniqueThreadId = events[i].uniqueThreadId;
		result[i].timeStart.sequence = events[i].timeStart.sequence;
		result[i].timeStart.step = events[i].timeStart.step;
		result[i].timeEnd.sequence = events[i].timeEnd.sequence;
		result[i].timeEnd.step = events[i].timeEnd.step;
		result[i].address = events[i].address;
		result[i].size = events[i].size;
		result[i].memoryAddress = events[i].memoryAddress;
		result[i].instructionAddress = events[i].instructionAddress;
		result[i].value = events[i].value;
		result[i].accessType = static_cast<BNDebuggerTTDMemoryAccessType>(events[i].accessType);
	}
	
	return result;
}

BNDebuggerTTDPosition BNDebuggerGetCurrentTTDPosition(BNDebuggerController* controller)
{
	auto position = controller->object->GetCurrentTTDPosition();
	BNDebuggerTTDPosition result;
	result.sequence = position.sequence;
	result.step = position.step;
	return result;
}

bool BNDebuggerSetTTDPosition(BNDebuggerController* controller, BNDebuggerTTDPosition position)
{
	TTDPosition pos(position.sequence, position.step);
	return controller->object->SetTTDPosition(pos);
}

bool BNDebuggerIsInstructionExecuted(BNDebuggerController* controller, uint64_t address)
{
	return controller->object->IsInstructionExecuted(address);
}

bool BNDebuggerRunCodeCoverageAnalysisRange(BNDebuggerController* controller, uint64_t startAddress, uint64_t endAddress)
{
	return controller->object->RunCodeCoverageAnalysis(startAddress, endAddress);
}

size_t BNDebuggerGetExecutedInstructionCount(BNDebuggerController* controller)
{
	return controller->object->GetExecutedInstructionCount();
}

bool BNDebuggerSaveCodeCoverageToFile(BNDebuggerController* controller, const char* filePath)
{
	return controller->object->SaveCodeCoverageToFile(filePath);
}

bool BNDebuggerLoadCodeCoverageFromFile(BNDebuggerController* controller, const char* filePath)
{
	return controller->object->LoadCodeCoverageFromFile(filePath);
}

void BNDebuggerFreeTTDMemoryEvents(BNDebuggerTTDMemoryEvent* events, size_t count)
{
	if (events && count > 0)
	{
		// Free strings for each event
		for (size_t i = 0; i < count; ++i)
		{
			if (events[i].eventType)
			{
				BNFreeString(events[i].eventType);
			}
		}
		delete[] events;
	}
}


BNDebuggerTTDCallEvent* BNDebuggerGetTTDCallsForSymbols(BNDebuggerController* controller,
	const char* symbols, uint64_t startReturnAddress, uint64_t endReturnAddress, size_t* count)
{
	if (!count)
		return nullptr;

	*count = 0;

	if (!symbols)
		return nullptr;

	std::string symbolsStr(symbols);
	if (symbolsStr.empty())
		return nullptr;

	auto events = controller->object->GetTTDCallsForSymbols(symbolsStr, startReturnAddress, endReturnAddress);
	if (events.empty())
		return nullptr;

	*count = events.size();
	auto result = new BNDebuggerTTDCallEvent[events.size()];

	for (size_t i = 0; i < events.size(); ++i)
	{
		// Copy string fields
		result[i].eventType = BNAllocString(events[i].eventType.c_str());
		result[i].function = BNAllocString(events[i].function.c_str());

		// Copy primitive fields
		result[i].threadId = events[i].threadId;
		result[i].uniqueThreadId = events[i].uniqueThreadId;
		result[i].functionAddress = events[i].functionAddress;
		result[i].returnAddress = events[i].returnAddress;
		result[i].returnValue = events[i].returnValue;
		result[i].hasReturnValue = events[i].hasReturnValue;

		// Copy parameters array
		result[i].parameterCount = events[i].parameters.size();
		if (result[i].parameterCount > 0)
		{
			result[i].parameters = new char*[result[i].parameterCount];
			for (size_t j = 0; j < result[i].parameterCount; ++j)
			{
				result[i].parameters[j] = BNAllocString(events[i].parameters[j].c_str());
			}
		}
		else
		{
			result[i].parameters = nullptr;
		}

		// Copy TTD positions
		result[i].timeStart.sequence = events[i].timeStart.sequence;
		result[i].timeStart.step = events[i].timeStart.step;
		result[i].timeEnd.sequence = events[i].timeEnd.sequence;
		result[i].timeEnd.step = events[i].timeEnd.step;
	}

	return result;
}


void BNDebuggerFreeTTDCallEvents(BNDebuggerTTDCallEvent* events, size_t count)
{
	if (!events || count == 0)
		return;

	// Free all strings for each event
	for (size_t i = 0; i < count; ++i)
	{
		if (events[i].eventType)
		{
			BNFreeString(events[i].eventType);
		}
		if (events[i].function)
		{
			BNFreeString(events[i].function);
		}

		// Free parameter strings
		if (events[i].parameters && events[i].parameterCount > 0)
		{
			for (size_t j = 0; j < events[i].parameterCount; ++j)
			{
				if (events[i].parameters[j])
				{
					BNFreeString(events[i].parameters[j]);
				}
			}
			delete[] events[i].parameters;
		}
	}

	delete[] events;
}


BNDebuggerTTDEvent* BNDebuggerGetTTDEvents(BNDebuggerController* controller,
	BNDebuggerTTDEventType eventType, size_t* count)
{
	if (!count)
		return nullptr;

	*count = 0;

	auto events = controller->object->GetTTDEvents(static_cast<TTDEventType>(eventType));
	if (events.empty())
		return nullptr;

	*count = events.size();
	auto result = new BNDebuggerTTDEvent[events.size()];

	for (size_t i = 0; i < events.size(); ++i)
	{
		// Copy event type and position
		result[i].type = static_cast<BNDebuggerTTDEventType>(events[i].type);
		result[i].position.sequence = events[i].position.sequence;
		result[i].position.step = events[i].position.step;

		// Copy optional module details
		if (events[i].module.has_value())
		{
			result[i].module = new BNDebuggerTTDModule();
			result[i].module->name = BNAllocString(events[i].module->name.c_str());
			result[i].module->address = events[i].module->address;
			result[i].module->size = events[i].module->size;
			result[i].module->checksum = events[i].module->checksum;
			result[i].module->timestamp = events[i].module->timestamp;
		}
		else
		{
			result[i].module = nullptr;
		}

		// Copy optional thread details
		if (events[i].thread.has_value())
		{
			result[i].thread = new BNDebuggerTTDThread();
			result[i].thread->uniqueId = events[i].thread->uniqueId;
			result[i].thread->id = events[i].thread->id;
			result[i].thread->lifetimeStart.sequence = events[i].thread->lifetimeStart.sequence;
			result[i].thread->lifetimeStart.step = events[i].thread->lifetimeStart.step;
			result[i].thread->lifetimeEnd.sequence = events[i].thread->lifetimeEnd.sequence;
			result[i].thread->lifetimeEnd.step = events[i].thread->lifetimeEnd.step;
			result[i].thread->activeTimeStart.sequence = events[i].thread->activeTimeStart.sequence;
			result[i].thread->activeTimeStart.step = events[i].thread->activeTimeStart.step;
			result[i].thread->activeTimeEnd.sequence = events[i].thread->activeTimeEnd.sequence;
			result[i].thread->activeTimeEnd.step = events[i].thread->activeTimeEnd.step;
		}
		else
		{
			result[i].thread = nullptr;
		}

		// Copy optional exception details
		if (events[i].exception.has_value())
		{
			result[i].exception = new BNDebuggerTTDException();
			result[i].exception->type = static_cast<BNDebuggerTTDExceptionType>(events[i].exception->type);
			result[i].exception->programCounter = events[i].exception->programCounter;
			result[i].exception->code = events[i].exception->code;
			result[i].exception->flags = events[i].exception->flags;
			result[i].exception->recordAddress = events[i].exception->recordAddress;
			result[i].exception->position.sequence = events[i].exception->position.sequence;
			result[i].exception->position.step = events[i].exception->position.step;
		}
		else
		{
			result[i].exception = nullptr;
		}
	}

	return result;
}


BNDebuggerTTDEvent* BNDebuggerGetAllTTDEvents(BNDebuggerController* controller, size_t* count)
{
	if (!count)
		return nullptr;

	*count = 0;

	auto events = controller->object->GetAllTTDEvents();
	if (events.empty())
		return nullptr;

	*count = events.size();
	auto result = new BNDebuggerTTDEvent[events.size()];

	for (size_t i = 0; i < events.size(); ++i)
	{
		// Copy event type and position
		result[i].type = static_cast<BNDebuggerTTDEventType>(events[i].type);
		result[i].position.sequence = events[i].position.sequence;
		result[i].position.step = events[i].position.step;

		// Copy optional module details
		if (events[i].module.has_value())
		{
			result[i].module = new BNDebuggerTTDModule();
			result[i].module->name = BNAllocString(events[i].module->name.c_str());
			result[i].module->address = events[i].module->address;
			result[i].module->size = events[i].module->size;
			result[i].module->checksum = events[i].module->checksum;
			result[i].module->timestamp = events[i].module->timestamp;
		}
		else
		{
			result[i].module = nullptr;
		}

		// Copy optional thread details
		if (events[i].thread.has_value())
		{
			result[i].thread = new BNDebuggerTTDThread();
			result[i].thread->uniqueId = events[i].thread->uniqueId;
			result[i].thread->id = events[i].thread->id;
			result[i].thread->lifetimeStart.sequence = events[i].thread->lifetimeStart.sequence;
			result[i].thread->lifetimeStart.step = events[i].thread->lifetimeStart.step;
			result[i].thread->lifetimeEnd.sequence = events[i].thread->lifetimeEnd.sequence;
			result[i].thread->lifetimeEnd.step = events[i].thread->lifetimeEnd.step;
			result[i].thread->activeTimeStart.sequence = events[i].thread->activeTimeStart.sequence;
			result[i].thread->activeTimeStart.step = events[i].thread->activeTimeStart.step;
			result[i].thread->activeTimeEnd.sequence = events[i].thread->activeTimeEnd.sequence;
			result[i].thread->activeTimeEnd.step = events[i].thread->activeTimeEnd.step;
		}
		else
		{
			result[i].thread = nullptr;
		}

		// Copy optional exception details
		if (events[i].exception.has_value())
		{
			result[i].exception = new BNDebuggerTTDException();
			result[i].exception->type = static_cast<BNDebuggerTTDExceptionType>(events[i].exception->type);
			result[i].exception->programCounter = events[i].exception->programCounter;
			result[i].exception->code = events[i].exception->code;
			result[i].exception->flags = events[i].exception->flags;
			result[i].exception->recordAddress = events[i].exception->recordAddress;
			result[i].exception->position.sequence = events[i].exception->position.sequence;
			result[i].exception->position.step = events[i].exception->position.step;
		}
		else
		{
			result[i].exception = nullptr;
		}
	}

	return result;
}


void BNDebuggerFreeTTDEvents(BNDebuggerTTDEvent* events, size_t count)
{
	if (!events || count == 0)
		return;

	// Free all allocated objects for each event
	for (size_t i = 0; i < count; ++i)
	{
		// Free module if present
		if (events[i].module)
		{
			if (events[i].module->name)
				BNFreeString(events[i].module->name);
			delete events[i].module;
		}

		// Free thread if present
		if (events[i].thread)
		{
			delete events[i].thread;
		}

		// Free exception if present
		if (events[i].exception)
		{
			delete events[i].exception;
		}
	}

	delete[] events;
}



void BNDebuggerPostDebuggerEvent(BNDebuggerController* controller, BNDebuggerEvent* event)
{
	DebuggerEvent evt;
	evt.type = event->type;
	evt.data.targetStoppedData.reason = event->data.targetStoppedData.reason;
	evt.data.targetStoppedData.exitCode = event->data.targetStoppedData.exitCode;
	evt.data.targetStoppedData.lastActiveThread = event->data.targetStoppedData.lastActiveThread;
	evt.data.targetStoppedData.data = event->data.targetStoppedData.data;

	evt.data.errorData.error = event->data.errorData.error;
	evt.data.errorData.shortError = event->data.errorData.shortError;
	evt.data.errorData.data = event->data.errorData.data;

	evt.data.exitData.exitCode = event->data.exitData.exitCode;

	evt.data.relativeAddress.module = event->data.relativeAddress.module;
	evt.data.relativeAddress.offset = event->data.relativeAddress.offset;

	evt.data.absoluteAddress = event->data.absoluteAddress;

	evt.data.messageData.message = event->data.messageData.message;

	controller->object->PostDebuggerEvent(evt);
}


bool BNDebuggerRemoveMemoryRegion(BNDebuggerController* controller)
{
	return controller->object->RemoveDebuggerMemoryRegion();
}


bool BNDebuggerReAddMemoryRegion(BNDebuggerController* controller)
{
	return controller->object->ReAddDebuggerMemoryRegion();
}


uint64_t BNDebuggerGetViewFileSegmentsStart(BNDebuggerController* controller)
{
	return controller->object->GetViewFileSegmentsStart();
}


bool BNDebuggerComputeLLILExprValue(BNDebuggerController* controller, BNLowLevelILFunction* function, size_t expr,
	uint8_t* buffer)
{
	Ref<LowLevelILFunction> llil = new LowLevelILFunction(BNNewLowLevelILFunctionReference(function));
	auto instr = llil->GetExpr(expr);
	intx::uint512 value;
	if (!controller->object->ComputeExprValueAPI(instr, value))
		return false;

	uint8_t temp[64] = {};
	intx::le::store(temp, value);
	memcpy(buffer, temp, 64);
	return true;
}


bool BNDebuggerComputeMLILExprValue(BNDebuggerController* controller, BNMediumLevelILFunction* function, size_t expr,
	uint8_t* buffer)
{
	Ref<MediumLevelILFunction> mlil = new MediumLevelILFunction(BNNewMediumLevelILFunctionReference(function));
	auto instr = mlil->GetExpr(expr);
	intx::uint512 value;
	if (!controller->object->ComputeExprValueAPI(instr, value))
		return false;

	uint8_t temp[64] = {};
	intx::le::store(temp, value);
	memcpy(buffer, temp, 64);
	return true;
}


bool BNDebuggerComputeHLILExprValue(BNDebuggerController* controller, BNHighLevelILFunction* function, size_t expr,
	uint8_t* buffer)
{
	Ref<HighLevelILFunction> hlil = new HighLevelILFunction(BNNewHighLevelILFunctionReference(function));
	auto instr = hlil->GetExpr(expr);
	intx::uint512 value;
	if (!controller->object->ComputeExprValueAPI(instr, value))
		return false;

	uint8_t temp[64] = {};
	intx::le::store(temp, value);
	memcpy(buffer, temp, 64);
	return true;
}


bool BNDebuggerGetVariableValue(BNDebuggerController* controller, BNVariable* variable, uint64_t address, size_t size,
	uint8_t* buffer)
{
	intx::uint512 value;
	if (!controller->object->GetVariableValue(*variable, address, size, value))
		return false;

	uint8_t temp[64] = {};
	intx::le::store(temp, value);
	memcpy(buffer, temp, 64);
	return true;
}


BNSettings* BNDebuggerGetAdapterSettings(BNDebuggerController* controller)
{
	auto settings = controller->object->GetAdapterSettings();
	if (!settings)
		return nullptr;
	return BNNewSettingsReference(settings->GetObject());
}


bool BNDebuggerFunctionExistsInOldView(BNDebuggerController* controller, uint64_t address)
{
	return controller->object->FunctionExistsInOldView(address);
}
