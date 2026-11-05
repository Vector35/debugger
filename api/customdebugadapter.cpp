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

#include "debuggerapi.h"
#include "ffi.h"
#include <cstring>
#include <memory>
#include <unordered_map>

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

// CustomDebugAdapter implementation
CustomDebugAdapter::CustomDebugAdapter()
{
	InitializeCallbacks();
}

CustomDebugAdapter::~CustomDebugAdapter()
{
}

void CustomDebugAdapter::PostEvent(BNDebuggerEvent event)
{
	if (m_adapterHandle)
		BNCustomDebugAdapterPostEvent(m_adapterHandle, &event);
}

void CustomDebugAdapter::InitializeCallbacks()
{
	memset(&m_callbacks, 0, sizeof(m_callbacks));
	m_callbacks.context = this;
	m_callbacks.init = InitCallback;
	m_callbacks.execute = ExecuteCallback;
	m_callbacks.executeWithArgs = ExecuteWithArgsCallback;
	m_callbacks.attach = AttachCallback;
	m_callbacks.connect = ConnectCallback;
	m_callbacks.connectToDebugServer = ConnectToDebugServerCallback;
	m_callbacks.detach = DetachCallback;
	m_callbacks.quit = QuitCallback;
	m_callbacks.getProcessList = GetProcessListCallback;
	m_callbacks.getActivePID = GetActivePIDCallback;
	m_callbacks.getThreadList = GetThreadListCallback;
	m_callbacks.getActiveThread = GetActiveThreadCallback;
	m_callbacks.getActiveThreadId = GetActiveThreadIdCallback;
	m_callbacks.setActiveThread = SetActiveThreadCallback;
	m_callbacks.setActiveThreadId = SetActiveThreadIdCallback;
	m_callbacks.suspendThread = SuspendThreadCallback;
	m_callbacks.resumeThread = ResumeThreadCallback;
	m_callbacks.addBreakpoint = AddBreakpointCallback;
	m_callbacks.addBreakpointRelative = AddBreakpointRelativeCallback;
	m_callbacks.removeBreakpoint = RemoveBreakpointCallback;
	m_callbacks.removeBreakpointRelative = RemoveBreakpointRelativeCallback;
	m_callbacks.getBreakpointList = GetBreakpointListCallback;
	m_callbacks.readAllRegisters = ReadAllRegistersCallback;
	m_callbacks.readRegister = ReadRegisterCallback;
	m_callbacks.writeRegister = WriteRegisterCallback;
	m_callbacks.readMemory = ReadMemoryCallback;
	m_callbacks.writeMemory = WriteMemoryCallback;
	m_callbacks.getModuleList = GetModuleListCallback;
	m_callbacks.getTargetArchitecture = GetTargetArchitectureCallback;
	m_callbacks.stopReason = StopReasonCallback;
	m_callbacks.exitCode = ExitCodeCallback;
	m_callbacks.breakInto = BreakIntoCallback;
	m_callbacks.go = GoCallback;
	m_callbacks.goReverse = GoReverseCallback;
	m_callbacks.stepInto = StepIntoCallback;
	m_callbacks.stepIntoReverse = StepIntoReverseCallback;
	m_callbacks.stepOver = StepOverCallback;
	m_callbacks.stepOverReverse = StepOverReverseCallback;
	m_callbacks.stepReturn = StepReturnCallback;
	m_callbacks.stepReturnReverse = StepReturnReverseCallback;
	m_callbacks.invokeBackendCommand = InvokeBackendCommandCallback;
	m_callbacks.getInstructionOffset = GetInstructionOffsetCallback;
	m_callbacks.getStackPointer = GetStackPointerCallback;
	m_callbacks.supportFeature = SupportFeatureCallback;
	m_callbacks.writeStdin = WriteStdinCallback;
	m_callbacks.getProperty = GetPropertyCallback;
	m_callbacks.setProperty = SetPropertyCallback;
	m_callbacks.getAdapterSettings = GetAdapterSettingsCallback;
	m_callbacks.freeProcessList = FreeProcessListCallback;
	m_callbacks.freeThreadList = FreeThreadListCallback;
	m_callbacks.freeBreakpointList = FreeBreakpointListCallback;
	m_callbacks.freeBreakpoint = FreeBreakpointCallback;
	m_callbacks.freeRegisterList = FreeRegisterListCallback;
	m_callbacks.freeRegister = FreeRegisterCallback;
	m_callbacks.freeModuleList = FreeModuleListCallback;
	m_callbacks.freeCallback = FreeCallback;
}

// Static callback implementations
bool CustomDebugAdapter::InitCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->Init();
}

bool CustomDebugAdapter::ExecuteCallback(void* ctxt, const char* path)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->Execute(string(path));
}

bool CustomDebugAdapter::ExecuteWithArgsCallback(void* ctxt, const char* path, const char* args, const char* workingDir)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->ExecuteWithArgs(string(path), string(args), string(workingDir));
}

bool CustomDebugAdapter::AttachCallback(void* ctxt, uint32_t pid)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->Attach(pid);
}

bool CustomDebugAdapter::ConnectCallback(void* ctxt, const char* server, uint32_t port)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->Connect(string(server), port);
}

bool CustomDebugAdapter::ConnectToDebugServerCallback(void* ctxt, const char* server, uint32_t port)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->ConnectToDebugServer(string(server), port);
}

bool CustomDebugAdapter::DetachCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->Detach();
}

bool CustomDebugAdapter::QuitCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->Quit();
}

BNDebugProcess* CustomDebugAdapter::GetProcessListCallback(void* ctxt, size_t* count)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto processes = adapter->GetProcessList();
	*count = processes.size();

	if (processes.empty())
		return nullptr;

	auto result = new BNDebugProcess[processes.size()];
	for (size_t i = 0; i < processes.size(); i++)
	{
		result[i] = {};
		result[i].m_pid = processes[i].m_pid;
		result[i].m_processName = BNDebuggerAllocString(processes[i].m_processName.c_str());
		result[i].m_commandLine = BNDebuggerAllocString(processes[i].m_commandLine.c_str());
	}
	return result;
}

BNDebugThread* CustomDebugAdapter::GetThreadListCallback(void* ctxt, size_t* count)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto threads = adapter->GetThreadList();
	*count = threads.size();

	if (threads.empty())
		return nullptr;

	auto result = new BNDebugThread[threads.size()];
	for (size_t i = 0; i < threads.size(); i++)
	{
		result[i] = {};
		result[i].m_tid = threads[i].m_tid;
		result[i].m_rip = threads[i].m_rip;
		result[i].m_isFrozen = threads[i].m_isFrozen;
	}
	return result;
}

uint32_t CustomDebugAdapter::GetActivePIDCallback(void* ctxt)
{
	return static_cast<CustomDebugAdapter*>(ctxt)->GetActivePID();
}

bool CustomDebugAdapter::GetActiveThreadCallback(void* ctxt, BNDebugThread* result)
{
	if (!result)
		return false;
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto thread = adapter->GetActiveThread();
	result->m_tid = thread.m_tid;
	result->m_rip = thread.m_rip;
	result->m_isFrozen = thread.m_isFrozen;
	return true;
}

uint32_t CustomDebugAdapter::GetActiveThreadIdCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->GetActiveThreadId();
}

bool CustomDebugAdapter::SetActiveThreadCallback(void* ctxt, BNDebugThread thread)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	DebugThread debugThread;
	debugThread.m_tid = thread.m_tid;
	debugThread.m_rip = thread.m_rip;
	debugThread.m_isFrozen = thread.m_isFrozen;
	return adapter->SetActiveThread(debugThread);
}

bool CustomDebugAdapter::SetActiveThreadIdCallback(void* ctxt, uint32_t tid)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->SetActiveThreadId(tid);
}

bool CustomDebugAdapter::SuspendThreadCallback(void* ctxt, uint32_t tid)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->SuspendThread(tid);
}

bool CustomDebugAdapter::ResumeThreadCallback(void* ctxt, uint32_t tid)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->ResumeThread(tid);
}

bool CustomDebugAdapter::AddBreakpointCallback(void* ctxt, uint64_t address, BNDebugBreakpoint* result)
{
	if (!result)
		return false;
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto bp = adapter->AddBreakpoint(address);
	*result = {};
	result->address = bp.address;
	result->enabled = bp.enabled;
	result->module = bp.module.empty() ? nullptr : BNDebuggerAllocString(bp.module.c_str());
	result->offset = bp.offset;
	result->condition = bp.condition.empty() ? nullptr : BNDebuggerAllocString(bp.condition.c_str());
	result->type = static_cast<BNDebugBreakpointType>(bp.type);
	result->size = bp.size;
	return true;
}

bool CustomDebugAdapter::AddBreakpointRelativeCallback(
	void* ctxt, const char* module, uint64_t offset, BNDebugBreakpoint* result)
{
	if (!result)
		return false;
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto bp = adapter->AddBreakpointRelative(string(module), offset);
	*result = {};
	result->address = bp.address;
	result->enabled = bp.enabled;
	result->module = BNDebuggerAllocString(bp.module.empty() ? module : bp.module.c_str());
	result->offset = bp.module.empty() ? offset : bp.offset;
	result->condition = bp.condition.empty() ? nullptr : BNDebuggerAllocString(bp.condition.c_str());
	result->type = static_cast<BNDebugBreakpointType>(bp.type);
	result->size = bp.size;
	return true;
}

bool CustomDebugAdapter::RemoveBreakpointCallback(void* ctxt, uint64_t address)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->RemoveBreakpoint(address);
}

bool CustomDebugAdapter::RemoveBreakpointRelativeCallback(void* ctxt, const char* module, uint64_t offset)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->RemoveBreakpointRelative(string(module), offset);
}

BNDebugBreakpoint* CustomDebugAdapter::GetBreakpointListCallback(void* ctxt, size_t* count)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto breakpoints = adapter->GetBreakpointList();
	*count = breakpoints.size();

	if (breakpoints.empty())
		return nullptr;

	auto result = new BNDebugBreakpoint[breakpoints.size()];
	for (size_t i = 0; i < breakpoints.size(); i++)
	{
		result[i] = {};
		result[i].address = breakpoints[i].address;
		result[i].enabled = breakpoints[i].enabled;
		result[i].module = breakpoints[i].module.empty() ? nullptr :
			BNDebuggerAllocString(breakpoints[i].module.c_str());
		result[i].offset = breakpoints[i].offset;
		result[i].condition = breakpoints[i].condition.empty() ? nullptr :
			BNDebuggerAllocString(breakpoints[i].condition.c_str());
		result[i].type = static_cast<BNDebugBreakpointType>(breakpoints[i].type);
		result[i].size = breakpoints[i].size;
	}
	return result;
}

BNDebugRegister* CustomDebugAdapter::ReadAllRegistersCallback(void* ctxt, size_t* count)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto registers = adapter->ReadAllRegisters();
	*count = registers.size();

	if (registers.empty())
		return nullptr;

	auto result = new BNDebugRegister[registers.size()];
	size_t i = 0;
	for (const auto& pair : registers)
	{
		result[i] = {};
		result[i].m_name = BNDebuggerAllocString(pair.second.m_name.c_str());
		intx::le::store(result[i].m_value, pair.second.m_value);
		result[i].m_width = pair.second.m_width;
		result[i].m_registerIndex = pair.second.m_registerIndex;
		result[i].m_hint = BNDebuggerAllocString(pair.second.m_hint.c_str());
		i++;
	}
	return result;
}

bool CustomDebugAdapter::ReadRegisterCallback(void* ctxt, const char* reg, BNDebugRegister* result)
{
	if (!result)
		return false;
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto debugReg = adapter->ReadRegister(string(reg));
	*result = {};
	result->m_name = BNDebuggerAllocString(debugReg.m_name.c_str());
	intx::le::store(result->m_value, debugReg.m_value);
	result->m_width = debugReg.m_width;
	result->m_registerIndex = debugReg.m_registerIndex;
	result->m_hint = BNDebuggerAllocString(debugReg.m_hint.c_str());
	return true;
}

bool CustomDebugAdapter::WriteRegisterCallback(void* ctxt, const char* reg, const uint8_t* value)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	vector<uint8_t> valueVec(value, value + 64);  // Assuming max 64 bytes for register value
	return adapter->WriteRegister(string(reg), valueVec);
}

BNDataBuffer* CustomDebugAdapter::ReadMemoryCallback(void* ctxt, uint64_t address, size_t size)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto data = adapter->ReadMemory(address, size);

	if (data.empty())
		return nullptr;

	return BNCreateDataBuffer(data.data(), data.size());
}

bool CustomDebugAdapter::WriteMemoryCallback(void* ctxt, uint64_t address, BNDataBuffer* buffer)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);

	size_t size = BNGetDataBufferLength(buffer);
	const uint8_t* data = static_cast<const uint8_t*>(BNGetDataBufferContents(buffer));
	vector<uint8_t> dataVec(data, data + size);

	return adapter->WriteMemory(address, dataVec);
}

BNDebugModule* CustomDebugAdapter::GetModuleListCallback(void* ctxt, size_t* count)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto modules = adapter->GetModuleList();
	*count = modules.size();

	if (modules.empty())
		return nullptr;

	auto result = new BNDebugModule[modules.size()];
	for (size_t i = 0; i < modules.size(); i++)
	{
		result[i] = {};
		result[i].m_name = BNDebuggerAllocString(modules[i].m_name.c_str());
		result[i].m_short_name = BNDebuggerAllocString(modules[i].m_short_name.c_str());
		result[i].m_address = modules[i].m_address;
		result[i].m_size = modules[i].m_size;
		result[i].m_loaded = modules[i].m_loaded;
	}
	return result;
}

char* CustomDebugAdapter::GetTargetArchitectureCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto arch = adapter->GetTargetArchitecture();
	return BNDebuggerAllocString(arch.c_str());
}

BNDebugStopReason CustomDebugAdapter::StopReasonCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return static_cast<BNDebugStopReason>(adapter->StopReason());
}

uint64_t CustomDebugAdapter::ExitCodeCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->ExitCode();
}

bool CustomDebugAdapter::BreakIntoCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->BreakInto();
}

bool CustomDebugAdapter::GoCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->Go();
}

bool CustomDebugAdapter::GoReverseCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->GoReverse();
}

bool CustomDebugAdapter::StepIntoCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->StepInto();
}

bool CustomDebugAdapter::StepIntoReverseCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->StepIntoReverse();
}

bool CustomDebugAdapter::StepOverCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->StepOver();
}

bool CustomDebugAdapter::StepOverReverseCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->StepOverReverse();
}

bool CustomDebugAdapter::StepReturnCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->StepReturn();
}

bool CustomDebugAdapter::StepReturnReverseCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->StepReturnReverse();
}

char* CustomDebugAdapter::InvokeBackendCommandCallback(void* ctxt, const char* command)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto result = adapter->InvokeBackendCommand(string(command));
	return BNDebuggerAllocString(result.c_str());
}

uint64_t CustomDebugAdapter::GetInstructionOffsetCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->GetInstructionOffset();
}

uint64_t CustomDebugAdapter::GetStackPointerCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->GetStackPointer();
}

bool CustomDebugAdapter::SupportFeatureCallback(void* ctxt, uint32_t feature)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	return adapter->SupportFeature(feature);
}

void CustomDebugAdapter::WriteStdinCallback(void* ctxt, const char* msg)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	adapter->WriteStdin(string(msg));
}

BNMetadata* CustomDebugAdapter::GetPropertyCallback(void* ctxt, const char* name)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto metadata = adapter->GetProperty(string(name));
	if (metadata)
		return BNNewMetadataReference(metadata->GetObject());
	return nullptr;
}

bool CustomDebugAdapter::SetPropertyCallback(void* ctxt, const char* name, BNMetadata* value)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	if (value)
	{
		auto metadata = new Metadata(BNNewMetadataReference(value));
		return adapter->SetProperty(string(name), metadata);
	}
	return adapter->SetProperty(string(name), nullptr);
}

BNSettings* CustomDebugAdapter::GetAdapterSettingsCallback(void* ctxt)
{
	auto adapter = static_cast<CustomDebugAdapter*>(ctxt);
	auto settings = adapter->GetAdapterSettings();
	if (settings)
		return BNNewSettingsReference(settings->GetObject());
	return nullptr;
}

void CustomDebugAdapter::FreeProcessListCallback(void*, BNDebugProcess* values, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(values[i].m_processName);
		BNDebuggerFreeString(values[i].m_commandLine);
	}
	delete[] values;
}

void CustomDebugAdapter::FreeThreadListCallback(void*, BNDebugThread* values, size_t)
{
	delete[] values;
}

void CustomDebugAdapter::FreeBreakpointListCallback(void*, BNDebugBreakpoint* values, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(values[i].module);
		BNDebuggerFreeString(values[i].condition);
	}
	delete[] values;
}

void CustomDebugAdapter::FreeRegisterListCallback(void*, BNDebugRegister* values, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(values[i].m_name);
		BNDebuggerFreeString(values[i].m_hint);
	}
	delete[] values;
}

void CustomDebugAdapter::FreeBreakpointCallback(void*, BNDebugBreakpoint* value)
{
	BNDebuggerFreeString(value->module);
	BNDebuggerFreeString(value->condition);
}

void CustomDebugAdapter::FreeRegisterCallback(void*, BNDebugRegister* value)
{
	BNDebuggerFreeString(value->m_name);
	BNDebuggerFreeString(value->m_hint);
}

void CustomDebugAdapter::FreeModuleListCallback(void*, BNDebugModule* values, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNDebuggerFreeString(values[i].m_name);
		BNDebuggerFreeString(values[i].m_short_name);
	}
	delete[] values;
}

void CustomDebugAdapter::FreeCallback(void* ctxt)
{
	delete static_cast<CustomDebugAdapter*>(ctxt);
}

// CustomDebugAdapterType implementation
CustomDebugAdapterType::CustomDebugAdapterType(const std::string& name) : DebugAdapterType(nullptr), m_name(name)
{
	InitializeCallbacks();
}

CustomDebugAdapterType::~CustomDebugAdapterType()
{
}

bool CustomDebugAdapterType::Register()
{
	if (m_object)
		return false;
	auto handle = BNRegisterCustomDebugAdapterType(m_name.c_str(), &m_callbacks);
	if (!handle)
		return false;
	m_object = handle;
	AddRefForRegistration();
	return true;
}

void CustomDebugAdapterType::InitializeCallbacks()
{
	memset(&m_callbacks, 0, sizeof(m_callbacks));
	m_callbacks.context = this;
	m_callbacks.create = CreateCallback;
	m_callbacks.isValidForData = IsValidForDataCallback;
	m_callbacks.canExecute = CanExecuteCallback;
	m_callbacks.canConnect = CanConnectCallback;
	m_callbacks.freeCallback = FreeCallback;
}

// Static callback implementations for CustomDebugAdapterType
BNDebugAdapter* CustomDebugAdapterType::CreateCallback(void* ctxt, BNBinaryView* data)
{
	DbgRef<CustomDebugAdapterType> adapterType = static_cast<CustomDebugAdapterType*>(ctxt);
	Ref<BinaryView> binaryView = new BinaryView(BNNewViewReference(data));
	auto adapter = adapterType->Create(binaryView);
	if (adapter)
	{
		auto bridge = BNCreateCustomDebugAdapter(data, &adapter->m_callbacks);
		if (bridge)
		{
			adapter->m_adapterHandle = bridge;
			adapter.release(); // Released by the bridge's FreeCallback.
		}
		return bridge;
	}
	return nullptr;
}

bool CustomDebugAdapterType::IsValidForDataCallback(void* ctxt, BNBinaryView* data)
{
	DbgRef<CustomDebugAdapterType> adapterType = static_cast<CustomDebugAdapterType*>(ctxt);
	Ref<BinaryView> binaryView = new BinaryView(BNNewViewReference(data));
	return adapterType->IsValidForData(binaryView);
}

bool CustomDebugAdapterType::CanExecuteCallback(void* ctxt, BNBinaryView* data)
{
	DbgRef<CustomDebugAdapterType> adapterType = static_cast<CustomDebugAdapterType*>(ctxt);
	Ref<BinaryView> binaryView = new BinaryView(BNNewViewReference(data));
	return adapterType->CanExecute(binaryView);
}

bool CustomDebugAdapterType::CanConnectCallback(void* ctxt, BNBinaryView* data)
{
	DbgRef<CustomDebugAdapterType> adapterType = static_cast<CustomDebugAdapterType*>(ctxt);
	Ref<BinaryView> binaryView = new BinaryView(BNNewViewReference(data));
	return adapterType->CanConnect(binaryView);
}

void CustomDebugAdapterType::FreeCallback(void* ctxt)
{
	// Don't delete the adapter type here - it's managed by the C++ side
}
