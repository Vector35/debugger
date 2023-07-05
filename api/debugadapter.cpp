#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

DebugAdapter::DebugAdapter(BinaryNinja::BinaryView *data)
{
	BNDebuggerCustomDebugAdapter adapter;
	adapter.context = this;
	adapter.init = InitCallback;
	adapter.freeObject = FreeCallback;
	adapter.executeWithArgs = ExecuteWithArgsCallback;
	adapter.attach = AttachCallback;
	adapter.connect = ConnectCallback;
	adapter.connectToDebugServer = ConnectToDebugServerCallback;
	adapter.disConnectDebugServer = DisconnectDebugServerCallback;
	adapter.detach = DetachCallback;
	adapter.quit = QuitCallback;
	adapter.getProcessList = GetProcessListCallback;
	adapter.getThreadList = GetThreadListCallback;
	adapter.getActiveThread = GetActiveThreadCallback;
	adapter.getActiveThreadId = GetActiveThreadIdCallback;
	adapter.setActiveThread = SetActiveThreadCallback;
	adapter.setActiveThreadId = SetActiveThreadIdCallback;
	adapter.suspendThread = SuspendThreadCallback;
	adapter.resumeThread = ResumeThreadCallback;
	adapter.getFramesOfThread = GetFramesOfThreadCallback;
	adapter.addBreakpointWithAddress = AddBreakpointWithAddressCallback;
	adapter.addBreakpointWithModuleAndOffset = AddBreakpointWithModuleAndOffsetCallback;
	adapter.removeBreakpoint = RemoveBreakpointCallback;
	adapter.removeBreakpointWithModuleAndOffset = RemoveBreakpointWithModuleAndOffsetCallback;
	adapter.getBreakpointList = GetBreakpointListCallback;
	adapter.readAllRegisters = ReadAllRegistersCallback;
	adapter.readRegister = ReadRegisterCallback;
	adapter.writeRegister = WriteRegisterCallback;
	adapter.readMemory = ReadMemoryCallback;
	adapter.writeMemory = WriteMemoryCallback;
	adapter.getModuleList = GetModuleListCallback;
	adapter.getTargetArchitecture = GetTargetArchitectureCallback;
	adapter.stopReason = StopReasonCallback;
	adapter.exitCode = ExitCodeCallback;
	adapter.breakInto = BreakIntoCallback;
	adapter.go = GoCallback;
	adapter.stepInto = StepIntoCallback;
	adapter.stepOver = StepOverCallback;
	adapter.stepReturn = StepReturnCallback;
	adapter.invokeBackendCommand = InvokeBackendCommandCallback;
	adapter.getInstructionOffset = GetInstructionOffsetCallback;
	adapter.getStackPointer = GetStackPointerCallback;
	adapter.writeStdin = WriteStdinCallback;

	AddRefForRegistration();
	m_object = BNDebuggerCreateCustomDebugAdapter(data ? data->GetObject() : nullptr, &adapter);
}


DebugAdapter::DebugAdapter(BNDebugAdapter *adapter)
{
	m_object = adapter;
}


DebugAdapter::~DebugAdapter()
{

}


bool DebugAdapter::InitCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Init();
}


void DebugAdapter::FreeCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	adapter->ReleaseForRegistration();
}


bool DebugAdapter::ExecuteWithArgsCallback(void *ctxt, const char *path, const char *args, const char *workingDir, const BNLaunchConfigurations *configs)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	LaunchConfigurations launchConfigs;
	launchConfigs.requestTerminalEmulator = configs->requestTerminalEmulator;
	launchConfigs.inputFile = configs->inputFile;
	return adapter->ExecuteWithArgs(path, args, workingDir, launchConfigs);
}


bool DebugAdapter::AttachCallback(void *ctxt, uint32_t pid)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Attach(pid);
}


bool DebugAdapter::ConnectCallback(void *ctxt, const char *server, uint32_t port)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Connect(server, port);
}


bool DebugAdapter::ConnectToDebugServerCallback(void *ctxt, const char *server, uint32_t port)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->ConnectToDebugServer(server, port);
}


bool DebugAdapter::DisconnectDebugServerCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->DisconnectDebugServer();
}


bool DebugAdapter::DetachCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Detach();
}


bool DebugAdapter::QuitCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Quit();
}


BNDebugProcess* DebugAdapter::GetProcessListCallback(void *ctxt, size_t *count)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto processes = adapter->GetProcessList();
	if (processes.empty())
		return nullptr;

	*count = processes.size();
	BNDebugProcess* result = new BNDebugProcess[*count];
	for (size_t i = 0; i < *count; i++)
	{
		result[i].m_processName = BNDebuggerAllocString(processes[i].m_processName.c_str());
		result[i].m_pid = processes[i].m_pid;
	}
	return result;
}


BNDebugThread* DebugAdapter::GetThreadListCallback(void *ctxt, size_t *count)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto threads = adapter->GetThreadList();
	if (threads.empty())
		return nullptr;

	*count = threads.size();
	BNDebugThread* result = new BNDebugThread[*count];
	for (size_t i = 0; i < *count; i++)
	{
		result[i].m_isFrozen = threads[i].m_isFrozen;
		result[i].m_tid = threads[i].m_tid;
		result[i].m_rip = threads[i].m_rip;
	}
	return result;
}


BNDebugThread DebugAdapter::GetActiveThreadCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	DebugThread thread = adapter->GetActiveThread();
	BNDebugThread result;
	result.m_rip = thread.m_rip;
	result.m_tid = thread.m_tid;
	result.m_isFrozen = thread.m_isFrozen;
	return result;
}


uint32_t DebugAdapter::GetActiveThreadIdCallback(void* ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->GetActiveThreadId();
}


bool DebugAdapter::SetActiveThreadCallback(void *ctxt, BNDebugThread thread)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	DebugThread t;
	t.m_isFrozen = thread.m_isFrozen;
	t.m_tid = thread.m_tid;
	t.m_rip = thread.m_rip;
	return adapter->SetActiveThread(t);
}


bool DebugAdapter::SetActiveThreadIdCallback(void *ctxt, uint32_t tid)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->SetActiveThreadId(tid);
}


bool DebugAdapter::SuspendThreadCallback(void *ctxt, uint32_t tid)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->SuspendThread(tid);
}


bool DebugAdapter::ResumeThreadCallback(void *ctxt, uint32_t tid)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->ResumeThread(tid);
}


BNDebugFrame* DebugAdapter::GetFramesOfThreadCallback(void *ctxt, uint32_t tid, size_t *count)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto frames = adapter->GetFramesOfThread(tid);

	if (frames.empty())
		return nullptr;

	*count = frames.size();
	BNDebugFrame* result = new BNDebugFrame[*count];
	for (size_t i = 0; i < *count; i++)
	{
		result[i].m_fp = frames[i].m_fp;
		result[i].m_functionName = BNDebuggerAllocString(frames[i].m_functionName.c_str());
		result[i].m_functionStart = frames[i].m_functionStart;
		result[i].m_index = frames[i].m_index;
		result[i].m_module = BNDebuggerAllocString(frames[i].m_module.c_str());
		result[i].m_pc = frames[i].m_pc;
		result[i].m_sp = frames[i].m_sp;
	}
	return result;
}


BNDebugBreakpoint DebugAdapter::AddBreakpointWithAddressCallback(void *ctxt, const uint64_t address, unsigned long breakpoint_type)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto bp = adapter->AddBreakpoint(address, breakpoint_type);
	BNDebugBreakpoint result;
	result.module = BNDebuggerAllocString(bp.module.c_str());
	result.address = bp.address;
	result.offset = bp.offset;
	result.enabled = bp.enabled;
	return result;
}


BNDebugBreakpoint DebugAdapter::AddBreakpointWithModuleAndOffsetCallback(void *ctxt, const char *module, uint64_t offset, unsigned long type)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto bp = adapter->AddBreakpoint({module, offset});

	BNDebugBreakpoint result;
	result.module = BNDebuggerAllocString(bp.module.c_str());
	result.address = bp.address;
	result.offset = bp.offset;
	result.enabled = bp.enabled;
	return result;
}


bool DebugAdapter::RemoveBreakpointCallback(void *ctxt, BNDebugBreakpoint breakpoint)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	DebugBreakpoint bp;
	bp.module = breakpoint.module;
	bp.offset = breakpoint.offset;
	bp.enabled = breakpoint.enabled;
	bp.address = breakpoint.address;
	return adapter->RemoveBreakpoint(bp);
}


bool DebugAdapter::RemoveBreakpointWithModuleAndOffsetCallback(void *ctxt, const char *module, uint64_t offset)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	ModuleNameAndOffset bp;
	bp.module = module;
	bp.offset = offset;
	return adapter->RemoveBreakpoint(bp);
}


BNDebugBreakpoint* DebugAdapter::GetBreakpointListCallback(void* ctxt, size_t* count)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto breakpoints = adapter->GetBreakpointList();
	if (breakpoints.empty())
		return nullptr;

	*count = breakpoints.size();
	auto* result = new BNDebugBreakpoint[*count];

	for (size_t i = 0; i < *count; i++)
	{
		result[i].offset = breakpoints[i].offset;
		result[i].module = BNDebuggerAllocString(breakpoints[i].module.c_str());
		result[i].address = breakpoints[i].address;
		result[i].enabled = breakpoints[i].enabled;
	}
	return result;
}


BNDebugRegister* DebugAdapter::ReadAllRegistersCallback(void *ctxt, size_t *count)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto registers = adapter->ReadAllRegisters();
	if (registers.empty())
		return nullptr;

	*count = registers.size();
	BNDebugRegister* result = new BNDebugRegister[*count];
	size_t i = 0;
	for (const auto& it: registers)
	{
		result[i].m_name = BNDebuggerAllocString(it.second.m_name.c_str());
		result[i].m_hint = BNDebuggerAllocString(it.second.m_hint.c_str());
		result[i].m_value = it.second.m_value;
		result[i].m_registerIndex = it.second.m_registerIndex;
		result[i].m_width = it.second.m_width;
	}
	return result;
}


BNDebugRegister* DebugAdapter::ReadRegisterCallback(void *ctxt, const char *reg)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto r = adapter->ReadRegister(reg);
	auto* result = new BNDebugRegister;
	result->m_width = r.m_width;
	result->m_registerIndex = r.m_registerIndex;
	result->m_value = r.m_value;
	result->m_name = BNDebuggerAllocString(r.m_name.c_str());
	result->m_hint = BNDebuggerAllocString(r.m_hint.c_str());
	return result;
}


bool DebugAdapter::WriteRegisterCallback(void *ctxt, const char *reg, uint64_t value)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->WriteRegister(reg, value);
}


BNDataBuffer* DebugAdapter::ReadMemoryCallback(void *ctxt, uint64_t address, size_t size)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->ReadMemory(address, size).GetBufferObject();
}


bool DebugAdapter::WriteMemoryCallback(void *ctxt, uint64_t address, BNDataBuffer *buffer)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	DataBuffer buf;
	BNAppendDataBuffer(buf.GetBufferObject(), buffer);
	return adapter->WriteMemory(address, buf);
}


BNDebugModule* DebugAdapter::GetModuleListCallback(void *ctxt, size_t *count)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto modules = adapter->GetModuleList();
	if (modules.empty())
		return nullptr;

	*count = modules.size();
	auto* result = new BNDebugModule[*count];
	for (size_t i = 0; i < *count; i++)
	{
		result[i].m_name = BNDebuggerAllocString(modules[i].m_name.c_str());
		result[i].m_size = modules[i].m_size;
		result[i].m_short_name = BNDebuggerAllocString(modules[i].m_short_name.c_str());
		result[i].m_loaded = modules[i].m_loaded;
		result[i].m_address = modules[i].m_address;
	}
	return result;
}


char* DebugAdapter::GetTargetArchitectureCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto arch = adapter->GetTargetArchitecture();
	if (arch.empty())
		return nullptr;
	return BNDebuggerAllocString(arch.c_str());
}


BNDebugStopReason DebugAdapter::StopReasonCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->StopReason();
}


uint64_t DebugAdapter::ExitCodeCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->ExitCode();
}


bool DebugAdapter::BreakIntoCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->BreakInto();
}


bool DebugAdapter::GoCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Go();
}


bool DebugAdapter::StepIntoCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->StepInto();
}


bool DebugAdapter::StepOverCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->StepOver();
}


bool DebugAdapter::StepReturnCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->StepReturn();
}


char* DebugAdapter::InvokeBackendCommandCallback(void *ctxt, const char *command)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	auto ret = adapter->InvokeBackendCommand(command);
	if (ret.empty())
		return nullptr;
	return BNDebuggerAllocString(ret.c_str());
}


uint64_t DebugAdapter::GetInstructionOffsetCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->GetInstructionOffset();
}


uint64_t DebugAdapter::GetStackPointerCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->GetStackPointer();
}


void DebugAdapter::WriteStdinCallback(void *ctxt, const char *msg)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	adapter->WriteStdin(msg);
}


void DebugAdapter::PostDebuggerEvent(const BinaryNinjaDebuggerAPI::DebuggerEvent& event)
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

	BNDebuggerPostDebuggerEventFromAdapter(m_object, evt);

	BNDebuggerFreeString(evt->data.errorData.error);
	BNDebuggerFreeString(evt->data.errorData.shortError);
	BNDebuggerFreeString(evt->data.relativeAddress.module);
	BNDebuggerFreeString(evt->data.messageData.message);
	delete evt;
}
