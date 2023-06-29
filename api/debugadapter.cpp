#include "debugadapter.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

DebugAdapter::DebugAdapter(BinaryNinja::BinaryView *data)
{
	BNDebuggerCustomDebugAdapter adapter;
	adapter.context = this;
	adapter.init = InitCallback;
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
}


DebugAdapter::~DebugAdapter()
{

}


bool DebugAdapter::InitCallback(void *ctxt)
{
	DebugAdapter* adapter = (DebugAdapter*)ctxt;
	return adapter->Init();
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
	adapter->SetActiveThreadId(tid);
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
