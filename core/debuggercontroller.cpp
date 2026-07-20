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

#include "debuggercontroller.h"
#include <algorithm>
#include <thread>
#include <fstream>
#include "base/assertions.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "debuggerfileaccessor.h"

using namespace BinaryNinjaDebugger;

namespace BinaryNinjaDebugger {
	thread_local DebuggerController* t_controllerOnWorker = nullptr;
}

DebuggerController::DebuggerController(BinaryViewRef data): BinaryDataNotification(Rebased)
{
	INIT_DEBUGGER_API_OBJECT();

	m_file = data->GetFile();
	m_data = data;
	m_data->RegisterNotification(this);
	m_viewStart = m_data->GetStart();

	m_state = new DebuggerState(data, this);
	m_adapter = nullptr;
	m_shouldAnnotateStackVariable = Settings::Instance()->Get<bool>("debugger.stackVariableAnnotations");

	m_debuggerEventThread = std::thread([&]{ DebuggerMainThread(); });

	m_workerShouldExit = false;
	m_workerThread = std::thread([this] { WorkerThreadMain(); });

	m_interruptThread = std::thread([this] { InterruptThreadMain(); });
}


DebuggerController::~DebuggerController()
{
	// The worker can be blocked on either condition variable -- m_workQueueCv (idle in
	// the outer loop) or m_adapterStopCv (inside WaitForAdapterStop during an op). Each
	// CV's wait predicate reads m_workerShouldExit, so the flag must be modified while
	// holding the matching mutex to publish the change correctly to that waiter. We hold
	// BOTH mutexes when setting the flag (scoped_lock is deadlock-safe) and then notify
	// both CVs. Otherwise a waiter on the CV whose mutex we didn't hold can miss the
	// wakeup and never observe the flag, hanging this destructor on join.
	{
		std::scoped_lock shutdownLock(m_workQueueMutex, m_adapterStopMutex);
		m_workerShouldExit = true;
	}
	m_workQueueCv.notify_all();
	m_adapterStopCv.notify_all();
	if (m_workerThread.joinable())
		m_workerThread.join();

	// Stop the interrupt thread before the adapter/state are torn down below: it touches
	// m_adapter and m_state->AdapterAccessMutex() in BreakInto, both of which outlive this
	// join but not the delete m_state further down.
	{
		std::lock_guard<std::mutex> interruptLock(m_interruptMutex);
		m_interruptShouldExit = true;
	}
	m_interruptCv.notify_all();
	if (m_interruptThread.joinable())
		m_interruptThread.join();

	m_shouldExit = true;
	m_cv.notify_all();
	if (m_debuggerEventThread.joinable())
		m_debuggerEventThread.join();

	m_data->UnregisterNotification(this);
	m_file = nullptr;

	if (m_state)
	{
		delete m_state;
		m_state = nullptr;
	}
}


void DebuggerController::WorkerThreadMain()
{
	t_controllerOnWorker = this;
	while (true)
	{
		std::function<void()> task;
		{
			std::unique_lock<std::mutex> lock(m_workQueueMutex);
			m_workQueueCv.wait(lock, [this] {
				return m_workerShouldExit || !m_workQueue.empty();
			});
			if (m_workerShouldExit && m_workQueue.empty())
				break;
			task = std::move(m_workQueue.front());
			m_workQueue.pop();
		}
		task();
	}
	t_controllerOnWorker = nullptr;
}


void DebuggerController::AddBreakpoint(uint64_t address)
{
	m_state->AddBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


void DebuggerController::AddBreakpoint(const ModuleNameAndOffset& address)
{
	m_state->AddBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


void DebuggerController::DeleteBreakpoint(uint64_t address)
{
	m_state->DeleteBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


void DebuggerController::DeleteBreakpoint(const ModuleNameAndOffset& address)
{
	m_state->DeleteBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


void DebuggerController::EnableBreakpoint(uint64_t address)
{
	m_state->EnableBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


void DebuggerController::EnableBreakpoint(const ModuleNameAndOffset& address)
{
	m_state->EnableBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


void DebuggerController::DisableBreakpoint(uint64_t address)
{
	m_state->DisableBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


void DebuggerController::DisableBreakpoint(const ModuleNameAndOffset& address)
{
	m_state->DisableBreakpoint(address);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
}


bool DebuggerController::ContainsBreakpoint(const ModuleNameAndOffset& address)
{
	return m_state->GetBreakpoints()->ContainsOffset(address);
}


bool DebuggerController::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	bool result = m_state->AddHardwareBreakpoint(address, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


bool DebuggerController::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	bool result = m_state->RemoveHardwareBreakpoint(address, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


bool DebuggerController::EnableHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	bool result = m_state->EnableHardwareBreakpoint(address, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


bool DebuggerController::DisableHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	bool result = m_state->DisableHardwareBreakpoint(address, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


// Hardware breakpoint methods - module+offset (ASLR-safe)

bool DebuggerController::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	bool result = m_state->AddHardwareBreakpoint(location, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


bool DebuggerController::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	bool result = m_state->RemoveHardwareBreakpoint(location, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


bool DebuggerController::EnableHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	bool result = m_state->EnableHardwareBreakpoint(location, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


bool DebuggerController::DisableHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	bool result = m_state->DisableHardwareBreakpoint(location, type, size);
	DebuggerEvent event;
	event.type = BreakpointChangedEvent;
	PostDebuggerEvent(event);
	return result;
}


bool DebuggerController::SetBreakpointCondition(uint64_t address, const std::string& condition)
{
	bool result = m_state->GetBreakpoints()->SetConditionAbsolute(address, condition);
	if (result)
	{
		DebuggerEvent event;
		event.type = BreakpointChangedEvent;
		event.data.absoluteAddress = address;
		PostDebuggerEvent(event);
	}
	return result;
}


bool DebuggerController::SetBreakpointCondition(const ModuleNameAndOffset& address, const std::string& condition)
{
	bool result = m_state->GetBreakpoints()->SetConditionOffset(address, condition);
	if (result)
	{
		DebuggerEvent event;
		event.type = BreakpointChangedEvent;
		event.data.relativeAddress = address;
		PostDebuggerEvent(event);
	}
	return result;
}


std::string DebuggerController::GetBreakpointCondition(uint64_t address)
{
	return m_state->GetBreakpoints()->GetConditionAbsolute(address);
}


std::string DebuggerController::GetBreakpointCondition(const ModuleNameAndOffset& address)
{
	return m_state->GetBreakpoints()->GetConditionOffset(address);
}


bool DebuggerController::SetIP(uint64_t address)
{
	std::string ipRegisterName;
	std::string targetArch = GetRemoteArchitecture()->GetName();

	if ((targetArch == "x86") || (targetArch == "i386"))
		ipRegisterName = "eip";
	else if (targetArch == "x86_64")
		ipRegisterName = "rip";
	else if ((targetArch == "aarch64") || (targetArch == "arm64"))
		ipRegisterName = "pc";
	else
		ipRegisterName = "pc";

	if (!SetRegisterValue(ipRegisterName, address))
		return false;

	// This allows the thread frame widget to update properly
	m_state->GetThreads()->MarkDirty();

	return true;
}


bool DebuggerController::Launch()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return false;

	Submit([this] { LaunchAndWaitOnWorker(); });
	return true;
}


DebugStopReason DebuggerController::LaunchAndWaitInternal()
{

	if (Settings::Instance()->Get<bool>("debugger.safeMode"))
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.shortError = "Safe mode enabled";
		event.data.errorData.error =
			fmt::format("Cannot launch the target because the debugger is in safe mode.");
		PostDebuggerEvent(event);
		return InternalError;
	}

	m_firstLaunch = false;

	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	if (!CreateDebugAdapter())
		return InternalError;

	m_inputFileLoaded = false;
	m_initialBreakpointSeen	 = false;
	m_state->MarkDirty();
	if (!CreateDebuggerBinaryView())
		return InternalError;

	return ExecuteAdapterAndWait(DebugAdapterLaunch);
}


DebugStopReason DebuggerController::LaunchAndWaitOnWorker()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return InvalidStatusOrOperation;

	auto reason = LaunchAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::LaunchAndWait(std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this] { return LaunchAndWaitOnWorker(); }, timeout);
}


bool DebuggerController::Attach()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return false;

	Submit([this] { AttachAndWaitOnWorker(); });
	return true;
}


DebugStopReason DebuggerController::AttachAndWaitInternal()
{
	m_firstAttach = false;

	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	if (!CreateDebugAdapter())
		return InternalError;

	m_inputFileLoaded = false;
	m_initialBreakpointSeen	 = false;
	m_state->MarkDirty();
	if (!CreateDebuggerBinaryView())
		return InternalError;

	return ExecuteAdapterAndWait(DebugAdapterAttach);
}


DebugStopReason DebuggerController::AttachAndWaitOnWorker()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return InvalidStatusOrOperation;

	auto reason = AttachAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::AttachAndWait(std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this] { return AttachAndWaitOnWorker(); }, timeout);
}


bool DebuggerController::Connect()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return false;

	Submit([this] { ConnectAndWaitOnWorker(); });
	return true;
}


DebugStopReason DebuggerController::ConnectAndWaitInternal()
{
	m_firstConnect = false;

	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	if (!CreateDebugAdapter())
		return InternalError;

	m_inputFileLoaded = false;
	m_initialBreakpointSeen	 = false;
	m_state->MarkDirty();
	if (!CreateDebuggerBinaryView())
		return InternalError;

	return ExecuteAdapterAndWait(DebugAdapterConnect);
}


DebugStopReason DebuggerController::ConnectAndWaitOnWorker()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return InvalidStatusOrOperation;

	auto reason = ConnectAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::ConnectAndWait(std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this] { return ConnectAndWaitOnWorker(); }, timeout);
}


bool DebuggerController::Execute()
{
	std::string filePath = m_state->GetExecutablePath();
	bool requestTerminal = m_state->GetRequestTerminalEmulator();
	LaunchConfigurations configs = {requestTerminal, m_state->GetInputFile(), m_state->IsConnectedToDebugServer()};

#ifdef WIN32
	/* temporary solution (not great, sorry!), we probably won't have to do this once we introduce std::filesystem::path */
	std::replace(filePath.begin(), filePath.end(), '/', '\\');
#endif

	return m_adapter->ExecuteWithArgs(
		filePath, m_state->GetCommandLineArguments(), m_state->GetWorkingDirectory(), configs);
}


bool DebuggerController::CreateDebugAdapter()
{
	// The current adapter type is the same as the last one, and the last adapter is still valid
	if (m_state->GetAdapterType() == m_lastAdapterName && m_adapter != nullptr)
	{
		ApplyBreakpoints();
		return true;
	}

	DebugAdapterType* type = DebugAdapterType::GetByName(m_state->GetAdapterType());
	if (!type)
	{
		LogWarn("Failed to get an debug adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
	}
	m_adapter = type->Create(GetData());
	if (!m_adapter)
	{
		LogWarn("Failed to create an adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
	}

	if (!m_adapter->Init())
	{
		LogWarn("Failed to init an adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
	}

	m_lastAdapterName = m_state->GetAdapterType();
	m_state->SetAdapter(m_adapter);
	// This is a very hacky way to let the adapter have a handle to the controller, and then be able to access the
	// Binary View object
	m_adapter->SetController(this);

	ApplyBreakpoints();

	// Forward the DebuggerEvent from the adapters to the controller
	m_adapter->SetEventCallback([this](const DebuggerEvent& event) { PostDebuggerEvent(event); });
	return true;
}


// Apply all breakpoints that are added before the adapter is created
void DebuggerController::ApplyBreakpoints()
{
	m_state->ApplyBreakpoints();
}


bool DebuggerController::CanStartDebgging()
{
	return !m_state->IsConnected();
}


bool DebuggerController::CanResumeTarget()
{
	return m_state->IsConnected() && (!m_state->IsRunning());
}


bool DebuggerController::ExpectSingleStep(DebugStopReason reason)
{
	//	On macOS, the stop reason we get for a single step is also the Breakpoint.
	//	To keep things working, we loosen the check.
	//	TODO: check how it works on other systems
	return (reason == SingleStep) || (reason == Breakpoint) || (reason == UnknownReason);
}


bool DebuggerController::Go()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	Submit([this] { GoAndWaitOnWorker(); });

	return true;
}

bool DebuggerController::GoReverse()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	Submit([this] { GoReverseAndWaitOnWorker(); });

	return true;
}


DebugStopReason DebuggerController::GoAndWaitOnWorker()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = GoAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::GoAndWait(std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this] { return GoAndWaitOnWorker(); }, timeout);
}


DebugStopReason DebuggerController::GoReverseAndWaitOnWorker()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = GoReverseAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::GoReverseAndWait(std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this] { return GoReverseAndWaitOnWorker(); }, timeout);
}


DebugStopReason DebuggerController::StepIntoIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepIntoAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("step into unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}


DebugStopReason DebuggerController::StepIntoReverseIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepIntoReverseAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("step into unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}


DebugStopReason DebuggerController::StepIntoReverseAndWaitInternal()
{
	// TODO: check if StepInto() succeeds
	return ExecuteAdapterAndWait(DebugAdapterStepIntoReverse);
}

bool DebuggerController::StepInto(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	Submit([this, il] { StepIntoAndWaitOnWorker(il); });

	return true;
}

bool DebuggerController::StepIntoReverse(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	Submit([this, il] { StepIntoReverseAndWaitOnWorker(il); });

	return true;
}

DebugStopReason DebuggerController::StepIntoReverseAndWaitOnWorker(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = StepIntoReverseIL(il);
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}

DebugStopReason DebuggerController::StepIntoReverseAndWait(BNFunctionGraphType il,
	std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this, il] { return StepIntoReverseAndWaitOnWorker(il); }, timeout);
}

DebugStopReason DebuggerController::StepIntoAndWaitOnWorker(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = StepIntoIL(il);
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}

DebugStopReason DebuggerController::StepIntoAndWait(BNFunctionGraphType il,
	std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this, il] { return StepIntoAndWaitOnWorker(il); }, timeout);
}

DebugStopReason DebuggerController::StepOverIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepOverAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;
			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("step over unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}

DebugStopReason DebuggerController::StepOverReverseIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepOverReverseAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;
			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("reverse step over unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}


bool DebuggerController::StepOver(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	Submit([this, il] { StepOverAndWaitOnWorker(il); });

	return true;
}


bool DebuggerController::StepOverReverse(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	Submit([this, il] { StepOverReverseAndWaitOnWorker(il); });

	return true;
}


DebugStopReason DebuggerController::StepOverAndWaitOnWorker(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = StepOverIL(il);
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::StepOverAndWait(BNFunctionGraphType il,
	std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this, il] { return StepOverAndWaitOnWorker(il); }, timeout);
}


DebugStopReason DebuggerController::StepOverReverseAndWaitOnWorker(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = StepOverReverseIL(il);
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::StepOverReverseAndWait(BNFunctionGraphType il,
	std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this, il] { return StepOverReverseAndWaitOnWorker(il); }, timeout);
}


DebugStopReason DebuggerController::EmulateStepReturnAndWait()
{
	uint64_t address = m_state->IP();
	std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(address);
	if (functions.empty())
		return InternalError;

	std::vector<uint64_t> returnAddresses;
	FunctionRef function = functions[0];
	MediumLevelILFunctionRef mlilFunc = function->GetMediumLevelIL();
	for (size_t i = 0; i < mlilFunc->GetInstructionCount(); i++)
	{
		MediumLevelILInstruction instruction = mlilFunc->GetInstruction(i);
		if ((instruction.operation == MLIL_RET) || (instruction.operation == MLIL_TAILCALL))
			returnAddresses.push_back(instruction.address);
	}

	return RunToAndWaitInternal(returnAddresses);
}


DebugStopReason DebuggerController::StepReturnAndWaitInternal()
{

	if (true /* StepReturnAvailable() */)
	{
		return ExecuteAdapterAndWait(DebugAdapterStepReturn);
	}
	else
	{
		// Emulate a step over
		return EmulateStepReturnAndWait();
	}
}


DebugStopReason DebuggerController::StepReturnReverseAndWaitInternal()
{

	if (true /* StepReturnReverseAvailable() */)
	{
		return ExecuteAdapterAndWait(DebugAdapterStepReturnReverse);
	}
}


bool DebuggerController::StepReturn()
{
	if (!CanResumeTarget())
		return false;

	Submit([this] { StepReturnAndWaitOnWorker(); });

	return true;
}


bool DebuggerController::StepReturnReverse()
{
	if (!CanResumeTarget())
		return false;

	Submit([this] { StepReturnReverseAndWaitOnWorker(); });

	return true;
}


DebugStopReason DebuggerController::StepReturnAndWaitOnWorker()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = StepReturnAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::StepReturnAndWait(std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this] { return StepReturnAndWaitOnWorker(); }, timeout);
}


DebugStopReason DebuggerController::StepReturnReverseAndWaitOnWorker()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = StepReturnReverseAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::StepReturnReverseAndWait(std::chrono::milliseconds timeout)
{
	return SubmitAndWait([this] { return StepReturnReverseAndWaitOnWorker(); }, timeout);
}


DebugStopReason DebuggerController::RunToAndWaitInternal(const std::vector<uint64_t>& remoteAddresses)
{

	for (uint64_t remoteAddress : remoteAddresses)
	{
		if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
		{
			m_adapter->AddBreakpoint(remoteAddress);
		}
	}

	auto reason = GoAndWaitInternal();

	for (uint64_t remoteAddress : remoteAddresses)
	{
		if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
		{
			m_adapter->RemoveBreakpoint(remoteAddress);
		}
	}

	return reason;
}


DebugStopReason DebuggerController::RunToReverseAndWaitInternal(const std::vector<uint64_t>& remoteAddresses)
{

	for (uint64_t remoteAddress : remoteAddresses)
	{
		if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
		{
			m_adapter->AddBreakpoint(remoteAddress);
		}
	}

	auto reason = GoReverseAndWaitInternal();

	for (uint64_t remoteAddress : remoteAddresses)
	{
		if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
		{
			m_adapter->RemoveBreakpoint(remoteAddress);
		}
	}

	return reason;
}


bool DebuggerController::RunTo(const std::vector<uint64_t>& remoteAddresses)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	Submit([this, remoteAddresses] { RunToAndWaitOnWorker(remoteAddresses); });

	return true;
}


bool DebuggerController::RunToReverse(const std::vector<uint64_t>& remoteAddresses)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	Submit([this, remoteAddresses] { RunToReverseAndWaitOnWorker(remoteAddresses); });

	return true;
}


DebugStopReason DebuggerController::RunToAndWaitOnWorker(const std::vector<uint64_t>& remoteAddresses)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = RunToAndWaitInternal(remoteAddresses);
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::RunToAndWait(const std::vector<uint64_t>& remoteAddresses,
	std::chrono::milliseconds timeout)
{
	return SubmitAndWait(
		[this, remoteAddresses] { return RunToAndWaitOnWorker(remoteAddresses); }, timeout);
}


DebugStopReason DebuggerController::RunToReverseAndWaitOnWorker(const std::vector<uint64_t>& remoteAddresses)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	auto reason = RunToReverseAndWaitInternal(remoteAddresses);
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	return reason;
}


DebugStopReason DebuggerController::RunToReverseAndWait(const std::vector<uint64_t>& remoteAddresses,
	std::chrono::milliseconds timeout)
{
	return SubmitAndWait(
		[this, remoteAddresses] { return RunToReverseAndWaitOnWorker(remoteAddresses); }, timeout);
}


bool DebuggerController::CreateDebuggerBinaryView()
{
	BinaryViewRef data = GetData();
	auto segment = data->GetSegmentAt(0);
	m_zeroSegmentAddedByDebugger = segment == nullptr;

	if (auto holdAnalysis = Settings::Instance()->Get<bool>("debugger.holdAnalysis"); holdAnalysis)
	{
		auto analysisProgress = data->GetAnalysisProgress();
		m_oldAnalysisState = analysisProgress.state;
		data->SetAnalysisHold(true);
	}

	m_state->GetMemory()->PrefillValueCache();

	m_accessor = new DebuggerFileAccessor(data);
	data->SetFunctionAnalysisUpdateDisabled(true);
	data->GetMemoryMap()->AddRemoteMemoryRegion("debugger", 0, m_accessor);
	data->SetFunctionAnalysisUpdateDisabled(false);


	return true;
}


void DebuggerController::DetectLoadedModule()
{
	// Rebase the binary and create DebugView
	uint64_t remoteBase;
	// Right now we only support applying the analysis info from one module into the debugger view, So we use a bool
	// here. In the future, we would like to support loading multiple modules, and we will need a more
	// robust mechanism.
	if (m_inputFileLoaded || (!m_state->GetRemoteBase(remoteBase)))
		return;

	m_inputFileLoaded = true;
	auto oldBase = GetViewFileSegmentsStart();

	if (remoteBase == oldBase)
		return;

	bool autoRebase = Settings::Instance()->Get<bool>("debugger.autoRebase");

	if (!autoRebase)
		return;

	if (!RebaseToAddress(remoteBase))
		LogWarn("Failed to rebase to remote base 0x%" PRIx64, remoteBase);
}


DebugThread DebuggerController::GetActiveThread() const
{
	return m_state->GetThreads()->GetActiveThread();
}


void DebuggerController::SetActiveThread(const DebugThread& thread)
{
	// TODO: check if the new thread is the same as the old one. If so, do nothing and return
	m_state->GetThreads()->SetActiveThread(thread);
	// We only need to update the register values after we switch to a different thread
	m_state->GetRegisters()->Update();
	// Post an event so the stack view can get updated
	DebuggerEvent event;
	event.type = ActiveThreadChangedEvent;
	PostDebuggerEvent(event);
}


bool DebuggerController::SuspendThread(std::uint32_t tid)
{
	auto result = m_state->GetThreads()->SuspendThread(tid);
	if (!result)
		return false;

	DebuggerEvent event;
	event.type = ThreadStateChangedEvent;
	PostDebuggerEvent(event);

	return result;
}

bool DebuggerController::ResumeThread(std::uint32_t tid)
{
	auto result = m_state->GetThreads()->ResumeThread(tid);
	if (!result)
		return false;

	DebuggerEvent event;
	event.type = ThreadStateChangedEvent;
	PostDebuggerEvent(event);

	return result;
}


std::vector<DebugFrame> DebuggerController::GetFramesOfThread(uint64_t tid)
{
	return m_state->GetThreads()->GetFramesOfThread((uint32_t)tid);
}


bool DebuggerController::Restart()
{
	if (!m_state->IsConnected())
		return false;

	// Interrupt any in-flight resume op so the queued Restart can actually run.
	// Without this, if the target is running the worker is blocked in WaitForAdapterStop
	// and Restart would sit in the queue indefinitely.
	RequestInterrupt();
	Submit([this] { RestartAndWaitOnWorker(); });
	return true;
}


DebugStopReason DebuggerController::RestartAndWaitOnWorker()
{
	if (!m_state->IsConnected())
		return InvalidStatusOrOperation;

	// Bypass the public sync wrappers; we are already on the worker and want to
	// run these inline without re-entering Submit.
	QuitAndWaitOnWorker();
	return LaunchAndWaitOnWorker();
}


DebugStopReason DebuggerController::RestartAndWait(std::chrono::milliseconds timeout)
{
	if (!m_state->IsConnected())
		return InvalidStatusOrOperation;

	if (std::this_thread::get_id() == m_dispatcherThreadId)
	{
		LogError("Synchronous debugger API called from debugger callback thread; use async APIs from callbacks");
		return InternalError;
	}

	RequestInterrupt();
	return SubmitAndWait([this] { return RestartAndWaitOnWorker(); }, timeout);
}


bool DebuggerController::ConnectToDebugServer()
{
	m_firstConnectToDebugServer = false;
	if (m_state->IsConnectedToDebugServer())
		return true;

	if (!CreateDebugAdapter())
		return false;

	bool ok = m_adapter->ConnectToDebugServer(m_state->GetRemoteHost(), m_state->GetRemotePort());
	if (!ok)
		LogWarn("Failed to connect to the debug server");
	else
		m_state->SetConnectedToDebugServer(true);

	return ok;
}


bool DebuggerController::DisconnectDebugServer()
{
	if (!m_state->IsConnectedToDebugServer())
		return true;

	bool ok = m_adapter->DisconnectDebugServer();
	if (!ok)
		LogWarn("Failed to disconnect from the debug server");
	else
		m_state->SetConnectedToDebugServer(false);

	return ok;
}


bool DebuggerController::IsConnectedToDebugServer()
{
	return m_state->IsConnectedToDebugServer();
}


void DebuggerController::Detach()
{
	if (!m_state->IsConnected())
		return;

	// Interrupt any in-flight resume op (see Restart for rationale).
	RequestInterrupt();
	Submit([this] { DetachAndWaitOnWorker(); });
}


void DebuggerController::DetachAndWaitOnWorker()
{
	if (!m_state->IsConnected())
		return;

	// TODO: return whether the operation is successful
	ExecuteAdapterAndWait(DebugAdapterDetach);

	// There is no need to notify a detached event at this point, since the detach event is already processed
	// by all the callback
}


void DebuggerController::DetachAndWait(std::chrono::milliseconds timeout)
{
	if (!m_state->IsConnected())
		return;

	if (std::this_thread::get_id() == m_dispatcherThreadId)
	{
		LogError("Synchronous debugger API called from debugger callback thread; use async APIs from callbacks");
		return;
	}

	RequestInterrupt();
	SubmitAndWait([this] { DetachAndWaitOnWorker(); }, timeout);
}


void DebuggerController::Quit()
{
	if (!m_state->IsConnected())
		return;

	// Interrupt any in-flight resume op (see Restart for rationale).
	RequestInterrupt();
	Submit([this] { QuitAndWaitOnWorker(); });
}


void DebuggerController::QuitAndWaitOnWorker()
{
	if (!m_state->IsConnected())
		return;

	if (m_state->IsRunning())
	{
		// We must pause the target if it is currently running, at least for DbgEngAdapter.
		// Call PauseAndWaitInternal (not the public PauseAndWait) so we go through
		// ExecuteAdapterAndWait(Pause) and actually wait for the engine to stop via the
		// adapter-stop channel. The public PauseAndWait would re-enter Submit inline here
		// (we are on the worker) and return without waiting, leaving the engine still
		// running when we issue Quit below.
		PauseAndWaitInternal();
	}

	// TODO: return whether the operation is successful
	ExecuteAdapterAndWait(DebugAdapterQuit);

	// There is no need to notify a TargetExitedEvent at this point, since the exit event is already processed
	// by all the callback
}


void DebuggerController::QuitAndWait(std::chrono::milliseconds timeout)
{
	if (!m_state->IsConnected())
		return;

	if (std::this_thread::get_id() == m_dispatcherThreadId)
	{
		LogError("Synchronous debugger API called from debugger callback thread; use async APIs from callbacks");
		return;
	}

	RequestInterrupt();
	SubmitAndWait([this] { QuitAndWaitOnWorker(); }, timeout);
}


bool DebuggerController::Pause()
{
	if (!m_state->IsConnected())
		return false;

	// Out-of-band: ask the interrupt thread to break the engine (returns immediately).
	// The worker is presumed to be blocked inside ExecuteAdapterAndWait for whatever op
	// is in flight (Go/Step/RunTo/etc.); when the engine receives the break it will
	// report a stop, the worker's op will return, and its OnWorker wrapper will
	// call NotifyStopped. We do not queue any work for the worker here.
	RequestInterrupt();
	return true;
}


DebugStopReason DebuggerController::PauseAndWaitInternal()
{
	return ExecuteAdapterAndWait(DebugAdapterPause);
}


DebugStopReason DebuggerController::PauseAndWait(std::chrono::milliseconds timeout)
{
	if (!m_state->IsConnected())
		return InvalidStatusOrOperation;

	if (std::this_thread::get_id() == m_dispatcherThreadId)
	{
		LogError("Synchronous debugger API called from debugger callback thread; use async APIs from callbacks");
		return InternalError;
	}

	RequestInterrupt();

	// Wait for the currently-running worker task (if any) to finish processing
	// the break. Submitting a no-op gives us a future that resolves once the
	// worker drains past whatever was in flight at the time of the break.
	auto fut = Submit([] {});
	if (timeout == std::chrono::milliseconds::max())
	{
		fut.wait();
	}
	else if (fut.wait_for(timeout) != std::future_status::ready)
	{
		// BreakInto has already been signaled; there's nothing else to do.
		return TimedOut;
	}

	return DebugStopReason::UserRequestedBreak;
}


DebugStopReason DebuggerController::GoAndWaitInternal()
{
	return ExecuteAdapterAndWait(DebugAdapterGo);
}

DebugStopReason DebuggerController::GoReverseAndWaitInternal()
{
	return ExecuteAdapterAndWait(DebugAdapterGoReverse);
}


DebugStopReason DebuggerController::StepIntoAndWaitInternal()
{
	// TODO: check if StepInto() succeeds
	return ExecuteAdapterAndWait(DebugAdapterStepInto);
}


DebugStopReason DebuggerController::EmulateStepOverAndWait()
{
	uint64_t remoteIP = m_state->IP();

	// TODO: support the case where we cannot determined the remote arch
	ArchitectureRef remoteArch = m_state->GetRemoteArchitecture();
	if (!remoteArch)
		return InternalError;

	size_t size = remoteArch->GetMaxInstructionLength();
	DataBuffer buffer;
	{
		std::lock_guard<std::recursive_mutex> adapterLock(m_state->AdapterAccessMutex());
		buffer = m_adapter->ReadMemory(remoteIP, size);
	}
	size_t bytesRead = buffer.GetLength();

	Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(remoteArch, nullptr);
	ilFunc->SetCurrentAddress(remoteArch, remoteIP);
	remoteArch->GetInstructionLowLevelIL((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, *ilFunc);

	if (ilFunc->GetInstructionCount() == 0)
		return InternalError;

	const auto& instr = (*ilFunc)[0];
	if (instr.operation != LLIL_CALL)
	{
		return StepIntoAndWaitInternal();
	}
	else
	{
		InstructionInfo info;
		if (!remoteArch->GetInstructionInfo((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, info))
		{
			// Whenever there is a failure, we fail back to step into
			return StepIntoAndWaitInternal();
		}

		if (info.length == 0)
		{
			return StepIntoAndWaitInternal();
		}

		uint64_t remoteIPNext = remoteIP + info.length;
		return RunToAndWaitInternal({remoteIPNext});
	}
}

DebugStopReason DebuggerController::EmulateStepOverReverseAndWait()
{
	// This cannot be implemented here unless we have hardware breakpoint supports
	LogWarn("EmulateStepOverReverseAndWait() is not implemented");
	return InternalError;
}

DebugStopReason DebuggerController::StepOverAndWaitInternal()
{

	if (m_adapter && m_adapter->SupportFeature(DebugAdapterSupportStepOver))
	{
		return ExecuteAdapterAndWait(DebugAdapterStepOver);
	}
	else
	{
		// Emulate a step over
		return EmulateStepOverAndWait();
	}
}

DebugStopReason DebuggerController::StepOverReverseAndWaitInternal()
{

	if (m_adapter && m_adapter->SupportFeature(DebugAdapterSupportStepOverReverse))
	{
		return ExecuteAdapterAndWait(DebugAdapterStepOverReverse);
	}
	else
	{
		// Emulate a step over reverse
		return EmulateStepOverReverseAndWait();
	}
}


void DebuggerController::LaunchOrConnect()
{
	std::string adapter = m_state->GetAdapterType();
	auto adapterType = DebugAdapterType::GetByName(adapter);
	if (!adapterType)
		return;

	if (adapterType->CanExecute(GetData()))
		Launch();
	else if (adapterType->CanConnect(GetData()))
		Connect();
}


// Use a function-local static to avoid two problems:
// 1. Static initialization order fiasco -- if any other translation unit's static initializer
//    calls GetController before this TU is initialized, a global would not yet be constructed.
// 2. Static destruction order -- during process exit, a namespace-scope std::mutex can be
//    destroyed before cleanup code (e.g., Python GC calling Destroy() via FFI) tries to lock it,
//    causing "mutex lock failed: Invalid argument". Bundling the mutex and vector in the same
//    function-local static ensures they share the same lifetime.
DebuggerController::ControllerState& DebuggerController::GetControllerState()
{
	// Intentionally heap-allocated and never freed. A function-local static would still be
	// destroyed during static cleanup, but Python's GC can call Destroy() -> DeleteController()
	// even later than that, hitting a destroyed mutex. Leaking the allocation ensures the mutex
	// and vector remain valid for the entire process lifetime. The OS reclaims the memory at exit.
	static ControllerState* state = new ControllerState();
	return *state;
}


DbgRef<DebuggerController> DebuggerController::GetController(BinaryViewRef data)
{
	auto& state = GetControllerState();
	std::lock_guard<std::mutex> lock(state.mutex);
	for (auto& c : state.controllers)
	{
		if (c && c->m_file == data->GetFile())
			return c;
	}

	auto controller = new DebuggerController(data);
	state.controllers.emplace_back(controller);
	return controller;
}


void DebuggerController::DeleteController(BinaryViewRef data)
{
	auto& state = GetControllerState();
	std::lock_guard<std::mutex> lock(state.mutex);
	state.controllers.erase(
		std::remove_if(state.controllers.begin(), state.controllers.end(),
			[&](const DbgRef<DebuggerController>& c) { return c && c->GetFile() == data->GetFile(); }),
		state.controllers.end());
}


bool DebuggerController::ControllerExists(BinaryViewRef data)
{
	auto& state = GetControllerState();
	std::lock_guard<std::mutex> lock(state.mutex);
	for (auto& c : state.controllers)
	{
		if (c && c->GetFile() == data->GetFile())
			return true;
	}

	return false;
}


DbgRef<DebuggerController> DebuggerController::GetController(FileMetadataRef file)
{
	auto& state = GetControllerState();
	std::lock_guard<std::mutex> lock(state.mutex);
	for (auto& c : state.controllers)
	{
		if (c && c->GetFile() == file)
			return c;
	}

	// You cannot create a controller from a file -- you must use a binary view for it
	return nullptr;
}


bool DebuggerController::ControllerExists(FileMetadataRef file)
{
	auto& state = GetControllerState();
	std::lock_guard<std::mutex> lock(state.mutex);
	for (auto& c : state.controllers)
	{
		if (c && c->GetFile() == file)
			return true;
	}

	return false;
}


void DebuggerController::DeleteController(FileMetadataRef file)
{
	auto& state = GetControllerState();
	std::lock_guard<std::mutex> lock(state.mutex);
	state.controllers.erase(
		std::remove_if(state.controllers.begin(), state.controllers.end(),
			[&](const DbgRef<DebuggerController>& c) { return c && c->GetFile() == file; }),
		state.controllers.end());
}


void DebuggerController::Destroy()
{
	// Contrary to the name, DebuggerController::Destroy() actually only removes the object from the global debugger
	// controller array (g_debuggerControllers). This enabling its ref count to go down to zero and eventually get freed.
	// The actual cleanup happens in DebuggerController::~DebuggerController().
	// TODO: I should change the function name later
	DebuggerController::DeleteController(m_file);
}


// The controller's own state mutations for each event type. Called inline from
// PostDebuggerEvent (on whichever thread posted the event) BEFORE the event is
// enqueued for the dispatcher. Previously this body lived in EventHandler running
// on the dispatcher thread; that created a race where the worker could observe
// stale m_state after WaitForAdapterStop returned but before the dispatcher had
// gotten around to running EventHandler. Now the controller's state is updated
// happen-before the broadcast, and the dispatcher only fans out to external
// (UI, plugin, scripting) consumers.
//
// Thread-safety: this body touches m_state's connection/execution status, plus
// m_lastIP / m_currentIP / m_exitCode on the controller -- all plain (non-atomic,
// unlocked) fields read from other threads (UI render layer, file accessor) without
// synchronization. Those are pre-existing data races reported in #1091; this PR
// does not address them, and adding synchronization there is tracked separately.
// Moving the mutations off the dispatcher and onto the event-posting thread (this
// function vs the old EventHandler) does not change the race set -- it just changes
// which thread is the writer -- but it does fix the unrelated *control-flow* race
// where the worker resumed before the dispatcher had updated state, which is what
// this commit is for.
void DebuggerController::ApplyOwnStateForEvent(const DebuggerEvent& event)
{
	switch (event.type)
	{
	case LaunchEventType:
	case ResumeEventType:
	case StepIntoEventType:
	{
		// Todo: this is just a temporary workaround. Otherwise, the connection status would not be set properly
		m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterRunningStatus);
		break;
	}
	case TargetExitedEventType:
		m_exitCode = (uint32_t)event.data.exitData.exitCode;
		[[fallthrough]];
	case DetachedEventType:
	case LaunchFailureEventType:
	{
		// Light, lock-free state only -- safe to run even while the adapter lock is held (it is,
		// when this runs synchronously inside a locked ExecuteAdapterAndWait op such as Quit).
		m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterInvalidStatus);
		m_inputFileLoaded = false;
		m_initialBreakpointSeen = false;
		ClearTTDPositionHistory();

		m_lastIP = m_currentIP;
		m_currentIP = 0;

		// The remaining cleanup (MarkDirty / RemoveDebuggerMemoryRegion / accessor disposal /
		// analysis hold) calls into BN core, which takes the file lock. Running it here would mean
		// holding the adapter lock across a BN-core call whenever this fires inside a locked op
		// (Quit/Detach) -- the AB-BA deadlock with the analysis read path. For target-gone/detach
		// it is instead run by ExecuteAdapterAndWait / the worker AFTER the adapter lock is
		// released (see FinalizeTargetGoneCleanup). LaunchFailure does not flow through that path
		// (and has no live memory region to remove), so finalize it inline.
		//
		// Note: the accessor MUST be disposed in FinalizeTargetGoneCleanup, AFTER
		// RemoveDebuggerMemoryRegion -- the BinaryView's MemoryMap holds a raw pointer to it from
		// AddRemoteMemoryRegion, and any in-flight or about-to-fire BinaryView::Read (e.g. a
		// LinearView refresh triggered by the very same TargetExited event reaching the UI) would
		// otherwise hit a freed accessor.
		if (event.type == LaunchFailureEventType)
			FinalizeTargetGoneCleanup();
		break;
	}
	case TargetStoppedEventType:
	{
		m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterPausedStatus);
		m_state->MarkDirty();
		m_state->UpdateCaches();
		m_lastIP = m_currentIP;
		m_currentIP = m_state->IP();
		m_ranges.clear();

		DetectLoadedModule();
		UpdateStackVariables();
		AddRegisterValuesToExpressionParser();
		AddModuleValuesToExpressionParser();
		RecordTTDPosition();
		break;
	}
	case ActiveThreadChangedEvent:
	{
		m_state->UpdateCaches();
		m_lastIP = m_currentIP;
		m_currentIP = m_state->IP();
		AddRegisterValuesToExpressionParser();
		break;
	}
	case RegisterChangedEvent:
	{
		m_lastIP = m_currentIP;
		m_currentIP = m_state->IP();
		AddRegisterValuesToExpressionParser();
		break;
	}
	case ErrorEventType:
	{
		LogError("%s", event.data.errorData.error.c_str());
		break;
	}
	default:
		break;
	}
}


// Idempotent. Calls into BN core (memory map / analysis), which takes the file lock, so it MUST be
// invoked with no adapter lock held. Safe to call more than once: MarkDirty re-marks an
// already-cleared cache, RemoveMemoryRegion no-ops when the region is already gone, accessor
// disposal is guarded by the nullptr check, and SetAnalysisHold(false) is idempotent -- so the
// redundant case (e.g. both WindowsNativeAdapter::Quit and the debug loop posted TargetExited) is
// harmless.
void DebuggerController::FinalizeTargetGoneCleanup()
{
	// The backend symbols we added are at absolute target addresses that are meaningless once the target
	// is gone, so remove them. Idempotent: the map is cleared, so a second call is a no-op. Pass
	// updateAnalysis = false: we are about to remove the debugger memory region below, so we must not
	// schedule an async analysis pass that could read from it mid-teardown.
	RemoveAllLoadedSymbols(false);
	m_state->MarkDirty();
	// Remove the region from the BinaryView's MemoryMap BEFORE disposing of m_accessor: the
	// MemoryMap holds a raw pointer to it (see AddRemoteMemoryRegion in DebuggerController::Start),
	// so freeing the accessor first would leave the map with a dangling pointer that any concurrent
	// BinaryView::Read (e.g. a linear-view refresh triggered by TargetExited) would dereference.
	RemoveDebuggerMemoryRegion();
	if (m_accessor)
	{
		// Defer deletion to a detached thread. The accessor holds a DbgRef<DebuggerController>;
		// if it's the last reference, deleting it here would trigger ~DebuggerController which
		// calls m_workerThread.join() and m_debuggerEventThread.join(). FinalizeTargetGoneCleanup
		// itself runs on the worker (via ExecuteAdapterAndWait or the Submit fallback in
		// PostDebuggerEvent), so a synchronous delete on the last ref would self-join and deadlock.
		// A detached thread sidesteps that regardless of who called us.
		auto* accessor = m_accessor;
		m_accessor = nullptr;
		std::thread([accessor]() { delete accessor; }).detach();
	}
	if (m_oldAnalysisState != HoldState)
		m_data->SetAnalysisHold(false);
}


size_t DebuggerController::RegisterEventCallback(
	std::function<void(const DebuggerEvent&)> callback, const std::string& name)
{
	std::unique_lock lock(m_callbackMutex);
	DebuggerEventCallback object;
	object.function = callback;
	object.index = m_callbackIndex++;
	object.name = name;
	m_eventCallbacks.push_back(object);
	return object.index;
}


bool DebuggerController::RemoveEventCallback(size_t index)
{
	std::unique_lock lock(m_callbackMutex);
	for (auto it = m_eventCallbacks.begin(); it != m_eventCallbacks.end(); it++)
	{
		if (it->index == index)
		{
			// It is fine to directly remove the callback from m_eventCallbacks. Because in DebuggerMainThread, the
			// code makes a copy of the events before trying to dispatch them.
			// The reason that we need m_disabledCallbacks is because during dispatching of an earlier event, the code
			// may lead to the deletion of a later event. In that case, the change is not reflected on the copy of the
			// list, so we must look up the index in m_disabledCallbacks before dispatching them
			m_disabledCallbacks.insert(index);
			m_eventCallbacks.erase(it);
			return true;
		}
	}
	return false;
}


bool DebuggerController::RemoveEventCallbackInternal(size_t index)
{
	for (auto it = m_eventCallbacks.begin(); it != m_eventCallbacks.end(); it++)
	{
		if (it->index == index)
		{
			m_eventCallbacks.erase(it);
			return true;
		}
	}
	return false;
}


// The design goal here is:
// 1. The PostDebuggerEvent is blocking, i.e., it only returns when the event has been processed. This is important for
// ensuring proper internal state updates. The only exception is that when a new debugger event is posted from one of
// the callbacks (the caller is already in the dispatcher loop), then PostDebuggerEvent will only queue the event but
// not block on it. Because doing so will cause a deadlock.
// 2. Thread-safe. Any thread can call PostDebuggerEvent and not cause unexpected behavior
// 3. Re-entrant safe. PostDebuggerEvent can be called within a callback, and there would not be chaos. But at the same
// time, as mentioned above, when it is re-entered from the dispatcher loop, the call is non-blocking. This means that
// in DebuggerController::DetectLoadedModule(), the code cannot post a ModuleLoadedEvent and block on it. Instead, a
// direct callback must be used to inform the UI to perform the rebase, and then the core can continue its processing

void DebuggerController::PostDebuggerEvent(const DebuggerEvent& event)
{
	// Adapter stops are an internal signal to the worker, not a user-facing event.
	// Route them to the adapter-stop channel and skip the public dispatcher queue.
	if (event.type == AdapterStoppedEventType)
	{
		DebugStopReason reason = event.data.targetStoppedData.reason;
		bool inWait;
		{
			std::lock_guard lk(m_adapterStopMutex);
			inWait = m_inAdapterWait;
			if (inWait)
				m_adapterStopPending = reason;
		}
		if (inWait)
		{
			m_adapterStopCv.notify_all();
		}
		else
		{
			// No controller op is in flight — the adapter stopped on its own (e.g.
			// the user typed `si` directly into the LLDB REPL). Queue a handler on
			// the worker to update caches and synthesize a TargetStoppedEvent.
			Submit([this, reason] { HandleSpontaneousAdapterStop(reason); });
		}
		return;
	}

	// Apply the controller's own state mutations synchronously, before this event
	// reaches anyone else. Previously this happened in EventHandler running on the
	// dispatcher thread, which created a race: the worker could observe stale
	// m_state after WaitForAdapterStop returned but before EventHandler had run.
	// Doing the mutations here means the broadcast is purely informational to
	// external consumers; the controller's own state is already consistent.
	ApplyOwnStateForEvent(event);

	// Target-exit / detach also unblock any in-flight WaitForAdapterStop -- the
	// engine isn't going to issue a separate AdapterStoppedEvent. We do this AFTER
	// ApplyOwnStateForEvent so the worker wakes to a fully-updated m_state.
	if (event.type == TargetExitedEventType || event.type == DetachedEventType)
	{
		bool inWait;
		{
			std::lock_guard lk(m_adapterStopMutex);
			inWait = m_inAdapterWait;
			if (inWait)
				m_adapterStopPending = ProcessExited;
		}
		if (inWait)
			m_adapterStopCv.notify_all();
		else
			// No controller op is in flight (e.g. the target exited on its own, or an adapter that
			// reports exits asynchronously). No ExecuteAdapterAndWait will run the deferred cleanup,
			// so queue it on the worker, where no adapter lock is held. Idempotent, so it is fine
			// even if a later op also triggers it.
			Submit([this] { FinalizeTargetGoneCleanup(); });
		// Fall through: still goes through the public dispatcher queue.
	}

	auto pending = std::make_shared<PendingEvent>();
	pending->event = event;
	std::future<void> future = pending->done.get_future();

	{
		std::lock_guard lock(m_eventsMutex);
		m_eventQueue.push(pending);
	}
	m_cv.notify_one();

	if (std::this_thread::get_id() == m_dispatcherThreadId)
	{
		// Posting a new debugger event from a callback should be *fine*, but it will also be non-blocking, so we should
		// be aware of that
		LogWarn("A debugger event with type %d is posted from the dispatcher thread and is unexpected", event.type);
	}
	else
	{
		// Block until the event is handled (unless this is the dispatcher thread)
		future.get();
	}
}


DebugStopReason DebuggerController::WaitForAdapterStop()
{
	std::unique_lock lk(m_adapterStopMutex);
	m_adapterStopCv.wait(lk, [this] {
		return m_adapterStopPending.has_value() || m_workerShouldExit;
	});
	if (m_workerShouldExit && !m_adapterStopPending.has_value())
		return InternalError;
	DebugStopReason reason = *m_adapterStopPending;
	m_adapterStopPending = std::nullopt;
	return reason;
}


bool DebuggerController::ShouldSilentResumeAfterStop()
{
	// Only breakpoint stops are candidates for silent resume on a false condition.
	// Step operations always surface, even if they land on a breakpoint.
	bool isStepOperation = (m_lastOperation == DebugAdapterStepInto)
		|| (m_lastOperation == DebugAdapterStepOver)
		|| (m_lastOperation == DebugAdapterStepReturn)
		|| (m_lastOperation == DebugAdapterStepIntoReverse)
		|| (m_lastOperation == DebugAdapterStepOverReverse)
		|| (m_lastOperation == DebugAdapterStepReturnReverse);
	if (isStepOperation)
		return false;

	m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
	m_state->SetExecutionStatus(DebugAdapterPausedStatus);
	m_state->MarkDirty();
	m_state->UpdateCaches();
	AddRegisterValuesToExpressionParser();
	AddModuleValuesToExpressionParser();

	uint64_t ip = m_state->IP();
	if (!m_state->GetBreakpoints()->ContainsAbsolute(ip))
		return false;
	if (EvaluateBreakpointCondition(ip))
		return false;

	return true;
}


void DebuggerController::HandleSpontaneousAdapterStop(DebugStopReason reason)
{
	// The adapter reported a stop with no controller op in flight. This is the
	// case the dispatcher previously synthesized a TargetStoppedEvent for at
	// `debuggercontroller.cpp:2279` in the pre-refactor code.
	m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
	m_state->SetExecutionStatus(DebugAdapterPausedStatus);
	m_state->MarkDirty();
	m_state->UpdateCaches();
	AddRegisterValuesToExpressionParser();
	AddModuleValuesToExpressionParser();
	NotifyStopped(reason);
}


void DebuggerController::RequestInterrupt()
{
	// Purely out-of-band, and fully asynchronous: hand the break off to the interrupt
	// thread and return immediately. The caller (Pause/Restart/Quit/Detach, possibly on
	// the UI thread) never blocks on the adapter call. The in-flight worker op (blocked
	// in WaitForAdapterStop) wakes up via the adapter-stop channel once the engine breaks;
	// its OnWorker wrapper then calls NotifyStopped. We do not call NotifyStopped here and
	// we do not queue any work for the worker.
	//
	// Multiple requests collapse to one flag: BreakInto is only meaningful per in-flight
	// op, and the worker cannot advance to the next queued op until this break unsticks it,
	// so a coalesced break can never land on a later operation's target.
	{
		std::lock_guard<std::mutex> lock(m_interruptMutex);
		m_interruptRequested = true;
	}
	m_interruptCv.notify_one();
}


void DebuggerController::InterruptThreadMain()
{
	while (true)
	{
		{
			std::unique_lock<std::mutex> lock(m_interruptMutex);
			m_interruptCv.wait(lock, [this] { return m_interruptShouldExit || m_interruptRequested; });
			if (m_interruptShouldExit && !m_interruptRequested)
				break;
			m_interruptRequested = false;
		}

		// Snapshot the adapter pointer once so the null check and the call see the same
		// value. The pointed-to object outlives this thread: the adapter is destroyed in
		// ~DebuggerState, which runs in ~DebuggerController only after this thread has been
		// joined. The adapter-access lock serializes BreakInto against in-flight resume
		// requests and UI memory reads; it is safe to acquire even while the target is
		// running because the worker holds the lock only around the resume request, not
		// across the run-wait.
		if (DebugAdapter* adapter = m_adapter)
		{
			std::lock_guard<std::recursive_mutex> adapterLock(m_state->AdapterAccessMutex());
			adapter->BreakInto();
		}
	}
}


void DebuggerController::DebuggerMainThread()
{
	m_shouldExit = false;
	m_dispatcherThreadId = std::this_thread::get_id();

	while (true)
	{
		std::shared_ptr<PendingEvent> current;
		std::unique_lock lock(m_eventsMutex);
		m_cv.wait(lock, [&] { return !m_eventQueue.empty() || m_shouldExit; });

		if (m_shouldExit && m_eventQueue.empty())
			break;

		current = m_eventQueue.front();
		m_eventQueue.pop();
		lock.unlock();

		std::unique_lock callbackLock(m_callbackMutex);
		std::list<DebuggerEventCallback> eventCallbacks = m_eventCallbacks;
		callbackLock.unlock();

		auto event = current->event;

		// AdapterStoppedEventType no longer reaches the dispatcher: PostDebuggerEvent
		// intercepts it and routes the reason to the worker's adapter-stop channel.
		// Conditional-breakpoint silent-resume and spontaneous-stop synthesis now live
		// in ExecuteAdapterAndWait / HandleSpontaneousAdapterStop on the worker.

		DebuggerEvent eventToSend = event;
		if ((eventToSend.type == TargetStoppedEventType) && !m_initialBreakpointSeen)
		{
			m_initialBreakpointSeen = true;
			eventToSend.data.targetStoppedData.reason = InitialBreakpoint;
		}

		for (const DebuggerEventCallback& cb : eventCallbacks)
		{
			std::unique_lock callbackLock2(m_callbackMutex);
			if (m_disabledCallbacks.find(cb.index) != m_disabledCallbacks.end())
				continue;

			callbackLock2.unlock();
			cb.function(eventToSend);
		}

		CleanUpDisabledEvent();
		current->done.set_value();
	}
}


void DebuggerController::CleanUpDisabledEvent()
{
	std::unique_lock lock(m_callbackMutex);
	// We only need to clear the vector of index here because the entries in m_eventCallbacks have already been
	// deleted by RemoveEventCallback
	m_disabledCallbacks.clear();
}


void DebuggerController::NotifyStopped(DebugStopReason reason, void* data)
{
	DebuggerEvent event;
	event.type = TargetStoppedEventType;
	event.data.targetStoppedData.reason = reason;
	event.data.targetStoppedData.data = data;
	PostDebuggerEvent(event);
}


void DebuggerController::NotifyError(const std::string& error, const std::string& shortError, void* data)
{
	DebuggerEvent event;
	event.type = ErrorEventType;
	event.data.errorData.error = error;
	event.data.errorData.shortError = shortError;
	event.data.errorData.data = data;
	PostDebuggerEvent(event);
}


void DebuggerController::NotifyEvent(DebuggerEventType eventType)
{
	DebuggerEvent event;
	event.type = eventType;
	PostDebuggerEvent(event);
}


// We should call these two function instead of DebugAdapter::ReadMemory(), which will skip the memory cache
DataBuffer DebuggerController::ReadMemory(std::uintptr_t address, std::size_t size)
{
	if (!GetData())
		return DataBuffer {};

	if (!m_state->IsConnected())
		return DataBuffer {};

	DebuggerMemory* memory = m_state->GetMemory();
	if (!memory)
		return DataBuffer {};

	return memory->ReadMemory(address, size);
}


bool DebuggerController::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	if (!GetData())
		return false;

	if (!m_state->IsConnected())
		return false;

	if (m_state->IsRunning())
		return false;

	DebuggerMemory* memory = m_state->GetMemory();
	if (!memory)
		return false;

	return memory->WriteMemory(address, buffer);
}


std::vector<DebugModule> DebuggerController::GetAllModules()
{
	return m_state->GetModules()->GetAllModules();
}

std::vector<DebugMemoryRegion> DebuggerController::GetMemoryMap()
{
	return m_state->GetMemoryMap()->GetAllRegions();
}


size_t DebuggerController::LoadSymbolsForModule(const std::string& moduleName)
{
	DebugModule module = m_state->GetModules()->GetModuleByName(moduleName);
	if (module.m_name.empty() && module.m_short_name.empty())
	{
		LogWarn("Cannot load symbols: no module named \"%s\" is loaded in the target", moduleName.c_str());
		return 0;
	}
	return LoadSymbolsForModule(module);
}


size_t DebuggerController::LoadSymbolsForModule(const DebugModule& module)
{
	if (!m_adapter)
		return 0;

	if (!m_adapter->SupportFeature(DebugAdapterSupportSymbols))
	{
		LogWarn("The current debug adapter does not support reading symbols from the backend");
		return 0;
	}

	auto data = GetData();
	if (!data)
		return 0;

	std::vector<DebugSymbol> symbols;
	{
		std::lock_guard<std::recursive_mutex> adapterLock(m_state->AdapterAccessMutex());
		symbols = m_adapter->GetSymbolsForModule(module);
	}

	if (symbols.empty())
		return 0;

	std::lock_guard<std::recursive_mutex> lock(m_loadedModuleSymbolsMutex);

	auto id = data->BeginUndoActions();
	// Adding a large module's symbols one at a time generates a per-symbol analysis notification; disable
	// the updates while we add them in bulk and re-enable afterwards (see the design notes on issue #210).
	data->SetFunctionAnalysisUpdateDisabled(true);
	size_t count = ApplyModuleSymbolsLocked(data, module, symbols);
	data->SetFunctionAnalysisUpdateDisabled(false);
	data->ForgetUndoActions(id);
	// The data variables above were defined while function-analysis updates were disabled, so nothing has
	// processed them into the view yet. Without this, the newly added symbols show up "bare" (no data
	// variable) in the symbols/linear views until the user manually refreshes. Kick an async update so the
	// pending data variables are materialized and the views are notified.
	data->UpdateAnalysis();

	LogInfo("Loaded %zu symbols for module %s from the debugger backend", count,
		module.m_short_name.empty() ? module.m_name.c_str() : module.m_short_name.c_str());
	return count;
}


size_t DebuggerController::LoadSymbolsForAllModules()
{
	if (!m_adapter)
		return 0;

	if (!m_adapter->SupportFeature(DebugAdapterSupportSymbols))
	{
		LogWarn("The current debug adapter does not support reading symbols from the backend");
		return 0;
	}

	auto data = GetData();
	if (!data)
		return 0;

	// Read every module's symbols from the backend first (this needs the adapter lock), then apply them
	// all inside a single analysis-update window below. Toggling function-analysis updates once for the
	// whole batch -- rather than once per module -- is what makes loading "all modules" behave the same as
	// loading each module on its own: re-enabling analysis starts an async update, and a per-module disable
	// would supersede the previous module's still-pending update, leaving only the last module's references
	// (e.g. IAT pointers to freshly-named API functions) re-resolved. See ApplyModuleSymbolsLocked / #210.
	std::vector<std::pair<DebugModule, std::vector<DebugSymbol>>> moduleSymbols;
	{
		std::lock_guard<std::recursive_mutex> adapterLock(m_state->AdapterAccessMutex());
		for (const DebugModule& module : GetAllModules())
		{
			std::vector<DebugSymbol> symbols = m_adapter->GetSymbolsForModule(module);
			if (!symbols.empty())
				moduleSymbols.emplace_back(module, std::move(symbols));
		}
	}

	if (moduleSymbols.empty())
		return 0;

	std::lock_guard<std::recursive_mutex> lock(m_loadedModuleSymbolsMutex);

	auto id = data->BeginUndoActions();
	data->SetFunctionAnalysisUpdateDisabled(true);
	size_t total = 0;
	for (auto& [module, symbols] : moduleSymbols)
		total += ApplyModuleSymbolsLocked(data, module, symbols);
	data->SetFunctionAnalysisUpdateDisabled(false);
	data->ForgetUndoActions(id);
	// Materialize the data variables added under the disabled-update window and notify the views; see
	// LoadSymbolsForModule for why this is needed (otherwise the symbols render "bare" until a refresh).
	data->UpdateAnalysis();

	LogInfo("Loaded %zu symbols across %zu modules from the debugger backend", total, moduleSymbols.size());
	return total;
}


size_t DebuggerController::ApplyModuleSymbolsLocked(
	BinaryViewRef data, const DebugModule& module, const std::vector<DebugSymbol>& symbols)
{
	// If symbols were already loaded for this module, remove them first so that re-loading the same
	// module is idempotent and does not create duplicate symbols.
	for (auto it = m_loadedModuleSymbols.begin(); it != m_loadedModuleSymbols.end(); ++it)
	{
		if (module.IsSameBaseModule(it->first))
		{
			RemoveTrackedSymbolsLocked(data, it->second);
			m_loadedModuleSymbols.erase(it);
			break;
		}
	}

	std::string key = !module.m_name.empty() ? DebugModule::GetPathBaseName(module.m_name) : module.m_short_name;
	std::vector<Ref<Symbol>>* symbolList = &m_loadedModuleSymbols[key];

	auto voidType = Type::VoidType();
	for (const DebugSymbol& sym : symbols)
	{
		BNSymbolType symbolType = sym.m_isFunction ? FunctionSymbol : DataSymbol;
		std::string rawName = sym.m_rawName.empty() ? sym.m_name : sym.m_rawName;
		// Use DefineAutoSymbol (not DefineUserSymbol) so these never override the user's own symbols.
		Ref<Symbol> symbol = new Symbol(symbolType, sym.m_name, sym.m_fullName, rawName, sym.m_address);
		data->DefineAutoSymbol(symbol);
		// A data variable is needed for BN to actually render the symbol in the views. Define it with a
		// void type, mirroring the design notes on issue #210.
		data->DefineDataVariable(sym.m_address, Confidence<Ref<Type>>(voidType));
		// Track the exact symbol object so we can remove precisely it later, even when the linker folds
		// several symbols onto one address (GetSymbolByAddress would only return one of them).
		symbolList->push_back(symbol);
	}
	return symbols.size();
}


size_t DebuggerController::RemoveTrackedSymbolsLocked(BinaryViewRef data, const std::vector<Ref<Symbol>>& symbols)
{
	for (const Ref<Symbol>& symbol : symbols)
	{
		if (!symbol)
			continue;
		// Undo in the inverse order of ApplyModuleSymbolsLocked (which defines the symbol, then the data
		// variable). Removing the data variable first avoids leaving it briefly symbol-less, which on
		// some platforms makes the core auto-create an anonymous "data_..." symbol that would then leak.
		// Undefining a data variable is keyed on the address; calling it more than once for an address
		// shared by several folded symbols is harmless (the later calls are no-ops).
		//
		// Pass blacklist = false: the default (true) blacklists the address so auto analysis will not
		// recreate an auto data variable there. Since ApplyModuleSymbolsLocked adds these as *auto* data
		// variables, blacklisting would make a later re-load's DefineDataVariable a no-op -- the symbol
		// would then have no data variable and would not render in the linear view. We manage these
		// variables ourselves, so removal must not blacklist them.
		data->UndefineDataVariable(symbol->GetAddress(), false);
		data->UndefineAutoSymbol(symbol);
	}
	return symbols.size();
}


size_t DebuggerController::UndefineTrackedSymbols(const std::vector<Ref<Symbol>>& symbols)
{
	auto data = GetData();
	if (!data)
		return 0;

	auto id = data->BeginUndoActions();
	data->SetFunctionAnalysisUpdateDisabled(true);
	size_t count = RemoveTrackedSymbolsLocked(data, symbols);
	data->SetFunctionAnalysisUpdateDisabled(false);
	data->ForgetUndoActions(id);
	// Flush the undefines to the views (mirrors the load path); otherwise the removed symbols/data
	// variables linger in the views until a manual refresh.
	data->UpdateAnalysis();
	return count;
}


size_t DebuggerController::RemoveSymbolsForModule(const DebugModule& module)
{
	return RemoveSymbolsForModule(module.m_name.empty() ? module.m_short_name : module.m_name);
}


size_t DebuggerController::RemoveSymbolsForModule(const std::string& moduleName)
{
	std::lock_guard<std::recursive_mutex> lock(m_loadedModuleSymbolsMutex);
	for (auto it = m_loadedModuleSymbols.begin(); it != m_loadedModuleSymbols.end(); ++it)
	{
		if (DebugModule::IsSameBaseModule(it->first, moduleName))
		{
			size_t count = UndefineTrackedSymbols(it->second);
			m_loadedModuleSymbols.erase(it);
			return count;
		}
	}
	return 0;
}


size_t DebuggerController::RemoveAllLoadedSymbols(bool updateAnalysis)
{
	std::lock_guard<std::recursive_mutex> lock(m_loadedModuleSymbolsMutex);

	auto data = GetData();
	if (!data)
	{
		// The view is already gone (e.g. shutdown); there is nothing to undefine, just drop our tracking.
		m_loadedModuleSymbols.clear();
		return 0;
	}

	// Remove every module's symbols inside one analysis-update window, for the same reason the load path
	// batches them (see LoadSymbolsForAllModules).
	auto id = data->BeginUndoActions();
	data->SetFunctionAnalysisUpdateDisabled(true);
	size_t count = 0;
	for (auto& [key, symbols] : m_loadedModuleSymbols)
		count += RemoveTrackedSymbolsLocked(data, symbols);
	data->SetFunctionAnalysisUpdateDisabled(false);
	data->ForgetUndoActions(id);
	// Flush the undefines to the views so they update without a manual refresh. The teardown caller
	// (FinalizeTargetGoneCleanup) passes updateAnalysis = false: it is about to remove the debugger memory
	// region, and scheduling an async analysis pass here could trigger a linear-view read against memory
	// that is being torn down (see the ordering note in FinalizeTargetGoneCleanup).
	if (updateAnalysis)
		data->UpdateAnalysis();

	m_loadedModuleSymbols.clear();
	return count;
}


std::vector<std::string> DebuggerController::GetModulesWithLoadedSymbols()
{
	std::lock_guard<std::recursive_mutex> lock(m_loadedModuleSymbolsMutex);
	std::vector<std::string> result;
	result.reserve(m_loadedModuleSymbols.size());
	for (const auto& [key, symbols] : m_loadedModuleSymbols)
		result.push_back(key);
	return result;
}


size_t DebuggerController::GetLoadedSymbolCountForModule(const std::string& module)
{
	std::lock_guard<std::recursive_mutex> lock(m_loadedModuleSymbolsMutex);
	for (const auto& [key, symbols] : m_loadedModuleSymbols)
	{
		if (DebugModule::IsSameBaseModule(key, module))
			return symbols.size();
	}
	return 0;
}


std::vector<DebugProcess> DebuggerController::GetProcessList()
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return {};
	}

	return m_adapter->GetProcessList();
}


std::vector<DebugThread> DebuggerController::GetAllThreads()
{
	return m_state->GetThreads()->GetAllThreads();
}


std::vector<DebugRegister> DebuggerController::GetAllRegisters()
{
	return m_state->GetRegisters()->GetAllRegisters();
}


intx::uint512 DebuggerController::GetRegisterValue(const std::string& name)
{
	return m_state->GetRegisters()->GetRegisterValue(name);
}


bool DebuggerController::SetRegisterValue(const std::string& name, intx::uint512 value)
{
	return m_state->GetRegisters()->SetRegisterValue(name, value);
}


DebugAdapterTargetStatus DebuggerController::GetExecutionStatus()
{
	return m_state->GetTargetStatus();
}


DebugAdapterConnectionStatus DebuggerController::GetConnectionStatus()
{
	return m_state->GetConnectionStatus();
}


ArchitectureRef DebuggerController::GetRemoteArchitecture()
{
	return m_state->GetRemoteArchitecture();
}


uint32_t DebuggerController::GetExitCode()
{
	return m_exitCode;
}


uint32_t DebuggerController::GetActivePID()
{
	if (!m_adapter)
		return 0;
	return m_adapter->GetActivePID();
}


void DebuggerController::WriteStdIn(const std::string message)
{
	if (m_adapter && m_state->IsRunning())
	{
		m_adapter->WriteStdin(message);
	}
	else
	{
		NotifyError("Cannot send to stdin, target is not running", "Cannot send to stdin, target is not running");
	}
}


std::string DebuggerController::InvokeBackendCommand(const std::string& cmd)
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return "Error: invalid adapter\n";
	}

	if (m_adapter)
	{
		std::string cmdToSend = cmd;
		if (cmdToSend.empty())
			cmdToSend = m_lastCommand;
		else
			m_lastCommand = cmdToSend;

		return m_adapter->InvokeBackendCommand(cmdToSend);
	}

	return "Error: invalid adapter\n";
}


void DebuggerController::ProcessOneVariable(uint64_t varAddress, Confidence<Ref<Type>> type, const std::string& name)
{
	StackVariableNameAndType varNameAndType(type, name);
	auto iter = m_debuggerVariables.find(varAddress);
	if ((iter == m_debuggerVariables.end()) || (iter->second != varNameAndType))
	{
		// The variable is not yet defined, or has changed. Define it.
		// Should we use DataVariable, or UserDataVariable?
		GetData()->DefineDataVariable(varAddress, type);
		if (!name.empty())
		{
			SymbolRef sym = new BinaryNinja::Symbol(DataSymbol, name, name, name, varAddress);
			GetData()->DefineUserSymbol(sym);
		}
		m_debuggerVariables[varAddress] = varNameAndType;
	}

	m_addressesWithVariable.insert(varAddress);

	// If there is still a data variable at varAddress, we remove it from the oldAddresses set.
	// After we process all data variables, values in the set oldAddresses means where there was a data var,
	// but there no longer should be one. Later we iterate over it and remove all data vars and symbols at
	// these addresses.
	auto iter2 = m_oldAddresses.find(varAddress);
	if (iter2 != m_oldAddresses.end())
		m_oldAddresses.erase(iter2);
}


void DebuggerController::DefineVariablesRecursive(uint64_t address, Confidence<Ref<Type>> type)
{
	size_t addressSize = GetData()->GetAddressSize();
	if (type->IsPointer())
	{
		auto reader = BinaryReader(GetData());
		reader.Seek(address);
		uint64_t targetAddress = 0;
		bool readOk = false;
		if (addressSize == 8)
		{
			readOk = reader.TryRead64(targetAddress);
		}
		else if (addressSize == 4)
		{
			uint32_t addr;
			readOk = reader.TryRead32(addr);
			if (readOk)
				targetAddress = addr;
		}
		if (readOk)
		{
			// Define a data variable for the child
			ProcessOneVariable(targetAddress, type->GetChildType(), "");
			// Recurse into the child
			DefineVariablesRecursive(targetAddress, type->GetChildType());
		}
	}
	else if (type->IsStructure())
	{
		auto structure = type->GetStructure();
		auto members = structure->GetMembers();
		auto memberType = type->GetChildType();
		for (size_t i = 0; i < members.size(); i++)
		{
			uint64_t memberOffset = address + members[i].offset;
			DefineVariablesRecursive(memberOffset, members[i].type);
		}
	}
	else if (type->IsArray())
	{
		auto memberType = type->GetChildType();
		for (size_t i = 0; i < type->GetElementCount(); i++)
		{
			uint64_t memberOffset = address + i * memberType->GetWidth();
			DefineVariablesRecursive(memberOffset, memberType);
		}
	}
}


void DebuggerController::UpdateStackVariables()
{
	if (!m_shouldAnnotateStackVariable)
		return;

	if (!GetData())
		return;

	auto id = GetData()->BeginUndoActions();
	std::vector<DebugThread> threads = GetAllThreads();
	uint64_t frameAdjustment = 0;
	if (!GetData()->GetDefaultArchitecture())
		return;

	std::string archName = GetData()->GetDefaultArchitecture()->GetName();
	if ((archName == "x86") || (archName == "x86_64"))
		frameAdjustment = 8;

	m_oldAddresses = m_addressesWithVariable;
	m_addressesWithVariable.clear();
	auto oldAddressWithComment = m_addressesWithComment;
	m_addressesWithComment.clear();

	const DebugThread thread = GetActiveThread();
	std::vector<DebugFrame> frames = GetFramesOfThread(thread.m_tid);
	if (frames.size() >= 2)
	{
		for (size_t i = 0; i < frames.size() - 1; i++)
		{
			const DebugFrame& frame = frames[i];
			const DebugFrame& prevFrame = frames[i + 1];
			// If there is no function at a stacktrace function start, add one
			auto functions = GetData()->GetAnalysisFunctionsForAddress(frame.m_functionStart);
			if (functions.empty())
				continue;

			FunctionRef func = functions[0];

			auto vars = func->GetVariables();
			// BN's variable storage offset is calculated against the entry status of the function, i.e.,
			// before the current stack frame is created. Here we take the stack pointer of the previous stack frame,
			// and subtract the size of return address from it
			uint64_t framePointer = prevFrame.m_sp - frameAdjustment;
			for (const auto& [var, varNameAndType] : vars)
			{
				if (var.type != StackVariableSourceType)
					continue;

				uint64_t varAddress = framePointer + var.storage;
				ProcessOneVariable(varAddress, varNameAndType.type, varNameAndType.name);
				DefineVariablesRecursive(varAddress, varNameAndType.type);
			}
		}

		for (const DebugFrame& frame : frames)
		{
			// Annotate the stack pointer and the frame pointer, using the current stack frame
			GetData()->SetCommentForAddress(frame.m_sp, fmt::format("Stack #{}\n====================", frame.m_index));
			GetData()->SetCommentForAddress(frame.m_fp, fmt::format("Frame #{}", frame.m_index));
			m_addressesWithComment.insert(frame.m_sp);
			m_addressesWithComment.insert(frame.m_fp);

			auto iter2 = oldAddressWithComment.find(frame.m_sp);
			if (iter2 != oldAddressWithComment.end())
				oldAddressWithComment.erase(iter2);

			iter2 = oldAddressWithComment.find(frame.m_fp);
			if (iter2 != oldAddressWithComment.end())
				oldAddressWithComment.erase(iter2);
		}
	}

	for (uint64_t address : m_oldAddresses)
	{
		auto iter = m_addressesWithVariable.find(address);
		if (iter != m_addressesWithVariable.end())
			m_addressesWithVariable.erase(iter);

		GetData()->UndefineDataVariable(address);
		auto symbol = GetData()->GetSymbolByAddress(address);
		if (symbol)
			GetData()->UndefineUserSymbol(symbol);
	}

	for (uint64_t address : oldAddressWithComment)
	{
		GetData()->SetCommentForAddress(address, "");
	}
	GetData()->ForgetUndoActions(id);
}


void DebuggerController::AddRegisterValuesToExpressionParser()
{
	auto regs = GetAllRegisters();
	std::vector<std::string> names;
	names.reserve(regs.size());
	std::vector<uint64_t> values;
	values.reserve(regs.size());

	for (const auto& reg: regs)
	{
		names.push_back(std::string(reg.m_name));
		values.emplace_back(reg.m_value);
	}

	GetData()->AddExpressionParserMagicValues(names, values);
}


void DebuggerController::AddModuleValuesToExpressionParser()
{
	auto modules = GetAllModules();
	std::vector<std::string> names;
	std::vector<uint64_t> values;

	for (const auto& module : modules)
	{
		if (!module.m_short_name.empty())
		{
			names.push_back(module.m_short_name);
			values.push_back(module.m_address);
		}
	}

	GetData()->AddExpressionParserMagicValues(names, values);
}


bool DebuggerController::EvaluateBreakpointCondition(uint64_t address)
{
	const std::string condition = m_state->GetBreakpoints()->GetConditionAbsolute(address);
	if (condition.empty())
		return true;  // no condition means always break

	uint64_t result = 0;
	std::string errorString;

	if (const bool parseSuccess = BinaryView::ParseExpression(GetData(), condition, result, address, errorString);
		!parseSuccess)
	{
		LogWarn("Failed to parse breakpoint condition '%s' at 0x%" PRIx64 ": %s",
			condition.c_str(), address, errorString.c_str());
		return true;  // parse failure means break (don't silently continue)
	}

	return result != 0;  // non-zero means condition is true
}


std::string DebuggerController::GetStopReasonString(DebugStopReason reason)
{
	switch (reason)
	{
	case UnknownReason:
		return "UnknownReason";
	case InitialBreakpoint:
		return "InitialBreakpoint";
	case ProcessExited:
		return "ProcessExited";
	case AccessViolation:
		return "AccessViolation";
	case SingleStep:
		return "SingleStep";
	case Calculation:
		return "Calculation";
	case Breakpoint:
		return "Breakpoint";
	case IllegalInstruction:
		return "IllegalInstruction";
	case SignalHup:
		return "SignalHup";
	case SignalInt:
		return "SignalInt";
	case SignalQuit:
		return "SignalQuit";
	case SignalIll:
		return "SignalIll";
	case SignalAbrt:
		return "SignalAbrt";
	case SignalEmt:
		return "SignalEmt";
	case SignalFpe:
		return "SignalFpe";
	case SignalKill:
		return "SignalKill";
	case SignalBus:
		return "SignalBus";
	case SignalSegv:
		return "SignalSegv";
	case SignalSys:
		return "SignalSys";
	case SignalPipe:
		return "SignalPipe";
	case SignalAlrm:
		return "SignalAlrm";
	case SignalTerm:
		return "SignalTerm";
	case SignalUrg:
		return "SignalUrg";
	case SignalStop:
		return "SignalStop";
	case SignalTstp:
		return "SignalTstp";
	case SignalCont:
		return "SignalCont";
	case SignalChld:
		return "SignalChld";
	case SignalTtin:
		return "SignalTtin";
	case SignalTtou:
		return "SignalTtou";
	case SignalIo:
		return "SignalIo";
	case SignalXcpu:
		return "SignalXcpu";
	case SignalXfsz:
		return "SignalXfsz";
	case SignalVtalrm:
		return "SignalVtalrm";
	case SignalProf:
		return "SignalProf";
	case SignalWinch:
		return "SignalWinch";
	case SignalInfo:
		return "SignalInfo";
	case SignalUsr1:
		return "SignalUsr1";
	case SignalUsr2:
		return "SignalUsr2";
	case SignalStkflt:
		return "SignalStkflt";
	case SignalBux:
		return "SignalBux";
	case SignalPoll:
		return "SignalPoll";
	case ExcEmulation:
		return "ExcEmulation";
	case ExcSoftware:
		return "ExcSoftware";
	case ExcSyscall:
		return "ExcSyscall";
	case ExcMachSyscall:
		return "ExcMachSyscall";
	case ExcRpcAlert:
		return "ExcRpcAlert";
	case ExcCrash:
		return "ExcCrash";
	case InternalError:
		return "InternalError";
	case InvalidStatusOrOperation:
		return "InvalidStatusOrOperation";
	case UserRequestedBreak:
		return "UserRequestedBreak";
	case OperationNotSupported:
		return "OperationNotSupported";
	case TimedOut:
		return "TimedOut";
	default:
		return "";
	}
}


DebugStopReason DebuggerController::StopReason() const
{
	if (!m_adapter)
		return UnknownReason;

	return m_adapter->StopReason();
}


DebugStopReason DebuggerController::ExecuteAdapterAndWait(const DebugAdapterOperation operation)
{
	// Invariant: ExecuteAdapterAndWait only ever runs on m_workerThread. The worker queue
	// serializes all adapter operations, so the previous m_adapterMutex / m_adapterMutex2
	// pair (which guarded against concurrent adapter access from multiple spawned threads)
	// is no longer needed. The new Pause path bypasses this method entirely and calls
	// m_adapter->BreakInto() out-of-band; everything else funnels through here on the worker.
	BN_RELEASE_ASSERT(t_controllerOnWorker == this);

	// Claim the adapter-stop channel for the duration of this call. Any AdapterStoppedEvent
	// posted by the adapter from now until we clear m_inAdapterWait is delivered to
	// WaitForAdapterStop below, not treated as spontaneous. We hold this across the
	// entire silent-resume loop so that an adapter stop between iterations (after we
	// kick off m_adapter->Go() for a false breakpoint condition) is still consumed
	// by us, not synthesized as a spontaneous stop.
	{
		std::lock_guard lk(m_adapterStopMutex);
		m_inAdapterWait = true;
		m_adapterStopPending = std::nullopt;
	}

	m_lastOperation = operation;

	bool resumeOK = false;
	bool operationRequested = false;
	// Hold the adapter-access lock only around the resume REQUEST (these calls return
	// promptly; the actual wait for the stop happens below, lock-free, so Pause/BreakInto
	// can acquire the same lock while the target runs).
	std::unique_lock<std::recursive_mutex> adapterLock(m_state->AdapterAccessMutex());
	switch (operation)
	{
	case DebugAdapterGo:
		resumeOK = m_adapter->Go();
		break;
	case DebugAdapterGoReverse:
        resumeOK = m_adapter->GoReverse();
        break;
	case DebugAdapterStepInto:
		resumeOK = m_adapter->StepInto();
		break;
	case DebugAdapterStepIntoReverse:
        resumeOK = m_adapter->StepIntoReverse();
        break;
	case DebugAdapterStepOver:
		resumeOK = m_adapter->StepOver();
		break;
	case DebugAdapterStepOverReverse:
        resumeOK = m_adapter->StepOverReverse();
        break;
	case DebugAdapterStepReturn:
		resumeOK = m_adapter->StepReturn();
		break;
	case DebugAdapterStepReturnReverse:
		resumeOK = m_adapter->StepReturnReverse();
		break;
	case DebugAdapterPause:
		operationRequested = m_adapter->BreakInto();
		break;
	case DebugAdapterQuit:
		operationRequested = m_adapter->Quit();
		break;
	case DebugAdapterDetach:
		operationRequested = m_adapter->Detach();
		break;
	case DebugAdapterLaunch:
		resumeOK = Execute();
		break;
	case DebugAdapterAttach:
		resumeOK = m_adapter->Attach(m_state->GetPIDAttach());
		break;
	case DebugAdapterConnect:
		resumeOK = m_adapter->Connect(m_state->GetRemoteHost(), m_state->GetRemotePort());
		break;
	default:
		break;
	}
	// Resume request issued; drop the lock so the run-wait below is lock-free.
	adapterLock.unlock();

	bool ok = false;
	if ((operation == DebugAdapterGo) || (operation == DebugAdapterStepInto) || (operation == DebugAdapterStepOver)
		|| (operation == DebugAdapterStepReturn) || (operation == DebugAdapterLaunch)
		|| (operation == DebugAdapterConnect) || (operation == DebugAdapterAttach)
		|| (operation == DebugAdapterGoReverse) || (operation == DebugAdapterStepIntoReverse)
		|| (operation == DebugAdapterStepOverReverse) || (operation == DebugAdapterStepReturnReverse))
	{
		ok = resumeOK;
	}
	else if ((operation == DebugAdapterPause) || (operation == DebugAdapterQuit) || (operation == DebugAdapterDetach))
	{
		ok = operationRequested;
	}
	else
	{
		ok = true;
	}

	DebugStopReason reason = UnknownReason;
	if (!ok)
	{
		reason = InternalError;
	}
	else
	{
		// Loop: wait for the adapter to stop. If the stop is a breakpoint whose
		// condition evaluates to false (and the user didn't explicitly step or
		// request a break), silently resume and wait again. Otherwise return.
		while (true)
		{
			reason = WaitForAdapterStop();
			if (reason == ProcessExited || reason == InternalError)
				break;
			if (reason == Breakpoint && ShouldSilentResumeAfterStop())
			{
				m_state->SetExecutionStatus(DebugAdapterRunningStatus);
				bool resumed;
				{
					std::lock_guard<std::recursive_mutex> resumeLock(m_state->AdapterAccessMutex());
					resumed = m_adapter && m_adapter->Go();
				}
				if (!resumed)
				{
					reason = InternalError;
					break;
				}
				continue;
			}
			break;
		}
	}

	{
		std::lock_guard lk(m_adapterStopMutex);
		m_inAdapterWait = false;
		m_adapterStopPending = std::nullopt;
	}

	// The target is gone (process exit or detach -- both surface as ProcessExited). Run the
	// BN-core cleanup that ApplyOwnStateForEvent deliberately deferred. The adapter lock was
	// dropped above (before the run-wait), so we are NOT holding it across these file-lock-taking
	// calls -- this is what avoids the AB-BA deadlock with the analysis read path. Running it here,
	// on the worker before we return, keeps the caller's post-wait view fully finalized.
	if (reason == ProcessExited)
		FinalizeTargetGoneCleanup();

	return reason;
}


Ref<Metadata> DebuggerController::GetAdapterProperty(const std::string& name)
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return nullptr;

		if (!m_adapter)
			return nullptr;
	}

	return m_adapter->GetProperty(name);
}


bool DebuggerController::SetAdapterProperty(
	const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value)
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return false;

		if (!m_adapter)
			return false;
	}

	return m_adapter->SetProperty(name, value);
}


bool DebuggerController::ActivateDebugAdapter()
{
	return CreateDebugAdapter();
}


static inline bool IsPrintableChar(uint8_t c)
{
	return (c == '\r') || (c == '\n') || (c == '\t') || ((c >= 0x20) && (c <= 0x7e));
}


static std::string CheckForASCIIString(const DataBuffer& memory)
{
	std::string result;
	size_t i = 0;
	while (true)
	{
		if (i > memory.GetLength() - 1)
			break;
		if (IsPrintableChar(memory[i]))
		{
			result += memory[i];
			i++;
		}
		else
		{
			break;
		}
	}

	if (result.length() >= 4)
		return result;
	else
		return "";
}


static std::string CheckForUTF16String(const DataBuffer& memory)
{
	std::string result;
	size_t i = 0;
	while (true)
	{
		if (i > memory.GetLength() - 2)
			break;
		if (IsPrintableChar(memory[i]) && (memory[i + 1] == 0))
		{
			result += memory[i];
			i += 2;
		}
		else
		{
			break;
		}
	}

	if (result.length() >= 4)
		return result;
	else
		return "";
}


static std::string CheckForUTF32String(const DataBuffer& memory)
{
	std::string result;
	size_t i = 0;
	while (true)
	{
		if (i > memory.GetLength() - 4)
			break;
		if (IsPrintableChar(memory[i]) && (memory[i + 1] == 0) && (memory[i + 2] == 0) && (memory[i + 3] == 0))
		{
			result += memory[i];
			i += 4;
		}
		else
		{
			break;
		}
	}

	if (result.length() >= 4)
		return result;
	else
		return "";
}


static std::string CheckForPrintableString(const DataBuffer& memory)
{
	std::string result;
	result = CheckForASCIIString(memory);
	if (!result.empty())
		return fmt::format("\"{}\"", BinaryNinja::EscapeString(result));

	result = CheckForUTF16String(memory);
	if (!result.empty())
		return fmt::format("L\"{}\"", BinaryNinja::EscapeString(result));;

	result = CheckForUTF32String(memory);
	if (!result.empty())
		return fmt::format("L\"{}\"", BinaryNinja::EscapeString(result));;

	return "";
}


static std::string CheckForLiteralString(intx::uint512 value)
{
	bool ok = true;
	bool zeroFound = false;
	std::string result;
	for (size_t i = 0; i < 64; i++)
	{
		uint8_t c = (uint8_t)(value >> (8 * i)) & 0xff;
		if (IsPrintableChar(c) && (!zeroFound))
		{
			// Add the new char at the end to account for little-endianness
			result += c;
		}
		else if (c == 0)
		{
			// Skip 0x0 (e.g., for unicode strings)
			zeroFound = true;
		}
		else if (c != 0)
		{
			ok = false;
			break;
		}
	}

	if (ok)
		return fmt::format("'{}'", BinaryNinja::EscapeString(result));

	return "";
}


std::string DebuggerController::GetAddressInformation(intx::uint512 value)
{
	// Avoid too many results in the register widget when the address is 0x0
	if (value == 0)
		return "";

	// For the first few things, they still need an address to work with
	uint64_t address = (uint64_t)value;

	const DataBuffer memory = ReadMemory(address, 128);
	auto result = CheckForPrintableString(memory);
	// If we can find a string at the address, return it
	if (!result.empty())
		return result;

	// Check pointer to strings
	auto buffer = GetData()->ReadBuffer(address, GetData()->GetAddressSize());
	if (buffer.GetLength() == GetData()->GetAddressSize())
	{
		uint64_t pointerValue = *reinterpret_cast<std::uintptr_t*>(buffer.GetData());
		if (pointerValue != 0)
		{
			const DataBuffer pointerMemory = ReadMemory(pointerValue, 128);
			result = CheckForPrintableString(pointerMemory);
			if (!result.empty())
				return std::string("&") + result;
		}
	}


	// Look for functions starting at the address
	auto func = GetData()->GetAnalysisFunction(GetData()->GetDefaultPlatform(), address);
	if (func)
	{
		auto sym = func->GetSymbol();
		if (sym)
			return sym->GetShortName();
	}

	// Look for functions containing the address
	for (const auto& func: GetData()->GetAnalysisFunctionsContainingAddress(address))
	{
		auto sym = func->GetSymbol();
		if (sym)
		{
			return fmt::format("{} + 0x{:x}", sym->GetShortName(), address - func->GetStart());
		}
	}

	// Look for symbols
	auto sym = GetData()->GetSymbolByAddress(address);
	if (sym)
	{
		return sym->GetShortName();
	}

	//	Look for data variables
	DataVariable var;
	if (GetData()->GetDataVariableAtAddress(address, var))
	{
		sym = GetData()->GetSymbolByAddress(var.address);
		if (sym)
		{
			return fmt::format("{} + 0x{:x}", sym->GetShortName(), address - var.address);
		}
		else
		{
			result = fmt::format("data_{:x}", var.address);
			if (address != var.address)
				result += fmt::format(" + 0x{:x}", address - var.address);
			return result;
		}
	}

	// Check if the address itself is a printable string, e.g., 0x61626364 ==> "abcd"
	result = CheckForLiteralString(value);
	if (!result.empty())
		return result;

	return "";
}


bool DebuggerController::IsFirstLaunch()
{
	return m_firstLaunch;
}


bool DebuggerController::IsFirstConnect()
{
	return m_firstConnect;
}


bool DebuggerController::IsFirstConnectToDebugServer()
{
	return m_firstConnectToDebugServer;
}


bool DebuggerController::IsFirstAttach()
{
	return m_firstAttach;
}


bool DebuggerController::IsTTD()
{
	if(!m_adapter)
		return false;
	return m_adapter->SupportFeature(DebugAdapterSupportTTD);
}


std::vector<TTDMemoryEvent> DebuggerController::GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType)
{
	std::vector<TTDMemoryEvent> events;

	if (!m_state->IsConnected() || !IsTTD())
	{
		LogError("Current adapter does not support TTD");
		return events;
	}

	if (m_adapter)
	{
		events = m_adapter->GetTTDMemoryAccessForAddress(startAddress, endAddress, accessType);
	}

	return events;
}

std::vector<TTDPositionRangeIndexedMemoryEvent> DebuggerController::GetTTDMemoryAccessForPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, const TTDPosition startTime, const TTDPosition endTime)
{
	std::vector<TTDPositionRangeIndexedMemoryEvent> events;

	if (!m_state->IsConnected() || !IsTTD())
	{
		LogError("Current adapter does not support TTD");
		return events;
	}

	if (m_adapter)
	{
		events = m_adapter->GetTTDMemoryAccessForPositionRange(startAddress, endAddress, accessType, startTime, endTime);
	}

	return events;
}

std::vector<TTDCallEvent> DebuggerController::GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress)
{
	std::vector<TTDCallEvent> events;

	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return events;
	}

	return m_adapter->GetTTDCallsForSymbols(symbols, startReturnAddress, endReturnAddress);
}


std::vector<TTDEvent> DebuggerController::GetTTDEvents(TTDEventType eventType)
{
	std::vector<TTDEvent> events;

	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return events;
	}

	return m_adapter->GetTTDEvents(eventType);
}


std::vector<TTDEvent> DebuggerController::GetAllTTDEvents()
{
	std::vector<TTDEvent> events;

	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return events;
	}

	return m_adapter->GetAllTTDEvents();
}


void DebuggerController::RecordTTDPosition()
{
	if (!m_adapter || !m_adapter->SupportFeature(DebugAdapterSupportTTD) || m_suppressTTDPositionRecording)
		return;

	TTDPosition position = m_adapter->GetCurrentTTDPosition();
	if (position.sequence == 0 && position.step == 0)
		return;

	// If we're not at the end of the history (i.e., the user navigated back and then did something new),
	// truncate the forward history
	if (m_ttdPositionHistoryIndex >= 0
		&& m_ttdPositionHistoryIndex < static_cast<int>(m_ttdPositionHistory.size()) - 1)
	{
		m_ttdPositionHistory.resize(m_ttdPositionHistoryIndex + 1);
	}

	// Don't record duplicates
	if (!m_ttdPositionHistory.empty() && m_ttdPositionHistory.back() == position)
		return;

	m_ttdPositionHistory.push_back(position);
	m_ttdPositionHistoryIndex = static_cast<int>(m_ttdPositionHistory.size()) - 1;
}


bool DebuggerController::TTDNavigateBack()
{
	if (!CanTTDNavigateBack())
		return false;

	m_ttdPositionHistoryIndex--;
	m_suppressTTDPositionRecording = true;
	bool result = SetTTDPosition(m_ttdPositionHistory[m_ttdPositionHistoryIndex]);
	m_suppressTTDPositionRecording = false;
	return result;
}


bool DebuggerController::TTDNavigateForward()
{
	if (!CanTTDNavigateForward())
		return false;

	m_ttdPositionHistoryIndex++;
	m_suppressTTDPositionRecording = true;
	bool result = SetTTDPosition(m_ttdPositionHistory[m_ttdPositionHistoryIndex]);
	m_suppressTTDPositionRecording = false;
	return result;
}


bool DebuggerController::CanTTDNavigateBack() const
{
	return m_adapter && m_adapter->SupportFeature(DebugAdapterSupportTTD) && m_ttdPositionHistoryIndex > 0;
}


bool DebuggerController::CanTTDNavigateForward() const
{
	return m_adapter && m_adapter->SupportFeature(DebugAdapterSupportTTD)
		&& m_ttdPositionHistoryIndex >= 0
		&& m_ttdPositionHistoryIndex < static_cast<int>(m_ttdPositionHistory.size()) - 1;
}


void DebuggerController::ClearTTDPositionHistory()
{
	m_ttdPositionHistory.clear();
	m_ttdPositionHistoryIndex = -1;
}


TTDPosition DebuggerController::GetCurrentTTDPosition()
{
	TTDPosition position;

	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return position;
	}

	if (m_adapter)
	{
		position = m_adapter->GetCurrentTTDPosition();
	}

	return position;
}

bool DebuggerController::SetTTDPosition(const TTDPosition& position)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return false;
	}

	if (m_adapter)
	{
		return m_adapter->SetTTDPosition(position);
	}

	return false;
}


std::pair<bool, TTDMemoryEvent> DebuggerController::GetTTDNextMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return {false, TTDMemoryEvent()};
	}

	if (m_adapter)
	{
		return m_adapter->GetTTDNextMemoryAccess(address, size, accessType);
	}

	return {false, TTDMemoryEvent()};
}


std::pair<bool, TTDMemoryEvent> DebuggerController::GetTTDPrevMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return {false, TTDMemoryEvent()};
	}

	if (m_adapter)
	{
		return m_adapter->GetTTDPrevMemoryAccess(address, size, accessType);
	}

	return {false, TTDMemoryEvent()};
}


std::pair<bool, TTDRegisterWriteEvent> DebuggerController::GetTTDNextRegisterWrite(const std::string& reg)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return {false, TTDRegisterWriteEvent()};
	}

	if (m_adapter)
	{
		return m_adapter->GetTTDNextRegisterWrite(reg);
	}

	return {false, TTDRegisterWriteEvent()};
}


std::pair<bool, TTDRegisterWriteEvent> DebuggerController::GetTTDPrevRegisterWrite(const std::string& reg)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return {false, TTDRegisterWriteEvent()};
	}

	if (m_adapter)
	{
		return m_adapter->GetTTDPrevRegisterWrite(reg);
	}

	return {false, TTDRegisterWriteEvent()};
}


static const char* TTD_BOOKMARKS_METADATA_KEY = "debugger.ttd_bookmarks";

std::vector<TTDBookmark> DebuggerController::GetTTDBookmarks()
{
	std::vector<TTDBookmark> result;
	auto data = GetData();
	if (!data)
		return result;

	Ref<Metadata> metadata = data->QueryMetadata(TTD_BOOKMARKS_METADATA_KEY);
	if (!metadata || !metadata->IsArray())
		return result;

	for (auto& element : metadata->GetArray())
	{
		if (!element || !element->IsKeyValueStore())
			continue;

		auto info = element->GetKeyValueStore();
		TTDBookmark bookmark;

		if (info.count("sequence") && info["sequence"]->IsUnsignedInteger())
			bookmark.position.sequence = info["sequence"]->GetUnsignedInteger();
		else
			continue;

		if (info.count("step") && info["step"]->IsUnsignedInteger())
			bookmark.position.step = info["step"]->GetUnsignedInteger();
		else
			continue;

		if (info.count("view_address") && info["view_address"]->IsUnsignedInteger())
			bookmark.viewAddress = info["view_address"]->GetUnsignedInteger();

		if (info.count("note") && info["note"]->IsString())
			bookmark.note = info["note"]->GetString();

		result.push_back(bookmark);
	}
	return result;
}

static void SaveBookmarks(BinaryViewRef data, const std::vector<TTDBookmark>& bookmarks)
{
	std::vector<Ref<Metadata>> arr;
	for (const auto& bm : bookmarks)
	{
		std::map<std::string, Ref<Metadata>> info;
		info["sequence"] = new Metadata(bm.position.sequence);
		info["step"] = new Metadata(bm.position.step);
		info["view_address"] = new Metadata(bm.viewAddress);
		info["note"] = new Metadata(bm.note);
		arr.push_back(new Metadata(info));
	}
	data->StoreMetadata(TTD_BOOKMARKS_METADATA_KEY, new Metadata(arr));
}

bool DebuggerController::AddTTDBookmark(const TTDPosition& position, const std::string& note, uint64_t viewAddress)
{
	auto data = GetData();
	if (!data)
		return false;

	auto bookmarks = GetTTDBookmarks();

	// Deduplicate by position
	for (auto& bm : bookmarks)
	{
		if (bm.position == position)
		{
			bm.note = note;
			bm.viewAddress = viewAddress;
			SaveBookmarks(data, bookmarks);

			DebuggerEvent event;
			event.type = TTDBookmarkChangedEvent;
			PostDebuggerEvent(event);
			return true;
		}
	}

	bookmarks.emplace_back(position, note, viewAddress);
	SaveBookmarks(data, bookmarks);

	DebuggerEvent event;
	event.type = TTDBookmarkChangedEvent;
	PostDebuggerEvent(event);
	return true;
}

bool DebuggerController::RemoveTTDBookmark(const TTDPosition& position)
{
	auto data = GetData();
	if (!data)
		return false;

	auto bookmarks = GetTTDBookmarks();
	auto it = std::remove_if(bookmarks.begin(), bookmarks.end(),
		[&](const TTDBookmark& bm) { return bm.position == position; });

	if (it == bookmarks.end())
		return false;

	bookmarks.erase(it, bookmarks.end());
	SaveBookmarks(data, bookmarks);

	DebuggerEvent event;
	event.type = TTDBookmarkChangedEvent;
	PostDebuggerEvent(event);
	return true;
}

bool DebuggerController::UpdateTTDBookmark(const TTDPosition& position, const std::string& note, uint64_t viewAddress)
{
	auto data = GetData();
	if (!data)
		return false;

	auto bookmarks = GetTTDBookmarks();
	for (auto& bm : bookmarks)
	{
		if (bm.position == position)
		{
			bm.note = note;
			bm.viewAddress = viewAddress;
			SaveBookmarks(data, bookmarks);

			DebuggerEvent event;
			event.type = TTDBookmarkChangedEvent;
			PostDebuggerEvent(event);
			return true;
		}
	}
	return false;
}

void DebuggerController::ClearTTDBookmarks()
{
	auto data = GetData();
	if (!data)
		return;

	data->StoreMetadata(TTD_BOOKMARKS_METADATA_KEY, new Metadata(std::vector<Ref<Metadata>>()));

	DebuggerEvent event;
	event.type = TTDBookmarkChangedEvent;
	PostDebuggerEvent(event);
}


bool DebuggerController::IsInstructionExecuted(uint64_t address)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		return false;
	}

	if (!m_codeCoverageAnalysisRun)
	{
		return false;
	}

	return m_executedInstructionCounts.find(address) != m_executedInstructionCounts.end();
}

size_t DebuggerController::GetInstructionExecutionCount(uint64_t address)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		return 0;
	}

	if (!m_codeCoverageAnalysisRun)
	{
		return 0;
	}

	auto iter = m_executedInstructionCounts.find(address);
	if (iter != m_executedInstructionCounts.end())
	{
		return iter->second;
	}
	return 0;
}


bool DebuggerController::RunCodeCoverageAnalysis(uint64_t startAddress, uint64_t endAddress, TTDPosition startTime, TTDPosition endTime)
{
	if (!m_state->IsConnected() || !IsTTD())
	{
		LogWarn("Current adapter does not support TTD");
		return false;
	}

	if (startAddress >= endAddress)
	{
		LogError("Invalid address range: start address must be less than end address");
		return false;
	}

	// Clear previous analysis results
	m_executedInstructionCounts.clear();
	m_codeCoverageAnalysisRun = false;
	
	LogInfo("Starting TTD code coverage analysis.");
	LogInfo("\tAddress range: 0x%" PRIX64 " - 0x%" PRIX64, startAddress, endAddress);
	//log time range
	bool endTimeIsMax = endTime.sequence== std::numeric_limits<uint64_t>::max() && endTime.step == std::numeric_limits<uint64_t>::max();
	if(endTimeIsMax)
	{
		LogInfo("\tTime range:  %" PRIX64 ":%" PRIX64 " - end of trace", startTime.sequence, startTime.step);
	}
	else{
		LogInfo("\tTime range:  %" PRIX64 ":%" PRIX64 " - %" PRIX64 ":%" PRIX64, startTime.sequence, startTime.step,
			endTime.sequence, endTime.step);
	}
	
	// Query TTD for execute access covering the specified range
	auto events = GetTTDMemoryAccessForPositionRange(startAddress, endAddress, TTDMemoryExecute, startTime, endTime);

	for (const auto& event : events)
	{
		if (event.accessType == TTDMemoryExecute)
		{
			// Add all executed instruction addresses within the range
			if (event.instructionAddress >= startAddress && event.instructionAddress <= endAddress)
			{
				m_executedInstructionCounts[event.instructionAddress]++;
			}
		}
	}

	m_codeCoverageAnalysisRun = true;
	LogInfo("TTD code coverage analysis completed for ranges. Found %" PRIu64 " executed instructions.",
			(uint64_t)m_executedInstructionCounts.size());

	return true;
}


size_t DebuggerController::GetExecutedInstructionCount() const
{
	return m_executedInstructionCounts.size();
}


bool DebuggerController::SaveCodeCoverageToFile(const std::string& filePath) const
{
	if (!m_codeCoverageAnalysisRun)
	{
		LogError("No code coverage analysis has been run");
		return false;
	}

	try
	{
		std::ofstream file(filePath, std::ios::binary);
		if (!file.is_open())
		{
			LogError("%s", fmt::format("Failed to open file for writing: {}", filePath.c_str()).c_str());
			return false;
		}

		// Write header
		uint32_t magic = 0x54544443; // "TTDC" - TTD Coverage
		uint32_t version = 2;
		size_t count = m_executedInstructionCounts.size();

		file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
		file.write(reinterpret_cast<const char*>(&version), sizeof(version));
		file.write(reinterpret_cast<const char*>(&count), sizeof(count));

		// Write addresses and execution counts in pairs
		for (const auto& [addr, execCount] : m_executedInstructionCounts)
		{
			file.write(reinterpret_cast<const char*>(&addr), sizeof(addr));
			file.write(reinterpret_cast<const char*>(&execCount), sizeof(execCount));
		}

		file.close();
		LogInfo("%s", fmt::format("Saved {} executed instruction addresses to {}", count, filePath.c_str()).c_str());

		return true;
	}
	catch (const std::exception& e)
	{
		LogError("%s", fmt::format("Error saving code coverage: {}", e.what()).c_str());
		return false;
	}
}


bool DebuggerController::LoadCodeCoverageFromFile(const std::string& filePath)
{
	try
	{
		std::ifstream file(filePath, std::ios::binary);
		if (!file.is_open())
		{
			LogError("%s", fmt::format("Failed to open file for reading: {}", filePath.c_str()).c_str());
			return false;
		}

		// Read header
		uint32_t magic, version;
		size_t count;

		file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
		if (magic != 0x54544443)
		{
			LogError("Invalid file format (magic number mismatch)");
			return false;
		}

		file.read(reinterpret_cast<char*>(&version), sizeof(version));
		if (version != 1 && version != 2)
		{
			LogError("%s", fmt::format("Unsupported file version: {}", version).c_str());
			return false;
		}

		file.read(reinterpret_cast<char*>(&count), sizeof(count));

		// Clear existing data
		m_executedInstructionCounts.clear();

		// Read executed instruction addresses according to version
		if (version == 1)
		{
			// Version 1 files don't have execution counts, so assume count = 1 for backward compatibility
			for (size_t i = 0; i < count; i++)
			{
				uint64_t addr;
				file.read(reinterpret_cast<char*>(&addr), sizeof(addr));
				m_executedInstructionCounts[addr] = 1;
			}
		}
		else if (version > 1)
		{
			for (size_t i = 0; i < count; i++)
			{
				uint64_t addr;
				uint32_t execCount;
				file.read(reinterpret_cast<char*>(&addr), sizeof(addr));
				file.read(reinterpret_cast<char*>(&execCount), sizeof(execCount));
				m_executedInstructionCounts[addr] = execCount;
			}
		}

		file.close();
		m_codeCoverageAnalysisRun = true;

		LogInfo("%s", fmt::format("Loaded {} executed instruction addresses from {}", count, filePath.c_str()).c_str());
		return true;
	}
	catch (const std::exception& e)
	{
		LogError("%s", fmt::format("Error loading code coverage: {}", e.what()).c_str());
		return false;
	}
}


void DebuggerController::OnRebased(BinaryView* oldView, BinaryView* newView)
{
	m_data = newView;
	m_viewStart = newView->GetStart();
	// UnregisterNotification() is not designed to be called from one of the callbacks, so we cannot call it
	// here. Also, there is no need to do so -- the oldView is about to be deleted
	// oldView->UnregisterNotification(this);
	newView->RegisterNotification(this);
	m_state->GetMemory()->OnRebased();
}


bool DebuggerController::RemoveDebuggerMemoryRegion()
{
	GetData()->SetFunctionAnalysisUpdateDisabled(true);
	auto ret = GetData()->GetMemoryMap()->RemoveMemoryRegion("debugger");
	GetData()->SetFunctionAnalysisUpdateDisabled(false);
	return ret;
}


bool DebuggerController::ReAddDebuggerMemoryRegion()
{
	GetData()->SetFunctionAnalysisUpdateDisabled(true);
	auto ret = GetData()->GetMemoryMap()->AddRemoteMemoryRegion("debugger", 0, GetMemoryAccessor());
	GetData()->SetFunctionAnalysisUpdateDisabled(false);
	return ret;
}


// TODO: these 3 functions should be moved to the BinaryNinjaAPI namespace for wider audiences
static intx::uint512 MaskToSize(intx::uint512 value, size_t size)
{
	if (size >= 64)
		return value;
	if (size == 0)
		return value & 1;
	return value & ((intx::uint512(1) << (size * 8)) - 1);
}


static intx::uint512 ZeroExtend(intx::uint512 value, size_t sourceSize, size_t destSize)
{
	if (destSize <= sourceSize)
		return MaskToSize(value, destSize);
	return MaskToSize(value & ((intx::uint512(1) << (sourceSize * 8)) - 1), destSize);
}


static intx::uint512 SignExtend(intx::uint512 value, size_t sourceSize, size_t destSize)
{
	if (destSize <= sourceSize)
		return MaskToSize(value, destSize);
	if (value & (1LL << ((sourceSize * 8) - 1)))
		return MaskToSize(value | (~((intx::uint512(1) << (sourceSize * 8)) - 1)), destSize);
	else
		return MaskToSize(value & ((intx::uint512(1) << (sourceSize * 8)) - 1), destSize);
}


static inline intx::uint512 GetActualShift(intx::uint512 value, size_t instrSize)
{
	if (instrSize <= 4)
		return value & 0b11111;
	else
		return value & 0b111111;
}


bool DebuggerController::ComputeExprValueAPI(const BinaryNinja::LowLevelILInstruction &instr, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return ComputeExprValue(instr, value);
}


bool DebuggerController::ComputeExprValue(const LowLevelILInstruction &instr, intx::uint512& value)
{
	if (instr.size > 64)
		return false;

	intx::uint512 left, right;
	intx::uint512 sizeMask = (intx::uint512(1) << (instr.size * 8)) - 1;

	switch (instr.operation)
	{
	case LLIL_CONST:
		value = instr.GetConstant<LLIL_CONST>() & sizeMask;
		return true;
	case LLIL_CONST_PTR:
		value = instr.GetConstant<LLIL_CONST_PTR>() & sizeMask;
		return true;
	case LLIL_FLOAT_CONST:
		value = instr.GetConstant<LLIL_FLOAT_CONST>() & sizeMask;
		return true;
	case LLIL_REG:
	{
		auto reg = instr.GetSourceRegister<LLIL_REG>();
		if (LLIL_REG_IS_TEMP(reg))
			return false;

		auto name = GetData()->GetDefaultArchitecture()->GetRegisterName(reg);
		// TODO: what if the name reported by the adapter is different from that in the architecture?
		// GetRegisterValue should return if the value can be retrieved

		// Cheat for arm64
		if (name == "x29") name = "fp";

		value = GetRegisterValue(name) & sizeMask;
		return true;
	}
	case LLIL_ADD:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_ADD>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_ADD>(), right))
			return false;
		value = left + right;
		value &= sizeMask;
		return true;
	case LLIL_SUB:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_SUB>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_SUB>(), right))
			return false;
		value = left - right;
		value &= sizeMask;
		return true;
	case LLIL_LOAD:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_LOAD>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case LLIL_STORE:
	{
		if (!ComputeExprValue(instr.GetDestExpr<LLIL_STORE>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case LLIL_LSL:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_LSL>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_LSL>(), right))
			return false;
		value = left << GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case LLIL_LSR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_LSR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_LSR>(), right))
			return false;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case LLIL_ASR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_ASR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_ASR>(), right))
			return false;
		if (left & (1LL << ((instr.size * 8) - 1)))
			left |= ~sizeMask;
		else
			left &= sizeMask;
		value = ((int64_t)left) >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case LLIL_XOR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_XOR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_XOR>(), right))
			return false;
		value = left ^ right;
		value &= sizeMask;
		return true;
	}
	case LLIL_AND:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_AND>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_AND>(), right))
			return false;
		value = left & right;
		value &= sizeMask;
		return true;
	}
	case LLIL_OR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_OR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_OR>(), right))
			return false;
		value = left | right;
		value &= sizeMask;
		return true;
	}
	case LLIL_NEG:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_NEG>(), left))
			return false;
		value = -left;
		value &= sizeMask;
		return true;
	}
	case LLIL_NOT:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_NOT>(), left))
			return false;
		value = ~left;
		value &= sizeMask;
		return true;
	}
	case LLIL_SX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_SX>(), left))
			return false;
		value = SignExtend(left, instr.GetSourceExpr<LLIL_SX>().size, instr.size);
		return true;
	}
	case LLIL_ZX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_ZX>(), left))
			return false;
		value = ZeroExtend(left, instr.GetSourceExpr<LLIL_ZX>().size, instr.size);
		return true;
	}
	case LLIL_PUSH:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_PUSH>(), left))
			return false;
		value &= sizeMask;
		return true;
	}
	case LLIL_POP:
	case LLIL_RET:
	{
		auto stackPointer = GetState()->StackPointer();
		auto buffer = ReadMemory(stackPointer, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case LLIL_CMP_E:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_E>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_E>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_NE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_NE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_NE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SLT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SLT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SLT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_ULT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_ULT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_ULT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SLE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SLE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SLE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_ULE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_ULE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_ULE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SGE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_UGE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_UGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_UGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SGT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_UGT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_UGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_UGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	default:
		break;
	}
	return false;
}


intx::uint512 DebuggerController::GetValueFromComparison(const BNLowLevelILOperation op, intx::uint512 left,
	intx::uint512 right, size_t size)
{
	switch (op)
	{
		case LLIL_CMP_E:
			return left == right;
			break;
		case LLIL_CMP_NE:
			return left != right;
			break;
		case LLIL_CMP_SLT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b);
			break;
		}
		case LLIL_CMP_ULT:
			return left < right;
			break;
		case LLIL_CMP_SLE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b) || (a == b);
			break;
		}
		case LLIL_CMP_ULE:
			return left <= right;
			break;
		case LLIL_CMP_SGE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !slt(a, b);
			break;
		}
		case LLIL_CMP_UGE:
			return left >= right;
			break;
		case LLIL_CMP_SGT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !(slt(a, b) || (a == b));
			break;
		}
		case LLIL_CMP_UGT:
			return left > right;
			break;
		default:
			break;
	}
	return -1;
}


intx::uint512 DebuggerController::GetValueFromComparison(const BNMediumLevelILOperation op, intx::uint512 left,
	intx::uint512 right, size_t size)
{
	switch (op)
	{
		case MLIL_CMP_E:
			return left == right;
			break;
		case MLIL_CMP_NE:
			return left != right;
			break;
		case MLIL_CMP_SLT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b);
			break;
		}
		case MLIL_CMP_ULT:
			return left < right;
			break;
		case MLIL_CMP_SLE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b) || (a == b);
			break;
		}
		case MLIL_CMP_ULE:
			return left <= right;
			break;
		case MLIL_CMP_SGE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !slt(a, b);
			break;
		}
		case MLIL_CMP_UGE:
			return left >= right;
			break;
		case MLIL_CMP_SGT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !(slt(a, b) || (a == b));
			break;
		}
		case MLIL_CMP_UGT:
			return left > right;
			break;
		default:
			break;
	}
	return -1;
}


intx::uint512 DebuggerController::GetValueFromComparison(const BNHighLevelILOperation op, intx::uint512 left,
	intx::uint512 right, size_t size)
{
	switch (op)
	{
		case HLIL_CMP_E:
			return left == right;
			break;
		case HLIL_CMP_NE:
			return left != right;
			break;
		case HLIL_CMP_SLT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b);
			break;
		}
		case HLIL_CMP_ULT:
			return left < right;
			break;
		case HLIL_CMP_SLE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b) || (a == b);
			break;
		}
		case HLIL_CMP_ULE:
			return left <= right;
			break;
		case HLIL_CMP_SGE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !slt(a, b);
			break;
		}
		case HLIL_CMP_UGE:
			return left >= right;
			break;
		case HLIL_CMP_SGT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !(slt(a, b) || (a == b));
			break;
		}
		case HLIL_CMP_UGT:
			return left > right;
			break;
		default:
			break;
	}
	return -1;
}


bool DebuggerController::ComputeExprValueAPI(const BinaryNinja::MediumLevelILInstruction &instr, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return ComputeExprValue(instr, value);
}


bool DebuggerController::ComputeExprValue(const MediumLevelILInstruction &instr, intx::uint512& value)
{
	if (instr.size > 64)
		return false;

	intx::uint512 left, right;
	intx::uint512 sizeMask = (intx::uint512(1) << (instr.size * 8)) - 1;

	switch (instr.operation)
	{
	case MLIL_CONST:
		value = instr.GetConstant<MLIL_CONST>() & sizeMask;
		return true;
	case MLIL_CONST_PTR:
		value = instr.GetConstant<MLIL_CONST_PTR>() & sizeMask;
		return true;
	case MLIL_FLOAT_CONST:
		value = instr.GetConstant<MLIL_CONST_PTR>() & sizeMask;
		return true;
	case MLIL_VAR:
	{
		const auto var = instr.GetSourceVariable<MLIL_VAR>();
		return GetVariableValue(var, instr.address, instr.size, value);
		break;
	}
	case MLIL_ADD:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_ADD>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_ADD>(), right))
			return false;
		value = left + right;
		value &= sizeMask;
		return true;
	case MLIL_SUB:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_SUB>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_SUB>(), right))
			return false;
		value = left - right;
		value &= sizeMask;
		return true;
	case MLIL_LOAD:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_LOAD>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case MLIL_STORE:
	{
		if (!ComputeExprValue(instr.GetDestExpr<MLIL_STORE>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case MLIL_LSL:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_LSL>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_LSL>(), right))
			return false;
		value = left << GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case MLIL_LSR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_LSR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_LSR>(), right))
			return false;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case MLIL_ASR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_ASR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_ASR>(), right))
			return false;
		if (left & (1LL << ((instr.size * 8) - 1)))
			left |= ~sizeMask;
		else
			left &= sizeMask;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case MLIL_XOR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_XOR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_XOR>(), right))
			return false;
		value = left ^ right;
		value &= sizeMask;
		return true;
	}
	case MLIL_AND:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_AND>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_AND>(), right))
			return false;
		value = left & right;
		value &= sizeMask;
		return true;
	}
	case MLIL_OR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_OR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_OR>(), right))
			return false;
		value = left | right;
		value &= sizeMask;
		return true;
	}
	case MLIL_NEG:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_NEG>(), left))
			return false;
		value = -left;
		value &= sizeMask;
		return true;
	}
	case MLIL_NOT:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_NOT>(), left))
			return false;
		value = ~left;
		value &= sizeMask;
		return true;
	}
	case MLIL_SX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_SX>(), left))
			return false;
		value = SignExtend(left, instr.GetSourceExpr<MLIL_SX>().size, instr.size);
		return true;
	}
	case MLIL_ZX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_ZX>(), left))
			return false;
		value = ZeroExtend(left, instr.GetSourceExpr<MLIL_ZX>().size, instr.size);
		return true;
	}
	case MLIL_CMP_E:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_E>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_E>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_NE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_NE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_NE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SLT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SLT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SLT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_ULT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_ULT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_ULT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SLE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SLE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SLE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_ULE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_ULE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_ULE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SGE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_UGE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_UGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_UGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SGT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_UGT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_UGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_UGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	default:
		return false;
	}
}


bool DebuggerController::GetVariableValueAPI(const Variable& var, uint64_t address, size_t size, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return GetVariableValue(var, address, size, value);
}


bool DebuggerController::GetVariableValue(const Variable& var, uint64_t address, size_t size, intx::uint512 &value)
{
	intx::uint512 sizeMask = -1;
	if (size > 0 && size < 64)
		sizeMask = (intx::uint512(1) << (size * 8)) - 1;

	if (var.type == RegisterVariableSourceType)
	{
		auto reg = var.storage;
		if (LLIL_REG_IS_TEMP(reg))
			return false;

		auto name = GetData()->GetDefaultArchitecture()->GetRegisterName((uint32_t)reg);
		// TODO: what if the name reported by the adapter is different from that in the architecture?
		// GetRegisterValue should return if the value can be retrieved

		// Cheat for arm64
		if (name == "x29") name = "fp";

		value = GetRegisterValue(name) & sizeMask;
		return true;
	}
	else if (var.type == StackVariableSourceType)
	{
		auto stack = m_state->StackPointer();
		auto ip = m_state->IP();
		auto funcs = GetData()->GetAnalysisFunctionsContainingAddress(address);
		if (funcs.empty())
			return false;
		auto func = funcs[0];
		if (!func)
			return false;
		auto arch = GetData()->GetDefaultArchitecture();
		if (!arch)
			return false;
		auto stackReg = arch->GetStackPointerRegister();
		auto stackValue = func->GetRegisterValueAtInstruction(arch, ip, stackReg);
		if (stackValue.state != StackFrameOffset)
			return false;
		auto stackAtFuncEntry = stack - stackValue.value;
		auto addrOfVar = stackAtFuncEntry + var.storage;

		auto type = func->GetVariableType(var);
		if (!type)
			return false;

		size_t width = type->GetWidth();
		if (width > 64)
			return false;

		auto buffer = ReadMemory(addrOfVar, width);
		if (buffer.GetLength() != width)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), width);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}

	return false;
}


bool DebuggerController::ComputeExprValueAPI(const BinaryNinja::HighLevelILInstruction &instr, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return ComputeExprValue(instr, value);
}


bool DebuggerController::ComputeExprValue(const HighLevelILInstruction &instr, intx::uint512& value)
{
	if (instr.size > 64)
		return false;

	intx::uint512 left, right;
	intx::uint512 sizeMask = (intx::uint512(1) << (instr.size * 8)) - 1;

	switch (instr.operation)
	{
	case HLIL_CONST:
		value = instr.GetConstant<HLIL_CONST>() & sizeMask;
		return true;
	case HLIL_CONST_PTR:
		value = instr.GetConstant<HLIL_CONST_PTR>() & sizeMask;
		return true;
	case HLIL_FLOAT_CONST:
		value = instr.GetConstant<HLIL_CONST_PTR>() & sizeMask;
		return true;
	case HLIL_VAR:
	{
		const auto var = instr.GetVariable<HLIL_VAR>();
		return GetVariableValue(var, instr.address, instr.size, value);
		break;
	}
	case HLIL_ADD:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_ADD>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_ADD>(), right))
			return false;
		value = left + right;
		value &= sizeMask;
		return true;
	case HLIL_SUB:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_SUB>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_SUB>(), right))
			return false;
		value = left - right;
		value &= sizeMask;
		return true;
	case HLIL_LSL:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_LSL>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_LSL>(), right))
			return false;
		value = left << GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case HLIL_LSR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_LSR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_LSR>(), right))
			return false;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case HLIL_ASR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_ASR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_ASR>(), right))
			return false;
		if (left & (1LL << ((instr.size * 8) - 1)))
			left |= ~sizeMask;
		else
			left &= sizeMask;
		value = ((int64_t)left) >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case HLIL_XOR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_XOR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_XOR>(), right))
			return false;
		value = left ^ right;
		value &= sizeMask;
		return true;
	}
	case HLIL_AND:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_AND>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_AND>(), right))
			return false;
		value = left & right;
		value &= sizeMask;
		return true;
	}
	case HLIL_OR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_OR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_OR>(), right))
			return false;
		value = left | right;
		value &= sizeMask;
		return true;
	}
	case HLIL_NEG:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_NEG>(), left))
			return false;
		value = -left;
		value &= sizeMask;
		return true;
	}
	case HLIL_NOT:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_NOT>(), left))
			return false;
		value = ~left;
		value &= sizeMask;
		return true;
	}
	case HLIL_SX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_SX>(), left))
			return false;
		value = SignExtend(left, instr.GetSourceExpr<HLIL_SX>().size, instr.size);
		return true;
	}
	case HLIL_ZX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_ZX>(), left))
			return false;
		value = ZeroExtend(left, instr.GetSourceExpr<HLIL_ZX>().size, instr.size);
		return true;
	}
	case HLIL_CMP_E:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_E>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_E>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_NE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_NE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_NE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SLT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SLT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SLT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_ULT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_ULT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_ULT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SLE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SLE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SLE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_ULE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_ULE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_ULE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SGE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_UGE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_UGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_UGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SGT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_UGT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_UGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_UGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	default:
		return false;
	}
}


Ref<Settings> DebuggerController::GetAdapterSettings()
{
	CreateDebugAdapter();
	if (!m_adapter)
		return nullptr;

	return m_adapter->GetAdapterSettings();
}


void DebuggerController::SetDebuggerUICallbacks(BNDebuggerUICallbacks* cb, void* ctxt)
{
	if (cb)
		m_uiCallbacks = std::make_unique<DebuggerUICallbacks>(cb, ctxt);
	else
		m_uiCallbacks.reset();
}


void DebuggerUICallbacks::NotifyRebaseBinaryView(uint64_t remoteBase)
{
	if (m_callbacks && m_callbacks->rebaseBinaryView)
		m_callbacks->rebaseBinaryView(m_context, remoteBase);
}


bool DebuggerController::FunctionExistsInOldView(uint64_t address)
{
	if (m_ranges.empty())
		return false;

	address -= (m_newViewBase - m_oldViewBase);
	for (const auto& range: m_ranges)
	{
		if (address >= range.start && address < range.end)
			return true;
	}
	return false;
}


bool DebuggerController::RebaseToRemoteBase()
{
	uint64_t remoteBase;
	if (!GetRemoteBase(remoteBase))
		return false;

	return RebaseToAddress(remoteBase);
}


bool DebuggerController::GetRemoteBase(uint64_t& address)
{
	if (!m_state->IsConnected())
		return false;

	return m_state->GetRemoteBase(address);
}


bool DebuggerController::RebaseToAddress(uint64_t newBase)
{
	const auto data = GetData();
	if (!data)
		return false;

	const uint64_t oldBase = GetViewFileSegmentsStart();

	if (newBase == oldBase)
		return true;

	// Check UI callbacks early before modifying state
	if (BinaryNinja::IsUIEnabled() && !m_uiCallbacks)
		return false;

	m_oldViewBase = oldBase;
	m_newViewBase = newBase;

	m_ranges.clear();
	for (const auto& func: data->GetAnalysisFunctionList())
	{
		for (const auto& range: func->GetAddressRanges())
			m_ranges.emplace_back(range);
	}

	if (BinaryNinja::IsUIEnabled())
	{
		m_uiCallbacks->NotifyRebaseBinaryView(newBase);
		return true;  // Rebase completes asynchronously via UI callback
	}

	data->AbortAnalysis();
	data->UpdateAnalysisAndWait();

	RemoveDebuggerMemoryRegion();

	const auto shouldHoldAnalysis = Settings::Instance()->Get<bool>("debugger.holdAnalysis");
	if (shouldHoldAnalysis)
		data->SetAnalysisHold(false);

	const auto viewType = data->GetTypeName();
	if (!m_file->Rebase(data, newBase, [&](size_t, size_t) { return true; }))
	{
		LogWarn("Failed to rebase to remote base 0x%" PRIx64, newBase);
		ReAddDebuggerMemoryRegion();
		return false;
	}

	const auto rebasedView = m_file->GetViewOfType(viewType);
	if (!rebasedView)
	{
		ReAddDebuggerMemoryRegion();
		return false;
	}

	if (shouldHoldAnalysis)
	{
		// Store in member variable to keep alive until callback fires
		m_rebaseCompletionEvent = rebasedView->AddAnalysisCompletionEvent([=]() {
			rebasedView->SetAnalysisHold(true);
		});
		rebasedView->UpdateAnalysis();
	}

	ReAddDebuggerMemoryRegion();
	GetData()->UpdateAnalysis();

	return true;
}
