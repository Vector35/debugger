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

#include "debuggercontroller.h"
#include <thread>
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"

using namespace BinaryNinjaDebugger;

DebuggerController::DebuggerController(BinaryViewRef data): m_data(data)
{
	INIT_DEBUGGER_API_OBJECT();

    m_state = new DebuggerState(data, this);
    RegisterEventCallback([this](const DebuggerEvent& event){
        EventHandler(event);
    });
}


void DebuggerController::AddBreakpoint(uint64_t address)
{
    m_state->AddBreakpoint(address);
    DebuggerEvent event;
    event.type = AbsoluteBreakpointAddedEvent;
    event.data.absoluteAddress = address;
    PostDebuggerEvent(event);
}


void DebuggerController::AddBreakpoint(const ModuleNameAndOffset& address)
{
    m_state->AddBreakpoint(address);
    DebuggerEvent event;
    event.type = RelativeBreakpointAddedEvent;
    event.data.relativeAddress = address;
    PostDebuggerEvent(event);
}


void DebuggerController::DeleteBreakpoint(uint64_t address)
{
    m_state->DeleteBreakpoint(address);
    DebuggerEvent event;
    event.type = AbsoluteBreakpointRemovedEvent;
    event.data.absoluteAddress = address;
    PostDebuggerEvent(event);
}


void DebuggerController::DeleteBreakpoint(const ModuleNameAndOffset& address)
{
    m_state->DeleteBreakpoint(address);
    DebuggerEvent event;
    event.type = RelativeBreakpointRemovedEvent;
    event.data.relativeAddress = address;
    PostDebuggerEvent(event);
}


bool DebuggerController::Launch()
{
	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	if (!CreateDebugAdapter())
		return false;

    m_state->MarkDirty();
	bool result = Execute();
	if (result)
	{
		m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
        m_state->SetExecutionStatus(DebugAdapterPausedStatus);
		HandleInitialBreakpoint();
	}
	else
	{
//		TODO: Right now, the LLDBAdapter directly notifies about the failure. In the future, we should let the backend
//		return both an error value and an error string. And the error will be notified at API level.
//		NotifyError("Failed to launch the target");
	}
	return result;
}


bool DebuggerController::Attach(int32_t pid)
{
	NotifyEvent(AttachEventType);
	if (!CreateDebugAdapter())
		return false;

	m_state->MarkDirty();
	bool result = m_adapter->Attach(pid);
	if (result)
	{
		m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterPausedStatus);
		HandleInitialBreakpoint();
	}
	return result;
}


bool DebuggerController::Execute()
{
	std::string filePath = m_state->GetExecutablePath();
	bool requestTerminal = m_state->GetRequestTerminalEmulator();
	LaunchConfigurations configs = {requestTerminal};

	#ifdef WIN32
		/* temporary solution (not great, sorry!), we probably won't have to do this once we introduce std::filesystem::path */
		std::replace(filePath.begin(), filePath.end(), '/', '\\');
	#endif

	return m_adapter->ExecuteWithArgs(filePath, m_state->GetCommandLineArguments(), m_state->GetWorkingDirectory(),
									  configs);
}


bool DebuggerController::CreateDebugAdapter()
{
    // The current adapter type is the same as the last one, and the last adapter is still valid
    if (m_state->GetAdapterType() == m_lastAdapterName && m_adapter != nullptr)
        return true;

    DebugAdapterType* type = DebugAdapterType::GetByName(m_state->GetAdapterType());
    if (!type)
    {
        LogWarn("fail to get an debug adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
    }
    m_adapter = type->Create(m_data);
	if (!m_adapter)
	{
		LogWarn("fail to create an adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
	}

    m_lastAdapterName = m_state->GetAdapterType();
	m_state->SetAdapter(m_adapter);

	ApplyBreakpoints();

	// Forward the DebuggerEvent from the adapters to the controller
	m_adapter->SetEventCallback([this](const DebuggerEvent& event){
		PostDebuggerEvent(event);
	});
	return true;
}


// Apply all breakpoints that are added before the adapter is created
void DebuggerController::ApplyBreakpoints()
{
	m_state->ApplyBreakpoints();
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


// Synchronously resume the target, only returns when the target stops.
void DebuggerController::GoInternal()
{
	m_adapter->Go();
}


bool DebuggerController::Go()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	std::thread([&](){
		GoInternal();
	}).detach();

	return true;
}


DebugStopReason DebuggerController::GoAndWait()
{
	if (!Go())
		return InvalidStatusOrOperation;

	return WaitForTargetStop();
}


// Synchronously step into the target. It waits until the target stops and returns the stop reason
void DebuggerController::StepIntoInternal()
{
	m_adapter->StepInto();
}


void DebuggerController::StepIntoIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		StepIntoInternal();
		return;
	}
	case LowLevelILFunctionGraph:
	{
		m_treatAdapterStopAsTargetStop = false;
		// TODO: This might cause infinite loop
		while (true)
		{
			StepIntoInternal();
			DebugStopReason reason = WaitForAdapterStop();
			if (!ExpectSingleStep(reason))
			{
				m_treatAdapterStopAsTargetStop = true;
				NotifyStopped(reason);
			}

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.size() == 0)
			    return;

			for (FunctionRef& func: functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelIL();
				size_t start = llil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
					{
						m_treatAdapterStopAsTargetStop = true;
						NotifyStopped(SingleStep);
						return;
					}
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		m_treatAdapterStopAsTargetStop = false;
		// TODO: This might cause infinite loop
		while (true)
		{
			StepIntoInternal();
			DebugStopReason reason = WaitForAdapterStop();
			if (!ExpectSingleStep(reason))
			{
				m_treatAdapterStopAsTargetStop = true;
				NotifyStopped(reason);
			}

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

			for (FunctionRef& func: functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelIL();
				size_t start = mlil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
					{
						m_treatAdapterStopAsTargetStop = true;
						NotifyStopped(SingleStep);
						return;
					}
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		m_treatAdapterStopAsTargetStop = false;
		// TODO: This might cause infinite loop
		while (true)
		{
			StepIntoInternal();
			DebugStopReason reason = WaitForAdapterStop();
			if (!ExpectSingleStep(reason))
			{
				m_treatAdapterStopAsTargetStop = true;
				NotifyStopped(reason);
			}

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

			for (FunctionRef& func: functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelIL();
				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
					{
						m_treatAdapterStopAsTargetStop = true;
						NotifyStopped(SingleStep);
						return;
					}
				}
			}
		}
		break;
	}
	default:
		LogWarn("step into unimplemented in the current il type");
        return;
	}
}


bool DebuggerController::StepInto(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
        return false;

	std::thread([&, il](){
		StepIntoIL(il);
	}).detach();

	return true;
}


DebugStopReason DebuggerController::StepIntoAndWait(BNFunctionGraphType il)
{
	StepInto(il);
	return WaitForTargetStop();
}


void DebuggerController::StepOverInternal()
{
	// If the adapter supports step return, then use it
	DebugStopReason reason = m_adapter->StepOver();
	if ((reason != DebugStopReason::OperationNotSupported) && (reason != DebugStopReason::InternalError))
		return;

    uint64_t remoteIP = m_state->IP();

    // TODO: support the case where we cannot determined the remote arch
	ArchitectureRef remoteArch = m_state->GetRemoteArchitecture();
    size_t size = remoteArch->GetMaxInstructionLength();
    DataBuffer buffer = m_adapter->ReadMemory(remoteIP, size);
    size_t bytesRead = buffer.GetLength();

    Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(remoteArch, nullptr);
    ilFunc->SetCurrentAddress(remoteArch, remoteIP);
    remoteArch->GetInstructionLowLevelIL((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, *ilFunc);

    const auto& instr = (*ilFunc)[0];
    if (instr.operation != LLIL_CALL)
    {
        StepIntoInternal();
    }
    else
    {
        InstructionInfo info;
        if (!remoteArch->GetInstructionInfo((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, info))
        {
            // Whenever there is a failure, we fail back to step into
			StepIntoInternal();
        }

        if (info.length == 0)
        {
			return StepIntoInternal();
        }

        uint64_t remoteIPNext = remoteIP + info.length;
        RunToInternal({remoteIPNext});
    }
}


void DebuggerController::StepOverIL(BNFunctionGraphType il)
{
    switch (il)
    {
    case NormalFunctionGraph:
    {
        StepOverInternal();
		return;
    }
    case LowLevelILFunctionGraph:
    {
		m_treatAdapterStopAsTargetStop = false;
        // TODO: This might cause infinite loop
        while (true)
        {
			StepOverInternal();
			DebugStopReason reason = WaitForAdapterStop();
			if (!ExpectSingleStep(reason))
			{
				m_treatAdapterStopAsTargetStop = true;
				NotifyStopped(reason);
			}

            uint64_t newRemoteRip = m_state->IP();
            std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                LowLevelILFunctionRef llil = func->GetLowLevelIL();
                size_t start = llil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
                if (start < llil->GetInstructionCount())
                {
                    if (llil->GetInstruction(start).address == newRemoteRip)
					{
						m_treatAdapterStopAsTargetStop = true;
						NotifyStopped(SingleStep);
						return;
					}
                }
            }
        }
        break;
    }
    case MediumLevelILFunctionGraph:
    {
		m_treatAdapterStopAsTargetStop = false;
        // TODO: This might cause infinite loop
        while (true)
        {
			StepOverInternal();
			DebugStopReason reason = WaitForAdapterStop();
			if (!ExpectSingleStep(reason))
			{
				m_treatAdapterStopAsTargetStop = true;
				NotifyStopped(reason);
			}

            uint64_t newRemoteRip = m_state->IP();
            std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                MediumLevelILFunctionRef mlil = func->GetMediumLevelIL();
                size_t start = mlil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
                if (start < mlil->GetInstructionCount())
                {
                    if (mlil->GetInstruction(start).address == newRemoteRip)
					{
						m_treatAdapterStopAsTargetStop = true;
						NotifyStopped(SingleStep);
						return;
					}
                }
            }
        }
        break;
    }
    case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
    {
		m_treatAdapterStopAsTargetStop = false;
        // TODO: This might cause infinite loop
        while (true)
        {
			StepOverInternal();
			DebugStopReason reason = WaitForAdapterStop();
			if (!ExpectSingleStep(reason))
			{
				m_treatAdapterStopAsTargetStop = true;
				NotifyStopped(reason);
			}

            uint64_t newRemoteRip = m_state->IP();
            std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
			    return;

            for (FunctionRef& func: functions)
            {
                HighLevelILFunctionRef hlil = func->GetHighLevelIL();
                for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
                {
                    if (hlil->GetInstruction(i).address == newRemoteRip)
					{
						m_treatAdapterStopAsTargetStop = true;
						NotifyStopped(SingleStep);
						return;
					}
                }
            }
        }
        break;
    }
    default:
        LogWarn("step over unimplemented in the current il type");
        return;
    }
}


bool DebuggerController::StepOver(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
	    return false;

	std::thread([&, il](){
		StepOverIL(il);
	}).detach();

	return true;
}


DebugStopReason DebuggerController::StepOverAndWait(BNFunctionGraphType il)
{
	StepOver(il);
	return WaitForTargetStop();
}


void DebuggerController::StepReturnInternal()
{
	// If the adapter supports step return, then use it
	DebugStopReason reason = m_adapter->StepReturn();
	if ((reason != DebugStopReason::OperationNotSupported) && (reason != DebugStopReason::InternalError))
		return;

	// TODO: dbgeng supports step out natively, consider using that as well once we implement a similar functionality
	// for gdb and lldb
	uint64_t address = m_state->IP();
	std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(address);
	if (functions.size() == 0)
        return;

	std::vector<uint64_t> returnAddresses;
	FunctionRef function = functions[0];
	MediumLevelILFunctionRef mlilFunc = function->GetMediumLevelIL();
	for (size_t i = 0; i < mlilFunc->GetInstructionCount(); i++)
	{
		MediumLevelILInstruction instruction = mlilFunc->GetInstruction(i);
		if ((instruction.operation == MLIL_RET) || (instruction.operation == MLIL_TAILCALL))
			returnAddresses.push_back(instruction.address);
	}

	RunToInternal(returnAddresses);
}


bool DebuggerController::StepReturn()
{
	if (!CanResumeTarget())
	    return false;

	std::thread([&](){
		StepReturnInternal();
	}).detach();

	return false;
}


DebugStopReason DebuggerController::StepReturnAndWait()
{
	StepReturn();
	return WaitForTargetStop();
}


void DebuggerController::RunToInternal(const std::vector<uint64_t>& remoteAddresses)
{
    for (uint64_t remoteAddress: remoteAddresses)
    {
        if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
        {
            m_adapter->AddBreakpoint(remoteAddress);
        }
    }

	m_treatAdapterStopAsTargetStop = false;
	GoInternal();
	WaitForAdapterStop();
	m_treatAdapterStopAsTargetStop = true;

    for (uint64_t remoteAddress: remoteAddresses)
    {
        if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
        {
            m_adapter->RemoveBreakpoint(remoteAddress);
        }
    }

	NotifyStopped(Breakpoint);
}


bool DebuggerController::RunTo(const std::vector<uint64_t>& remoteAddresses)
{
	if (!CanResumeTarget())
	    return false;

	std::thread([&, remoteAddresses](){
		RunToInternal(remoteAddresses);
	}).detach();

	return true;
}


DebugStopReason DebuggerController::RunToAndWait(const std::vector<uint64_t>& remoteAddresses)
{
	RunTo(remoteAddresses);
	return WaitForTargetStop();
}


void DebuggerController::HandleInitialBreakpoint()
{
	m_state->UpdateCaches();
	// Rebase the binary and create DebugView
	uint64_t remoteBase = m_state->GetRemoteBase();

	FileMetadataRef fileMetadata = m_data->GetFile();
	if (remoteBase != m_data->GetStart())
	{
		// remote base is different from the local base, first need a rebase
		ExecuteOnMainThreadAndWait([=](){
//			ProgressIndicator progress(nullptr, "Rebase", "Rebasing...");
			if (!fileMetadata->Rebase(m_data, remoteBase,
									  [&](size_t cur, size_t total) { return true; }))
			{
				LogWarn("rebase failed");
			}
		});
	}

	Ref<BinaryView> rebasedView = fileMetadata->GetViewOfType(m_data->GetTypeName());
	SetData(rebasedView);

	ExecuteOnMainThreadAndWait([=](){
//		ProgressIndicator progress(nullptr, "Debugger View", "Creating debugger view...");
		bool ok = fileMetadata->CreateSnapshotedView(rebasedView, "Debugger",
												[&](size_t cur, size_t total) { return true; });
		if (!ok)
			LogWarn("create snapshoted view failed");
	});

	BinaryViewRef liveView = fileMetadata->GetViewOfType("Debugger");
	if (!liveView)
	{
		LogWarn("Invalid Debugger view!");
		return;
	}
	SetLiveView(liveView);

	NotifyStopped(DebugStopReason::InitialBreakpoint);
}


DebugThread DebuggerController::GetActiveThread() const
{
	return m_state->GetThreads()->GetActiveThread();
}


void DebuggerController::SetActiveThread(const DebugThread &thread)
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


std::vector<DebugFrame> DebuggerController::GetFramesOfThread(uint64_t tid)
{
	return m_state->GetThreads()->GetFramesOfThread(tid);
}


void DebuggerController::Restart()
{
    Quit();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    Launch();
}


void DebuggerController::Connect()
{
    if (m_state->IsConnected())
        return;

    if (!CreateDebugAdapter())
        return;

    m_state->MarkDirty();

    m_state->SetConnectionStatus(DebugAdapterConnectingStatus);

    NotifyEvent(ConnectEventType);

    bool ok = m_adapter->Connect(m_state->GetRemoteHost(), m_state->GetRemotePort());

    if (ok)
    {
        m_state->MarkDirty();
        m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
        m_state->SetExecutionStatus(DebugAdapterPausedStatus);
		HandleInitialBreakpoint();
    }
    else
    {
        LogWarn("fail to connect to the target");
    }
}


bool DebuggerController::ConnectToDebugServer()
{
    if (m_state->IsConnectedToDebugServer())
        return true;

    if (!CreateDebugAdapter())
        return false;

    bool ok = m_adapter->ConnectToDebugServer(m_state->GetRemoteHost(), m_state->GetRemotePort());
    if (!ok)
        LogWarn("fail to connect to the debug server");
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
        LogWarn("fail to disconnect from the debug server");
    else
        m_state->SetConnectedToDebugServer(false);

    return ok;
}


void DebuggerController::Detach()
{
    if (!m_state->IsConnected())
        return;

    // TODO: return whether the operation is successful
    m_adapter->Detach();
}


void DebuggerController::Quit()
{
    if (!m_state->IsConnected())
        return;

    if (m_state->IsRunning())
    {
        // We must pause the target if it is currently running, at least for DbgEngAdapter
        PauseInternal();
    }

    // TODO: return whether the operation is successful
    m_adapter->Quit();
}


void DebuggerController::PauseInternal()
{
	if (m_state->IsRunning())
    {
        m_adapter->BreakInto();
    }
}


bool DebuggerController::Pause()
{
    if (!(m_state->IsConnected() && m_state->IsRunning()))
        return false;

	std::thread([&](){
		PauseInternal();
	}).detach();

	return true;
}


DebugStopReason DebuggerController::PauseAndWait()
{
	if (!Pause())
		return InvalidStatusOrOperation;

	return WaitForTargetStop();
}


void DebuggerController::LaunchOrConnect()
{
	std::string adapter = m_state->GetAdapterType();
	auto adapterType = DebugAdapterType::GetByName(adapter);
	if (!adapterType)
		return;

	if (adapterType->CanExecute(m_data))
		Launch();
	else if (adapterType->CanConnect(m_data))
		Connect();
}


DebuggerController* DebuggerController::GetController(BinaryViewRef data)
{
    for (auto& controller: g_debuggerControllers)
    {
		if (controller->GetData() == data)
			return controller;
		if (controller->GetLiveView() == data)
			return controller;
//        if (controller->GetData()->GetFile()->GetOriginalFilename() == data->GetFile()->GetOriginalFilename())
//            return controller;
//        if (controller->GetData()->GetFile()->GetOriginalFilename() == data->GetParentView()->GetFile()->GetOriginalFilename())
//            return controller;
//        if (controller->GetData()->GetFile() == data->GetFile())
//            return controller;
//        if (controller->GetLiveView() && (controller->GetLiveView()->GetFile() == data->GetFile()))
//            return controller;
    }

    DebuggerController* controller = new DebuggerController(data);
    g_debuggerControllers.push_back(controller);
    return controller;
}


void DebuggerController::DeleteController(BinaryViewRef data)
{
    for (auto it = g_debuggerControllers.begin(); it != g_debuggerControllers.end(); )
    {
        if ((*it)->GetData()->GetFile()->GetOriginalFilename() == data->GetFile()->GetOriginalFilename())
        {
            it = g_debuggerControllers.erase(it);
        }
        else
        {
            ++it;
        }
    }
}


void DebuggerController::Destroy()
{
	DebuggerController::DeleteController(m_data);
	// Uncommenting this line of code disrupts ref counting and causes crashes. This is not the correct way to
	// free up a DebuggerController anyways.
	// TODO: we need to do ref-counting on the debugger objects later.
//	delete this;
}


// This is the central hub of event dispatch. All events first arrive here and then get dispatched based on the content
void DebuggerController::EventHandler(const DebuggerEvent& event)
{
    switch (event.type)
    {
	case ResumeEventType:
	case StepIntoEventType:
	{
		m_state->SetExecutionStatus(DebugAdapterRunningStatus);
		m_state->MarkDirty();
		break;
	}
	case TargetExitedEventType:
		m_exitCode = event.data.exitData.exitCode;
	case DetachedEventType:
	{
        SetLiveView(nullptr);
        m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
        m_state->SetExecutionStatus(DebugAdapterInvalidStatus);
		break;
	}
    case TargetStoppedEventType:
	{
		m_state->UpdateCaches();
		m_state->SetExecutionStatus(DebugAdapterPausedStatus);
		m_lastIP = m_currentIP;
		m_currentIP = m_state->IP();

		UpdateStackVariables();
		break;
	}
	case ActiveThreadChangedEvent:
    {
		m_state->UpdateCaches();
		m_lastIP = m_currentIP;
        m_currentIP = m_state->IP();
        break;
    }
    default:
        break;
    }
}


size_t DebuggerController::RegisterEventCallback(std::function<void(const DebuggerEvent&)> callback)
{
	std::unique_lock<std::recursive_mutex> lock(m_callbackMutex);
    DebuggerEventCallback object;
    object.function = callback;
    object.index = m_callbackIndex++;
    m_eventCallbacks.push_back(object);
    return object.index;
}


bool DebuggerController::RemoveEventCallback(size_t index)
{
	std::unique_lock<std::recursive_mutex> lock(m_callbackMutex);
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


void DebuggerController::PostDebuggerEvent(const DebuggerEvent& event)
{
    std::unique_lock<std::recursive_mutex> callbackLock(m_callbackMutex);
    std::vector<DebuggerEventCallback> eventCallbacks = m_eventCallbacks;
    callbackLock.unlock();

    for (const auto& cb: eventCallbacks)
    {
        cb.function(event);
    }

	// If the current event is an AdapterStoppedEvent, and no callback objects it, then we also notify a
	// TargetStoppedEvent.
	if (event.type == AdapterStoppedEventType && m_treatAdapterStopAsTargetStop)
	{
		DebuggerEvent stopEvent = event;
		stopEvent.type = TargetStoppedEventType;
		for (const auto& cb: eventCallbacks)
		{
			cb.function(stopEvent);
		}
	}
}


void DebuggerController::NotifyStopped(DebugStopReason reason, void *data)
{
    DebuggerEvent event;
    event.type = TargetStoppedEventType;
    event.data.targetStoppedData.reason = reason;
    event.data.targetStoppedData.data = data;
    PostDebuggerEvent(event);
}


void DebuggerController::NotifyError(const std::string& error, void *data)
{
    DebuggerEvent event;
    event.type = ErrorEventType;
    event.data.errorData.error = error;
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
    if (!m_liveView)
        return DataBuffer{};

	if (!m_state->IsConnected())
		return DataBuffer{};

	if (m_state->IsRunning())
		return DataBuffer{};

	DebuggerMemory* memory = m_state->GetMemory();
	if (!memory)
		return DataBuffer{};

	return memory->ReadMemory(address, size);
}


bool DebuggerController::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
    if (!m_liveView)
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


std::vector<DebugThread> DebuggerController::GetAllThreads()
{
	return m_state->GetThreads()->GetAllThreads();
}


std::vector<DebugRegister> DebuggerController::GetAllRegisters()
{
	return m_state->GetRegisters()->GetAllRegisters();
}


uint64_t DebuggerController::GetRegisterValue(const std::string &name)
{
	return m_state->GetRegisters()->GetRegisterValue(name);
}


bool DebuggerController::SetRegisterValue(const std::string &name, uint64_t value)
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


void DebuggerController::WriteStdIn(const std::string message)
{
	if (m_adapter && m_state->IsConnected())
	{
		m_adapter->WriteStdin(message);
	}
	NotifyError("Cannot send to stdin, target is not running");
}


std::string DebuggerController::InvokeBackendCommand(const std::string &cmd)
{
	if (m_adapter && m_state->IsConnected())
	{
		return m_adapter->InvokeBackendCommand(cmd);
	}
	return "Error: target is not running yet\n";
}


void DebuggerController::ProcessOneVariable(uint64_t varAddress, Confidence<Ref<Type>> type, const std::string &name)
{
	StackVariableNameAndType varNameAndType(type, name);
	auto iter = m_debuggerVariables.find(varAddress);
	if ((iter == m_debuggerVariables.end()) || (iter->second != varNameAndType))
	{
		// The variable is not yet defined, or has changed. Define it.
		// Should we use DataVariable, or UserDataVariable?
		m_liveView->DefineDataVariable(varAddress, type);
		if (!name.empty())
		{
			SymbolRef sym = new Symbol(DataSymbol, name, name, name, varAddress);
			m_liveView->DefineUserSymbol(sym);
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
	size_t addressSize = m_liveView->GetAddressSize();
	if (type->IsPointer())
	{
		auto reader = BinaryReader(m_liveView);
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
	std::vector<DebugThread> threads = GetAllThreads();
	uint64_t frameAdjustment = 0;
	std::string archName = m_liveView->GetDefaultArchitecture()->GetName();
	if ((archName == "x86") || (archName == "x86_64"))
		frameAdjustment = 8;
	size_t addressSize = m_liveView->GetAddressSize();

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
			auto functions = m_liveView->GetAnalysisFunctionsForAddress(frame.m_functionStart);
			if (functions.empty())
				continue;

			FunctionRef func = functions[0];

			auto vars = func->GetVariables();
			// BN's variable storage offset is calculated against the entry status of the function, i.e.,
			// before the current stack frame is created. Here we take the stack pointer of the previous stack frame,
			// and subtract the size of return address from it
			uint64_t framePointer = prevFrame.m_sp - frameAdjustment;
			for (const auto& [var, varNameAndType]: vars)
			{
				if (var.type != StackVariableSourceType)
					continue;

				uint64_t varAddress = framePointer + var.storage;
				ProcessOneVariable(varAddress, varNameAndType.type, varNameAndType.name);
				DefineVariablesRecursive(varAddress, varNameAndType.type);
			}
		}

		for (const DebugFrame& frame: frames)
		{
			// Annotate the stack pointer and the frame pointer, using the current stack frame
			m_liveView->SetCommentForAddress(frame.m_sp, fmt::format("Stack #{}\n====================", frame.m_index));
			m_liveView->SetCommentForAddress(frame.m_fp, fmt::format("Frame #{}", frame.m_index));
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

	for (uint64_t address: m_oldAddresses)
	{
		auto iter = m_addressesWithVariable.find(address);
		if (iter != m_addressesWithVariable.end())
			m_addressesWithVariable.erase(iter);

		m_liveView->UndefineDataVariable(address);
		auto symbol = m_liveView->GetSymbolByAddress(address);
		if (symbol)
			m_liveView->UndefineUserSymbol(symbol);
	}

	for (uint64_t address: oldAddressWithComment)
	{
		m_liveView->SetCommentForAddress(address, "");
	}
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


DebugStopReason DebuggerController::WaitForTargetStop()
{
//	TODO: we need to explicitly set m_state as running before we turn this on. Currently, the state transition is done
//	in the callback to LaunchEvent, which executes LATER than WaitForTargetStop().
//	if (!m_state->IsRunning())
//		LogWarn("target is not running\n");

	Semaphore sem;
	DebugStopReason reason = UnknownReason;
	size_t callback = RegisterEventCallback([&](const DebuggerEvent& event){
		switch (event.type)
		{
		case TargetStoppedEventType:
			reason = event.data.targetStoppedData.reason;
			sem.Release();
			break;
		case TargetExitedEventType:
		case DetachedEventType:
			reason = ProcessExited;
			sem.Release();
			break;
		default:
			break;
		}
	});
	sem.Wait();
	RemoveEventCallback(callback);
	return reason;
}


DebugStopReason DebuggerController::WaitForAdapterStop()
{
	Semaphore sem;
	DebugStopReason reason = UnknownReason;
	size_t callback = RegisterEventCallback([&](const DebuggerEvent& event){
		if (event.type == AdapterStoppedEventType)
		{
			reason = event.data.targetStoppedData.reason;
			sem.Release();
		}
	});
	sem.Wait();
	RemoveEventCallback(callback);
	return reason;
}
