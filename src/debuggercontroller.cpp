#include "debuggercontroller.h"
#include <thread>
#include "progress.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"

DebuggerController::DebuggerController(BinaryViewRef data): m_data(data)
{
    m_state = new DebuggerState(data, this);
    m_hasUI = BinaryNinja::IsUIEnabled();
//    if (m_hasUI)
//    {
//        // DebugerUI is an abstract container of three things, the DebugView, the SideBar widget, and the status bar.
//        // None of the three necessarily exists when the DebuggerUI is constructed. So they must register themselves to
//        // the DebuggerUI when they are constructed.
//        m_ui = new DebuggerUI(this);
//    }

    RegisterEventCallback([this](const DebuggerEvent& event){
        EventHandler(event);
    });

    // start the event queue worker
    std::thread worker([&](){
        Worker();
    });
    worker.detach();

	// TODO: we should add an option whether to add a breakpoint at program entry
	AddEntryBreakpoint();
}


void DebuggerController::AddEntryBreakpoint()
{
    uint64_t entryPoint = m_data->GetEntryPoint();
    uint64_t localEntryOffset = entryPoint - m_data->GetStart();
    ModuleNameAndOffset address(m_data->GetFile()->GetOriginalFilename(), localEntryOffset);

    AddBreakpoint(address);
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


TagTypeRef DebuggerController::getPCTagType(BinaryViewRef data)
{
    TagTypeRef type = data->GetTagType("Program Counter");
    if (type)
        return type;

    TagTypeRef pcTagType = new TagType(data, "Program Counter", "=>");
    data->AddTagType(pcTagType);
    return pcTagType;
}


TagTypeRef DebuggerController::getBreakpointTagType(BinaryViewRef data)
{
    TagTypeRef type = data->GetTagType("Breakpoints");
    if (type)
        return type;

    TagTypeRef pcTagType = new TagType(data, "Breakpoints", "🛑");
    data->AddTagType(pcTagType);
    return pcTagType;
}


bool DebuggerController::Launch()
{
	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	m_adapter = CreateDebugAdapter();
	if (!m_adapter)
		return false;

	m_state->SetAdapter(m_adapter);
	bool result = Execute();
	if (result)
	{
		m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
        m_state->SetExecutionStatus(DebugAdapterPausedStatus);
		NotifyStopped(DebugStopReason::InitialBreakpoint);
	}
	return result;
}


bool DebuggerController::Execute()
{
	std::string filePath = m_state->GetExecutablePath();
	// We should switch to use std::filesystem::exists() later
	FILE* file = fopen(filePath.c_str(), "r");
	if (!file)
	{
		LogWarn("file \"%s\" does not exist, fail to execute it", filePath.c_str());
		return false;
	}
	else
	{
		fclose(file);
	}

	bool requestTerminal = m_state->GetRequestTerminalEmulator();
	LaunchConfigurations configs = {requestTerminal};

	#ifdef WIN32
		/* temporary solution (not great, sorry!), we probably won't have to do this once we introduce std::filesystem::path */
		std::replace(filePath.begin(), filePath.end(), '/', '\\');
	#endif

	return m_adapter->ExecuteWithArgs(filePath, m_state->GetCommandLineArguments(), configs);
}


DebugAdapter* DebuggerController::CreateDebugAdapter()
{
    DebugAdapterType* type = DebugAdapterType::GetByName(m_state->GetAdapterType());
    if (!type)
    {
        LogWarn("fail to get an debug adapter of type %s", m_state->GetAdapterType().c_str());
		return nullptr;
    }
    DebugAdapter* adapter = type->Create(m_data);
	if (!adapter)
	{
		LogWarn("fail to create an adapter of type %s", m_state->GetAdapterType().c_str());
		return nullptr;
	}

	// Forward the DebuggerEvent from the adapters to the controller
	adapter->SetEventCallback([this](const DebuggerEvent& event){
		PostDebuggerEvent(event);
	});
	return adapter;
}


bool DebuggerController::CanResumeTarget()
{
	return m_state->IsConnected() && (!m_state->IsRunning());
}


// Synchronously resume the target, only returns when the target stops.
DebugStopReason DebuggerController::GoInternal()
{
	uint64_t remoteIP = m_state->IP();
	// TODO: for dbgeng, it handles this sequence of operations for us, so we can simply can Go()
	if (m_state->GetAdapterType() != "Local DBGENG" && m_state->GetBreakpoints()->ContainsAbsolute(remoteIP))
	{
        DebugStopReason reason = StepIntoInternal();
		if (reason != DebugStopReason::SingleStep)
			return reason;

		return m_adapter->Go();
	}
	else
	{
		return m_adapter->Go();
	}
}


DebugStopReason DebuggerController::Go()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return DebugStopReason::InvalidStatusOrOperation;

	// The m_targetStatus represents the external (API-level) target status. To track the adapter execution status,
	// use a different variable. Right now there is no need to track it, so no such variable exists.
	// Always keep in mind the difference between this external and internal status when dealing with related code.
    m_state->SetExecutionStatus(DebugAdapterRunningStatus);

	DebuggerEvent event;
	event.type = ResumeEventType;
	PostDebuggerEvent(event);

    DebugStopReason reason = GoInternal();

	// Right now we are only marking the state as dirty at the external API level. This reduces unnecessary updates
	// while we carry out certain internal operations. However, this might cause correctness problems, e.g., the target
	// might have modified its own code and we do not know about it. So the internal operation is still carried out based
	// on the old caches. We should handle this case later and consider marking state as dirty after every adapter
	// operation finishes.
	// This would NOT cause a huge problem since cache update is switched to a lazy strategy. So even if we aggressively
	// invalidate the caches, as long as no one queries it, no update will be done.
	// Another note is even if we invalidate the memory caches, do we need to update analysis to have the changes
	// reflected? If so, I think the cost is so high that it does not deserve it.
    m_state->MarkDirty();
    m_state->SetExecutionStatus(DebugAdapterPausedStatus);

    HandleTargetStop(reason);
	return reason;
}


// Synchronously step into the target. It waits until the target stops and returns the stop reason
DebugStopReason DebuggerController::StepIntoInternal()
{
	uint64_t remoteIP = m_state->IP();
	if (m_state->GetAdapterType() != "LOCAL DBGENG" && m_state->GetBreakpoints()->ContainsAbsolute(remoteIP))
	{
		m_adapter->RemoveBreakpoint(remoteIP);
		DebugStopReason reason = m_adapter->StepInto();
		m_adapter->AddBreakpoint(remoteIP);
		return reason;
	}
	else
	{
        return m_adapter->StepInto();
	}
}


DebugStopReason DebuggerController::StepIntoIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepIntoInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoInternal();
			if (reason != DebugStopReason::SingleStep)
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.size() == 0)
			    return DebugStopReason::InternalError;

			for (FunctionRef& func: functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelIL();
				size_t start = llil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return reason;
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
			DebugStopReason reason = StepIntoInternal();
            if (reason != DebugStopReason::SingleStep)
                return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return DebugStopReason::InternalError;

			for (FunctionRef& func: functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelIL();
				size_t start = mlil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return reason;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
            DebugStopReason reason = StepIntoInternal();
            if (reason != DebugStopReason::SingleStep)
                return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return DebugStopReason::InternalError;

			for (FunctionRef& func: functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelIL();
				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return reason;
				}
			}
		}
		break;
	}
	default:
		LogWarn("step into unimplemented in the current il type");
        return DebugStopReason::InternalError;
	}
}


DebugStopReason DebuggerController::StepInto(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
        return DebugStopReason::InvalidStatusOrOperation;

    m_state->SetExecutionStatus(DebugAdapterRunningStatus);

	DebuggerEvent event;
	event.type = StepIntoEventType;
	PostDebuggerEvent(event);

	DebugStopReason reason = StepIntoIL(il);

	m_state->MarkDirty();
    m_state->SetExecutionStatus(DebugAdapterPausedStatus);

    HandleTargetStop(reason);
	return reason;
}


DebugStopReason DebuggerController::StepOverInternal()
{
    if (m_adapter->SupportFeature(DebugAdapterSupportStepOver))
        return m_adapter->StepOver();

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
        return StepIntoInternal();
    }
    else
    {
        InstructionInfo info;
        if (!remoteArch->GetInstructionInfo((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, info))
        {
            // Whenever there is a failure, we fail back to step into
			return StepIntoInternal();
        }

        if (info.length == 0)
        {
			return StepIntoInternal();
        }

        uint64_t remoteIPNext = remoteIP + info.length;
        return StepToInternal({remoteIPNext});
    }
}


DebugStopReason DebuggerController::StepOverIL(BNFunctionGraphType il)
{
    switch (il)
    {
    case NormalFunctionGraph:
    {
        return StepOverInternal();
    }
    case LowLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
			DebugStopReason reason = StepOverInternal();
			if (reason != DebugStopReason::SingleStep)
				return reason;

            uint64_t newRemoteRip = m_state->IP();
            std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return DebugStopReason::InternalError;

            for (FunctionRef& func: functions)
            {
                LowLevelILFunctionRef llil = func->GetLowLevelIL();
                size_t start = llil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
                if (start < llil->GetInstructionCount())
                {
                    if (llil->GetInstruction(start).address == newRemoteRip)
                        return reason;
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
			DebugStopReason reason = StepOverInternal();
			if (reason != DebugStopReason::SingleStep)
				return reason;

            uint64_t newRemoteRip = m_state->IP();
            std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return DebugStopReason::InternalError;

            for (FunctionRef& func: functions)
            {
                MediumLevelILFunctionRef mlil = func->GetMediumLevelIL();
                size_t start = mlil->GetInstructionStart(m_liveView->GetDefaultArchitecture(), newRemoteRip);
                if (start < mlil->GetInstructionCount())
                {
                    if (mlil->GetInstruction(start).address == newRemoteRip)
                        return reason;
                }
            }
        }
        break;
    }
    case HighLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
			DebugStopReason reason = StepOverInternal();
			if ((reason != DebugStopReason::SingleStep))
				return reason;

            uint64_t newRemoteRip = m_state->IP();
            std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
			    return DebugStopReason::InternalError;

            for (FunctionRef& func: functions)
            {
                HighLevelILFunctionRef hlil = func->GetHighLevelIL();
                for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
                {
                    if (hlil->GetInstruction(i).address == newRemoteRip)
                        return reason;
                }
            }
        }
        break;
    }
    default:
        LogWarn("step over unimplemented in the current il type");
        return DebugStopReason::InternalError;
        break;
    }
}


DebugStopReason DebuggerController::StepOver(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
	    return DebugStopReason::InvalidStatusOrOperation;

    m_state->SetExecutionStatus(DebugAdapterRunningStatus);

	DebuggerEvent event;
	event.type = StepOverEventType;
	PostDebuggerEvent(event);

	DebugStopReason reason = StepOverIL(il);

	m_state->MarkDirty();
    m_state->SetExecutionStatus(DebugAdapterPausedStatus);

    HandleTargetStop(reason);
	return reason;
}


DebugStopReason DebuggerController::StepReturnInternal()
{
	// TODO: dbgeng supports step out natively, consider using that as well once we implement a similar functionality
	// for gdb and lldb
	uint64_t address = m_state->IP();
	std::vector<FunctionRef> functions = m_liveView->GetAnalysisFunctionsContainingAddress(address);
	if (functions.size() == 0)
        return DebugStopReason::InternalError;

	std::vector<uint64_t> returnAddresses;
	FunctionRef function = functions[0];
	MediumLevelILFunctionRef mlilFunc = function->GetMediumLevelIL();
	for (size_t i = 0; i < mlilFunc->GetInstructionCount(); i++)
	{
		MediumLevelILInstruction instruction = mlilFunc->GetInstruction(i);
		if ((instruction.operation == MLIL_RET) || (instruction.operation == MLIL_TAILCALL))
			returnAddresses.push_back(instruction.address);
	}

	return StepToInternal(returnAddresses);
}


DebugStopReason DebuggerController::StepReturn()
{
	if (!CanResumeTarget())
	    DebugStopReason::InvalidStatusOrOperation;

    m_state->SetExecutionStatus(DebugAdapterRunningStatus);

	DebuggerEvent event;
	event.type = StepOverEventType;
	PostDebuggerEvent(event);

	DebugStopReason reason = StepReturnInternal();

	m_state->MarkDirty();
    m_state->SetExecutionStatus(DebugAdapterPausedStatus);

    HandleTargetStop(reason);
	return reason;
}


DebugStopReason DebuggerController::StepToInternal(const std::vector<uint64_t>& remoteAddresses)
{
    for (uint64_t remoteAddress: remoteAddresses)
    {
        if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
        {
            m_adapter->AddBreakpoint(remoteAddress);
        }
    }

	DebugStopReason reason = GoInternal();

    for (uint64_t remoteAddress: remoteAddresses)
    {
        if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
        {
            m_adapter->RemoveBreakpoint(remoteAddress);
        }
    }

	return reason;
}


DebugStopReason DebuggerController::StepTo(const std::vector<uint64_t>& remoteAddresses)
{
	if (!CanResumeTarget())
	    return DebugStopReason::InvalidStatusOrOperation;

    m_state->SetExecutionStatus(DebugAdapterRunningStatus);

	DebuggerEvent event;
	event.type = StepOverEventType;
	PostDebuggerEvent(event);

	DebugStopReason reason = StepToInternal(remoteAddresses);

	m_state->MarkDirty();
    m_state->SetExecutionStatus(DebugAdapterPausedStatus);

    HandleTargetStop(reason);
	return reason;
}


void DebuggerController::HandleTargetStop(DebugStopReason reason)
{
    if (reason == DebugStopReason::ProcessExited)
    {
        DebuggerEvent event;
        event.type = TargetExitedEventType;
        // get exit code
        PostDebuggerEvent(event);
    }
    else if (reason == DebugStopReason::InternalError)
    {
        DebuggerEvent event;
        event.type = InternalErrorEventType;
        PostDebuggerEvent(event);
    }
    else if (reason == DebugStopReason::InvalidStatusOrOperation)
    {
        DebuggerEvent event;
        event.type = InvalidOperationEventType;
        PostDebuggerEvent(event);
    }
    else
    {
        DebuggerEvent event;
        event.type = TargetStoppedEventType;
        event.data.targetStoppedData.reason = reason;
        PostDebuggerEvent(event);
    }
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


void DebuggerController::Restart()
{
    Quit();
    Launch();
}


void DebuggerController::Attach()
{
    if (m_state->IsConnected())
        return;

    m_adapter = CreateDebugAdapter();
    if (!m_adapter)
        return;

    m_state->SetAdapter(m_adapter);

    m_state->SetConnectionStatus(DebugAdapterConnectingStatus);

    DebuggerEvent event;
    event.type = AttachEventType;
    PostDebuggerEvent(event);

    bool ok = m_adapter->Connect(m_state->GetRemoteHost(), m_state->GetRemotePort());

    if (ok)
    {
        m_state->MarkDirty();
        m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
        m_state->SetExecutionStatus(DebugAdapterPausedStatus);
        NotifyStopped(DebugStopReason::InitialBreakpoint);
    }
    else
    {
        LogWarn("fail to connect to the target");
    }
}


void DebuggerController::Detach()
{
    if (!m_state->IsConnected())
        return;

    NotifyEvent(DetachEventType);

    // TODO: return whether the operation is successful
    m_adapter->Detach();

    m_state->MarkDirty();
    m_adapter = nullptr;
    SetLiveView(nullptr);
    m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
    m_state->SetExecutionStatus(DebugAdapterInvalidStatus);
    NotifyEvent(DetachedEventType);
}


void DebuggerController::Quit()
{
    if (!m_state->IsConnected())
        return;

    if (m_state->IsRunning())
    {
        Pause();
        while (m_state->IsRunning()) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    }

//    NotifyEvent(DetachEventType);

    // TODO: return whether the operation is successful
    m_adapter->Quit();

    m_state->MarkDirty();
    m_adapter = nullptr;
    SetLiveView(nullptr);
    m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
    m_state->SetExecutionStatus(DebugAdapterInvalidStatus);

    NotifyEvent(QuitDebuggingEventType);
}


void DebuggerController::Pause()
{
    if (!(m_state->IsConnected() && m_state->IsRunning()))
        return;

    // Don't do anything else here-- one of the other running thread will post it
    m_adapter->BreakInto();
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
		Attach();
}


DebuggerController* DebuggerController::GetController(BinaryViewRef data)
{
    for (auto& controller: g_debuggerControllers)
    {
        if (controller->GetData()->GetFile()->GetOriginalFilename() == data->GetFile()->GetOriginalFilename())
            return controller;
        if (controller->GetData()->GetFile()->GetOriginalFilename() == data->GetParentView()->GetFile()->GetOriginalFilename())
            return controller;
//        if (controller->GetData()->GetFile() == data->GetFile())
//            return controller;
//        if (controller->GetLiveView() && (controller->GetLiveView()->GetFile() == data->GetFile()))
//            return controller;
    }

    DebuggerController* controller = new DebuggerController(data);
    g_debuggerControllers.push_back(controller);
    return controller;
}


bool DebuggerController::ControllerExists(BinaryViewRef data)
{
	// TODO: this function duplicates some code in DebuggerController::GetController()
    for (auto& controller: g_debuggerControllers)
    {
        if (controller->GetData()->GetFile()->GetOriginalFilename() == data->GetFile()->GetOriginalFilename())
            return true;
        if (controller->GetData()->GetFile()->GetOriginalFilename() == data->GetParentView()->GetFile()->GetOriginalFilename())
            return true;
    }
	return false;
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


// This is the central hub of event dispatch. All events first arrive here and then get dispatched based on the content
void DebuggerController::EventHandler(const DebuggerEvent& event)
{
    switch (event.type)
    {
	case StdoutMessageEventType:
	{
		const std::string message = event.data.messageData.message;
		LogWarn("%s\n", message.c_str());
		break;
	}
//	case ResumeEventType:
//	case StepIntoEventType:
//	case StepOverEventType:
//	case StepReturnEventType:
//	case StepToEventType:
//		// TODO: I am not super sure whether we should do it here, or we should let DebuggerState manage this by itself.
//		// The problem is, if we do not do it here, then the DebuggerState will also have to emit these events.
//		// Otherwise, there is a race condition that the callbacks (registered by other consumers) will execute before
//		// DebuggerState updates its state, causing nondeterministic behavior.
//		m_state->SetExecutionStatus(DebugAdapterRunningStatus);
//		break;

//	case DetachedEventType:
//	case QuitDebuggingEventType:
	case TargetExitedEventType:
	{
        m_state->MarkDirty();
        m_adapter = nullptr;
        SetLiveView(nullptr);
        m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
        m_state->SetExecutionStatus(DebugAdapterInvalidStatus);
		break;
	}
    case TargetStoppedEventType:
    {
        // Initial breakpoint is reached after successfully launching or attaching to the target
        if (event.data.targetStoppedData.reason == DebugStopReason::InitialBreakpoint)
        {
            m_state->UpdateCaches();
            // We need to apply the breakpoints that the user has set up before launching the target. Note this requires
            // the modules to be updated properly beforehand.
            m_state->ApplyBreakpoints();

            // Rebase the binary and create DebugView
            uint64_t remoteBase = m_state->GetRemoteBase();

            FileMetadataRef fileMetadata = m_data->GetFile();
            if (remoteBase != m_data->GetStart())
            {
                // remote base is different from the local base, first need a rebase
				ExecuteOnMainThreadAndWait([=](){
					ProgressIndicator progress(nullptr, "Rebase", "Rebasing...");
					if (!fileMetadata->Rebase(m_data, remoteBase,
											  [&](size_t cur, size_t total) { progress.update((int)cur, (int)total); }))
					{
						LogWarn("rebase failed");
					}
				});
            }

            Ref<BinaryView> rebasedView = fileMetadata->GetViewOfType(m_data->GetTypeName());
//			TODO: I do not think we should use the rebased view to replace m_data right now, but I remember there was
//			an discussion on it. Remember to check this out later.
//			Update: this line must be kept unless we change the FileMetadata::Rebase(), so that it does not register
//			the rebased view. Otherwise, it causes random crashes and/or unexpected behavior
            SetData(rebasedView);
            LogWarn("the base of the rebased view is 0x%lx", rebasedView->GetStart());

			ExecuteOnMainThreadAndWait([=](){
				ProgressIndicator progress(nullptr, "Debugger View", "Creating debugger view...");
				bool ok = fileMetadata->CreateSnapshotedView(rebasedView, "Debugger",
														[&](size_t cur, size_t total) { progress.update((int)cur, (int)total); });
				if (!ok)
					LogWarn("create snapshoted view failed");
			});

            BinaryViewRef liveView = fileMetadata->GetViewOfType("Debugger");
			if (!liveView)
			{
				LogWarn("Invalid Debugger view!");
				break;
			}
            SetLiveView(liveView);

            DebuggerEvent event;
            event.type = InitialViewRebasedEventType;
            PostDebuggerEvent(event);
        }
		else
        {
            m_state->UpdateCaches();
        }

        // Update the instruction pointer
        m_lastIP = m_currentIP;
        m_currentIP = m_state->IP();

        break;
    }
	case RelativeBreakpointAddedEvent:
	{
		DebuggerModules* modules = m_state->GetModules();
		uint64_t address = modules->RelativeAddressToAbsolute(event.data.relativeAddress);

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		if (m_liveView)
			dataAndAddress.emplace_back(m_liveView, address);

		if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module,
										  m_data->GetFile()->GetOriginalFilename()))
		{
			dataAndAddress.emplace_back(m_data, m_data->GetStart() + event.data.relativeAddress.offset);
		}

		for (auto& [data, address]: dataAndAddress)
		{
			for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
			{
				bool tagFound = false;
				for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
				{
					if (tag->GetType() == getBreakpointTagType(data))
					{
						tagFound = true;
						break;
					}
				}

				if (!tagFound)
				{
					func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, RedHighlightColor);
					func->CreateUserAddressTag(data->GetDefaultArchitecture(), address, getBreakpointTagType(data),
												   "breakpoint");
				}
			}
		}
		break;
	}
	case AbsoluteBreakpointAddedEvent:
	{
		uint64_t address = event.data.absoluteAddress;

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		BinaryViewRef data = GetLiveView();
		if (data)
			dataAndAddress.emplace_back(data, address);

		DebuggerModules* modules = m_state->GetModules();
		ModuleNameAndOffset relative = modules->AbsoluteAddressToRelative(address);
		if (DebugModule::IsSameBaseModule(relative.module, m_data->GetFile()->GetOriginalFilename()))
		{
			dataAndAddress.emplace_back(m_data, m_data->GetStart() + relative.offset);
		}

		for (auto& [data, address]: dataAndAddress)
		{
			for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
			{
				bool tagFound = false;
				for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
				{
					if (tag->GetType() == getBreakpointTagType(data))
					{
						tagFound = true;
						break;
					}
				}

				if (!tagFound)
				{
					func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, RedHighlightColor);
					func->CreateUserAddressTag(data->GetDefaultArchitecture(), address, getBreakpointTagType(data),
												   "breakpoint");
				}
			}
		}
		break;
	}
	case RelativeBreakpointRemovedEvent:
	{
		DebuggerModules* modules = m_state->GetModules();
		uint64_t address = modules->RelativeAddressToAbsolute(event.data.relativeAddress);

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		if (m_liveView)
			dataAndAddress.emplace_back(m_liveView, address);

		if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module,
										  m_data->GetFile()->GetOriginalFilename()))
		{
			dataAndAddress.emplace_back(m_data, m_data->GetStart() + event.data.relativeAddress.offset);
		}

		for (auto& [data, address]: dataAndAddress)
		{
			for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
			{
				func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, NoHighlightColor);
				for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
				{
					if (tag->GetType() != getBreakpointTagType(data))
						continue;

					func->RemoveUserAddressTag(data->GetDefaultArchitecture(), address, tag);
				}
			}
		}
		break;
	}
	case AbsoluteBreakpointRemovedEvent:
	{
		uint64_t address = event.data.absoluteAddress;

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		BinaryViewRef data = GetLiveView();
		if (data)
			dataAndAddress.emplace_back(data, address);

		DebuggerModules* modules = m_state->GetModules();
		ModuleNameAndOffset relative = modules->AbsoluteAddressToRelative(address);
		if (DebugModule::IsSameBaseModule(relative.module, m_data->GetFile()->GetOriginalFilename()))
		{
			dataAndAddress.emplace_back(m_data, m_data->GetStart() + relative.offset);
		}

		for (auto& [data, address]: dataAndAddress)
		{
			for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
			{
				func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, NoHighlightColor);
				for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
				{
					if (tag->GetType() != getBreakpointTagType(data))
						continue;

					func->RemoveUserAddressTag(data->GetDefaultArchitecture(), address, tag);
				}
			}
		}
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
    std::unique_lock<std::recursive_mutex> lock(m_queueMutex);
    m_events.push(event);
}


void DebuggerController::Worker()
{
    while (true)
    {
		std::unique_lock<std::recursive_mutex> callbackLock(m_callbackMutex);
		std::vector<DebuggerEventCallback> eventCallbacks = m_eventCallbacks;
		callbackLock.unlock();

        std::unique_lock<std::recursive_mutex> lock(m_queueMutex);
        if (m_events.size() != 0)
        {
            const DebuggerEvent event = m_events.front();
            m_events.pop();

            lock.unlock();

            for (auto cb: eventCallbacks)
            {
				// TODO: what if cb.function calls PostDebuggerEvent()? Which would try to acquire the queue mutex
                cb.function(event);
            }
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

	std::vector<uint8_t > buffer;
	buffer.resize(size);
	size_t bytesRead = m_liveView->Read(buffer.data(), address, size);
	if (bytesRead == 0)
		return DataBuffer{};

	return DataBuffer(buffer.data(), bytesRead);
}


bool DebuggerController::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
    if (!m_liveView)
        return false;

	return m_liveView->WriteBuffer(address, buffer);
}
