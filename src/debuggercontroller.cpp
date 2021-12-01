#include "debuggercontroller.h"
#include <thread>
#include "../../ui/mainwindow.h"

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

    // TODO: we should add an option whether to add a breakpoint at program entry
    AddEntryBreakpoint();

    RegisterEventCallback([this](const DebuggerEvent& event){
        EventHandler(event);
    });

    // start the event queue worker
    std::thread worker([&](){
        Worker();
    });
    worker.detach();
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


void DebuggerController::Run()
{
	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);
    std::thread worker([this](){
        m_state->Run();
        NotifyStopped(DebugStopReason::InitalBreakpoint, nullptr);
    });
    worker.detach();
}


//    If one wishes to have a synchronous version of this, wait on a semaphore
void DebuggerController::Go()
{
	DebuggerEvent event;
	event.type = ResumeEventType;
	PostDebuggerEvent(event);
    std::thread worker([this](){
        m_state->Go();
		// This is actually problematic as NotifyStopped will always send a TargetStoppedEvent, but when the target exits,
		// a TargetExited event is already sent by the backend.
		// I am not 100% sure whether TargetExited should be a specific case of the general targetStoppedEvent, or
		// it should be an event type by its own. Remember to get back to this and resolve the issue.
        NotifyStopped(m_state->GetLastStopReason(), nullptr);
    });
    worker.detach();
}


void DebuggerController::StepInto(BNFunctionGraphType il)
{
    std::thread worker([this, il](){
        m_state->StepInto(il);
        NotifyStopped(m_state->GetLastStopReason(), nullptr);
    });
    worker.detach();
}


void DebuggerController::StepOver(BNFunctionGraphType il)
{
    std::thread worker([this, il](){
        m_state->StepOver(il);
//		WaitForTargetStop();
        NotifyStopped(m_state->GetLastStopReason(), nullptr);
    });
    worker.detach();
}


void DebuggerController::StepReturn(BNFunctionGraphType il)
{
    std::thread worker([this, il](){
        m_state->StepReturn();
        NotifyStopped(m_state->GetLastStopReason(), nullptr);
    });
    worker.detach();
}


void DebuggerController::Restart()
{
    std::thread worker([this](){
        m_state->Restart();
        NotifyStopped(DebugStopReason::InitalBreakpoint, nullptr);
    });
    worker.detach();
}


void DebuggerController::Attach()
{
    std::thread worker([this](){
        m_state->Attach();
        NotifyStopped(DebugStopReason::InitalBreakpoint, nullptr);
    });
    worker.detach();
}


void DebuggerController::Detach()
{
    std::thread worker([this](){
        m_state->Detach();
		NotifyEvent(DetachedEventType);
    });
    worker.detach();
}


void DebuggerController::Quit()
{
    std::thread worker([this](){
        m_state->Quit();
		NotifyEvent(QuitDebuggingEventType);
    });
    worker.detach();
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

    LogWarn("Creating a new Controller");
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
	case DetachedEventType:
	case QuitDebuggingEventType:
	case TargetExitedEventType:
	{
		m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterInvalidStatus);
		break;
	}
    case TargetStoppedEventType:
    {
        m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
        m_state->SetExecutionStatus(DebugAdapterPausedStatus);

        // Initial breakpoint is reached after successfully launching or attaching to the target
        if (event.data.targetStoppedData.reason == DebugStopReason::InitalBreakpoint)
        {
            // There are some extra processing needed when the initial breakpoint hits
            // HELP NEEDED: I do not think we should do it in this way, but I cannot think of a better one
            m_state->SetConnectionStatus(DebugAdapterConnectedStatus);

            m_state->UpdateRemoteArch();

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
//                DatabaseProgress progress(nullptr, "Rebase", "Rebasing...");
//                if (!fileMetadata->Rebase(m_data, remoteBase, [&](size_t cur, size_t total) { progress.update((int)cur, (int)total); }))
                if (!fileMetadata->Rebase(m_data, remoteBase))
                {
                    LogWarn("rebase failed");
                }
            }

            Ref<BinaryView> rebasedView = fileMetadata->GetViewOfType(m_data->GetTypeName());
            SetData(rebasedView);
            LogWarn("the base of the rebased view is 0x%lx", rebasedView->GetStart());
//            DatabaseProgress progress(nullptr, "Debug View", "Creating a BinaryView for debugging...");
//            if (!fileMetadata->CreateSnapshotedView(rebasedView, "Debugged Process", "Debugged Process Memory",
            if (!fileMetadata->CreateSnapshotedView(rebasedView, "Debugger", ""))
            {
                LogWarn("create snapshoted view failed");
            }
            else
            {
                LogWarn("create snapshoted view ok");
            }
            BinaryViewRef liveView = fileMetadata->GetViewOfType("Debugger");
            SetLiveView(liveView);

            DebuggerEvent event;
            event.type = InitialViewRebasedEventType;
            PostDebuggerEvent(event);
        }
        else if (event.data.targetStoppedData.reason == DebugStopReason::ProcessExited)
		{
			m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
			m_state->SetExecutionStatus(DebugAdapterInvalidStatus);
			break;
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
	std::vector<uint8_t > buffer;
	buffer.resize(size);
	size_t bytesRead = m_liveView->Read(buffer.data(), address, size);
	if (bytesRead == 0)
		return DataBuffer{};

	return DataBuffer(buffer.data(), bytesRead);
}


bool DebuggerController::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	return m_liveView->WriteBuffer(address, buffer);
}
