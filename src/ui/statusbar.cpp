#include "statusbar.h"


DebuggerStatusBar::DebuggerStatusBar(DebuggerController* controller): m_controller(controller)
{
	setText("Inactive");
	m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
		uiEventHandler(event);
	});
}


DebuggerStatusBar::~DebuggerStatusBar()
{
	m_controller->RemoveEventCallback(m_eventCallback);
}


void DebuggerStatusBar::uiEventHandler(const DebuggerEvent &event)
{
	switch (event.type)
	{
	case LaunchEventType:
		updateText("Launching");
		break;
	case ResumeEventType:
		updateText("Running");
		break;
	case StepIntoEventType:
		updateText("Stepping into");
		break;
	case StepOverEventType:
		updateText("Stepping over");
		break;
	case StepReturnEventType:
		updateText("Stepping return");
		break;
	case RestartEventType:
		updateText("Restarting");
		break;
	case AttachEventType:
		updateText("Attaching");
		break;

    case TargetStoppedEventType:
		// TODO: add reason of stop
		updateText("Stopped");
		break;
	case TargetExitedEventType:
		// TODO: add exit code
		updateText("Exited");
		break;
    case DetachedEventType:
		updateText("Detached");
		break;
    case QuitDebuggingEventType:
		updateText("Aborted");
		break;
    case BackEndDisconnectedEventType:
		updateText("Backend disconnected");
		break;

		// The update should be stateless, i.e., does not require knowing what the last event is.
		// Instead, it should work by querying the status of the controller.
		// Only in this way, the status bar can display the correct content when the user switched to different tabs
		// and get back. For now, just do it in the simple way.
		// One issue complicating the situation is the controller's callback MUST be executed before any other callback.
		// Otherwise, the update could be incomplete and the status will be wrong.
		// We can either have the controller always call its own callback first, or put the callbacks into a priority queue.
		// updateText();

	default:
		break;
	}
}


void DebuggerStatusBar::updateText(QString text)
{
	m_controller->GetState()->GetConnectionStatus();
	// some text might show up and disappear so quickly that we cannot see it. Log all of them to the console.
	LogWarn("debugger: %s", text.toStdString().c_str());
	setText(text);
}
