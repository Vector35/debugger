#include "statusbar.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "inttypes.h"
#include "fmt/format.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

DebuggerStatusBarWidget::DebuggerStatusBarWidget(QWidget* parent, ViewFrame* frame, BinaryViewRef data):
	QWidget(parent), m_view(frame)
{
	m_debugger = DebuggerController::GetController(data);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);
	setFont(getMonospaceFont(this));

	m_status = new QLabel("Inactive");
	layout->addWidget(m_status);

	setLayout(layout);

	connect(this, &DebuggerStatusBarWidget::debuggerEvent, this, &DebuggerStatusBarWidget::updateStatusText);
    m_debuggerEventCallback = m_debugger->RegisterEventCallback([this](const DebuggerEvent& event){
		ExecuteOnMainThreadAndWait([=](){
			emit debuggerEvent(event);
		});
    });
}


DebuggerStatusBarWidget::~DebuggerStatusBarWidget()
{
	m_debugger->RemoveEventCallback(m_debuggerEventCallback);
}


void DebuggerStatusBarWidget::setStatusText(const QString &text)
{
	m_status->setText(text);
}


void DebuggerStatusBarWidget::updateStatusText(const DebuggerEvent &event)
{
	switch (event.type)
	{
	case LaunchEventType:
		setStatusText("Launching");
		break;
	case ResumeEventType:
		setStatusText("Running");
		break;
	case StepIntoEventType:
		setStatusText("Stepping into");
		break;
	case StepOverEventType:
		setStatusText("Stepping over");
		break;
	case StepReturnEventType:
		setStatusText("Stepping return");
		break;
	case StepToEventType:
		setStatusText("Stepping to");
		break;
	case RestartEventType:
		setStatusText("Restarting");
		break;
	case AttachEventType:
		setStatusText("Attaching");
		break;
	case ConnectEventType:
		setStatusText("Connecting");
		break;

    case TargetStoppedEventType:
	{
		DebugStopReason reason = event.data.targetStoppedData.reason;
		const std::string reasonString = DebuggerController::GetDebugStopReasonString(reason);
		setStatusText(QString::fromStdString(fmt::format("Stopped ({})", reasonString)));
		break;
	}
	case TargetExitedEventType:
	{
		uint8_t exitCode = event.data.exitData.exitCode;
		setStatusText(QString::fromStdString(fmt::format("Exited with code {}", exitCode)));
		break;
	}
    case DetachedEventType:
		setStatusText("Detached");
		break;
    case QuitDebuggingEventType:
		setStatusText("Aborted");
		break;
    case BackEndDisconnectedEventType:
		setStatusText("Backend disconnected");
		break;
	default:
		break;
	}
}


DebuggerStatusBarContainer::DebuggerStatusBarContainer():
	m_currentFrame(nullptr), m_consoleStack(new QStackedWidget)
{
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_consoleStack);

	auto* noViewLabel = new QLabel("No active view.");
//	noViewLabel->setStyleSheet("QLabel { background: palette(base); }");
	noViewLabel->setAlignment(Qt::AlignCenter);

	m_consoleStack->addWidget(noViewLabel);
}


DebuggerStatusBarWidget* DebuggerStatusBarContainer::currentConsole() const
{
	if (m_consoleStack->currentIndex() == 0)
		return nullptr;

	return qobject_cast<DebuggerStatusBarWidget*>(m_consoleStack->currentWidget());
}


void DebuggerStatusBarContainer::freeDebuggerConsoleForView(QObject* obj)
{
	// A old-style cast must be used here since qobject_cast will fail because
	// the object is on the brink of deletion.
	auto* vf = (ViewFrame*)obj;

	auto data = vf->getCurrentBinaryView();
	auto controller = DebuggerController::GetController(data);

	// Confirm there is a record of this view.
	if (!m_consoleMap.count(controller)) {
		LogWarn("Attempted to free DebuggerConsole for untracked view %p", obj);
		return;
	}

	auto* console = m_consoleMap[controller];
	m_consoleStack->removeWidget(console);
	m_consoleMap.erase(controller);

	// Must be called so the ChatBox is guaranteed to be destoryed. If two
	// instances for the same view/database exist, things will break.
	console->deleteLater();
}


void DebuggerStatusBarContainer::notifyViewChanged(ViewFrame* frame)
{
	// The "no active view" message widget is always located at index 0. If the
	// frame passed is nullptr, show it.
	if (!frame) {
		m_consoleStack->setCurrentIndex(0);
		m_currentFrame = nullptr;

		return;
	}

	// The notifyViewChanged event can fire multiple times for the same frame
	// even if there is no apparent change. Compare the new frame to the
	// current one before continuing to avoid unnecessary work.
	if (frame == m_currentFrame)
		return;
	m_currentFrame = frame;

	auto data = frame->getCurrentBinaryView();
	Ref<DebuggerController> controller = DebuggerController::GetController(data);

	// Get the appropriate DebuggerConsole for this ViewFrame, or create a new one if it
	// doesn't yet exist. The default value for non-existent keys of pointer
	// types in Qt containers is nullptr, which allows this logic below to work.
	auto iter = m_consoleMap.find(controller);
	DebuggerStatusBarWidget* currentConsole;
	if (iter == m_consoleMap.end())
	{
		currentConsole = new DebuggerStatusBarWidget(this, frame, data);

		// DockWidgets related to a ViewFrame are automatically cleaned up as
		// part of the ViewFrame destructor. To ensure there is never a DebuggerConsole
		// for a non-existent ViewFrame, the cleanup must be configured manually.
//		connect(frame, &QObject::destroyed, this, &GlobalConsoleContainer::freeDebuggerConsoleForView);

		m_consoleMap[controller] = currentConsole;
		m_consoleStack->addWidget(currentConsole);
	}
	else
	{
		currentConsole = iter->second;
	}

	m_consoleStack->setCurrentWidget(currentConsole);
}
