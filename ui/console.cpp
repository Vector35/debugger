#include "console.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

DebuggerConsole::DebuggerConsole(QWidget* parent, ViewFrame* frame, BinaryViewRef data):
	QWidget(parent), m_view(frame)
{
	m_debugger = DebuggerController::GetController(data);

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);
	setFont(getMonospaceFont(this));

	// Initialize widgets and layout
	m_consoleLog = new QTextBrowser(this);
	m_consoleLog->setReadOnly(true);
	m_consoleLog->setTextInteractionFlags(m_consoleLog->textInteractionFlags() | Qt::LinksAccessibleByMouse);

	m_consoleInput = new QLineEdit(this);
	m_consoleInput->setPlaceholderText("");

	connect(m_consoleInput, &QLineEdit::returnPressed, this, &DebuggerConsole::sendMessage);

	layout->addWidget(m_consoleLog);
	layout->addWidget(m_consoleInput);
	setLayout(layout);

	// Set up colors
	QPalette widgetPalette = this->palette();
	QColor foreground = widgetPalette.color(QWidget::foregroundRole());
	QColor background = widgetPalette.color(QWidget::backgroundRole());

	m_debuggerEventCallback = m_debugger->RegisterEventCallback([&](const DebuggerEvent& event){
		if (event.type == StdoutMessageEventType)
		{
			const std::string message = event.data.messageData.message;
			ExecuteOnMainThreadAndWait([&](){
				addMessage(QString::fromStdString(message));
			});
		}
	});
}


DebuggerConsole::~DebuggerConsole()
{
	m_debugger->RemoveEventCallback(m_debuggerEventCallback);
}


void DebuggerConsole::sendMessage()
{
	QString message = m_consoleInput->text();
	sendText(message + '\n');
	m_consoleInput->clear();
}


void DebuggerConsole::addMessage(const QString &msg)
{
	m_consoleLog->setText(m_consoleLog->toPlainText() + msg);
}


void DebuggerConsole::sendText(const QString &msg)
{
	m_debugger->WriteStdin(msg.toStdString());
}


GlobalConsoleContainer::GlobalConsoleContainer(const QString& title) : GlobalAreaWidget(title),
	m_currentFrame(nullptr), m_consoleStack(new QStackedWidget)
{
	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_consoleStack);

	auto* noViewLabel = new QLabel("No active view.");
	noViewLabel->setStyleSheet("QLabel { background: palette(base); }");
	noViewLabel->setAlignment(Qt::AlignCenter);

	m_consoleStack->addWidget(noViewLabel);
}


DebuggerConsole* GlobalConsoleContainer::currentConsole() const
{
	if (m_consoleStack->currentIndex() == 0)
		return nullptr;

	return qobject_cast<DebuggerConsole*>(m_consoleStack->currentWidget());
}


void GlobalConsoleContainer::freeDebuggerConsoleForView(QObject* obj)
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


void GlobalConsoleContainer::sendText(const QString &msg) const
{
	auto* cc = currentConsole();
	if (!cc)
		return;

	cc->sendText(msg);
}


void GlobalConsoleContainer::notifyViewChanged(ViewFrame* frame)
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
	DebuggerConsole* currentConsole;
	if (iter == m_consoleMap.end())
	{
		currentConsole = new DebuggerConsole(this, frame, data);

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
