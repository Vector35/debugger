#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QStatusBar>
#include "debuggerwidget.h"
#include "statusbar.h"
#include "ui.h"

using namespace BinaryNinja;
using namespace std;


DebuggerWidget::DebuggerWidget(const QString& name, ViewFrame* view, BinaryViewRef data):
    SidebarWidget(name), m_view(view), m_data(data)
{
	bool newController = !DebuggerController::ControllerExists(data);
    m_controller = DebuggerController::GetController(m_data);

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->setAlignment(Qt::AlignTop);

    m_splitter = new QSplitter(Qt::Vertical, this);
    m_splitter->setChildrenCollapsible(true);

    m_controlsWidget = new DebugControlsWidget(this, "Controls", data);

    m_registersWidget = new DebugRegistersWidget("Native Debugger Registers",
                                                     m_view, m_data);

    m_breakpointsWidget = new DebugBreakpointsWidget("Native Debugger Breakpoints",
                                                                           m_view, m_data, m_menu);

    m_modulesWidget = new DebugModulesWidget("Native Debugger Modules",
                                                                           m_view, m_data);

    m_threadsWidget = new DebugThreadsWidget("Native Debugger Threads",
                                                                           m_view, m_data);

    m_stackWidget = new DebugStackWidget("Native Debugger Stack",
                                                               m_view, m_data);

    auto registerLayout = new QVBoxLayout();
    registerLayout->setContentsMargins(0, 0, 0, 0);
    registerLayout->addWidget(m_registersWidget);

    auto bpLayout = new QVBoxLayout();
    bpLayout->setContentsMargins(0, 0, 0, 0);
    bpLayout->addWidget(m_breakpointsWidget);

    auto modulesLayout = new QVBoxLayout();
    modulesLayout->setContentsMargins(0, 0, 0, 0);
    modulesLayout->addWidget(m_modulesWidget);

    auto threadsLayout = new QVBoxLayout();
    threadsLayout->setContentsMargins(0, 0, 0, 0);
    threadsLayout->addWidget(m_threadsWidget);

    auto stackLayout = new QVBoxLayout();
    stackLayout->setContentsMargins(0, 0, 0, 0);
    stackLayout->addWidget(m_stackWidget);

    m_registersGroup = new ExpandableGroup(registerLayout, "Registers");
    m_breakpointsGroup = new ExpandableGroup(bpLayout, "Breakpoints");
    m_stackGroup = new ExpandableGroup(stackLayout, "Stack");
    m_modulesGroup = new ExpandableGroup(modulesLayout, "Modules");
    m_threadsGroup = new ExpandableGroup(threadsLayout, "Threads");

    m_splitter->addWidget(m_controlsWidget);
    m_splitter->addWidget(m_registersGroup);
    m_splitter->addWidget(m_breakpointsGroup);
    m_splitter->addWidget(m_stackGroup);
    m_splitter->addWidget(m_modulesGroup);
    m_splitter->addWidget(m_threadsGroup);

    layout->addWidget(m_splitter);
    setLayout(layout);

	UIContext* context = UIContext::contextForWidget(view);
	if (context && newController)
	{
		// Only add one status bar widget for one controller
		// This is only a temporary solution, a better way to deal with it is to leverage UIContext,
		// similar to how collab does it
		DebuggerStatusBar* statusBar = new DebuggerStatusBar(m_controller);
		context->mainWindow()->statusBar()->insertWidget(0, statusBar);
	}

    m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
        uiEventHandler(event);
    });
}


DebuggerWidget::~DebuggerWidget()
{
//    disconnect(m_ui, &DebuggerUI::contextChanged, 0, 0);
	m_controller->RemoveEventCallback(m_eventCallback);
}


void DebuggerWidget::notifyFontChanged()
{
    LogWarn("font changed");
}


void DebuggerWidget::updateContent()
{
    LogWarn("DebuggerWidget::updateContext()");
    m_registersWidget->updateContent();
    m_modulesWidget->updateContent();
    m_threadsWidget->updateContent();
    m_stackWidget->updateContent();
}


void DebuggerWidget::uiEventHandler(const DebuggerEvent &event)
{
    switch (event.type)
    {
    case TargetStoppedEventType:
        // These updates ensure the widgets become empty after the target stops
    case DetachedEventType:
    case QuitDebuggingEventType:
    case BackEndDisconnectedEventType:
        updateContent();
    default:
        break;
    }
}
