#include "ui.h"
#include "binaryninjaapi.h"
#include "breakpointswidget.h"
#include "moduleswidget.h"
#include "threadswidget.h"
#include "stackwidget.h"
#include "debuggerwidget.h"
#include "QPainter"

using namespace BinaryNinja;

DebuggerUI::DebuggerUI(DebuggerController* controller): m_controller(controller)
{
    // TODO: The constructor of DebuggerUI does not create the DebugView. Instead, the DebugView is
    // created by BinaryNinja, and the constructor of DebugView sets itself as the m_debugView of the
    // DebuggerUI. I understand the reason for this implementation, but its realy not a good idea.
    m_sidebar = nullptr;

//    m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
//        uiEventHandler(event);
//    });
}


void DebuggerUI::uiEventHandler(const DebuggerEvent &event)
{
}


void DebuggerUI::SetDebuggerSidebar(DebuggerWidget* widget)
{
    m_sidebar = widget;
}


static void BreakpointToggleCallback(BinaryView* view, uint64_t addr)
{
    DebuggerController* controller = DebuggerController::GetController(view);
    DebuggerState* state = controller->GetState();

    bool isAbsoluteAddress = false;
    // TODO: check if this works
    if (view->GetTypeName() == "Debugger")
        isAbsoluteAddress = true;

    DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
    if (isAbsoluteAddress)
    {
		ModuleNameAndOffset relativeAddress = state->GetModules()->AbsoluteAddressToRelative(addr);
        if (breakpoints->ContainsOffset(relativeAddress))
        {
            controller->DeleteBreakpoint(relativeAddress);
        }
        else
        {
            controller->AddBreakpoint(relativeAddress);
        }
    }
    else
    {
        std::string filename = view->GetFile()->GetOriginalFilename();
        uint64_t offset = addr - view->GetStart();
        ModuleNameAndOffset info = {filename, offset};
        if (breakpoints->ContainsOffset(info))
        {
            controller->DeleteBreakpoint(info);
        }
        else
        {
            controller->AddBreakpoint(info);
        }
    }
}


static bool BinaryViewValid(BinaryView* view, uint64_t addr)
{
    return true;
}


static void StepToHereCallback(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	controller->StepTo({addr});
}


static bool ConnectedAndStopped(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	return controller->GetState()->IsConnected() && (!controller->GetState()->IsRunning());
}


static bool ConnectedAndRunning(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	return controller->GetState()->IsConnected() && controller->GetState()->IsRunning();
}


void DebuggerUI::InitializeUI()
{
    auto create_icon_with_letter = [](const QString& letter) {
        auto icon = QImage(56, 56, QImage::Format_RGB32);
        icon.fill(0);
        auto painter = QPainter();
        painter.begin(&icon);
        painter.setFont(QFont("Open Sans", 56));
        painter.setPen(QColor(255, 255, 255, 255));
        painter.drawText(QRectF(0, 0, 56, 56), Qt::Alignment(Qt::AlignCenter), letter);
        painter.end();
        return icon;
    };

    Sidebar::addSidebarWidgetType(
        new DebuggerWidgetType(create_icon_with_letter("D"), "Native Debugger"));

	// We must use the sequence of these four calls to do the job, otherwise the keybinding does not work.
	// Though it really should be the case where I can specify the keybinding in the first registerAction() call.
	UIAction::registerAction("Native Debugger\\Toggle Breakpoint");
	UIAction::registerAction("Selection Target\\Native Debugger\\Toggle Breakpoint");
	PluginCommand::RegisterForAddress("Native Debugger\\Toggle Breakpoint",
            "Sets/clears breakpoint at right-clicked address",
            BreakpointToggleCallback, BinaryViewValid);
    UIAction::setUserKeyBinding("Native Debugger\\Toggle Breakpoint", { QKeySequence(Qt::Key_F2) });

	UIAction::registerAction("Native Debugger\\Step To Here");
	UIAction::registerAction("Selection Target\\Native Debugger\\Step To Here");
	PluginCommand::RegisterForAddress("Native Debugger\\Step To Here",
            "Steps over until the current address",
            StepToHereCallback, ConnectedAndStopped);

	std::string actionName = "Run";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Launch, connect to or resume the target",
			[](BinaryView* view, uint64_t addr){
					DebuggerController* controller = DebuggerController::GetController(view);
					if (controller->GetState()->IsConnected() && (!controller->GetState()->IsRunning()))
					{
						controller->Go();
					}
					else if (!controller->GetState()->IsConnected())
					{
						controller->LaunchOrConnect();
					}
				},
			BinaryViewValid);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F9) });

	actionName = "Step Into";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Step into",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					controller->StepInto(graphType);
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F7) });

	actionName = "Step Over";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Step over",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					controller->StepOver(graphType);
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F8) });

	actionName = "Step Return";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Step return",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					controller->StepReturn(graphType);
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::ControlModifier | Qt::Key_F9) });

	actionName = "Pause";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Pause the target",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					controller->StepReturn(graphType);
				},
			ConnectedAndRunning);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F12) });
}
