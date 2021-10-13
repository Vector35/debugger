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
//    switch (event.type)
//    {
//    case InitialViewRebasedEventType:
//    {
//        LogWarn("InitialViewRebasedEventType event");
//        break;
//    }
//    default:
//        break;
//    }
}

//
//void DebuggerUI::OnStep()
//{
//    DetectNewCode();
//    AnnotateContext();
//}
//
//
//void DebuggerUI::DetectNewCode()
//{
//
//}
//
//
//void DebuggerUI::AnnotateContext()
//{
//
//}


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
    if (view->GetTypeName() == "Debugged Process")
        isAbsoluteAddress = true;

    DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
    if (isAbsoluteAddress)
    {
        if (breakpoints->ContainsAbsolute(addr))
        {
            controller->DeleteBreakpoint(addr);
        }
        else
        {
            controller->AddBreakpoint(addr);
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


static bool BreakpointToggleValid(BinaryView* view, uint64_t addr)
{
    return true;
}


static void StepToHereCallback(BinaryView* view, uint64_t addr)
{
    DebuggerState* state = DebuggerState::GetState(view);
    uint64_t remoteAddr = state->GetMemoryView()->LocalAddressToRemote(addr);
    state->StepTo({remoteAddr});
    // TODO: this does not work since the UI state will not be updated after this
}


static bool StepToHereValid(BinaryView* view, uint64_t addr)
{
    return true;
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

//    Sidebar::addSidebarWidgetType(
//            new DebugRegistersWidgetType(create_icon_with_letter("R"), "Native Debugger Registers"));

    PluginCommand::RegisterForAddress("Native Debugger\\Toggle Breakpoint",
            "sets/clears breakpoint at right-clicked address",
            BreakpointToggleCallback, BreakpointToggleValid);
    UIAction::setUserKeyBinding("Native Debugger\\Toggle Breakpoint", { QKeySequence(Qt::Key_F2) });

    PluginCommand::RegisterForAddress("Native Debugger\\Step To Here",
            "step over to the current selected address",
            StepToHereCallback, StepToHereValid);
}
