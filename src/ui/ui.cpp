#include "ui.h"
#include "binaryninjaapi.h"
#include "widget.h"
#include "breakpointswidget.h"
#include "moduleswidget.h"
#include "threadswidget.h"
#include "stackwidget.h"

using namespace BinaryNinja;

DebuggerUI::DebuggerUI(DebuggerState* state): m_state(state)
{
    // TODO: The constructor of DebuggerUI does not create the DebugView. Instead, the DebugView is 
    // created by BinaryNinja, and the constructor of DebugView sets itself as the m_debugView of the
    // DebuggerUI. I understand the reason for this implementation, but its realy not a good idea.
    m_debugView = nullptr;
    m_lastIP = 0;

    CreateBreakpointTagType();
    CreateProgramCounterTagType();

    ContextDisplay();
    UpdateHighlights();
    UpdateModules();
    UpdateBreakpoints();
}


void DebuggerUI::OnStep()
{
    DetectNewCode();
    AnnotateContext();
    ContextDisplay();
    UpdateBreakpoints();
    NavigateToIp();
}


void DebuggerUI::DetectNewCode()
{

}


void DebuggerUI::AnnotateContext()
{

}


void DebuggerUI::ContextDisplay()
{
    // This function assumes all of the cached information, e.g., registers, about the target is up-to-date.
    // It is the caller's responsibility to make sure that they are updated before calling this

    // TODO: lots of code above this are not implemennted yet

    DebugRegistersWidget* registersWidget = dynamic_cast<DebugRegistersWidget*>(widget("Native Debugger Registers"));
    DebugModulesWidget* modulesWidget = dynamic_cast<DebugModulesWidget*>(widget("Native Debugger Modules"));
    DebugThreadsWidget* threadsWidget = dynamic_cast<DebugThreadsWidget*>(widget("Native Debugger Threads"));
    DebugStackWidget* stackWidget = dynamic_cast<DebugStackWidget*>(widget("Native Debugger Stack"));

    if (!m_state->IsConnected())
    {
        // TODO: notify widgets with empty data
        if (registersWidget)
            registersWidget->notifyRegistersChanged({});
        if (modulesWidget)
            modulesWidget->notifyModulesChanged({});
        if (threadsWidget)
        {
            threadsWidget->notifyThreadsChanged({});
            if (m_debugView)
                m_debugView->getControls()->setThreadList({});
        }
        stackWidget->notifyStackChanged({});
        return;
    }

    if (registersWidget)
    {
        std::vector<DebugRegister> registers = m_state->GetRegisters()->GetAllRegisters();
        registersWidget->notifyRegistersChanged(registers);
    }

    if (modulesWidget)
    {
        std::vector<DebugModule> modules = m_state->GetModules()->GetAllModules();
        modulesWidget->notifyModulesChanged(modules);
    }

    if (threadsWidget)
    {
        std::vector<DebuggerThreadCache> threads = m_state->GetThreads()->GetAllThreads();
        threadsWidget->notifyThreadsChanged(threads);
        if (m_debugView)
            m_debugView->getControls()->setThreadList(threads);
    }

    if (stackWidget)
    {
        std::vector<DebugStackItem> stackItems;
        BinaryReader* reader = new BinaryReader(m_state->GetMemoryView());
        uint64_t stackPointer = m_state->StackPointer();
        size_t addressSize = m_state->GetRemoteArchitecture()->GetAddressSize();
        for (ptrdiff_t i = -8; i < 60 + 1; i++)
        {
            ptrdiff_t offset = i * addressSize;
            if ((offset < 0) && (stackPointer < (uint64_t)-offset))
                continue;

            uint64_t address = stackPointer + offset;
            reader->Seek(address);
            uint64_t value = -1ULL;
            switch (addressSize)
            {
            case 1:
                value = reader->Read8();
                break;
            case 2:
                value = reader->Read16();
                break;
            case 4:
                value = reader->Read32();
                break;
            case 8:
                value = reader->Read64();
                break;
            default:
                break;
            }
            stackItems.emplace_back(offset, address, value);
        }
        delete reader;

        stackWidget->notifyStackChanged(stackItems);
    }

    uint64_t localIP = m_state->LocalIP();
    BinaryNinja::LogWarn("localIP: 0x%" PRIx64 "\n", localIP);

    UpdateHighlights();
    m_lastIP = localIP;

    if (m_debugView)
    {
        if (m_state->GetData()->GetAnalysisFunctionsContainingAddress(localIP).size() > 0)
            m_debugView->getControls()->stateStopped();
        else
            m_debugView->getControls()->stateStoppedExtern();
    }
}


void DebuggerUI::NavigateToIp()
{
    if (!m_debugView)
        return;

    uint64_t ip;
    if (!m_state->IsConnected())
    {
        ip = m_state->GetData()->GetEntryPoint();
    }
    else
    {
        ip = m_state->IP();
    }

    ViewFrame* frame = ViewFrame::viewFrameForWidget(m_debugView);
    frame->navigate(m_state->GetData(), ip, true, true);
}


void DebuggerUI::SetDebugView(DebugView* debugView)
{
    m_debugView = debugView;
}


void DebuggerUI::CreateBreakpointTagType()
{
    TagTypeRef type = m_state->GetData()->GetTagType("Breakpoints");
    if (type)
    {
        m_breakpointTagType = type;
        return;
    }

    m_breakpointTagType = new TagType(m_state->GetData(), "Breakpoints", "🛑");
    m_state->GetData()->AddTagType(m_breakpointTagType);
}


void DebuggerUI::CreateProgramCounterTagType()
{
    TagTypeRef type = m_state->GetData()->GetTagType("Program Counter");
    if (type)
    {
        m_pcTagType = type;
        return;
    }

    m_pcTagType = new TagType(m_state->GetData(), "Program Counter", "==>");
    m_state->GetData()->AddTagType(m_pcTagType);
}


void DebuggerUI::UpdateHighlights()
{
    for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(m_lastIP))
    {
        ModuleNameAndOffset addr;
        addr.module = m_state->GetData()->GetFile()->GetOriginalFilename();
        addr.offset = m_lastIP - m_state->GetData()->GetStart();
    
        BNHighlightStandardColor oldColor = NoHighlightColor;
        if (m_state->GetBreakpoints()->ContainsOffset(addr))
            oldColor = RedHighlightColor;

        func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(), m_lastIP, oldColor);
        for (TagRef tag: func->GetAddressTags(m_state->GetData()->GetDefaultArchitecture(), m_lastIP))
        {
            if (tag->GetType() != m_pcTagType)
                continue;

            func->RemoveUserAddressTag(m_state->GetData()->GetDefaultArchitecture(), m_lastIP, tag);
        }
    }

    // There should be no need to manually set the breakpoint highlight like this.
    // Any changes to the DebuggerBreakpoints class should automatically trigger display updates, if the UI is present.
    // We also need a notion of internal breakpoints, e.g., thsoe used when continuing execution at a breakpoint,
    // whose changes do not trigger UI updates.
    // One concern is it might cause excessive UI updates when the breakpoints are added in bulky amounts.
    // Another concern is when new functions are added during debugging, any breakpoints added beforehand will not be
    // visiable.

    // for (const ModuleNameAndOffset& info: m_state->GetBreakpoints()->GetBreakpointList())
    // {
    //     if (info.module != m_state->GetData()->GetFile()->GetOriginalFilename())
    //         continue;

    //     uint64_t bp = m_state->GetData()->GetStart() + info.offset;
    //     for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(bp))
    //     {
    //         func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(), bp, RedHighlightColor);
    //     }
    // }

    if (m_state->IsConnected())
    {
        uint64_t localIP = m_state->LocalIP();
        for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(localIP))
        {
            func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(),
                    localIP, BlueHighlightColor);
            func->CreateUserAddressTag(m_state->GetData()->GetDefaultArchitecture(), localIP, m_pcTagType,
                    "program counter");
        }
    }
}


void DebuggerUI::UpdateModules()
{
    // TODO
}


void DebuggerUI::UpdateBreakpoints()
{
    std::vector<BreakpointItem> bps;
    std::vector<DebugBreakpoint> remoteList;
    if (m_state->IsConnected())
        std::vector<DebugBreakpoint> remoteList = m_state->GetAdapter()->GetBreakpointList();

    for (const ModuleNameAndOffset& address: m_state->GetBreakpoints()->GetBreakpointList())
    {
        uint64_t remoteAddress = m_state->GetModules()->RelativeAddressToAbsolute(address);
        bool enabled = false;
        for (const DebugBreakpoint& bp: remoteList)
        {
            if (bp.m_address == remoteAddress)
            {
                enabled = true;
                break;
            }
        }
        bps.emplace_back(enabled, address, remoteAddress);
    }

    DebugBreakpointsWidget* bpWidget = dynamic_cast<DebugBreakpointsWidget*>(widget("Native Debugger Breakpoints"));
    if (bpWidget)
        bpWidget->notifyBreakpointsChanged(bps);
    else
        LogWarn("Cannot find the breakpoint widget");

    // if (m_debugView)
        // m_debugView->refreshRawDisassembly();
}


void DebuggerUI::AddBreakpointTag(uint64_t localAddress)
{
    for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(localAddress))
    {
        if (!func)
            continue;

        bool tagFound = false;
        for (TagRef tag: func->GetAddressTags(m_state->GetData()->GetDefaultArchitecture(), localAddress))
        {
            if (tag->GetType() == m_breakpointTagType)
            {
                tagFound = true;
                break;
            }
        }

        if (!tagFound)
        {
            func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(), localAddress,
                    RedHighlightColor);
            func->CreateUserAddressTag(m_state->GetData()->GetDefaultArchitecture(), localAddress, m_breakpointTagType,
                    "breakpoint");
        }
    }

    ContextDisplay();
}


// breakpoint TAG removal - strictly presentation
// (doesn't remove actual breakpoints, just removes the binja tags that mark them)
void DebuggerUI::DeleteBreakpointTag(std::vector<uint64_t> localAddress)
{
    if (localAddress.size() == 0)
    {
        for (const ModuleNameAndOffset& info: m_state->GetBreakpoints()->GetBreakpointList())
        {
            if (info.module == m_state->GetData()->GetFile()->GetOriginalFilename())
            {
                localAddress.push_back(m_state->GetData()->GetStart() + info.offset);
            }
        }
    }

    for (uint64_t address: localAddress)
    {
        for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(address))
        {
            func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(), address, NoHighlightColor);
            for (TagRef tag: func->GetAddressTags(m_state->GetData()->GetDefaultArchitecture(), address))
            {
                if (tag->GetType() != m_breakpointTagType)
                    continue;

                func->RemoveUserAddressTag(m_state->GetData()->GetDefaultArchitecture(), address, tag);
            }
        }
    }

    ContextDisplay();
}


static void BreakpointToggleCallback(BinaryView* view, uint64_t addr)
{
    DebuggerState* state = DebuggerState::GetState(view);

    bool isAbsoluteAddress = false;
    // TODO: check if this works
    if ((view == state->GetMemoryView()) ||
        (view->GetParentView().GetPtr() == state->GetMemoryView()))
    {
        isAbsoluteAddress = true;
    }

    DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
    if (isAbsoluteAddress)
    {
        if (breakpoints->ContainsAbsolute(addr))
        {
            breakpoints->RemoveAbsolute(addr);
        }
        else
        {
            breakpoints->AddAbsolute(addr);
        }
    }
    else
    {
        std::string filename = view->GetFile()->GetOriginalFilename();
        uint64_t offset = addr - view->GetStart();
        ModuleNameAndOffset info = {filename, offset};
        if (breakpoints->ContainsOffset(info))
        {
            breakpoints->RemoveOffset(info);
            state->GetDebuggerUI()->DeleteBreakpointTag({addr});
        }
        else
        {
            breakpoints->AddOffset(info);
            state->GetDebuggerUI()->AddBreakpointTag({addr});
        }
    }
    // TODO: this is not the best way to organize the highlight of breakpoints. It only works when the breakpoint is 
    // added through the UI, and when the breakpoint is added through the planned API, the display will be outdated
    state->GetDebuggerUI()->UpdateBreakpoints();
}


static bool BreakpointToggleValid(BinaryView* view, uint64_t addr)
{
    return true;
}


void DebuggerUI::InitializeUI()
{
    Widget::registerDockWidget(
        [&](ViewFrame* parent, const QString& name, BinaryViewRef data) -> QWidget* {
            return new DebugBreakpointsWidget(parent, name, data);
        },
        "Native Debugger Breakpoints", Qt::BottomDockWidgetArea, Qt::Horizontal, false);

    Widget::registerDockWidget(
        [&](ViewFrame* parent, const QString& name, BinaryViewRef data) -> QWidget* {
            return new DebugRegistersWidget(parent, name, data);
        },
        "Native Debugger Registers", Qt::RightDockWidgetArea, Qt::Vertical, false);

    Widget::registerDockWidget(
        [&](ViewFrame* parent, const QString& name, BinaryViewRef data) -> QWidget* {
            return new DebugStackWidget(parent, name, data);
        },
        "Native Debugger Stack", Qt::LeftDockWidgetArea, Qt::Vertical, false);

    Widget::registerDockWidget(
        [&](ViewFrame* parent, const QString& name, BinaryViewRef data) -> QWidget* {
            return new DebugModulesWidget(parent, name, data);
        },
        "Native Debugger Modules", Qt::BottomDockWidgetArea, Qt::Horizontal, false);

    Widget::registerDockWidget(
        [&](ViewFrame* parent, const QString& name, BinaryViewRef data) -> QWidget* {
            return new DebugThreadsWidget(parent, name, data);
        },
        "Native Debugger Threads", Qt::BottomDockWidgetArea, Qt::Horizontal, false);

    PluginCommand::RegisterForAddress("Native Debugger\\Toggle Breakpoint",
            "sets/clears breakpoint at right-clicked address",
            BreakpointToggleCallback, BreakpointToggleValid);
    UIAction::setUserKeyBinding("Native Debugger\\Toggle Breakpoint", { QKeySequence(Qt::Key_F2) });
}


QWidget* DebuggerUI::widget(const std::string& name)
{
    return Widget::getDockWidget(m_state->GetData(), name);
}
