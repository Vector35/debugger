#include "ui.h"
#include "binaryninjaapi.h"

DebuggerUI::DebuggerUI(DebuggerState* state): m_state(state)
{
    // TODO: The constructor of DebuggerUI does not create the DebugView. Instead, the DebugView is 
    // created by BinaryNinja, and the constructor of DebugView sets itself as the m_debugView of the
    // DebuggerUI. I understand the reason for this implementation, but its realy not a good idea.
    m_debugView = nullptr;
    m_lastIP = 0;

    CreateBreakpointTagType();

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

    if (!m_state->IsConnected())
    {
        // TODO: notify widgets with empty data
        return;
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
        m_breakpointType = type;
        return;
    }

    m_breakpointType = new TagType(m_state->GetData(), "Breakpoints", "🛑");
    m_state->GetData()->AddTagType(m_breakpointType);
}


void DebuggerUI::UpdateHighlights()
{
    for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(m_lastIP))
    {
        func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(), m_lastIP, NoHighlightColor);
    }

    for (const ModuleNameAndOffset& info: m_state->GetBreakpoints()->GetBreakpointList())
    {
        if (info.module != m_state->GetData()->GetFile()->GetOriginalFilename())
            continue;

        uint64_t bp = m_state->GetData()->GetStart() + info.offset;
        for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(bp))
        {
            func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(), bp, RedHighlightColor);
        }
    }

    if (m_state->IsConnected())
    {
        uint64_t localIP = m_state->LocalIP();
        for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(localIP))
        {
            func->SetAutoInstructionHighlight(m_state->GetData()->GetDefaultArchitecture(),
                    localIP, BlueHighlightColor);
        }
    }
}


void DebuggerUI::UpdateModules()
{
    // TODO
}


void DebuggerUI::UpdateBreakpoints()
{
    // TODO
}


void DebuggerUI::AddBreakpointTag(uint64_t localAddress)
{
    for (FunctionRef func: m_state->GetData()->GetAnalysisFunctionsContainingAddress(localAddress))
    {
        if (!func)
            continue;

        for (TagRef tag: func->GetAddressTags(m_state->GetData()->GetDefaultArchitecture(), localAddress))
        {
            if (tag->GetType() != m_breakpointType)
                continue;

            func->CreateUserAddressTag(m_state->GetData()->GetDefaultArchitecture(), localAddress, m_breakpointType,
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
                if (tag->GetType() != m_breakpointType)
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
    if ((view == state->GetMemoryView()) ||
        (view->GetParentView() == (BinaryViewRef)state->GetMemoryView()))
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
            state->GetDebuggerUI()->DeleteBreakpointTag({addr});
            breakpoints->RemoveOffset(info);
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
    DockHandler* activeDocks = DockHandler::getActiveDockHandler();
	activeDocks->addDockWidget("Native Debugger Registers", [](const QString& name, ViewFrame* frame, BinaryViewRef data) { return new DebugRegisterWidget(frame, name, data); }, Qt::RightDockWidgetArea, Qt::Horizontal, false);

    PluginCommand::RegisterForAddress("Native Debugger\\Toggle Breakpoint",
            "sets/clears breakpoint at right-clicked address",
            BreakpointToggleCallback, BreakpointToggleValid);
}
