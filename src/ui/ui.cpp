#include "ui.h"

DebuggerUI::DebuggerUI(DebuggerState* state): m_state(state)
{
    // TODO: The constructor of DebuggerUI does not create the DebugView. Instead, the DebugView is 
    // created by BinaryNinja, and the constructor of DebugView sets itself as the m_debugView of the
    // DebuggerUI. I understand the reason for this implementation, but its realy not a good idea.
    m_debugView = nullptr;
    m_lastIP = 0;
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

    if (m_debugView)
    {
        uint64_t localIP = m_state->LocalIP();
        BinaryNinja::LogWarn("localIP: 0x%" PRIx64 "\n", localIP);
        m_lastIP = localIP;;
        if (m_state->GetData()->GetAnalysisFunctionsContainingAddress(localIP).size() > 0)
            m_debugView->getControls()->stateStopped();
        else
            m_debugView->getControls()->stateStoppedExtern();
    }
}


void DebuggerUI::UpdateBreakpoints()
{

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
