#include "ui.h"

DebuggerUI::DebuggerUI(DebuggerState* state): m_state(state)
{
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
        ip = m_state->getData()->GetEntryPoint();
    }
    else
    {
        ip = m_state->ip();
    }

    ViewFrame* frame = ViewFrame::viewFrameForWidget(m_debugView);
    frame->navigate(m_state->getData(), ip, true, true);
}
