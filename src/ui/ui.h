#pragma once

#include <QtWidgets/QToolBar>
#include <QtWidgets/QMenu>
#include <QtWidgets/QToolButton>
#include <QtGui/QIcon>
#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "debugview.h"
#include "registerwidget.h"

class DebuggerUI
{
private:
    DebuggerState* m_state;
    DebugView* m_debugView;
    uint64_t m_lastIP;
    
    DebugRegisterWidget* m_registersWidget;

public:
    DebuggerUI(DebuggerState* state);
    void OnStep();

    void DetectNewCode();
    void AnnotateContext();
    void ContextDisplay();
    void UpdateBreakpoints();
    void NavigateToIp();
};
