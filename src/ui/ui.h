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
    
    DebugRegistersWidget* m_registersWidget;
    TagTypeRef m_breakpointTagType, m_pcTagType;

public:
    DebuggerUI(DebuggerState* state);
    void OnStep();

    void DetectNewCode();
    void AnnotateContext();
    void ContextDisplay();
    void NavigateToIp();

    void SetDebugView(DebugView* debugView);
    void CreateBreakpointTagType();
    void CreateProgramCounterTagType();

    void UpdateHighlights();
    void UpdateModules();
    void UpdateBreakpoints();

    void AddBreakpointTag(uint64_t localAddress);
    void DeleteBreakpointTag(std::vector<uint64_t> localAddress);

    static void InitializeUI();

    QWidget* widget(const std::string& name);
};
