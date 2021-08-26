#pragma once

#include <QtWidgets/QToolBar>
#include <QtWidgets/QMenu>
#include <QtWidgets/QToolButton>
#include <QtGui/QIcon>
#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "../debuggercontroller.h"
#include "debugview.h"
#include "debuggerwidget.h"

class DebuggerController;
class DebugView;

class DebuggerWidget;
class DebuggerUI: public QObject
{
    Q_OBJECT

private:
//    DebuggerState* m_state;
    DebuggerController* m_controller;
    DebugView* m_debugView;
    DebuggerWidget* m_sidebar;
    uint64_t m_lastIP;

//    TagTypeRef m_breakpointTagType, m_pcTagType;

public:
    DebuggerUI(DebuggerController* controller);
    void OnStep();

    void DetectNewCode();
    void AnnotateContext();
    void ContextDisplay();
    void NavigateToIp();

    void SetDebugView(DebugView* debugView);
    void SetDebuggerSidebar(DebuggerWidget* widget);
    void CreateBreakpointTagType();
    void CreateProgramCounterTagType();

    void UpdateHighlights();
    void UpdateModules();
    void UpdateBreakpoints();

    void AddBreakpointTag(uint64_t localAddress);
    void DeleteBreakpointTag(std::vector<uint64_t> localAddress);
//    TagTypeRef GetBreakpointTagType() const { return m_breakpointTagType; }
//    TagTypeRef GetPCTagType() const { return m_pcTagType; }

    static void InitializeUI();

    QWidget* widget(const std::string& name);

    DebugView* GetDebugView() const { return m_debugView; }

signals:
    void contextChanged();
};
