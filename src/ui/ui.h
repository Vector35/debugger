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

public:
    DebuggerUI(DebuggerController* controller);
//    void OnStep();

//    void DetectNewCode();
//    void AnnotateContext();

    void SetDebugView(DebugView* debugView);
    void SetDebuggerSidebar(DebuggerWidget* widget);
    static void InitializeUI();

    DebugView* GetDebugView() const { return m_debugView; }

signals:
    void contextChanged();
};
