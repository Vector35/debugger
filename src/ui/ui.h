#pragma once

#include <QtWidgets/QToolBar>
#include <QtWidgets/QMenu>
#include <QtWidgets/QToolButton>
#include <QtGui/QIcon>
#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "../debuggercontroller.h"
#include "debuggerwidget.h"

class DebuggerController;

class DebuggerWidget;
class DebuggerUI: public QObject
{
    Q_OBJECT

private:
    DebuggerController* m_controller;
    DebuggerWidget* m_sidebar;

public:
    DebuggerUI(DebuggerController* controller);
//    void OnStep();

//    void DetectNewCode();
//    void AnnotateContext();

    void SetDebuggerSidebar(DebuggerWidget* widget);
    static void InitializeUI();
    // This will handle all debugger events that are related to the UI
    void UIEventHandler(const DebuggerEvent& event);

signals:
    void contextChanged();
};
