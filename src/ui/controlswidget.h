#pragma once

#include <QtWidgets/QToolBar>
#include <QtWidgets/QMenu>
#include <QtWidgets/QToolButton>
#include <QtGui/QIcon>
#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "../debugadapter.h"

class DebuggerState;
class DebuggerController;
class DebugControlsWidget: public QToolBar
{
    Q_OBJECT

    enum DebugControlAction
    {
        DebugControlRunAction,
        DebugControlRestartAction,
        DebugControlQuitAction,
        DebugControlAttachAction,
        DebugControlDetachAction,
        DebugControlSettingsAction,
        DebugControlPauseAction,
        DebugControlResumeAction,
        DebugControlStepIntoAction,
        DebugControlStepOverAction,
        DebugControlStepReturnAction,
    };

private:
    std::string m_name;
    DebuggerController* m_controller;

    size_t m_eventCallback;

    QAction* m_actionRun;
    QAction* m_actionRestart;
    QAction* m_actionQuit;
    QAction* m_actionAttach;
    QAction* m_actionDetach;
    QAction* m_actionSettings;
    QAction* m_actionPause;
    QAction* m_actionResume;
    QAction* m_actionStepInto;
    QAction* m_actionStepOver;
    QAction* m_actionStepReturn;

    bool canExec();
    bool canConnect();

public:
    DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data);
    virtual ~DebugControlsWidget();

    void setStepIntoEnabled(bool enabled);
    void setStepOverEnabled(bool enabled);
    void setStartingEnabled(bool enabled);
    void setStoppingEnabled(bool enabled);
    void setSteppingEnabled(bool enabled);

    void setDebuggerStatus(const std::string& status);

    void uiEventHandler(const DebuggerEvent& event);

    void updateButtons();

public Q_SLOTS:
    void performLaunch();
    void performRestart();
    void performQuit();
    void performAttach();
    void performDetach();
    void performSettings();
    void performPause();
    void performResume();
    void performStepInto();
    void performStepOver();
    void performStepReturn();
};
