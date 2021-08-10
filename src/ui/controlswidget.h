#pragma once

#include <QtWidgets/QToolBar>
#include <QtWidgets/QMenu>
#include <QtWidgets/QToolButton>
#include <QtGui/QIcon>
#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "../debuggerstate.h"

class DebuggerState;
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
        DebugControlStepIntoAsmAction,
        DebugControlStepIntoILAction,
        DebugControlStepOverAsmAction,
        DebugControlStepOverILAction,
        DebugControlStepReturnAction,
    };

private:
    std::string m_name;
    BinaryViewRef m_data;
    DebuggerState* m_state;

    QAction* m_actionRun;
    QAction* m_actionRestart;
    QAction* m_actionQuit;
    QAction* m_actionAttach;
    QAction* m_actionDetach;
    QAction* m_actionSettings;
    QAction* m_actionPause;
    QAction* m_actionResume;
    QAction* m_actionStepIntoAsm;
    QAction* m_actionStepIntoIL;
    QAction* m_actionStepOverAsm;
    QAction* m_actionStepOverIL;
    QAction* m_actionStepReturn;

    QMenu* m_controlMenu;
    QMenu* m_stepIntoMenu;
    QMenu* m_stepOverMenu;
    QMenu* m_threadMenu;

    QToolButton* m_btnControl;
    QToolButton* m_btnPauseResume;
    QToolButton* m_btnStepInto;
    QToolButton* m_btnStepOver;
    QToolButton* m_btnStepReturn;
    QToolButton* m_btnThreads;

    QLineEdit* m_editStatus;

    QIcon loadIcon(const std::string name);
    bool canExec();
    bool canConnect();

public:
    DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data, DebuggerState* state);
    virtual ~DebugControlsWidget() {}

    void setActionEnabled(DebugControlAction action, bool enabled);
    void setStepIntoEnabled(bool enabled);
    void setStepOverEnabled(bool enabled);
    void setStartingEnabled(bool enabled);
    void setStoppingEnabled(bool enabled);
    void setSteppingEnabled(bool enabled);

    void setDefaultProcessAction(DebugControlAction action);
    void setPauseOrResume(DebugControlAction action);

    void stateStarting(const std::string& msg = "");
    void stateInactive(const std::string& msg = "");
    void stateStopped(const std::string& msg = "");
    void stateStoppedExtern(const std::string& msg = "");
    void stateRunning(const std::string& msg = "");
    void stateBusy(const std::string& msg = "");
    void stateError(const std::string& msg = "");

    void clearThreadList();
    void setThreadList(std::vector<DebuggerThreadCache> threads);

    void handleStopReturn();

public Q_SLOTS:
    void performRun();
    void performRestart();
    void performQuit();
    void performAttach();
    void performDetach();
    void performSettings();
    void performPause();
    void performResume();
    void performStepIntoAsm();
    void performStepIntoIL();
    void performStepOverAsm();
    void performStepOverIL();
    void performStepReturn();
};
