#include "controlswidget.h"
#include <QtGui/QPixmap>

using namespace BinaryNinja;


QIcon DebugControlsWidget::loadIcon(const std::string name)
{
    std::string iconPath;
#if defined(WIN32)
    iconPath = GetPathRelativeToBundledPluginDirectory("debugger_icons\\" + name);
#else
    iconPath = GetPathRelativeToBundledPluginDirectory("debugger_icons/" + name);
#endif

    QPixmap pixmap(QString::fromStdString(iconPath));
    QIcon icon;
    icon.addPixmap(pixmap, QIcon::Normal);
    icon.addPixmap(pixmap, QIcon::Normal);
    return icon;
}


DebugControlsWidget::DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data,
    DebuggerState* state):
    QToolBar(parent), m_name(name), m_data(data), m_state(state)
{
    setStyleSheet(QString::fromStdString("QToolButton{padding: 4px 14px 4px 14px; font-size: 14pt;} "
		"QToolButton:disabled{color: palette(alternate-base)}"));
    
    m_actionRun = new QAction("Run", this);
    m_actionRun->setIcon(loadIcon("run.svg"));
    connect(m_actionRun, &QAction::triggered, this, &DebugControlsWidget::performRun);

    m_actionRestart = new QAction("Restart", this);
    m_actionRestart->setIcon(loadIcon("restart.svg"));
    connect(m_actionRestart, &QAction::triggered, this, &DebugControlsWidget::performRestart);

    m_actionQuit = new QAction("Quit", this);
    m_actionQuit->setIcon(loadIcon("quit.svg"));
    connect(m_actionQuit, &QAction::triggered, this, &DebugControlsWidget::performQuit);

    m_actionAttach = new QAction("Attach", this);
    m_actionAttach->setIcon(loadIcon("attach.svg"));
    connect(m_actionAttach, &QAction::triggered, this, &DebugControlsWidget::performAttach);

    m_actionDetach = new QAction("Detach", this);
    m_actionDetach->setIcon(loadIcon("detach.svg"));
    connect(m_actionDetach, &QAction::triggered, this, &DebugControlsWidget::performDetach);

    m_actionSettings = new QAction("Settings...", this);
    connect(m_actionSettings, &QAction::triggered, this, &DebugControlsWidget::performSettings);

    m_actionPause = new QAction("Pause", this);
    m_actionPause->setIcon(loadIcon("pause.svg"));
    connect(m_actionPause, &QAction::triggered, this, &DebugControlsWidget::performPause);

    m_actionResume = new QAction("Resume", this);
    m_actionResume->setIcon(loadIcon("resume.svg"));
    connect(m_actionResume, &QAction::triggered, this, &DebugControlsWidget::performResume);

    m_actionStepIntoAsm = new QAction("Step Into (Assembly)", this);
    m_actionStepIntoAsm->setIcon(loadIcon("stepinto.svg"));
    connect(m_actionStepIntoAsm, &QAction::triggered, this, &DebugControlsWidget::performStepIntoAsm);

    m_actionStepIntoIL = new QAction("Step Into", this);
    m_actionStepIntoIL->setIcon(loadIcon("stepinto.svg"));
    connect(m_actionStepIntoIL, &QAction::triggered, this, &DebugControlsWidget::performStepIntoIL);

    m_actionStepOverAsm = new QAction("Step Over (Assembly)", this);
    m_actionStepOverAsm->setIcon(loadIcon("stepover.svg"));
    connect(m_actionStepOverAsm, &QAction::triggered, this, &DebugControlsWidget::performStepOverAsm);

    m_actionStepOverIL = new QAction("Step Over", this);
    m_actionStepOverIL->setIcon(loadIcon("stepover.svg"));
    connect(m_actionStepOverIL, &QAction::triggered, this, &DebugControlsWidget::performStepOverIL);

    m_actionStepReturn = new QAction("Step Return", this);
    m_actionStepReturn->setIcon(loadIcon("stepout.svg"));
    connect(m_actionStepReturn, &QAction::triggered, this, &DebugControlsWidget::performStepReturn);

    m_controlMenu = new QMenu("Process Control", this);
    m_controlMenu->addAction(m_actionRun);
    m_controlMenu->addAction(m_actionRestart);
    m_controlMenu->addAction(m_actionQuit);
    m_controlMenu->addSeparator();
    m_controlMenu->addAction(m_actionAttach);
    m_controlMenu->addAction(m_actionDetach);
    m_controlMenu->addSeparator();
    m_controlMenu->addAction(m_actionSettings);

    m_stepIntoMenu = new QMenu("Step Into", this);
    m_stepIntoMenu->addAction(m_actionStepIntoIL);
    m_stepIntoMenu->addAction(m_actionStepIntoAsm);

    m_stepOverMenu = new QMenu("Step Over", this);
    m_stepOverMenu->addAction(m_actionStepOverIL);
    m_stepOverMenu->addAction(m_actionStepOverAsm);

    m_btnControl = new QToolButton(this);
    m_btnControl->setMenu(m_controlMenu);
    m_btnControl->setPopupMode(QToolButton::MenuButtonPopup);
    m_btnControl->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_btnControl->setDefaultAction(m_actionRun);
    addWidget(m_btnControl);

    m_btnPauseResume = new QToolButton(this);
    m_btnPauseResume->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_btnPauseResume->setDefaultAction(m_actionPause);
    addWidget(m_btnPauseResume);

    m_btnStepInto = new QToolButton(this);
    m_btnStepInto->setMenu(m_stepIntoMenu);
    m_btnStepInto->setPopupMode(QToolButton::MenuButtonPopup);
    m_btnStepInto->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_btnStepInto->setDefaultAction(m_actionStepIntoIL);
    addWidget(m_btnStepInto);

    m_btnStepInto = new QToolButton(this);
    m_btnStepInto->setMenu(m_stepOverMenu);
    m_btnStepInto->setPopupMode(QToolButton::MenuButtonPopup);
    m_btnStepInto->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_btnStepInto->setDefaultAction(m_actionStepIntoIL);
    addWidget(m_btnStepInto);

    m_btnStepReturn = new QToolButton(this);
    m_btnStepReturn->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_btnStepReturn->setDefaultAction(m_actionStepReturn);
    addWidget(m_btnStepReturn);

    m_threadMenu = new QMenu("Threads", this);

    m_btnThreads = new QToolButton(this);
    m_btnThreads->setMenu(m_threadMenu);
    m_btnThreads->setPopupMode(QToolButton::InstantPopup);
    m_btnThreads->setToolButtonStyle(Qt::ToolButtonTextOnly);
    addWidget(m_btnThreads);

    // setThreadList();

    m_editStatus = new QLineEdit("INACTIVE", this);
    m_editStatus->setReadOnly(true);
    m_editStatus->setAlignment(Qt::AlignCenter);
    addWidget(m_editStatus);

    setActionEnabled(DebugControlRunAction, canExec());
    setActionEnabled(DebugControlRestartAction, false);
    setActionEnabled(DebugControlAttachAction, canConnect());
    setActionEnabled(DebugControlDetachAction, false);
    setActionEnabled(DebugControlPauseAction, false);
    setActionEnabled(DebugControlResumeAction, false);
    setSteppingEnabled(false);

    setPauseOrResume(DebugControlPauseAction);
    setDefaultProcessAction(canConnect() ? DebugControlAttachAction :
        DebugControlRunAction);
}


void DebugControlsWidget::performRun()
{
    m_state->run();
}


void DebugControlsWidget::performRestart()
{
    m_state->restart();
}


void DebugControlsWidget::performQuit()
{
    m_state->quit();
}


void DebugControlsWidget::performAttach()
{
    m_state->attach();
}


void DebugControlsWidget::performDetach()
{
    m_state->detach();
}


void DebugControlsWidget::performSettings()
{
    // Show Settings Dialog
}


void DebugControlsWidget::performPause()
{
    m_state->pause();
}


void DebugControlsWidget::performResume()
{
    m_state->resume();
}


void DebugControlsWidget::performStepIntoAsm()
{
    m_state->stepIntoAsm();
}

void DebugControlsWidget::performStepIntoIL()
{
    m_state->stepIntoIL();
}


void DebugControlsWidget::performStepOverAsm()
{
    m_state->stepOverAsm();
}


void DebugControlsWidget::performStepOverIL()
{
    m_state->stepOverIL();
}


void DebugControlsWidget::performStepReturn()
{
    m_state->stepReturn();
}


void DebugControlsWidget::setActionEnabled(DebugControlAction action, bool enabled)
{
    switch(action)
    {
    case DebugControlRunAction:
        m_actionRun->setEnabled(enabled);
        break;
    case DebugControlRestartAction:
        m_actionRestart->setEnabled(enabled);
        break;
    case DebugControlQuitAction:
        m_actionAttach->setEnabled(enabled);
        break;
    case DebugControlAttachAction:
        m_actionAttach->setEnabled(enabled);
        break;
    case DebugControlDetachAction:
        m_actionDetach->setEnabled(enabled);
        break;
    case DebugControlSettingsAction:
        m_actionSettings->setEnabled(enabled);
        break;
    case DebugControlPauseAction:
        m_actionPause->setEnabled(enabled);
        break;
    case DebugControlResumeAction:
        m_actionResume->setEnabled(enabled);
        break;
    case DebugControlStepIntoAsmAction:
        m_actionStepIntoAsm->setEnabled(enabled);
        break;
    case DebugControlStepIntoILAction:
        m_actionStepIntoIL->setEnabled(enabled);
        break;
    case DebugControlStepOverAsmAction:
        m_actionStepOverAsm->setEnabled(enabled);
        break;
    case DebugControlStepOverILAction:
        m_actionStepOverIL->setEnabled(enabled);
        break;
    case DebugControlStepReturnAction:
        m_actionStepReturn->setEnabled(enabled);
        break;
    default:
        break;
    }
}


bool DebugControlsWidget::canExec()
{
    return m_state->canExec();
}


bool DebugControlsWidget::canConnect()
{
    return m_state->canConnect();
}


void DebugControlsWidget::setStepIntoEnabled(bool enabled)
{
    m_actionStepIntoAsm->setEnabled(enabled);
    m_actionStepIntoIL->setEnabled(enabled);
}


void DebugControlsWidget::setStepOverEnabled(bool enabled)
{
    m_actionStepOverAsm->setEnabled(enabled);
    m_actionStepOverIL->setEnabled(enabled);
}


void DebugControlsWidget::setStartingEnabled(bool enabled)
{
    m_actionRun->setEnabled(enabled && canExec());
    m_actionAttach->setEnabled(enabled && canConnect());
}


void DebugControlsWidget::setStoppingEnabled(bool enabled)
{
    m_actionRestart->setEnabled(enabled);
    m_actionQuit->setEnabled(enabled);
    m_actionDetach->setEnabled(enabled);
}


void DebugControlsWidget::setSteppingEnabled(bool enabled)
{
    m_actionStepIntoAsm->setEnabled(enabled);
    m_actionStepIntoIL->setEnabled(enabled);
    m_actionStepOverAsm->setEnabled(enabled);
    m_actionStepOverIL->setEnabled(enabled);
    m_actionStepReturn->setEnabled(enabled);    
}


void DebugControlsWidget::setDefaultProcessAction(DebugControlAction action)
{
    if (action == DebugControlRunAction)
        m_btnControl->setDefaultAction(m_actionRun);
    else if (action == DebugControlRestartAction)
        m_btnControl->setDefaultAction(m_actionRestart);
    else if (action == DebugControlQuitAction)
        m_btnControl->setDefaultAction(m_actionQuit);
    else if (action == DebugControlAttachAction)
        m_btnControl->setDefaultAction(m_actionAttach);
    else if (action == DebugControlDetachAction)
        m_btnControl->setDefaultAction(m_actionDetach);
}


void DebugControlsWidget::setPauseOrResume(DebugControlAction action)
{
    if (action == DebugControlPauseAction)
        m_btnPauseResume->setDefaultAction(m_actionPause);
    else if (action == DebugControlResumeAction)
        m_btnPauseResume->setDefaultAction(m_actionResume);
}