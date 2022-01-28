#include "controlswidget.h"
#include "adaptersettings.h"
#include <QtGui/QPixmap>
#include "binaryninjaapi.h"
#include "disassemblyview.h"
#include "ui.h"
#include <thread>
#include "../api/debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;


DebugControlsWidget::DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data):
    QToolBar(parent), m_name(name)
{
    m_controller = DebuggerController::GetController(data);

    m_actionRun = addAction(QIcon(":/icons/images/debugger/run.svg"), "Run",
                        [this](){ performLaunch(); });
    m_actionRestart = addAction(QIcon(":/icons/images/debugger/restart.svg"), "Restart",
                                [this](){ performRestart(); });
    m_actionQuit = addAction(QIcon(":/icons/images/debugger/cancel.svg"), "Quit",
                             [this](){ performQuit(); });
    addSeparator();

    m_actionAttach = addAction(QIcon(":/icons/images/debugger/connect.svg"), "Attach",
                            [this](){ performConnect(); });
    m_actionDetach = addAction(QIcon(":/icons/images/debugger/disconnect.svg"), "Detach",
                               [this](){ performDetach(); });
    addSeparator();

    m_actionPause = addAction(QIcon(":/icons/images/debugger/pause.svg"), "Pause",
                              [this](){ performPause(); });
    m_actionResume = addAction(QIcon(":/icons/images/debugger/resume.svg"), "Resume",
                               [this](){ performResume(); });
    addSeparator();

    m_actionStepInto = addAction(QIcon(":/icons/images/debugger/stepinto.svg"), "Step Into",
                                 [this](){ performStepInto(); });
    m_actionStepOver = addAction(QIcon(":/icons/images/debugger/stepover.svg"), "Step Over",
                                 [this](){ performStepOver(); });
    m_actionStepReturn = addAction(QIcon(":/icons/images/debugger/stepout.svg"), "Step Out",
                               [this](){ performStepReturn(); });
    addSeparator();

    m_actionSettings = addAction("Settings...",[this](){ performSettings(); });

    updateButtons();
}


DebugControlsWidget::~DebugControlsWidget()
{
}


void DebugControlsWidget::performLaunch()
{
    std::thread([&](){
        m_controller->Launch();
    }).detach();
}


void DebugControlsWidget::performRestart()
{
    std::thread([&](){
        m_controller->Restart();
    }).detach();
}


void DebugControlsWidget::performQuit()
{
    std::thread([&](){
        m_controller->Quit();
    }).detach();
}


void DebugControlsWidget::performConnect()
{
    std::thread([&](){
        m_controller->Connect();
    }).detach();
}


void DebugControlsWidget::performDetach()
{
    std::thread([&](){
        m_controller->Detach();
    }).detach();
}


void DebugControlsWidget::performSettings()
{
    AdapterSettingsDialog* dialog = new AdapterSettingsDialog(this, m_controller);
    dialog->show();
    QObject::connect(dialog, &QDialog::finished, [this](){
        updateButtons();
    });
}


void DebugControlsWidget::performPause()
{
    m_controller->Pause();
//    Don't update state here-- one of the other thread is running in a thread and updating for us
}


void DebugControlsWidget::performResume()
{
	std::thread([&](){
    	m_controller->Go();
	}).detach();
}


void DebugControlsWidget::performStepInto()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

    std::thread([&, graphType](){
        m_controller->StepInto(graphType);
    }).detach();
}


void DebugControlsWidget::performStepOver()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

    std::thread([&, graphType](){
        m_controller->StepOver(graphType);
    }).detach();
}


void DebugControlsWidget::performStepReturn()
{
    std::thread([&](){
        m_controller->StepReturn();
    }).detach();
}


bool DebugControlsWidget::canExec()
{
	auto currentAdapter = m_controller->GetAdapterType();
	if (currentAdapter == "")
		return false;
    auto adapter = DebugAdapterType::GetByName(currentAdapter);
	if (!adapter)
		return false;
	return adapter->CanExecute(m_controller->GetData());
}


bool DebugControlsWidget::canConnect()
{
	auto currentAdapter = m_controller->GetAdapterType();
	if (currentAdapter == "")
		return false;
	auto adapter = DebugAdapterType::GetByName(currentAdapter);
	if (!adapter)
		return false;
    return adapter->CanConnect(m_controller->GetData());
}


void DebugControlsWidget::setStepIntoEnabled(bool enabled)
{
    m_actionStepInto->setEnabled(enabled);
}


void DebugControlsWidget::setStepOverEnabled(bool enabled)
{
    m_actionStepOver->setEnabled(enabled);
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
    m_actionStepInto->setEnabled(enabled);
    m_actionStepOver->setEnabled(enabled);
    m_actionStepReturn->setEnabled(enabled);    
}


void DebugControlsWidget::uiEventHandler(const DebuggerEvent &event)
{
	updateButtons();
}


void DebugControlsWidget::updateButtons()
{
    DebugAdapterConnectionStatus connection = m_controller->GetConnectionStatus();
    DebugAdapterTargetStatus status = m_controller->GetTargetStatus();

    if (connection == DebugAdapterNotConnectedStatus)
    {
        setStartingEnabled(true);
        setStoppingEnabled(false);
        setSteppingEnabled(false);
        m_actionPause->setEnabled(false);
        m_actionResume->setEnabled(false);
    }
    else if (status == DebugAdapterRunningStatus)
    {
        setStartingEnabled(false);
        setStoppingEnabled(true);
        setSteppingEnabled(false);
        m_actionPause->setEnabled(true);
        m_actionResume->setEnabled(false);
    }
    else
    {
        setStartingEnabled(false);
        setStoppingEnabled(true);
        setSteppingEnabled(true);
        m_actionPause->setEnabled(false);
        m_actionResume->setEnabled(true);
    }
}
