/*
Copyright 2020-2022 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "controlswidget.h"
#include "adaptersettings.h"
#include <QPixmap>
#include <QInputDialog>
#include "binaryninjaapi.h"
#include "disassemblyview.h"
#include "ui.h"
#include <thread>

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;


DebugControlsWidget::DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data):
    QToolBar(parent), m_name(name)
{
    m_controller = DebuggerController::GetController(data);

    m_actionRun = addAction(QIcon(":/icons/images/debugger/run.svg"), "Run",
                        [this](){ performLaunch(); });
	// TODO: we need a different icon here
	m_actionAttachPid = addAction(QIcon(":/icons/images/debugger/connect.svg"), "Attach PID",
							[this](){ performAttachPID(); });
    m_actionRestart = addAction(QIcon(":/icons/images/debugger/restart.svg"), "Restart",
                                [this](){ performRestart(); });
    m_actionQuit = addAction(QIcon(":/icons/images/debugger/cancel.svg"), "Quit",
                             [this](){ performQuit(); });
    addSeparator();

    m_actionConnect = addAction(QIcon(":/icons/images/debugger/connect.svg"), "Connect",
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


void DebugControlsWidget::performAttachPID()
{
	int pid = QInputDialog::getInt(this, "PID", "Input PID:");
	if (pid == 0)
		return;

    std::thread([=](){
        m_controller->Attach(pid);
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
    m_controller->Quit();
}


void DebugControlsWidget::performConnect()
{
    std::thread([&](){
        m_controller->Connect();
    }).detach();
}


void DebugControlsWidget::performDetach()
{
	m_controller->Detach();
}


void DebugControlsWidget::performPause()
{
	m_controller->Pause();
}


void DebugControlsWidget::performResume()
{
	m_controller->Go();
}


void DebugControlsWidget::performStepInto()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

	if (graphType == InvalidILViewType)
		graphType = NormalFunctionGraph;

    m_controller->StepInto(graphType);
}


void DebugControlsWidget::performStepOver()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

	if (graphType == InvalidILViewType)
		graphType = NormalFunctionGraph;

    m_controller->StepOver(graphType);
}


void DebugControlsWidget::performStepReturn()
{
    m_controller->StepReturn();
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
	// TODO: we need to support specifying whether the adapter supports attaching to a pid
    m_actionAttachPid->setEnabled(enabled && canExec());
    m_actionConnect->setEnabled(enabled && canConnect());
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
