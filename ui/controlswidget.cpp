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
#include "theme.h"
#include "ui.h"
#include <thread>

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;


DebugControlsWidget::DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data):
    QToolBar(parent), m_name(name)
{
    m_controller = DebuggerController::GetController(data);

	auto cyan = getThemeColor(CyanStandardHighlightColor);
	auto green = getThemeColor(GreenStandardHighlightColor);
	auto red = getThemeColor(RedStandardHighlightColor);
	auto white = getThemeColor(WhiteStandardHighlightColor);

    m_actionRun = addAction(getColoredIcon(":/icons/images/debugger/run.svg", red), "Run",
                        [this](){ performLaunch(); });
	// TODO: we need a different icon here
	m_actionAttachPid = addAction(getColoredIcon(":/icons/images/debugger/connect.svg", white), "Attach PID",
							[this](){ performAttachPID(); });
    m_actionRestart = addAction(getColoredIcon(":/icons/images/debugger/restart.svg", red), "Restart",
                                [this](){ performRestart(); });
    m_actionQuit = addAction(getColoredIcon(":/icons/images/debugger/cancel.svg", red), "Quit",
                             [this](){ performQuit(); });
    m_actionDetach = addAction(getColoredIcon(":/icons/images/debugger/disconnect.svg", red), "Detach",
                               [this](){ performDetach(); });
    addSeparator();

    m_actionPause = addAction(getColoredIcon(":/icons/images/debugger/pause.svg", white), "Pause",
                              [this](){ performPause(); });
    m_actionResume = addAction(getColoredIcon(":/icons/images/debugger/resume.svg", green), "Resume",
                               [this](){ performResume(); });
    addSeparator();

    m_actionStepInto = addAction(getColoredIcon(":/icons/images/debugger/stepinto.svg", cyan), "Step Into",
                                 [this](){ performStepInto(); });
    m_actionStepOver = addAction(getColoredIcon(":/icons/images/debugger/stepover.svg", cyan), "Step Over",
                                 [this](){ performStepOver(); });
    m_actionStepReturn = addAction(getColoredIcon(":/icons/images/debugger/stepout.svg", cyan), "Step Out",
                               [this](){ performStepReturn(); });
    addSeparator();

    updateButtons();
}


DebugControlsWidget::~DebugControlsWidget()
{
}


QIcon DebugControlsWidget::getColoredIcon(const QString& iconPath, const QColor& color)
{
	auto pixmap = QPixmap(iconPath);
	auto mask = pixmap.createMaskFromColor(QColor("transparent"), Qt::MaskInColor);
	pixmap.fill(color);
	pixmap.setMask(mask);
	return QIcon(pixmap);
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
