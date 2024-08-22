/*
Copyright 2020-2024 Vector 35 Inc.

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
#include <QMessageBox>
#include "binaryninjaapi.h"
#include "disassemblyview.h"
#include "theme.h"
#include "platformdialog.h"
#include "ui.h"
#include <thread>
#include "progresstask.h"
#include "attachprocess.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;


DebugControlsWidget::DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data) :
	QToolBar(parent), m_name(name)
{
	m_controller = DebuggerController::GetController(data);
	if (!m_controller)
		return;

	auto cyan = getThemeColor(CyanStandardHighlightColor);
	auto green = getThemeColor(GreenStandardHighlightColor);
	auto red = getThemeColor(RedStandardHighlightColor);
	auto white = getThemeColor(WhiteStandardHighlightColor);

	m_actionRun = addAction(getColoredIcon(":/debugger/start", red), "Launch", [this]() {
		performLaunch();
	});
	m_actionRun->setToolTip(getToolTip("Launch"));

	m_actionPause = addAction(getColoredIcon(":/debugger/pause", white), "Pause", [this]() {
		performPause();
	});
	m_actionPause->setToolTip(getToolTip("Pause"));

	m_actionResume = addAction(getColoredIcon(":/debugger/resume", green), "Resume", [this]() {
		performResume();
	});
	m_actionResume->setToolTip(getToolTip("Resume"));

	// m_actionRun->setVisible(true);
	m_actionPause->setVisible(false);
	m_actionResume->setVisible(false);

	m_actionAttachPid = addAction(getColoredIcon(":/debugger/connect", white), "Attach To Process...", [this]() {
		performAttachPID(); 
	});
	m_actionAttachPid->setToolTip(getToolTip("Attach To Process..."));

	m_actionDetach = addAction(getColoredIcon(":/debugger/disconnect", red), "Detach", [this]() {
		performDetach();
	});
	m_actionDetach->setVisible(false);
	m_actionDetach->setToolTip(getToolTip("Detach"));

	m_actionRestart = addAction(getColoredIcon(":/debugger/restart", red), "Restart", [this]() {
		performRestart();
	});
	m_actionRestart->setToolTip(getToolTip("Restart"));

	m_actionQuit = addAction(getColoredIcon(":/debugger/cancel", red), "Kill", [this]() {
		performQuit();
	});
	m_actionQuit->setToolTip(getToolTip("Kill"));
	addSeparator();

	m_actionStepInto = addAction(getColoredIcon(":/debugger/step-into", cyan), "Step Into", [this]() {
		performStepInto();
	});
	m_actionStepInto->setToolTip(getToolTip("Step Into"));

	m_actionStepOver = addAction(getColoredIcon(":/debugger/step-over", cyan), "Step Over", [this]() {
		performStepOver();
	});
	m_actionStepOver->setToolTip(getToolTip("Step Over"));

	m_actionStepReturn = addAction(getColoredIcon(":/debugger/step-out", cyan), "Step Return", [this]() {
		performStepReturn();
	});
	m_actionStepReturn->setToolTip(getToolTip("Step Return"));
	addSeparator();

	m_actionSettings = addAction(getColoredIcon(":/debugger/settings", cyan), "Settings", [this]() {
		performSettings();
	});
	m_actionSettings->setToolTip(getToolTip("Debug Adapter Settings"));

	if(m_controller->IsTTD())
		addSeparator(); //TODO: IsTTD only updates when the adapter is connected. This leaves the separator in place when the adapter is disconnected.
	
	m_actionGoBack = addAction(getColoredIcon(":/debugger/resume-reverse", red), "Go Backwards", [this]() {
		performGoReverse();
	});
	m_actionGoBack->setToolTip(getToolTip("Go Backwards"));
	
	m_actionStepIntoBack = addAction(getColoredIcon(":/debugger/step-into-reverse", red), "Step Into Backwards", [this]() {
		performStepIntoReverse();
	});
	m_actionStepIntoBack->setToolTip(getToolTip("Step Into Backwards"));

	m_actionStepOverBack = addAction(getColoredIcon(":/debugger/step-back", red), "Step Over Backwards", [this]() {
		performStepOverReverse();
	});
	m_actionStepOverBack->setToolTip(getToolTip("Step Over Backwards"));

	m_actionStepReturnBack = addAction(getColoredIcon(":/debugger/step-out-reverse", red), "Step Return Backwards", [this]() {
		performStepReturnReverse();
	});
	m_actionStepReturnBack->setToolTip(getToolTip("Step Return Backwards"));
	updateButtons();
}


DebugControlsWidget::~DebugControlsWidget() {}


QIcon DebugControlsWidget::getColoredIcon(const QString& iconPath, const QColor& color)
{
	auto pixmap = QPixmap(iconPath);
	auto mask = pixmap.createMaskFromColor(QColor(0, 0, 0), Qt::MaskInColor);
	pixmap.fill(color);
	pixmap.setMask(mask);
	return QIcon(pixmap);
}


QString DebugControlsWidget::getToolTip(const QString& name)
{
	QString result = name;
	auto keyBinding = UIAction::getKeyBinding(name);
	if (!keyBinding.isEmpty())
		result += (QString(" (") + keyBinding[0].toString() + ")");

	return result;
}


void DebugControlsWidget::performLaunch()
{
	if (m_controller->IsFirstLaunch() && Settings::Instance()->Get<bool>("debugger.confirmFirstLaunch"))
	{
		auto prompt = QString("You are about to launch \n\n%1\n\non your machine. "
			"This may harm your machine. Are you sure to continue?").arg(QString::fromStdString(m_controller->GetExecutablePath()));
		if (QMessageBox::question(this, "Launch Target", prompt) != QMessageBox::Yes)
			return;
	}

	auto data = m_controller->GetData();
	if (!data->GetDefaultPlatform())
	{
		// No default platform, prompt user to choose one
		PlatformDialog dlg(this);
		if (dlg.exec() != QDialog::Accepted)
		{
			QMessageBox::warning(this, "No Platform", "The debugger cannot work if the binary view has no "
													  "platform and architecture");
			return;
		}

		auto platform = dlg.getPlatform();
		if (platform)
		{
			dlg.saveDefaults();
		}
		else
		{
			QMessageBox::warning(this, "Invalid Platform", "The debugger cannot work if the binary view has no "
													  "platform and architecture");
			return;
		}

		data->SetDefaultArchitecture(platform->GetArchitecture());
		data->SetDefaultPlatform(platform);
	}

	QString text = QString(
		"The debugger is %1 the target and preparing the debugger binary view. \n"
		"This might take a while.").arg("launching");
	ProgressTask* task =
		new ProgressTask(this, "Launching", text, "", [=](std::function<bool(size_t, size_t)> progress) {
			m_controller->Launch();

			// For now, this cant be canceled, as the Debugger model wasn't
		    // designed with that in mind. This function below can return false if canceling is enabled
			progress(1, 1);
			return;
		});
	task->wait();
}


void DebugControlsWidget::performAttachPID()
{
	AttachProcessDialog dialog(this, m_controller);
	if (dialog.exec() != QDialog::Accepted)
		return;

	uint32_t pid = dialog.GetSelectedPid();
	if (pid == 0)
		return;

	auto data = m_controller->GetData();
	if (!data->GetDefaultPlatform())
	{
		// No default platform, prompt user to choose one
		PlatformDialog dlg(this);
		if (dlg.exec() != QDialog::Accepted)
		{
			QMessageBox::warning(this, "No Platform", "The debugger cannot work if the binary view has no "
													  "platform and architecture");
			return;
		}

		auto platform = dlg.getPlatform();
		if (platform)
		{
			dlg.saveDefaults();
		}
		else
		{
			QMessageBox::warning(this, "Invalid Platform", "The debugger cannot work if the binary view has no "
													  "platform and architecture");
			return;
		}

		data->SetDefaultArchitecture(platform->GetArchitecture());
		data->SetDefaultPlatform(platform);
	}

	m_controller->SetPIDAttach(pid);
	QString text = QString(
		"The debugger is %1 the target and preparing the debugger binary view. \n"
		"This might take a while.").arg("attaching to");
	ProgressTask* task =
		new ProgressTask(this, "Attaching", text, "", [=](std::function<bool(size_t, size_t)> progress) {
			m_controller->Attach();

			// For now, this cant be canceled, as the Debugger model wasn't
		    // designed with that in mind. This function below can return false if canceling is enabled
			progress(1, 1);
			return;
		});
	task->wait();
}


void DebugControlsWidget::performRestart()
{
	std::thread([&]() { m_controller->Restart(); }).detach();
}


void DebugControlsWidget::performQuit()
{
	std::thread([&]() { m_controller->Quit(); }).detach();
}


void DebugControlsWidget::performDetach()
{
	std::thread([&]() { m_controller->Detach(); }).detach();
}


void DebugControlsWidget::performPause()
{
	std::thread([&]() { m_controller->Pause(); }).detach();
}


void DebugControlsWidget::performResume()
{
	m_controller->Go();
}


void DebugControlsWidget::performGoReverse()
{
	m_controller->GoReverse();
}


void DebugControlsWidget::performStepInto()
{
	BNFunctionGraphType graphType = NormalFunctionGraph;
	UIContext* context = UIContext::contextForWidget(this);
	if (context && context->getCurrentView())
		graphType = context->getCurrentView()->getILViewType().type;

	if (graphType == InvalidILViewType)
		graphType = NormalFunctionGraph;

	m_controller->StepInto(graphType);
}


void DebugControlsWidget::performStepIntoReverse()
{
	BNFunctionGraphType graphType = NormalFunctionGraph;
	UIContext* context = UIContext::contextForWidget(this);
	if (context && context->getCurrentView())
		graphType = context->getCurrentView()->getILViewType().type;

	if (graphType == InvalidILViewType)
		graphType = NormalFunctionGraph;
	m_controller->StepIntoReverse(graphType);
}


void DebugControlsWidget::performStepOver()
{
	BNFunctionGraphType graphType = NormalFunctionGraph;
	UIContext* context = UIContext::contextForWidget(this);
	if (context && context->getCurrentView())
		graphType = context->getCurrentView()->getILViewType().type;

	if (graphType == InvalidILViewType)
		graphType = NormalFunctionGraph;

	m_controller->StepOver(graphType);
}


void DebugControlsWidget::performStepOverReverse()
{
	BNFunctionGraphType graphType = NormalFunctionGraph;
	UIContext* context = UIContext::contextForWidget(this);
	if (context && context->getCurrentView())
		graphType = context->getCurrentView()->getILViewType().type;

	if (graphType == InvalidILViewType)
		graphType = NormalFunctionGraph;

	m_controller->StepOverReverse(graphType);
}


void DebugControlsWidget::performStepReturn()
{
	m_controller->StepReturn();
}

void DebugControlsWidget::performStepReturnReverse()
{
	m_controller->StepReturnReverse();
}

void DebugControlsWidget::performSettings()
{
	auto* dialog = new AdapterSettingsDialog(this, m_controller);
	dialog->show();
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


void DebugControlsWidget::setStartingEnabled(bool enabled)
{
	m_actionRun->setEnabled(enabled && canExec());
	// TODO: we need to support specifying whether the adapter supports attaching to a pid
	m_actionAttachPid->setEnabled(enabled && canExec());
	m_actionAttachPid->setVisible(enabled);
}


void DebugControlsWidget::setStoppingEnabled(bool enabled)
{
	m_actionRestart->setEnabled(enabled);
	m_actionQuit->setEnabled(enabled);
	m_actionDetach->setEnabled(enabled);
	m_actionDetach->setVisible(enabled);
}


void DebugControlsWidget::setSteppingEnabled(bool enabled)
{
	m_actionStepInto->setEnabled(enabled);
	m_actionStepOver->setEnabled(enabled);
	m_actionStepReturn->setEnabled(enabled);
}


void DebugControlsWidget::setReverseSteppingEnabled(bool enabled)
{
	m_actionStepIntoBack->setEnabled(enabled);
	m_actionStepIntoBack->setVisible(enabled);
	m_actionStepOverBack->setEnabled(enabled);
	m_actionStepOverBack->setVisible(enabled);
	m_actionStepReturnBack->setEnabled(enabled);
	m_actionStepReturnBack->setVisible(enabled);
}


void DebugControlsWidget::updateButtons()
{
	this->setIconSize(QSize(20, 20));

	DebugAdapterConnectionStatus connection = m_controller->GetConnectionStatus();
	DebugAdapterTargetStatus status = m_controller->GetTargetStatus();

	if (connection == DebugAdapterNotConnectedStatus)
	{
		setStartingEnabled(true);
		setStoppingEnabled(false);
		setSteppingEnabled(false);
		setReverseSteppingEnabled(false);
		m_actionPause->setEnabled(false);
		m_actionResume->setEnabled(false);
		m_actionGoBack->setEnabled(false);

		m_actionRun->setVisible(true);
		m_actionPause->setVisible(false);
		m_actionResume->setVisible(false);
		m_actionGoBack->setVisible(false);
	}
	else if (status == DebugAdapterRunningStatus)
	{
		setStartingEnabled(false);
		setStoppingEnabled(true);
		setSteppingEnabled(false);
		setReverseSteppingEnabled(false);
		m_actionStepIntoBack->setVisible(m_controller->IsTTD());
		m_actionStepOverBack->setVisible(m_controller->IsTTD());
		
		m_actionPause->setEnabled(true);
		m_actionResume->setEnabled(false);
		m_actionGoBack->setEnabled(false);

		m_actionRun->setVisible(false);
		m_actionPause->setVisible(true);
		m_actionResume->setVisible(false);
		m_actionGoBack->setVisible(false);
	}
	else  // status == DebugAdapterPausedStatus
	{
		setStartingEnabled(false);
		setStoppingEnabled(true);
		setSteppingEnabled(true);
		setReverseSteppingEnabled(m_controller->IsTTD());
		m_actionPause->setEnabled(false);
		m_actionResume->setEnabled(true);
		m_actionGoBack->setEnabled(m_controller->IsTTD());

		m_actionRun->setVisible(false);
		m_actionPause->setVisible(false);
		m_actionResume->setVisible(true);
		m_actionGoBack->setVisible(m_controller->IsTTD());
	}
}
