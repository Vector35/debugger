/*
Copyright 2020-2025 Vector 35 Inc.

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

#include "ttdrecord.h"
#include "uicontext.h"
#include "qfiledialog.h"
#include "fmt/format.h"
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QRadioButton>
#include <QButtonGroup>
#include <QLabel>
#include "attachprocess.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

TTDRecordDialog::TTDRecordDialog(QWidget* parent, BinaryView* data) :
	QDialog(), m_selectedPid(0)
{
	if (data)
		m_controller = DebuggerController::GetController(data);

	setWindowTitle("TTD Record");
	setAttribute(Qt::WA_DeleteOnClose);

	setModal(true);
	QVBoxLayout* layout = new QVBoxLayout;
	layout->setSpacing(10);

	// Mode selection
	m_launchModeRadio = new QRadioButton("Launch new process", this);
	m_attachModeRadio = new QRadioButton("Attach to running process", this);
	m_modeButtonGroup = new QButtonGroup(this);
	m_modeButtonGroup->addButton(m_launchModeRadio, 0);
	m_modeButtonGroup->addButton(m_attachModeRadio, 1);
	m_launchModeRadio->setChecked(true);
	
	connect(m_modeButtonGroup, QOverload<int>::of(&QButtonGroup::buttonClicked),
		this, &TTDRecordDialog::onModeChanged);

	QVBoxLayout* modeLayout = new QVBoxLayout;
	modeLayout->addWidget(m_launchModeRadio);
	modeLayout->addWidget(m_attachModeRadio);
	
	// Launch mode group
	m_launchGroup = new QGroupBox("Launch Settings", this);
	QVBoxLayout* launchLayout = new QVBoxLayout;
	
	m_pathEntry = new QLineEdit(this);
	m_pathEntry->setMinimumWidth(600);
	m_argumentsEntry = new QLineEdit(this);
	m_workingDirectoryEntry = new QLineEdit(this);
	m_launchWithoutTracing = new QCheckBox(this);

	auto* pathSelector = new QPushButton("...", this);
	pathSelector->setMaximumWidth(30);
	connect(pathSelector, &QPushButton::clicked, [&]() {
		auto fileName = QFileDialog::getOpenFileName(this, "Select Executable Path", m_pathEntry->text());
		if (!fileName.isEmpty())
			m_pathEntry->setText(fileName);
	});

	auto* workingDirSelector = new QPushButton("...", this);
	workingDirSelector->setMaximumWidth(30);
	connect(workingDirSelector, &QPushButton::clicked, [&]() {
		auto pathName = QFileDialog::getExistingDirectory(this, "Specify Working Directory",
			m_workingDirectoryEntry->text(), QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
		if (!pathName.isEmpty())
			m_workingDirectoryEntry->setText(pathName);
	});

	auto pathEntryLayout = new QHBoxLayout;
	pathEntryLayout->addWidget(m_pathEntry);
	pathEntryLayout->addWidget(pathSelector);

	auto workingDirLayout = new QHBoxLayout;
	workingDirLayout->addWidget(m_workingDirectoryEntry);
	workingDirLayout->addWidget(workingDirSelector);

	launchLayout->addWidget(new QLabel("Executable Path"));
	launchLayout->addLayout(pathEntryLayout);
	launchLayout->addWidget(new QLabel("Working Directory"));
	launchLayout->addLayout(workingDirLayout);
	launchLayout->addWidget(new QLabel("Command Line Arguments"));
	launchLayout->addWidget(m_argumentsEntry);
	launchLayout->addWidget(new QLabel("Start application With Recording Off"));
	launchLayout->addWidget(m_launchWithoutTracing);
	
	m_launchGroup->setLayout(launchLayout);

	// Attach mode group
	m_attachGroup = new QGroupBox("Attach Settings", this);
	QVBoxLayout* attachLayout = new QVBoxLayout;
	
	m_selectedProcessDisplay = new QLineEdit(this);
	m_selectedProcessDisplay->setReadOnly(true);
	m_selectedProcessDisplay->setPlaceholderText("No process selected");
	
	m_selectProcessButton = new QPushButton("Select Process...", this);
	connect(m_selectProcessButton, &QPushButton::clicked, this, &TTDRecordDialog::selectProcess);
	
	QHBoxLayout* processLayout = new QHBoxLayout;
	processLayout->addWidget(m_selectedProcessDisplay);
	processLayout->addWidget(m_selectProcessButton);
	
	attachLayout->addWidget(new QLabel("Target Process"));
	attachLayout->addLayout(processLayout);
	
	m_attachGroup->setLayout(attachLayout);
	m_attachGroup->setEnabled(false);

	// Common settings
	m_outputDirectory = new QLineEdit(this);
	auto* outputDirSelector = new QPushButton("...", this);
	outputDirSelector->setMaximumWidth(30);
	connect(outputDirSelector, &QPushButton::clicked, [&]() {
		auto pathName = QFileDialog::getExistingDirectory(this, "Specify Trace Output Directory",
			m_outputDirectory->text(), QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
		if (!pathName.isEmpty())
            m_outputDirectory->setText(pathName);
	});

	auto outputLayout = new QHBoxLayout;
	outputLayout->addWidget(m_outputDirectory);
	outputLayout->addWidget(outputDirSelector);

	// Button layout
	QHBoxLayout* buttonLayout = new QHBoxLayout;
	buttonLayout->setContentsMargins(0, 0, 0, 0);

	QPushButton* cancelButton = new QPushButton("Cancel");
	connect(cancelButton, &QPushButton::clicked, [&]() { reject(); });
	QPushButton* acceptButton = new QPushButton("Record");
	connect(acceptButton, &QPushButton::clicked, [&]() { apply(); });
	acceptButton->setDefault(true);

	buttonLayout->addStretch(1);
	buttonLayout->addWidget(cancelButton);
	buttonLayout->addWidget(acceptButton);

	// Main layout
	layout->addLayout(modeLayout);
	layout->addWidget(m_launchGroup);
	layout->addWidget(m_attachGroup);
	layout->addWidget(new QLabel("Trace Output Directory"));
	layout->addLayout(outputLayout);
	layout->addStretch(1);
	layout->addSpacing(10);
	layout->addLayout(buttonLayout);
	setLayout(layout);

	if (m_controller)
	{
		m_pathEntry->setText(QString::fromStdString(m_controller->GetExecutablePath()));
		m_argumentsEntry->setText(QString::fromStdString(m_controller->GetCommandLineArguments()));
		m_workingDirectoryEntry->setText(QString::fromStdString(m_controller->GetWorkingDirectory()));
		m_outputDirectory->setText(QString::fromStdString(m_controller->GetWorkingDirectory()));
	}
	m_launchWithoutTracing->setChecked(false);

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
}


void TTDRecordDialog::onModeChanged()
{
	bool isLaunchMode = m_launchModeRadio->isChecked();
	m_launchGroup->setEnabled(isLaunchMode);
	m_attachGroup->setEnabled(!isLaunchMode);
}


void TTDRecordDialog::selectProcess()
{
	AttachProcessDialog dialog(this, m_controller);
	if (dialog.exec() == QDialog::Accepted)
	{
		m_selectedPid = dialog.GetSelectedPid();
		if (m_selectedPid > 0)
		{
			m_selectedProcessDisplay->setText(QString("PID: %1").arg(m_selectedPid));
		}
	}
}


void TTDRecordDialog::apply()
{
	DoTTDTrace();

	accept();
}


static bool IsValidDbgEngTTDPaths(const std::string& path)
{
	if (path.empty())
		return false;

	auto enginePath = filesystem::path(path);
	if (!filesystem::exists(enginePath))
		return false;

	if (!filesystem::exists(enginePath / "TTD.exe"))
		return false;

	if (!filesystem::exists(enginePath / "TTDRecord.dll"))
		return false;

	return true;
}


std::string TTDRecordDialog::GetTTDRecorderPath()
{
	std::string path = Settings::Instance()->Get<string>("debugger.x64dbgEngPath");
	if (!path.empty())
	{
		// If the user has specified the path in the setting, then check it for validity. If it is valid, then use it;
		// if it is invalid, fail the operation -- do not fallback to the default one
        auto userTTDPath = filesystem::path(path) / "TTD";
		if (IsValidDbgEngTTDPaths(userTTDPath.string()))
			return userTTDPath.string();
		else
			return "";
	}

	std::string pluginRoot;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		pluginRoot = GetUserPluginDirectory();
	else
		pluginRoot = GetBundledPluginDirectory();

	// If the user does not specify a path (the default case), find the one from the plugins/dbgeng/arch
	auto TTDRecorderRoot = filesystem::path(pluginRoot)  / "dbgeng" / "amd64" / "TTD";
	if (IsValidDbgEngTTDPaths(TTDRecorderRoot.string()))
		return TTDRecorderRoot.string();

	return "";
}


void TTDRecordDialog::DoTTDTrace()
{
	auto ttdPath = GetTTDRecorderPath();
	if (ttdPath.empty())
	{
		QMessageBox::critical(this, "Recording Failed", "The debugger cannot find the path for the TTD recorder. "
			"If you have set debugger.x64dbgEngPath, check if it valid");
		return;
	}
	LogDebug("TTD Recorder in path %s", ttdPath.c_str());

	auto ttdRecorder = fmt::format("\"{}\\TTD.exe\"", ttdPath);
	std::string ttdCommandLine;
	
	if (m_launchModeRadio->isChecked())
	{
		// Launch mode - existing functionality
		if (m_pathEntry->text().isEmpty())
		{
			QMessageBox::critical(this, "Recording Failed", "Please specify an executable path for launch mode.");
			return;
		}
		
		ttdCommandLine = fmt::format("-accepteula -out \"{}\" {} -launch \"{}\" {}",
			m_outputDirectory->text().toStdString(),
			m_launchWithoutTracing->isChecked() ? "-tracingOff -recordMode Manual" : "",
			m_pathEntry->text().toStdString(),
			m_argumentsEntry->text().toStdString());
	}
	else
	{
		// Attach mode - new functionality
		if (m_selectedPid == 0)
		{
			QMessageBox::critical(this, "Recording Failed", "Please select a process to attach to.");
			return;
		}
		
		ttdCommandLine = fmt::format("-accepteula -out \"{}\" -attach {}",
			m_outputDirectory->text().toStdString(),
			m_selectedPid);
	}
	
	LogWarn("TTD tracer cmd: %s %s", ttdRecorder.c_str(), ttdCommandLine.c_str());

	SHELLEXECUTEINFOA info = {0};
	info.cbSize = sizeof(SHELLEXECUTEINFOA);
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpVerb = "runas";
	info.lpFile = ttdRecorder.c_str();
	info.lpParameters = ttdCommandLine.c_str();
	info.lpDirectory = m_launchModeRadio->isChecked() ? 
		m_workingDirectoryEntry->text().toStdString().c_str() : nullptr;
	info.nShow = SW_NORMAL;
	bool ret = ShellExecuteExA(&info);
	if (ret == FALSE)
	{
		QMessageBox::critical(this, "Recording Failed", QString::asprintf("TTD recording failed: %lu", GetLastError()));
		return;
	}

	LogDebug("info.hProcess: %d", info.hProcess);
	WaitForSingleObject(info.hProcess, INFINITE);
	QMessageBox::information(this, "Recording Completed", "The TTD recording has completed and you can now debug the trace");
}
