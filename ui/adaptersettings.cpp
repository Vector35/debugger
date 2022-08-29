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

#include "adaptersettings.h"
#include "uicontext.h"
#include "qfiledialog.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

AdapterSettingsDialog::AdapterSettingsDialog(QWidget* parent, DbgRef<DebuggerController> controller):
	QDialog(), m_controller(controller)
{
    setWindowTitle("Debug Adapter Settings");
    setMinimumSize(UIContext::getScaledWindowSize(400, 130));
    setAttribute(Qt::WA_DeleteOnClose);

	setModal(true);
    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);

    m_adapterEntry = new QComboBox(this);
	for (const std::string& adapter: DebugAdapterType::GetAvailableAdapters(m_controller->GetData()))
	{
		m_adapterEntry->addItem(QString::fromStdString(adapter));
	}
	if (m_controller->GetAdapterType() != "")
	{
		m_adapterEntry->setCurrentText(QString::fromStdString(m_controller->GetAdapterType()));
	}
	else
	{
		m_adapterEntry->setCurrentText("(No available debug adapter)");
	}

    connect(m_adapterEntry, &QComboBox::currentTextChanged, this, &AdapterSettingsDialog::selectAdapter);

    m_pathEntry = new QLineEdit(this);
	m_pathEntry->setMinimumWidth(800);
    m_argumentsEntry = new QLineEdit(this);
    m_workingDirectoryEntry = new QLineEdit(this);
	m_terminalEmulator = new QCheckBox(this);

	auto* pathSelector = new QPushButton("...", this);
	pathSelector->setMaximumWidth(30);
	connect(pathSelector, &QPushButton::clicked, [&](){
		auto fileName = QFileDialog::getOpenFileName(this, "Select Executable Path", m_workingDirectoryEntry->text());
		if (!fileName.isEmpty())
			m_pathEntry->setText(fileName);
	});

	auto* workingDirSelector = new QPushButton("...", this);
	workingDirSelector->setMaximumWidth(30);
	connect(workingDirSelector, &QPushButton::clicked, [&](){
		auto pathName = QFileDialog::getExistingDirectory(this, "Specify Working Directory",
														  m_workingDirectoryEntry->text(),
														  QFileDialog::ShowDirsOnly| QFileDialog::DontResolveSymlinks);
		if (!pathName.isEmpty())
			m_workingDirectoryEntry->setText(pathName);
	});

	auto pathEntryLayout = new QHBoxLayout;
	pathEntryLayout->addWidget(m_pathEntry);
	pathEntryLayout->addWidget(pathSelector);

	auto workingDirLayout = new QHBoxLayout;
	workingDirLayout->addWidget(m_workingDirectoryEntry);
	workingDirLayout->addWidget(workingDirSelector);

	QVBoxLayout* contentLayout = new QVBoxLayout;
	contentLayout->setSpacing(10);
	contentLayout->addWidget(new QLabel("Adapter Type"));
	contentLayout->addWidget(m_adapterEntry);
	contentLayout->addWidget(new QLabel("Executable Path"));
	contentLayout->addLayout(pathEntryLayout);
	contentLayout->addWidget(new QLabel("Working Directory"));
	contentLayout->addLayout(workingDirLayout);
	contentLayout->addWidget(new QLabel("Command Line Arguments"));
	contentLayout->addWidget(m_argumentsEntry);
	contentLayout->addWidget(new QLabel("Run In Separate Terminal"));
	contentLayout->addWidget(m_terminalEmulator);

    QHBoxLayout* buttonLayout = new QHBoxLayout;
    buttonLayout->setContentsMargins(0, 0, 0, 0);

    QPushButton* cancelButton = new QPushButton("Cancel");
    connect(cancelButton, &QPushButton::clicked, [&](){ reject(); });
    QPushButton* acceptButton = new QPushButton("Accept");
    connect(acceptButton, &QPushButton::clicked, [&](){ apply(); });
    acceptButton->setDefault(true);

    buttonLayout->addStretch(1);
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(acceptButton);

    layout->addLayout(contentLayout);
    layout->addStretch(1);
    layout->addSpacing(10);
    layout->addLayout(buttonLayout);
    setLayout(layout);

    m_pathEntry->setText(QString::fromStdString(m_controller->GetExecutablePath()));
	m_terminalEmulator->setChecked(m_controller->GetRequestTerminalEmulator());
    m_argumentsEntry->setText(QString::fromStdString(m_controller->GetCommandLineArguments()));
    m_workingDirectoryEntry->setText(QString::fromStdString(m_controller->GetWorkingDirectory()));

	selectAdapter(m_adapterEntry->currentText());
}


void AdapterSettingsDialog::selectAdapter(const QString& adapter)
{
	auto adapterType = DebugAdapterType::GetByName(adapter.toStdString());
	if (!adapterType)
		return;

	if (adapterType->CanExecute(m_controller->GetData()))
    {
        m_pathEntry->setEnabled(true);
        m_argumentsEntry->setEnabled(true);
		m_terminalEmulator->setEnabled(true);
	}
	else
	{
		m_pathEntry->setEnabled(false);
		m_argumentsEntry->setEnabled(false);
		m_terminalEmulator->setEnabled(false);
    }
}


void AdapterSettingsDialog::apply()
{
    std::string selectedAdapter = m_adapterEntry->currentText().toStdString();
	auto adapterType = DebugAdapterType::GetByName(selectedAdapter);
	if (adapterType == nullptr)
		selectedAdapter = "";

	m_controller->SetAdapterType(selectedAdapter);
    Ref<Metadata> data = new Metadata(selectedAdapter);
    m_controller->GetData()->StoreMetadata("debugger.adapter_type", data);

	// We need better support for shell-style cmd arguments
    std::string args = m_argumentsEntry->text().toStdString();
    m_controller->SetCommandLineArguments(args);
	data = new Metadata(args);
    m_controller->GetData()->StoreMetadata("debugger.command_line_args", data);

    std::string path = m_pathEntry->text().toStdString();
    m_controller->SetExecutablePath(path);
    data = new Metadata(path);
    m_controller->GetData()->StoreMetadata("debugger.executable_path", data);

	std::string workingDir = m_workingDirectoryEntry->text().toStdString();
	m_controller->SetWorkingDirectory(workingDir);
	data = new Metadata(workingDir);
	m_controller->GetData()->StoreMetadata("debugger.working_directory", data);

	bool requestTerminal = m_terminalEmulator->isChecked();
	m_controller->SetRequestTerminalEmulator(requestTerminal);
	data = new Metadata(requestTerminal);
	m_controller->GetData()->StoreMetadata("debugger.terminal_emulator", data);

    accept();
}
