/*
Copyright 2020-2026 Vector 35 Inc.

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

#ifdef WIN32

#include "windbgupdatedialog.h"
#include "../installer/windbg_version.h"
#include "debuggerapi.h"
#include "progresstask.h"
#include <QApplication>
#include <QGroupBox>
#include <QMessageBox>
#include <thread>

using namespace BinaryNinjaDebuggerAPI;

WinDbgUpdateDialog::WinDbgUpdateDialog(QWidget* parent, const std::string& installPath, const std::string& installedVersion)
	: QDialog(parent), m_installPath(installPath), m_installedVersion(installedVersion)
{
	setWindowTitle("WinDbg/TTD Version");
	setMinimumWidth(450);

	const std::string supportedVersion = WinDbgInstaller::kPinnedVersion;
	const bool versionMatches = !m_installedVersion.empty() && (m_installedVersion == supportedVersion);

	QVBoxLayout* mainLayout = new QVBoxLayout(this);

	/* Version information group */
	QGroupBox* versionGroup = new QGroupBox("Version Information", this);
	QVBoxLayout* versionLayout = new QVBoxLayout(versionGroup);

	QHBoxLayout* installedLayout = new QHBoxLayout();
	installedLayout->addWidget(new QLabel("Installed version:", this));
	QLabel* installedVersionLabel;
	if (m_installedVersion.empty()) {
		installedVersionLabel = new QLabel("Unknown", this);
		installedVersionLabel->setStyleSheet("font-weight: bold; color: gray;");
	} else {
		installedVersionLabel = new QLabel(QString::fromStdString(m_installedVersion), this);
		installedVersionLabel->setStyleSheet(versionMatches ? "font-weight: bold; color: green;"
		                                                    : "font-weight: bold; color: orange;");
	}
	installedLayout->addWidget(installedVersionLabel);
	installedLayout->addStretch();
	versionLayout->addLayout(installedLayout);

	QHBoxLayout* supportedLayout = new QHBoxLayout();
	supportedLayout->addWidget(new QLabel("Supported version:", this));
	QLabel* supportedVersionLabel = new QLabel(QString::fromStdString(supportedVersion), this);
	supportedVersionLabel->setStyleSheet("font-weight: bold;");
	supportedLayout->addWidget(supportedVersionLabel);
	supportedLayout->addStretch();
	versionLayout->addLayout(supportedLayout);

	mainLayout->addWidget(versionGroup);

	/* Status/explanation label */
	QLabel* statusLabel = new QLabel(this);
	statusLabel->setWordWrap(true);
	if (versionMatches) {
		statusLabel->setText(
			"You have the supported version of WinDbg/TTD installed.\n\n"
			"To reinstall it anyway, click 'Reinstall'. Binary Ninja will be closed and the "
			"installer will run."
		);
	} else if (m_installedVersion.empty()) {
		statusLabel->setText(
			"Unable to determine which version of WinDbg/TTD is installed.\n\n"
			"Click 'Install' to install the supported version. Binary Ninja will be closed and "
			"the installer will run."
		);
	} else {
		statusLabel->setText(
			"The installed version is not the version this debugger supports.\n\n"
			"Clicking 'Install' will:\n"
			"1. Close Binary Ninja\n"
			"2. Launch the installer to download and install the supported version\n"
			"3. You can restart Binary Ninja after the installation completes"
		);
	}
	mainLayout->addWidget(statusLabel);

	/* Explain why we do not simply track the latest WinDbg release */
	QLabel* noteLabel = new QLabel(
		"Binary Ninja installs a specific WinDbg version that has been validated against the "
		"debugger, rather than the newest release, because new WinDbg releases occasionally "
		"break the DbgEng/TTD adapter.", this);
	noteLabel->setWordWrap(true);
	noteLabel->setStyleSheet("color: gray;");
	mainLayout->addWidget(noteLabel);

	mainLayout->addStretch();

	/* Buttons */
	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->addStretch();

	m_cancelButton = new QPushButton("Cancel", this);
	connect(m_cancelButton, &QPushButton::clicked, this, &WinDbgUpdateDialog::onCancelClicked);
	buttonLayout->addWidget(m_cancelButton);

	/* Not "Update": when the installed version is newer than the supported one, this
	 * deliberately replaces it with an older build. */
	m_updateButton = new QPushButton(versionMatches ? "Reinstall" : "Install", this);
	m_updateButton->setDefault(true);
	connect(m_updateButton, &QPushButton::clicked, this, &WinDbgUpdateDialog::onUpdateClicked);
	buttonLayout->addWidget(m_updateButton);

	mainLayout->addLayout(buttonLayout);
}

void WinDbgUpdateDialog::onUpdateClicked()
{
	/* Confirm with user */
	QMessageBox::StandardButton reply = QMessageBox::question(
		this,
		"Confirm Installation",
		"Binary Ninja will now close and the WinDbg/TTD installer will start.\n\n"
		"Do you want to continue?",
		QMessageBox::Yes | QMessageBox::No,
		QMessageBox::Yes
	);

	if (reply != QMessageBox::Yes) {
		return;
	}

	/* Launch installer with --wait-for-binja flag (CLI will wait for binja to exit) */
	std::string installPath = m_installPath;

	/* Start installer in background - it will wait for Binary Ninja to exit */
	std::thread([installPath]() {
		(void)InstallWinDbg(installPath, true /* isUpdate */);
	}).detach();

	/* Accept dialog and signal to close Binary Ninja */
	accept();

	/* Close Binary Ninja */
	QApplication::quit();
}

void WinDbgUpdateDialog::onCancelClicked()
{
	reject();
}

#endif // WIN32
