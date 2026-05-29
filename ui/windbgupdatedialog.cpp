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
#include "debuggerapi.h"
#include "progresstask.h"
#include <QApplication>
#include <QGroupBox>
#include <QMessageBox>
#include <thread>

using namespace BinaryNinjaDebuggerAPI;

WinDbgUpdateDialog::WinDbgUpdateDialog(QWidget* parent, const std::filesystem::path& installPath, const std::string& installedVersion)
	: QDialog(parent), m_installPath(installPath), m_installedVersion(installedVersion)
{
	setWindowTitle("WinDbg/TTD Update");
	setMinimumWidth(450);

	QVBoxLayout* mainLayout = new QVBoxLayout(this);

	/* Version information group */
	QGroupBox* versionGroup = new QGroupBox("Version Information", this);
	QVBoxLayout* versionLayout = new QVBoxLayout(versionGroup);

	QHBoxLayout* installedLayout = new QHBoxLayout();
	installedLayout->addWidget(new QLabel("Installed version:", this));
	if (m_installedVersion.empty()) {
		m_installedVersionLabel = new QLabel("Unknown", this);
		m_installedVersionLabel->setStyleSheet("font-weight: bold; color: gray;");
	} else {
		m_installedVersionLabel = new QLabel(QString::fromStdString(m_installedVersion), this);
		m_installedVersionLabel->setStyleSheet("font-weight: bold;");
	}
	installedLayout->addWidget(m_installedVersionLabel);
	installedLayout->addStretch();
	versionLayout->addLayout(installedLayout);

	QHBoxLayout* latestLayout = new QHBoxLayout();
	latestLayout->addWidget(new QLabel("Latest version:", this));
	m_latestVersionLabel = new QLabel("Checking...", this);
	m_latestVersionLabel->setStyleSheet("font-weight: bold; color: gray;");
	latestLayout->addWidget(m_latestVersionLabel);
	latestLayout->addStretch();
	versionLayout->addLayout(latestLayout);

	mainLayout->addWidget(versionGroup);

	/* Status/explanation label */
	m_statusLabel = new QLabel(this);
	m_statusLabel->setWordWrap(true);
	m_statusLabel->setText(
		"To update or reinstall WinDbg/TTD, Binary Ninja must be closed first.\n\n"
		"Clicking 'Update' will:\n"
		"1. Close Binary Ninja\n"
		"2. Launch the installer to download and install the latest version\n"
		"3. You can restart Binary Ninja after the installation completes"
	);
	mainLayout->addWidget(m_statusLabel);

	mainLayout->addStretch();

	/* Buttons */
	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->addStretch();

	m_cancelButton = new QPushButton("Cancel", this);
	connect(m_cancelButton, &QPushButton::clicked, this, &WinDbgUpdateDialog::onCancelClicked);
	buttonLayout->addWidget(m_cancelButton);

	m_updateButton = new QPushButton("Update", this);
	m_updateButton->setDefault(true);
	connect(m_updateButton, &QPushButton::clicked, this, &WinDbgUpdateDialog::onUpdateClicked);
	buttonLayout->addWidget(m_updateButton);

	mainLayout->addLayout(buttonLayout);

	/* Connect signal for thread-safe UI update */
	connect(this, &WinDbgUpdateDialog::latestVersionReceived,
	        this, &WinDbgUpdateDialog::onLatestVersionReceived);

	/* Start fetching latest version in background */
	fetchLatestVersion();
}

void WinDbgUpdateDialog::fetchLatestVersion()
{
	/* Fetch in background thread */
	std::thread([this]() {
		std::string version = GetWinDbgLatestVersion();
		emit latestVersionReceived(QString::fromStdString(version));
	}).detach();
}

void WinDbgUpdateDialog::onLatestVersionReceived(const QString& version)
{
	m_latestVersion = version.toStdString();
	updateUI();
}

void WinDbgUpdateDialog::updateUI()
{
	if (m_latestVersion.empty()) {
		m_latestVersionLabel->setText("Unable to check");
		m_latestVersionLabel->setStyleSheet("font-weight: bold; color: red;");
		/* Can still reinstall even if we can't check latest version */
		m_statusLabel->setText(
			"Unable to check for the latest version.\n\n"
			"You can still reinstall the current version by clicking 'Reinstall'. "
			"Binary Ninja will be closed and the installer will run."
		);
		m_updateButton->setText("Reinstall");
	} else {
		m_latestVersionLabel->setText(QString::fromStdString(m_latestVersion));

		/* Handle case where installed version is unknown */
		if (m_installedVersion.empty()) {
			m_latestVersionLabel->setStyleSheet("font-weight: bold; color: orange;");
			m_statusLabel->setText(
				"Unable to determine installed version.\n\n"
				"Click 'Reinstall' to install the latest version. "
				"Binary Ninja will be closed and the installer will run."
			);
			m_updateButton->setText("Reinstall");
		} else if (m_latestVersion == m_installedVersion) {
			m_latestVersionLabel->setStyleSheet("font-weight: bold; color: green;");
			m_statusLabel->setText(
				"You already have the latest version installed.\n\n"
				"If you want to reinstall anyway, click 'Reinstall'. "
				"Binary Ninja will be closed and the installer will run."
			);
			m_updateButton->setText("Reinstall");
		} else {
			m_latestVersionLabel->setStyleSheet("font-weight: bold; color: orange;");
			m_statusLabel->setText(
				"A newer version is available!\n\n"
				"Clicking 'Update' will:\n"
				"1. Close Binary Ninja\n"
				"2. Launch the installer to download and install the latest version\n"
				"3. You can restart Binary Ninja after the installation completes"
			);
			m_updateButton->setText("Update");
		}
	}
}

void WinDbgUpdateDialog::onUpdateClicked()
{
	/* Confirm with user */
	QMessageBox::StandardButton reply = QMessageBox::question(
		this,
		"Confirm Update",
		"Binary Ninja will now close and the WinDbg/TTD installer will start.\n\n"
		"Do you want to continue?",
		QMessageBox::Yes | QMessageBox::No,
		QMessageBox::Yes
	);

	if (reply != QMessageBox::Yes) {
		return;
	}

	/* Launch installer with --wait-for-binja flag (CLI will wait for binja to exit) */
	std::filesystem::path installPath = m_installPath;

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
