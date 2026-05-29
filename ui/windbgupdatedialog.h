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

#pragma once

#ifdef WIN32

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <filesystem>
#include <string>

class WinDbgUpdateDialog : public QDialog
{
	Q_OBJECT

private:
	std::filesystem::path m_installPath;
	std::string m_installedVersion;
	std::string m_latestVersion;

	QLabel* m_installedVersionLabel;
	QLabel* m_latestVersionLabel;
	QLabel* m_statusLabel;
	QPushButton* m_updateButton;
	QPushButton* m_cancelButton;

	void fetchLatestVersion();
	void updateUI();

public:
	WinDbgUpdateDialog(QWidget* parent, const std::filesystem::path& installPath, const std::string& installedVersion);

public Q_SLOTS:
	void onLatestVersionReceived(const QString& version);
	void onUpdateClicked();
	void onCancelClicked();

Q_SIGNALS:
	void latestVersionReceived(const QString& version);
};

#endif // WIN32
