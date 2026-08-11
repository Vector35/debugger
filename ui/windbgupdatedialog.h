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
#include <string>

/* Dialog shown when WinDbg/TTD is already installed.
 *
 * The debugger installs a pinned WinDbg version rather than the latest release, so there is
 * nothing to check online: we compare what is on disk against that constant and offer to
 * (re)install it. */
class WinDbgUpdateDialog : public QDialog
{
	Q_OBJECT

private:
	std::string m_installPath;
	std::string m_installedVersion;

	QPushButton* m_updateButton;
	QPushButton* m_cancelButton;

public:
	WinDbgUpdateDialog(QWidget* parent, const std::string& installPath, const std::string& installedVersion);

public Q_SLOTS:
	void onUpdateClicked();
	void onCancelClicked();
};

#endif // WIN32
