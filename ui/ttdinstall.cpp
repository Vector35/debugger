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

	#include "ttdinstall.h"
	#include "windbgupdatedialog.h"
	#include "binaryninjaapi.h"
	#include "debuggerapi.h"
	#include <windows.h>
	#include <filesystem>
	#include <vector>
	#include <QApplication>
	#include <QCoreApplication>
	#include <QMessageBox>
	#include <QProcess>
	#include <QPushButton>
	#include <QThread>

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

namespace TTDInstall {

// The files each component is made of. The replay engine list matches the one DbgEngAdapter::GetDbgEngPath()
// validates, so that this check predicts whether the adapter will actually come up.
static vector<const char*> ComponentFiles(Component component)
{
	if (component == Recorder)
		return {"TTD.exe", "TTDRecord.dll"};

	return {"dbgeng.dll", "dbghelp.dll", "dbgmodel.dll", "dbgcore.dll", "dbgsrv.exe"};
}


static bool ContainsAllFiles(const filesystem::path& folder, const vector<const char*>& files)
{
	if (folder.empty() || !filesystem::exists(folder))
		return false;

	for (const auto& file : files)
	{
		if (!filesystem::exists(folder / file))
			return false;
	}

	return true;
}


std::string GetComponentPath(Component component)
{
	auto files = ComponentFiles(component);
	// The recorder lives in a TTD subfolder of the DbgEng installation
	auto resolve = [component](const filesystem::path& dbgEngRoot) {
		return (component == Recorder) ? dbgEngRoot / "TTD" : dbgEngRoot;
	};

	std::string path = Settings::Instance()->Get<string>("debugger.x64dbgEngPath");
	if (!path.empty())
	{
		// If the user has specified the path in the setting, then check it for validity. If it is valid, then use
		// it; if it is invalid, fail the operation -- do not fallback to the default one
		auto userPath = resolve(path);
		if (ContainsAllFiles(userPath, files))
			return userPath.string();
		return "";
	}

	std::string pluginRoot;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		pluginRoot = GetUserPluginDirectory();
	else
		pluginRoot = GetBundledPluginDirectory();

	auto bundledPath = resolve(filesystem::path(pluginRoot) / "dbgeng" / "amd64");
	if (ContainsAllFiles(bundledPath, files))
		return bundledPath.string();

	return "";
}


ComponentStatus GetComponentStatus(Component component)
{
	auto path = GetComponentPath(component);
	if (path.empty())
	{
		auto userPath = Settings::Instance()->Get<string>("debugger.x64dbgEngPath");
		return userPath.empty() ? ComponentMissing : ComponentUserPathInvalid;
	}

	// The DbgEng DLLs are loaded once, when the debugger plugin initializes. Installing them into a running
	// Binary Ninja does not help until it is restarted. The recorder is a separate process launched on demand,
	// so it does not have this problem.
	if ((component == ReplayEngine) && (GetModuleHandleA("dbgeng.dll") == nullptr))
		return ComponentNeedsRestart;

	return ComponentReady;
}


QString DescribeUnavailableComponent(Component component)
{
	auto status = GetComponentStatus(component);
	auto operation = (component == Recorder) ? QString("Recording a TTD trace") : QString("Time travel debugging");

	switch (status)
	{
	case ComponentNeedsRestart:
		return operation
			+ " requires WinDbg/TTD, which is installed but was not loaded when Binary Ninja started.\n\n"
			  "Restart Binary Ninja to use it.\n\nInstalled at: "
			+ QString::fromStdString(GetComponentPath(component));

	case ComponentUserPathInvalid:
		return operation
			+ " requires WinDbg/TTD, and the folder configured in debugger.x64dbgEngPath does not contain it.\n\n"
			  "The setting currently points at:\n\n"
			+ QString::fromStdString(Settings::Instance()->Get<string>("debugger.x64dbgEngPath"))
			+ "\n\nIt must be the amd64 folder of a WinDbg installation, holding dbgeng.dll along with a TTD "
			  "subfolder. Note that the debugger cannot use a WinDbg installed from the Microsoft Store or "
			  "through the standalone installer, since those are packaged in a form Binary Ninja cannot load "
			  "from -- Binary Ninja has to download its own copy.";

	case ComponentMissing:
		return operation
			+ " requires the WinDbg/TTD package that Binary Ninja downloads for itself.\n\n"
			  "Installing WinDbg from the Microsoft Store or through the standalone installer does not work, "
			  "since those are packaged in a form Binary Ninja cannot load from. Binary Ninja has to download "
			  "its own copy, which it installs into %APPDATA%\\Binary Ninja\\windbg.";

	default:
		return QString();
	}
}


bool EnsureComponentAvailable(QWidget* parent, Component component)
{
	auto status = GetComponentStatus(component);
	if (status == ComponentReady)
		return true;

	auto description = DescribeUnavailableComponent(component);

	// A restart is the only thing that helps here, there is nothing to install
	if (status == ComponentNeedsRestart)
	{
		QMessageBox::warning(parent, "Restart Required", description);
		return false;
	}

	QMessageBox box(parent);
	box.setIcon(QMessageBox::Warning);
	box.setWindowTitle("WinDbg/TTD Not Installed");
	box.setText(description);
	box.setInformativeText("Download and install it now? Binary Ninja needs to be restarted once it finishes.");

	auto* installButton = box.addButton("Install WinDbg/TTD", QMessageBox::AcceptRole);
	box.addButton(QMessageBox::Cancel);
	box.setDefaultButton(installButton);
	box.exec();

	if (box.clickedButton() == installButton)
		RunInstaller(parent);

	// Even when the install succeeds, Binary Ninja must be restarted before the operation can go ahead
	return false;
}


void RunInstaller(QWidget* parent)
{
	QWidget* mainWindow = parent ? parent->window() : nullptr;

	// Determine install path
	std::string userDir = GetUserDirectory();
	std::filesystem::path installTarget = std::filesystem::path(userDir) / "windbg";
	std::string installPath = installTarget.string();
	LogDebug("installTarget: %s", installPath.c_str());

	// Check if WinDbg is already installed
	if (std::filesystem::exists(installTarget) && IsWinDbgInstalled(installPath))
	{
		// Get installed version
		std::string installedVersion = GetWinDbgInstalledVersion(installPath);
		if (installedVersion.empty()) {
			installedVersion = "(unknown)";
		}

		// Show update dialog
		WinDbgUpdateDialog dialog(mainWindow, installPath, installedVersion);
		dialog.exec();
		return;
	}

	// Not installed - proceed with fresh installation
	// Show confirmation dialog first
	QMessageBox::StandardButton reply = QMessageBox::question(
		mainWindow,
		"Install WinDbg/TTD",
		"The WinDbg/TTD installer will be launched in a separate window.\n\n"
		"You can continue using Binary Ninja while the installation proceeds.\n"
		"You will be notified when the installation completes.\n\n"
		"Do you want to continue?",
		QMessageBox::Yes | QMessageBox::No,
		QMessageBox::Yes
	);

	if (reply != QMessageBox::Yes) {
		return;
	}

	// Create and start background installation task
	class InstallWorker : public QThread {
	public:
		InstallWorker(const std::string& path, QObject* parent = nullptr)
			: QThread(parent), m_installPath(path) {}

		void run() override {
			m_result = InstallWinDbg(m_installPath);
		}

		const InstallResult& result() const { return m_result; }
		const std::string& installPath() const { return m_installPath; }

	private:
		std::string m_installPath;
		InstallResult m_result;
	};

	InstallWorker* worker = new InstallWorker(installPath, mainWindow);

	// When installation completes, show result dialog and configure settings
	QObject::connect(worker, &QThread::finished, mainWindow, [worker, installPath, mainWindow]() {
		const InstallResult& result = worker->result();
		worker->deleteLater();

		if (result.success && IsWinDbgInstalled(installPath)) {
			// Configure debugger settings
			std::string dbgEngPath = installPath + "\\amd64";
			BinaryNinja::Settings::Instance()->Set("debugger.x64dbgEngPath", dbgEngPath);
			LogInfo("Configured debugger.x64dbgEngPath: %s", dbgEngPath.c_str());

			// Offer to restart Binary Ninja
			QMessageBox msgBox(mainWindow);
			msgBox.setWindowTitle("Installation Successful");
			msgBox.setText("WinDbg/TTD has been installed successfully!");
			msgBox.setInformativeText("The debugger settings have been configured automatically.\n\n"
				"Would you like to restart Binary Ninja now?");
			msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
			msgBox.setDefaultButton(QMessageBox::No);
			msgBox.button(QMessageBox::Yes)->setText("Restart Now");
			msgBox.button(QMessageBox::No)->setText("Restart Later");

			if (msgBox.exec() == QMessageBox::Yes) {
				// Restart Binary Ninja by spawning a new instance before quitting
				QStringList args = QCoreApplication::arguments();
				QString program = args.takeFirst();
				QProcess::startDetached(program, args);
				QApplication::quit();
			}
		} else {
			// Show error message with specific failure reason
			QString errorMsg = "WinDbg/TTD installation failed.";
			if (!result.errorMessage.empty()) {
				errorMsg += "\n\nError: " + QString::fromStdString(result.errorMessage);
			} else {
				errorMsg += "\n\nPlease check the installer console window for error details.";
			}
			QMessageBox::critical(mainWindow, "Installation Failed", errorMsg);
		}
	});

	worker->start();
}

}  // namespace TTDInstall

#endif
