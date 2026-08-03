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

#include "ttdrecord.h"
#include "uicontext.h"
#include "qfiledialog.h"
#include "fmt/format.h"
#include <QMessageBox>
#include <TlHelp32.h>
#include <winternl.h>

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;


// Function pointer type for NtQueryInformationProcess
typedef NTSTATUS (NTAPI *NtQueryInformationProcessFn)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);


static std::string GetProcessCommandLine(DWORD pid)
{
	std::string result;

	// Can't get command line for system processes
	if (pid == 0 || pid == 4)
		return result;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProcess)
		return result;

	// Get NtQueryInformationProcess from ntdll
	static NtQueryInformationProcessFn NtQueryInformationProcess = nullptr;
	if (!NtQueryInformationProcess)
	{
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		if (ntdll)
			NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(ntdll, "NtQueryInformationProcess");
	}

	if (!NtQueryInformationProcess)
	{
		CloseHandle(hProcess);
		return result;
	}

	// Get the PEB address
	PROCESS_BASIC_INFORMATION pbi;
	ULONG returnLength;
	NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
	if (status != 0)
	{
		CloseHandle(hProcess);
		return result;
	}

	// Read the PEB to get the process parameters address
	PEB peb;
	SIZE_T bytesRead;
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
	{
		CloseHandle(hProcess);
		return result;
	}

	// Read the RTL_USER_PROCESS_PARAMETERS
	RTL_USER_PROCESS_PARAMETERS params;
	if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead))
	{
		CloseHandle(hProcess);
		return result;
	}

	// Read the command line string
	if (params.CommandLine.Length > 0 && params.CommandLine.Buffer)
	{
		std::wstring cmdLine(params.CommandLine.Length / sizeof(WCHAR), L'\0');
		if (ReadProcessMemory(hProcess, params.CommandLine.Buffer, &cmdLine[0], params.CommandLine.Length, &bytesRead))
		{
			// Convert wide string to UTF-8
			int size = WideCharToMultiByte(CP_UTF8, 0, cmdLine.c_str(), -1, nullptr, 0, nullptr, nullptr);
			if (size > 0)
			{
				result.resize(size - 1);
				WideCharToMultiByte(CP_UTF8, 0, cmdLine.c_str(), -1, &result[0], size, nullptr, nullptr);
			}
		}
	}

	CloseHandle(hProcess);
	return result;
}


static std::vector<ProcessItem> EnumerateProcessesWithCommandLine()
{
	std::vector<ProcessItem> result;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return result;

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(entry);

	if (Process32FirstW(snapshot, &entry))
	{
		do
		{
			DWORD pid = entry.th32ProcessID;
			std::string processName;

			// Convert wide string to narrow string for process name
			int size = WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, nullptr, 0, nullptr, nullptr);
			if (size > 0)
			{
				processName.resize(size - 1);
				WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, &processName[0], size, nullptr, nullptr);
			}

			// Get command line for the process
			std::string commandLine = GetProcessCommandLine(pid);

			result.emplace_back(pid, processName, commandLine);
		} while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return result;
}

TTDRecordDialog::TTDRecordDialog(QWidget* parent, BinaryView* data) :
	QDialog()
{
	if (data)
		m_controller = DebuggerController::GetController(data);

	setWindowTitle("TTD Record");
	setAttribute(Qt::WA_DeleteOnClose);

	setModal(true);
	QVBoxLayout* layout = new QVBoxLayout;
	layout->setSpacing(0);

	m_pathEntry = new QLineEdit(this);
	m_pathEntry->setMinimumWidth(800);
	m_argumentsEntry = new QLineEdit(this);
	m_workingDirectoryEntry = new QLineEdit(this);
	m_outputDirectory = new QLineEdit(this);
	m_launchWithoutTracing = new QCheckBox(this);
	m_traceChildProcesses = new QCheckBox(this);

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

	auto* outputDirSelector = new QPushButton("...", this);
	outputDirSelector->setMaximumWidth(30);
	connect(outputDirSelector, &QPushButton::clicked, [&]() {
		auto pathName = QFileDialog::getExistingDirectory(this, "Specify Trace Output Directory",
			m_outputDirectory->text(), QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
		if (!pathName.isEmpty())
            m_outputDirectory->setText(pathName);
	});

	auto pathEntryLayout = new QHBoxLayout;
	pathEntryLayout->addWidget(m_pathEntry);
	pathEntryLayout->addWidget(pathSelector);

	auto workingDirLayout = new QHBoxLayout;
	workingDirLayout->addWidget(m_workingDirectoryEntry);
	workingDirLayout->addWidget(workingDirSelector);

	auto outputLayout = new QHBoxLayout;
	outputLayout->addWidget(m_outputDirectory);
	outputLayout->addWidget(outputDirSelector);

	auto launchWithoutTracingLayout = new QHBoxLayout;
	launchWithoutTracingLayout->addWidget(m_launchWithoutTracing);
	launchWithoutTracingLayout->addWidget(new QLabel("Start application With Recording Off"));
	launchWithoutTracingLayout->addStretch();

	auto traceChildProcessesLayout = new QHBoxLayout;
	traceChildProcessesLayout->addWidget(m_traceChildProcesses);
	traceChildProcessesLayout->addWidget(new QLabel("Trace Child Processes"));
	traceChildProcessesLayout->addStretch();

	QVBoxLayout* contentLayout = new QVBoxLayout;
	contentLayout->setSpacing(10);
	contentLayout->addWidget(new QLabel("Executable Path"));
	contentLayout->addLayout(pathEntryLayout);
	contentLayout->addWidget(new QLabel("Working Directory"));
	contentLayout->addLayout(workingDirLayout);
	contentLayout->addWidget(new QLabel("Command Line Arguments"));
	contentLayout->addWidget(m_argumentsEntry);
	contentLayout->addWidget(new QLabel("Trace Output Directory"));
	contentLayout->addLayout(outputLayout);
	contentLayout->addLayout(launchWithoutTracingLayout);
	contentLayout->addLayout(traceChildProcessesLayout);

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

	layout->addLayout(contentLayout);
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
	m_traceChildProcesses->setChecked(false);

	setFixedSize(QDialog::sizeHint());

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
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

	std::error_code ec;
	auto enginePath = filesystem::path(path);
	if (!filesystem::exists(enginePath, ec))
		return false;

	if (!filesystem::exists(enginePath / "TTD.exe", ec))
		return false;

	if (!filesystem::exists(enginePath / "TTDRecord.dll", ec))
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
	auto ttdCommandLine = fmt::format("-accepteula -out \"{}\" {} {} -launch \"{}\" {}",
		m_outputDirectory->text().toStdString(),
		m_launchWithoutTracing->isChecked() ? "-tracingOff -recordMode Manual" : "",
		m_traceChildProcesses->isChecked() ? "-children" : "",
		m_pathEntry->text().toStdString(),
		m_argumentsEntry->text().toStdString());
	LogWarn("TTD tracer cmd: %s %s", ttdRecorder.c_str(), ttdCommandLine.c_str());

	SHELLEXECUTEINFOA info = {0};
	info.cbSize = sizeof(SHELLEXECUTEINFOA);
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpVerb = "runas";
	info.lpFile = ttdRecorder.c_str();
	info.lpParameters = ttdCommandLine.c_str();
	info.lpDirectory = m_workingDirectoryEntry->text().toStdString().c_str();
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


TTDAttachDialog::TTDAttachDialog(QWidget* parent, BinaryView* data) :
	QDialog()
{
	if (data)
		m_controller = DebuggerController::GetController(data);

	setWindowTitle("TTD Attach to Process");
	setAttribute(Qt::WA_DeleteOnClose);
	setMinimumSize(UIContext::getScaledWindowSize(800, 600));
	setSizeGripEnabled(true);
	setModal(true);

	QVBoxLayout* layout = new QVBoxLayout;
	layout->setSpacing(10);

	// Process list section - pass nullptr to avoid using controller's GetProcessList
	// We always want to use our own EnumerateProcessesWithCommandLine() for TTD
	m_processListWidget = new ProcessListWidget(this, nullptr);
	m_separateEdit = new FilterEdit(m_processListWidget);
	m_filter = new FilteredView(this, m_processListWidget, m_processListWidget, m_separateEdit);
	m_filter->setFilterPlaceholderText("Search process");

	auto headerLayout = new QHBoxLayout();
	headerLayout->addWidget(m_separateEdit, 1);

	auto filterLayout = new QVBoxLayout();
	filterLayout->setContentsMargins(0, 0, 0, 0);
	filterLayout->addLayout(headerLayout);
	filterLayout->addWidget(m_filter, 1);

	// TTD options section
	m_outputDirectory = new QLineEdit(this);
	m_traceChildProcesses = new QCheckBox(this);

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

	auto traceChildProcessesLayout = new QHBoxLayout;
	traceChildProcessesLayout->addWidget(m_traceChildProcesses);
	traceChildProcessesLayout->addWidget(new QLabel("Trace Child Processes"));
	traceChildProcessesLayout->addStretch();

	QVBoxLayout* optionsLayout = new QVBoxLayout;
	optionsLayout->setSpacing(5);
	optionsLayout->addWidget(new QLabel("Trace Output Directory"));
	optionsLayout->addLayout(outputLayout);
	optionsLayout->addLayout(traceChildProcessesLayout);

	// Button layout
	QHBoxLayout* buttonLayout = new QHBoxLayout;
	buttonLayout->setContentsMargins(0, 0, 0, 0);

	QPushButton* cancelButton = new QPushButton("Cancel");
	connect(cancelButton, &QPushButton::clicked, [&]() { reject(); });
	QPushButton* acceptButton = new QPushButton("Attach and Record");
	connect(acceptButton, &QPushButton::clicked, [&]() { apply(); });
	acceptButton->setDefault(true);

	connect(m_processListWidget, &QTableView::doubleClicked, [&]() { apply(); });

	buttonLayout->addStretch(1);
	buttonLayout->addWidget(cancelButton);
	buttonLayout->addWidget(acceptButton);

	layout->addLayout(filterLayout);
	layout->addLayout(optionsLayout);
	layout->addSpacing(10);
	layout->addLayout(buttonLayout);
	setLayout(layout);

	// Set default output directory
	if (m_controller)
		m_outputDirectory->setText(QString::fromStdString(m_controller->GetWorkingDirectory()));
	m_traceChildProcesses->setChecked(false);

	// Always use direct Windows enumeration to get command lines
	m_processListWidget->updateContent(EnumerateProcessesWithCommandLine());

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
}


void TTDAttachDialog::apply()
{
	uint32_t pid = m_processListWidget->GetSelectedPid();
	if (!pid)
	{
		QMessageBox::warning(this, "No Process Selected", "Please select a process to attach to.");
		return;
	}

	DoTTDAttach(pid);
	accept();
}


void TTDAttachDialog::DoTTDAttach(uint32_t pid)
{
	auto ttdPath = TTDRecordDialog::GetTTDRecorderPath();
	if (ttdPath.empty())
	{
		QMessageBox::critical(this, "Recording Failed", "The debugger cannot find the path for the TTD recorder. "
			"If you have set debugger.x64dbgEngPath, check if it is valid");
		return;
	}
	LogDebug("TTD Recorder in path %s", ttdPath.c_str());

	auto ttdRecorder = fmt::format("\"{}\\TTD.exe\"", ttdPath);
	auto ttdCommandLine = fmt::format("-accepteula -out \"{}\" {} -attach {}",
		m_outputDirectory->text().toStdString(),
		m_traceChildProcesses->isChecked() ? "-children" : "",
		pid);
	LogWarn("TTD tracer cmd: %s %s", ttdRecorder.c_str(), ttdCommandLine.c_str());

	SHELLEXECUTEINFOA info = {0};
	info.cbSize = sizeof(SHELLEXECUTEINFOA);
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpVerb = "runas";
	info.lpFile = ttdRecorder.c_str();
	info.lpParameters = ttdCommandLine.c_str();
	info.nShow = SW_NORMAL;
	bool ret = ShellExecuteExA(&info);
	if (ret == FALSE)
	{
		QMessageBox::critical(this, "Recording Failed", QString::asprintf("TTD attach failed: %lu", GetLastError()));
		return;
	}

	LogDebug("info.hProcess: %d", info.hProcess);
	WaitForSingleObject(info.hProcess, INFINITE);
	QMessageBox::information(this, "Recording Completed", "The TTD recording has completed and you can now debug the trace");
}
