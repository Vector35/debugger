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

#include "gdbmiadapter.h"
#include "../debuggercontroller.h"
#include <filesystem>
#include <sstream>
#include <binaryninjaapi.h>
#include <fmt/format.h>

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;
using namespace std;

// GdbProcess implementation
GdbMiAdapter::GdbProcess::GdbProcess() : valid(false)
{
#ifdef _WIN32
	process = INVALID_HANDLE_VALUE;
	stdinPipe = INVALID_HANDLE_VALUE;
	stdoutPipe = INVALID_HANDLE_VALUE;
	stderrPipe = INVALID_HANDLE_VALUE;
#else
	pid = -1;
	stdinFd = -1;
	stdoutFd = -1;
	stderrFd = -1;
#endif
}

GdbMiAdapter::GdbProcess::~GdbProcess()
{
	Terminate();
}

bool GdbMiAdapter::GdbProcess::IsRunning()
{
#ifdef _WIN32
	if (process == INVALID_HANDLE_VALUE)
		return false;
	DWORD exitCode;
	if (GetExitCodeProcess(process, &exitCode))
		return exitCode == STILL_ACTIVE;
	return false;
#else
	if (pid <= 0)
		return false;
	int status;
	pid_t result = waitpid(pid, &status, WNOHANG);
	return result == 0; // 0 means still running
#endif
}

void GdbMiAdapter::GdbProcess::Terminate()
{
#ifdef _WIN32
	if (process != INVALID_HANDLE_VALUE)
	{
		TerminateProcess(process, 1);
		CloseHandle(process);
		process = INVALID_HANDLE_VALUE;
	}
	if (stdinPipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(stdinPipe);
		stdinPipe = INVALID_HANDLE_VALUE;
	}
	if (stdoutPipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(stdoutPipe);
		stdoutPipe = INVALID_HANDLE_VALUE;
	}
	if (stderrPipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(stderrPipe);
		stderrPipe = INVALID_HANDLE_VALUE;
	}
#else
	if (pid > 0)
	{
		kill(pid, SIGTERM);
		// Wait a bit for graceful shutdown
		usleep(100000); // 100ms
		if (IsRunning())
			kill(pid, SIGKILL);
		waitpid(pid, nullptr, 0);
		pid = -1;
	}
	if (stdinFd >= 0)
	{
		close(stdinFd);
		stdinFd = -1;
	}
	if (stdoutFd >= 0)
	{
		close(stdoutFd);
		stdoutFd = -1;
	}
	if (stderrFd >= 0)
	{
		close(stderrFd);
		stderrFd = -1;
	}
#endif
	valid = false;
}

// GdbMiAdapter implementation
GdbMiAdapter::GdbMiAdapter(BinaryView* data) : DebugAdapter(data)
{
	m_isTargetRunning = false;
	m_responseReady = false;
	m_exitCode = 0;
	GenerateDefaultAdapterSettings(data);
}

GdbMiAdapter::~GdbMiAdapter()
{
	StopGdbProcess();
}

std::string GdbMiAdapter::GetGdbExecutablePath()
{
	// Get the directory where debugger plugins are installed
	std::string pluginDir;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		pluginDir = GetUserPluginDirectory();
	else
		pluginDir = GetBundledPluginDirectory();

#ifdef _WIN32
	return pluginDir + "\\gdb\\bin\\gdb.exe";
#else
	return pluginDir + "/gdb/bin/gdb";
#endif
}

bool GdbMiAdapter::StartGdbProcess()
{
	if (m_gdbProcess && m_gdbProcess->IsRunning())
		return true;

	m_gdbProcess = std::make_unique<GdbProcess>();

	std::string gdbPath = GetGdbExecutablePath();
	if (!std::filesystem::exists(gdbPath))
	{
		LogError("GDB executable not found at: %s", gdbPath.c_str());
		return false;
	}

#ifdef _WIN32
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	HANDLE hStdinRead, hStdinWrite;
	HANDLE hStdoutRead, hStdoutWrite;
	HANDLE hStderrRead, hStderrWrite;

	if (!CreatePipe(&hStdinRead, &hStdinWrite, &saAttr, 0) ||
		!CreatePipe(&hStdoutRead, &hStdoutWrite, &saAttr, 0) ||
		!CreatePipe(&hStderrRead, &hStderrWrite, &saAttr, 0))
	{
		LogError("Failed to create pipes for GDB process");
		return false;
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.hStdError = hStderrWrite;
	si.hStdOutput = hStdoutWrite;
	si.hStdInput = hStdinRead;
	si.dwFlags |= STARTF_USESTDHANDLES;

	std::string cmdLine = fmt::format("\"{}\" --interpreter=mi", gdbPath);
	if (!CreateProcessA(NULL, const_cast<char*>(cmdLine.c_str()), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		LogError("Failed to start GDB process");
		CloseHandle(hStdinRead);
		CloseHandle(hStdinWrite);
		CloseHandle(hStdoutRead);
		CloseHandle(hStdoutWrite);
		CloseHandle(hStderrRead);
		CloseHandle(hStderrWrite);
		return false;
	}

	m_gdbProcess->process = pi.hProcess;
	m_gdbProcess->stdinPipe = hStdinWrite;
	m_gdbProcess->stdoutPipe = hStdoutRead;
	m_gdbProcess->stderrPipe = hStderrRead;
	m_gdbProcess->valid = true;

	CloseHandle(pi.hThread);
	CloseHandle(hStdinRead);
	CloseHandle(hStdoutWrite);
	CloseHandle(hStderrWrite);
#else
	int stdinPipe[2], stdoutPipe[2], stderrPipe[2];
	
	if (pipe(stdinPipe) == -1 || pipe(stdoutPipe) == -1 || pipe(stderrPipe) == -1)
	{
		LogError("Failed to create pipes for GDB process");
		return false;
	}

	pid_t pid = fork();
	if (pid == -1)
	{
		LogError("Failed to fork GDB process");
		close(stdinPipe[0]);
		close(stdinPipe[1]);
		close(stdoutPipe[0]);
		close(stdoutPipe[1]);
		close(stderrPipe[0]);
		close(stderrPipe[1]);
		return false;
	}

	if (pid == 0)
	{
		// Child process
		dup2(stdinPipe[0], STDIN_FILENO);
		dup2(stdoutPipe[1], STDOUT_FILENO);
		dup2(stderrPipe[1], STDERR_FILENO);

		close(stdinPipe[0]);
		close(stdinPipe[1]);
		close(stdoutPipe[0]);
		close(stdoutPipe[1]);
		close(stderrPipe[0]);
		close(stderrPipe[1]);

		execl(gdbPath.c_str(), "gdb", "--interpreter=mi", nullptr);
		_exit(1); // If execl fails
	}

	// Parent process
	m_gdbProcess->pid = pid;
	m_gdbProcess->stdinFd = stdinPipe[1];
	m_gdbProcess->stdoutFd = stdoutPipe[0];
	m_gdbProcess->stderrFd = stderrPipe[0];
	m_gdbProcess->valid = true;

	close(stdinPipe[0]);
	close(stdoutPipe[1]);
	close(stderrPipe[1]);
#endif

	// Start output processing threads
	m_outputThread = std::thread(&GdbMiAdapter::ProcessOutput, this);
	m_errorThread = std::thread(&GdbMiAdapter::ProcessError, this);

	return true;
}

void GdbMiAdapter::StopGdbProcess()
{
	if (m_gdbProcess)
	{
		m_gdbProcess->Terminate();
		m_gdbProcess.reset();
	}

	if (m_outputThread.joinable())
		m_outputThread.join();
	if (m_errorThread.joinable())
		m_errorThread.join();
}

std::string GdbMiAdapter::SendCommand(const std::string& command)
{
	if (!m_gdbProcess || !m_gdbProcess->valid)
		return "";

	std::lock_guard<std::mutex> lock(m_commandMutex);
	
	std::string fullCommand = command + "\n";

#ifdef _WIN32
	DWORD bytesWritten;
	if (!WriteFile(m_gdbProcess->stdinPipe, fullCommand.c_str(), fullCommand.length(), &bytesWritten, NULL))
		return "";
#else
	if (write(m_gdbProcess->stdinFd, fullCommand.c_str(), fullCommand.length()) == -1)
		return "";
#endif

	// Wait for response
	std::unique_lock<std::mutex> responseLock(m_commandMutex);
	m_responseCondition.wait(responseLock, [this] { return m_responseReady; });
	
	std::string response = m_lastResponse;
	m_responseReady = false;
	return response;
}

void GdbMiAdapter::ProcessOutput()
{
	char buffer[4096];
	std::string accumulated;

	while (m_gdbProcess && m_gdbProcess->valid)
	{
#ifdef _WIN32
		DWORD bytesRead;
		if (ReadFile(m_gdbProcess->stdoutPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
#else
		ssize_t bytesRead = read(m_gdbProcess->stdoutFd, buffer, sizeof(buffer) - 1);
		if (bytesRead > 0)
#endif
		{
			buffer[bytesRead] = '\0';
			accumulated += buffer;

			// Process complete lines
			size_t pos = 0;
			while ((pos = accumulated.find('\n')) != std::string::npos)
			{
				std::string line = accumulated.substr(0, pos);
				accumulated.erase(0, pos + 1);

				// Signal response ready
				{
					std::lock_guard<std::mutex> lock(m_commandMutex);
					m_lastResponse = line;
					m_responseReady = true;
				}
				m_responseCondition.notify_one();
			}
		}
		else
		{
			break; // EOF or error
		}
	}
}

void GdbMiAdapter::ProcessError()
{
	char buffer[4096];

	while (m_gdbProcess && m_gdbProcess->valid)
	{
#ifdef _WIN32
		DWORD bytesRead;
		if (ReadFile(m_gdbProcess->stderrPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
#else
		ssize_t bytesRead = read(m_gdbProcess->stderrFd, buffer, sizeof(buffer) - 1);
		if (bytesRead > 0)
#endif
		{
			buffer[bytesRead] = '\0';
			LogWarn("GDB stderr: %s", buffer);
		}
		else
		{
			break;
		}
	}
}

std::string GdbMiAdapter::ParseMiResponse(const std::string& response)
{
	// Basic MI response parsing - this is a simplified version
	// Real implementation would need proper MI parsing
	return response;
}

void GdbMiAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	// For now, no special settings needed
}

// Debug adapter interface implementation
bool GdbMiAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return ExecuteWithArgs(path, "", "", configs);
}

bool GdbMiAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
	const LaunchConfigurations& configs)
{
	if (!StartGdbProcess())
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.shortError = "Failed to start GDB";
		event.data.errorData.error = "Could not start GDB process";
		PostDebuggerEvent(event);
		return false;
	}

	// Set executable file
	std::string cmd = fmt::format("-file-exec-and-symbols \"{}\"", path);
	std::string response = SendCommand(cmd);

	// Set arguments if provided
	if (!args.empty())
	{
		cmd = fmt::format("-exec-arguments {}", args);
		SendCommand(cmd);
	}

	// Set working directory if provided
	if (!workingDir.empty())
	{
		cmd = fmt::format("-environment-cd \"{}\"", workingDir);
		SendCommand(cmd);
	}

	// Start execution
	response = SendCommand("-exec-run");

	m_isTargetRunning = true;

	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	return true;
}

bool GdbMiAdapter::Attach(std::uint32_t pid)
{
	if (!StartGdbProcess())
		return false;

	std::string cmd = fmt::format("-target-attach {}", pid);
	std::string response = SendCommand(cmd);

	m_isTargetRunning = true;

	DebuggerEvent event;
	event.type = AttachEventType;
	PostDebuggerEvent(event);

	return true;
}

bool GdbMiAdapter::Connect(const std::string& server, std::uint32_t port)
{
	// This adapter is for local debugging, not remote
	return false;
}

bool GdbMiAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port)
{
	// This adapter is for local debugging, not remote
	return false;
}

bool GdbMiAdapter::Detach()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-target-detach");
	m_isTargetRunning = false;

	DebuggerEvent event;
	event.type = DetachEventType;
	PostDebuggerEvent(event);

	return true;
}

bool GdbMiAdapter::Quit()
{
	if (m_gdbProcess)
	{
		SendCommand("-gdb-exit");
		StopGdbProcess();
	}

	DebuggerEvent event;
	event.type = TargetExitedEventType;
	event.data.exitData.exitCode = m_exitCode;
	PostDebuggerEvent(event);

	return true;
}

std::vector<DebugProcess> GdbMiAdapter::GetProcessList()
{
	// GDB MI doesn't provide process listing functionality
	return {};
}

std::vector<DebugThread> GdbMiAdapter::GetThreadList()
{
	std::vector<DebugThread> threads;
	
	if (!m_gdbProcess)
		return threads;

	std::string response = SendCommand("-thread-info");
	// Parse MI response and extract thread information
	// This is a simplified implementation
	
	return threads;
}

DebugThread GdbMiAdapter::GetActiveThread() const
{
	return DebugThread();
}

std::uint32_t GdbMiAdapter::GetActiveThreadId() const
{
	return 1; // Default thread ID
}

bool GdbMiAdapter::SetActiveThread(const DebugThread& thread)
{
	return SetActiveThreadId(thread.m_tid);
}

bool GdbMiAdapter::SetActiveThreadId(std::uint32_t tid)
{
	if (!m_gdbProcess)
		return false;

	std::string cmd = fmt::format("-thread-select {}", tid);
	SendCommand(cmd);
	return true;
}

std::vector<DebugBreakpoint> GdbMiAdapter::GetBreakpointList() const
{
	return {};
}

DebugBreakpoint GdbMiAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
	if (!m_gdbProcess)
		return DebugBreakpoint();

	std::string cmd = fmt::format("-break-insert *0x{:x}", address);
	SendCommand(cmd);

	DebugBreakpoint bp;
	bp.m_id = address; // Simplified
	bp.m_address = address;
	bp.m_enabled = true;
	return bp;
}

DebugBreakpoint GdbMiAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	// For now, just use the offset as address
	return AddBreakpoint(address.offset, breakpoint_type);
}

bool GdbMiAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	if (!m_gdbProcess)
		return false;

	std::string cmd = fmt::format("-break-delete {}", breakpoint.m_id);
	SendCommand(cmd);
	return true;
}

std::vector<DebugModule> GdbMiAdapter::GetModuleList()
{
	return {};
}

std::vector<DebugRegister> GdbMiAdapter::GetRegisters()
{
	return {};
}

bool GdbMiAdapter::SetRegisterValue(const std::string& name, std::uintptr_t value)
{
	if (!m_gdbProcess)
		return false;

	std::string cmd = fmt::format("-gdb-set ${} = 0x{:x}", name, value);
	SendCommand(cmd);
	return true;
}

std::vector<DebugFrame> GdbMiAdapter::GetFramesOfThread(uint32_t tid)
{
	return {};
}

DataBuffer GdbMiAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	DataBuffer buffer;
	if (!m_gdbProcess)
		return buffer;

	std::string cmd = fmt::format("-data-read-memory-bytes 0x{:x} {}", address, size);
	std::string response = SendCommand(cmd);
	
	// Parse response and fill buffer
	// This is a simplified implementation
	
	return buffer;
}

bool GdbMiAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	if (!m_gdbProcess)
		return false;

	// Convert buffer to hex string
	std::string hexData;
	for (size_t i = 0; i < buffer.GetLength(); i++)
	{
		hexData += fmt::format("{:02x}", buffer[i]);
	}

	std::string cmd = fmt::format("-data-write-memory-bytes 0x{:x} \"{}\"", address, hexData);
	SendCommand(cmd);
	return true;
}

std::string GdbMiAdapter::GetTargetArchitecture()
{
	if (!m_gdbProcess)
		return "";

	SendCommand("-data-evaluate-expression \"sizeof(void*)\"");
	// Parse response to determine architecture
	return m_defaultArchitecture;
}

uint64_t GdbMiAdapter::GetInstructionOffset()
{
	if (!m_gdbProcess)
		return 0;

	std::string response = SendCommand("-data-evaluate-expression \"$pc\"");
	// Parse response to get PC value
	return 0;
}

uint64_t GdbMiAdapter::GetStackPointer()
{
	if (!m_gdbProcess)
		return 0;

	std::string response = SendCommand("-data-evaluate-expression \"$sp\"");
	// Parse response to get SP value
	return 0;
}

DebugStopReason GdbMiAdapter::StopReason()
{
	return ProcessStopped;
}

bool GdbMiAdapter::BreakInto()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-interrupt");
	m_isTargetRunning = false;
	return true;
}

bool GdbMiAdapter::Go()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-continue");
	m_isTargetRunning = true;
	return true;
}

bool GdbMiAdapter::StepInto()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-step");
	return true;
}

bool GdbMiAdapter::StepOver()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-next");
	return true;
}

bool GdbMiAdapter::StepReturn()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-finish");
	return true;
}

bool GdbMiAdapter::GoReverse()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-continue --reverse");
	return true;
}

bool GdbMiAdapter::StepIntoReverse()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-step --reverse");
	return true;
}

bool GdbMiAdapter::StepOverReverse()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-next --reverse");
	return true;
}

bool GdbMiAdapter::StepReturnReverse()
{
	if (!m_gdbProcess)
		return false;

	SendCommand("-exec-finish --reverse");
	return true;
}

std::string GdbMiAdapter::InvokeBackendCommand(const std::string& command)
{
	if (!m_gdbProcess)
		return "";

	// For direct GDB commands, use -interpreter-exec console
	std::string cmd = fmt::format("-interpreter-exec console \"{}\"", command);
	return SendCommand(cmd);
}

bool GdbMiAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	switch (feature)
	{
	case DebugAdapterCapacityBreakpoint:
	case DebugAdapterCapacityStep:
	case DebugAdapterCapacityMemoryRead:
	case DebugAdapterCapacityMemoryWrite:
	case DebugAdapterCapacityRegisters:
		return true;
	default:
		return false;
	}
}

Ref<Settings> GdbMiAdapter::GetAdapterSettings()
{
	return GdbMiAdapterType::GetAdapterSettings();
}

// GdbMiAdapterType implementation
GdbMiAdapterType::GdbMiAdapterType() : DebugAdapterType("GDB MI") {}

DebugAdapter* GdbMiAdapterType::Create(BinaryNinja::BinaryView* data)
{
	return new GdbMiAdapter(data);
}

bool GdbMiAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	// Check if GDB executable exists
	GdbMiAdapter adapter(data);
	std::string gdbPath = adapter.GetGdbExecutablePath();
	return std::filesystem::exists(gdbPath);
}

bool GdbMiAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
	return IsValidForData(data);
}

bool GdbMiAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	return false; // This adapter is for local debugging only
}

Ref<Settings> GdbMiAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("GdbMiAdapterSettings");
	settings->SetResourceId("gdb_mi_adapter_settings");
	
	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Input file to use to find the base address of the binary view",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");

	return settings;
}

Ref<Settings> GdbMiAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}

void BinaryNinjaDebugger::InitGdbMiAdapterType()
{
	static GdbMiAdapterType* gdbMiAdapterType = new GdbMiAdapterType();
	DebugAdapterType::Register(gdbMiAdapterType);
}