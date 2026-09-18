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

#include "openocdadapter.h"

#include <chrono>
#include <thread>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <vector>
#ifndef WIN32
#include <spawn.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <crt_externs.h>
#else
extern char** environ;
#endif
#endif

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

namespace
{
	std::string ResolveOpenOCDExecutable(const std::string& executable)
	{
#ifdef WIN32
		DWORD length = SearchPathA(nullptr, executable.c_str(), ".exe", 0, nullptr, nullptr);
		if (length == 0)
			return executable;
		std::vector<char> path(length + 1);
		if (SearchPathA(nullptr, executable.c_str(), ".exe", static_cast<DWORD>(path.size()), path.data(), nullptr))
			return path.data();
#else
		// Absolute and explicitly relative paths should be used exactly as configured.
		if (executable.find('/') != std::string::npos)
			return executable;

		std::vector<std::string> directories;
		if (const char* path = std::getenv("PATH"))
		{
			std::string_view remaining(path);
			while (true)
			{
				auto separator = remaining.find(':');
				auto directory = remaining.substr(0, separator);
				directories.emplace_back(directory.empty() ? "." : directory);
				if (separator == std::string_view::npos)
					break;
				remaining.remove_prefix(separator + 1);
			}
		}

#ifdef __APPLE__
		// Applications launched from Finder do not inherit shell startup files. Cover
		// the standard Homebrew and MacPorts locations used by terminal installations.
		directories.insert(directories.end(), {"/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"});
#else
		directories.insert(directories.end(), {"/usr/local/bin", "/usr/bin", "/snap/bin"});
#endif
		for (const auto& directory : directories)
		{
			auto candidate = directory + "/" + executable;
			if (access(candidate.c_str(), X_OK) == 0)
				return candidate;
		}
#endif
		return executable;
	}

	bool LaunchError(const std::string& message, OpenOCDAdapter* adapter)
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.shortError = "OpenOCD connection failed";
		event.data.errorData.error = message;
		adapter->PostDebuggerEvent(event);
		return false;
	}

#ifdef WIN32
	// Escape an argv element using the Windows C runtime command-line rules.
	std::string QuoteArgument(const std::string& argument)
	{
		std::string result = "\"";
		size_t slashes = 0;
		for (char c : argument)
		{
			if (c == '\\')
			{
				++slashes;
				continue;
			}
			result.append(c == '"' ? slashes * 2 + 1 : slashes, '\\');
			slashes = 0;
			result += c;
		}
		result.append(slashes * 2, '\\');
		return result + '"';
	}
#endif
}

OpenOCDAdapter::OpenOCDAdapter(BinaryView* data) : GdbAdapter(data, false)
{
	m_socket = nullptr;
	GenerateDefaultAdapterSettings(data);
}

bool OpenOCDAdapter::StartOpenOCD()
{
	if (m_spawnedOpenOCD)
		return false;

	auto settings = GetAdapterSettings();
	auto data = GetData();
	auto configuredExecutable = settings->Get<std::string>("connect.openocdPath", data);
	auto files = settings->Get<std::vector<std::string>>("connect.configFiles", data);
	auto port = settings->Get<uint64_t>("connect.port", data);
	if (configuredExecutable.empty() || files.empty())
		return LaunchError("Specify an OpenOCD executable and at least one board or interface/target config file.", this);
	auto executable = ResolveOpenOCDExecutable(configuredExecutable);

	std::vector<std::string> arguments {executable, "-c", "gdb_port " + std::to_string(port)};
	auto searchPath = settings->Get<std::string>("connect.searchPath", data);
	if (!searchPath.empty())
		arguments.insert(arguments.end(), {"-s", searchPath});
	for (const auto& file : files)
	{
		if (file.empty())
			return LaunchError("OpenOCD config file names must not be empty.", this);
		arguments.insert(arguments.end(), {"-f", file});
	}
	// Initialize and halt without resetting or programming the board.
	arguments.insert(arguments.end(), {"-c", "init; halt"});
#ifdef WIN32
	std::string commandLine;
	for (const auto& argument : arguments)
		commandLine += QuoteArgument(argument) + " ";
	STARTUPINFOA startup{};
	startup.cb = sizeof(startup);
	if (!CreateProcessA(nullptr, commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
		nullptr, nullptr, &startup, &m_openocdProcess))
		return LaunchError("Unable to start OpenOCD executable '" + executable + "' (Windows error "
			+ std::to_string(GetLastError()) + "). Configure an absolute executable path if Binary Ninja cannot see your shell PATH.", this);
#else
	std::vector<char*> argv;
	for (auto& argument : arguments)
		argv.push_back(argument.data());
	argv.push_back(nullptr);
#ifdef __APPLE__
	char** environment = *_NSGetEnviron();
#else
	char** environment = environ;
#endif
	int error = posix_spawnp(&m_openocdPid, executable.c_str(), nullptr, nullptr, argv.data(), environment);
	if (error != 0)
	{
		m_openocdPid = -1;
		return LaunchError("Unable to start OpenOCD executable '" + executable + "': " + std::string(strerror(error))
			+ ". Configure an absolute executable path if Binary Ninja cannot see your shell PATH.", this);
	}
#endif
	m_spawnedOpenOCD = true;
	return true;
}

void OpenOCDAdapter::StopOpenOCD()
{
	if (!m_spawnedOpenOCD)
		return;
#ifdef WIN32
	if (WaitForSingleObject(m_openocdProcess.hProcess, 0) == WAIT_TIMEOUT)
	{
		TerminateProcess(m_openocdProcess.hProcess, 0);
		WaitForSingleObject(m_openocdProcess.hProcess, 2000);
	}
	CloseHandle(m_openocdProcess.hThread);
	CloseHandle(m_openocdProcess.hProcess);
	m_openocdProcess = {};
#else
	// Reap before signalling so an already exited child is handled safely.
	int status = 0;
	pid_t result;
	do { result = waitpid(m_openocdPid, &status, WNOHANG); } while (result < 0 && errno == EINTR);
	if (result == 0)
	{
		kill(m_openocdPid, SIGTERM);
		for (size_t i = 0; i < 40 && result == 0; ++i)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			do { result = waitpid(m_openocdPid, &status, WNOHANG); } while (result < 0 && errno == EINTR);
		}
		if (result == 0)
		{
			kill(m_openocdPid, SIGKILL);
			while (waitpid(m_openocdPid, &status, 0) < 0 && errno == EINTR) {}
		}
	}
	m_openocdPid = -1;
#endif
	m_spawnedOpenOCD = false;
}

void OpenOCDAdapter::JoinExecutionThread()
{
	if (m_executionThread.joinable())
		m_executionThread.join();
}

OpenOCDAdapter::~OpenOCDAdapter()
{
	if (m_rspConnector && m_socket)
		m_socket->Kill();
	JoinExecutionThread();
	delete m_rspConnector;
	delete m_socket;
	StopOpenOCD();
}

bool OpenOCDAdapter::Execute(const std::string&, const LaunchConfigurations&)
{
	return Connect({}, 0);
}

bool OpenOCDAdapter::ExecuteWithArgs(const std::string&, const std::string&, const std::string&,
	const LaunchConfigurations&)
{
	return Connect({}, 0);
}

bool OpenOCDAdapter::Attach(std::uint32_t)
{
	// OpenOCD exposes a debug target rather than a host process list. Treat Binary
	// Ninja's Attach action as a connection request and ignore its PID field.
	return Connect({}, 0);
}

std::vector<DebugProcess> OpenOCDAdapter::GetProcessList()
{
	// Binary Ninja requires a process-list selection before it calls Attach().
	// OpenOCD has one configured debug target rather than an OS process list, so
	// provide a synthetic entry. Its ID is intentionally ignored by Attach().
	auto settings = GetAdapterSettings();
	auto data = GetData();
	auto host = settings->Get<std::string>("connect.ipAddress", data);
	auto port = settings->Get<uint64_t>("connect.port", data);
	return {DebugProcess(1, "OpenOCD target", host + ":" + std::to_string(port))};
}

bool OpenOCDAdapter::Connect(const std::string& server, std::uint32_t port)
{
	if (m_rspConnector || m_spawnedOpenOCD)
		return LaunchError("An OpenOCD session is already active.", this);

	auto settings = GetAdapterSettings();
	auto data = GetData();
	auto host = settings->Get<std::string>("connect.ipAddress", data);
	auto configuredPort = settings->Get<uint64_t>("connect.port", data);
	if (configuredPort == 0 || configuredPort > 65535)
		return LaunchError("The GDB port must be between 1 and 65535.", this);
	if (settings->Get<bool>("connect.spawnOpenOCD", data))
	{
		if (host != "127.0.0.1")
			return LaunchError("Local OpenOCD startup requires IP address 127.0.0.1. Disable startup to connect remotely.", this);
		if (!StartOpenOCD())
			return false;
	}

	delete m_socket;
	m_socket = nullptr;
	m_registerInfo.clear();
	m_remoteArch.clear();
	InvalidateCache();

	// The base adapter reads connect.ipAddress/connect.port from our settings and retries
	// for 15 seconds, allowing OpenOCD time to initialize the debug probe.
	try
	{
		if (GdbAdapter::Connect(server, port))
		{
			if (m_resetOnNextConnect)
			{
				RunMonitorCommand("reset halt");
				m_resetOnNextConnect = false;
				InvalidateCache();
			}
			return true;
		}
	}
	catch (const std::exception& error)
	{
		LaunchError(error.what(), this);
	}
	if (m_rspConnector && m_socket)
		m_socket->Kill();
	delete m_rspConnector;
	m_rspConnector = nullptr;
	delete m_socket;
	m_socket = nullptr;
	StopOpenOCD();
	return false;
}

bool OpenOCDAdapter::Go()
{
	// The debugger controller expects resume requests to return promptly and waits
	// for AdapterStoppedEventType separately. GdbAdapter::Go waits synchronously for
	// the stop reply, which prevents the controller's interrupt thread from acquiring
	// its adapter lock when Pause, Detach, or Quit is requested.
	JoinExecutionThread();
	m_executionThread = std::thread([this] { GdbAdapter::Go(); });
	return true;
}

bool OpenOCDAdapter::StepInto()
{
	JoinExecutionThread();
	m_executionThread = std::thread([this] { GdbAdapter::StepInto(); });
	return true;
}

bool OpenOCDAdapter::Detach()
{
	JoinExecutionThread();
	bool result = GdbAdapter::Detach();
	delete m_socket;
	m_socket = nullptr;
	StopOpenOCD();
	return result;
}

bool OpenOCDAdapter::Quit()
{
	// DebuggerController implements Restart as Quit followed by Launch on the same
	// adapter. Remember that transition so the new connection resets and halts the
	// board. A standalone Quit still disconnects instead of sending an RSP process kill.
	m_resetOnNextConnect = true;
	return Detach();
}

std::vector<DebugModule> OpenOCDAdapter::GetModuleList()
{
	if (!m_rspConnector)
		return {};
	// Bare-metal firmware has no /proc/<pid>/maps. Use the loaded image's link
	// addresses so module-relative breakpoints resolve without Linux host I/O.
	auto data = GetData();
	DebugModule module;
	module.m_name = GetAdapterSettings()->Get<std::string>("common.inputFile", data);
	module.m_short_name = module.m_name;
	module.m_address = m_start;
	module.m_size = data->GetEnd() - m_start;
	module.m_loaded = true;
	return {module};
}

Ref<Settings> OpenOCDAdapter::GetAdapterSettings()
{
	return OpenOCDAdapterType::GetAdapterSettings();
}

OpenOCDAdapterType::OpenOCDAdapterType() : DebugAdapterType("OpenOCD") {}
DebugAdapter* OpenOCDAdapterType::Create(BinaryView* data) { return new OpenOCDAdapter(data); }
bool OpenOCDAdapterType::IsValidForData(BinaryView* data) { return true; }
bool OpenOCDAdapterType::CanExecute(BinaryView* data) { return true; }
bool OpenOCDAdapterType::CanConnect(BinaryView* data) { return true; }

void BinaryNinjaDebugger::InitOpenOCDAdapterType()
{
	static OpenOCDAdapterType type;
	DebugAdapterType::Register(&type);
}

Ref<Settings> OpenOCDAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}

Ref<Settings> OpenOCDAdapterType::RegisterAdapterSettings()
{
	auto settings = Settings::Instance("OpenOCDAdapterSettings");
	settings->SetResourceId("openocd_adapter_settings");
	settings->RegisterSetting("common.inputFile", R"({"title":"Input File","type":"string","default":"",
		"description":"Local firmware image used to identify the target module","uiSelectionAction":"file"})");
	settings->RegisterSetting("connect.ipAddress", R"({"title":"IP Address","type":"string","default":"127.0.0.1",
		"description":"IPv4 address of the OpenOCD GDB server"})");
	settings->RegisterSetting("connect.port", R"({"title":"GDB Port","type":"number","default":3333,
		"minValue":1,"maxValue":65535,"description":"OpenOCD GDB server port; config files must use the same port"})");
	settings->RegisterSetting("connect.spawnOpenOCD", R"({"title":"Start OpenOCD","type":"boolean","default":true,
		"description":"Start a local OpenOCD process when connecting and stop it when disconnecting"})");
	settings->RegisterSetting("connect.openocdPath", R"({"title":"OpenOCD Executable","type":"string","default":"openocd",
		"description":"Executable path or name on PATH; an absolute path also works when a GUI application does not inherit the shell PATH","uiSelectionAction":"file"})");
	settings->RegisterSetting("connect.configFiles", R"({"title":"OpenOCD Config Files","type":"array",
		"sorted":false,"default":["openocd.cfg"],
		"description":"Ordered -f arguments: board config, or interface config followed by target config"})");
	settings->RegisterSetting("connect.searchPath", R"({"title":"OpenOCD Script Directory","type":"string","default":"",
		"description":"Optional script search directory passed with -s","uiSelectionAction":"directory"})");
	return settings;
}
