/*
Copyright 2020-2024 Vector 35 Inc.

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

#include <thread>
#include <chrono>
#include <algorithm>
#include <string>
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>
#include <memory>
#include <filesystem>
#include "dbgengadapter.h"
#include "../../cli/log.h"
#include "../debuggerevent.h"
#include "shlobj_core.h"
#pragma warning(push)
// warning C40005, macro redefinition
#pragma warning(disable : 5)
#include "ntstatus.h"
#pragma warning(pop)

using namespace BinaryNinjaDebugger;
using namespace std;

static bool IsValidDbgEngPaths(const std::string& path)
{
	if (path.empty())
		return false;

	auto enginePath = filesystem::path(path);
	if (!filesystem::exists(enginePath))
		return false;

	if (!filesystem::exists(enginePath / "dbgeng.dll"))
		return false;

	if (!filesystem::exists(enginePath / "dbghelp.dll"))
		return false;

	if (!filesystem::exists(enginePath / "dbgmodel.dll"))
		return false;

	if (!filesystem::exists(enginePath / "dbgcore.dll"))
		return false;

	if (!filesystem::exists(enginePath / "dbgsrv.exe"))
		return false;

	return true;
}

std::string DbgEngAdapter::GetDbgEngPath(const std::string& arch)
{
	std::string path;
	if (arch == "amd64")
		path = Settings::Instance()->Get<string>("debugger.x64dbgEngPath");
	else
		path = Settings::Instance()->Get<string>("debugger.x86dbgEngPath");

	if (!path.empty())
	{
		// If the user has specified the path in the setting, then check it for validity. If it is valid, then use it;
		// if it is invalid, fail the operation -- do not fallback to the default one
		if (IsValidDbgEngPaths(path))
			return path;
		else
			return "";
	}

	std::string pluginRoot;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		pluginRoot = GetUserPluginDirectory();
	else
		pluginRoot = GetBundledPluginDirectory();

	// If the user does not specify a path (the default case), find the one from the plugins/dbgeng/arch
    auto debuggerRoot = filesystem::path(pluginRoot)  / "dbgeng" / arch;
    if (IsValidDbgEngPaths(debuggerRoot.string()))
        return debuggerRoot.string();

	return "";
}


static bool LoadOneDLL(const string& path, const string& name, bool strictCheckPath = true, bool forceUnload = true)
{
	auto handle = GetModuleHandleA(name.c_str());
	if (handle)
	{
		LogDebug("Module %s is already loaded before the debugger tries to load it, this is suspicious", name.c_str());
		if (!strictCheckPath)
			// The module is already loaded and we do not wish to validate its path, treat it as a success
			return true;

		char actualPath[MAX_PATH];
		if (!GetModuleFileNameA(handle, actualPath, MAX_PATH))
		{
			LogWarn("Failed to get the path of the loaded %s, error: %lu", name.c_str(), GetLastError());
			return false;
		}
		string path1 = actualPath;
		std::transform(path1.begin(), path1.end(), path1.begin(), ::toupper);
		string path2 = path + '\\' + name;
		std::transform(path2.begin(), path2.end(), path2.begin(), ::toupper);
		if (path1 == path2)
			// two paths match, ok
			return true;

		LogWarn("%s is loaded from %s, but we expect it from %s", name.c_str(), actualPath, path.c_str());
		if (!forceUnload)
			return false;

		size_t unloadMaxTries = 100;
		bool unloaded = false;
		for (size_t i = 0; i < unloadMaxTries; i++)
		{
			FreeLibrary(handle);
			handle = GetModuleHandleA(name.c_str());
			if (handle == NULL)
			{
				unloaded = true;
				break;
			}
		}
		if (!unloaded)
		{
			LogDebug("Failed to unload module %s", name.c_str());
			return false;
		}
		else
		{
			LogDebug("Module %s has been unloaded", name.c_str());
		}
	}

	auto dllFullPath = path + '\\' + name;
	handle = LoadLibraryA(dllFullPath.c_str());
	if (handle == nullptr)
	{
		LogWarn("Failed to load %s, error: %lu", dllFullPath.c_str(), GetLastError());
		return false;
	}

	return true;
}


bool DbgEngAdapter::LoadDngEngLibraries()
{
	auto enginePath = GetDbgEngPath("amd64");
	if (enginePath.empty())
	{
		LogWarn("The debugger cannot find the path for the DbgEng DLLs. "
			"If you have set debugger.x64dbgEngPath, check if it valid");
		return false;
	}
	LogDebug("DbgEng libraries in path %s", enginePath.c_str());

	auto settings = Settings::Instance();
	auto strictCheckPath = settings->Get<bool>("debugger.checkDbgEngDLLPath");
	auto forceUnload = settings->Get<bool>("debugger.tryUnloadWrongDbgEngDLL");

	if (!LoadOneDLL(enginePath, "dbghelp.dll", strictCheckPath, forceUnload))
		return false;

	if (!LoadOneDLL(enginePath, "dbgcore.dll", strictCheckPath, forceUnload))
		return false;

	if (!LoadOneDLL(enginePath, "dbgmodel.dll", strictCheckPath, forceUnload))
		return false;

	if (!LoadOneDLL(enginePath, "dbgeng.dll", strictCheckPath, forceUnload))
		return false;

	return true;
}

std::string DbgEngAdapter::GenerateRandomPipeName()
{
	const std::string chars = "abcdefghijklmnopqrstuvwxyz1234567890";
	constexpr size_t length = 16;
	srand(time(NULL));

	std::string result;
	result.resize(length);
	for (size_t i = 0; i < length; i++)
		result[i] = chars[rand() % chars.length()];

	return result;
}

bool DbgEngAdapter::LaunchDbgSrv(const std::string& commandLine)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	memset(&pi, 0, sizeof(pi));
	if (!CreateProcessA(NULL, (LPSTR)commandLine.c_str(), NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi))
	{
		return false;
	}
	m_dbgSrvLaunchedByAdapter = true;
	return true;
}

bool DbgEngAdapter::ConnectToDebugServerInternal(const std::string& connectionString)
{
	auto handle = GetModuleHandleA("dbgeng.dll");
	if (handle == nullptr)
	{
		LogWarn("Failed to get module handle for dbgeng.dll");
		return false;
	}

	//    HRESULT DebugCreate(
	//    [in]  REFIID InterfaceId,
	//    [out] PVOID  *Interface
	//    );
	typedef HRESULT(__stdcall * pfunDebugCreate)(REFIID, PVOID*);
	auto DebugCreate = (pfunDebugCreate)GetProcAddress(handle, "DebugCreate");
	if (DebugCreate == nullptr)
	{
		LogWarn("Failed to get the address of DebugCreate function");
		return false;
	}

	if (const auto result = DebugCreate(__uuidof(IDebugClient7), reinterpret_cast<void**>(&this->m_debugClient));
		result != S_OK)
	{
		LogWarn("Failed to create IDebugClient7");
		return false;
	}

	QUERY_DEBUG_INTERFACE(IDebugControl7, &this->m_debugControl);
	QUERY_DEBUG_INTERFACE(IDebugDataSpaces, &this->m_debugDataSpaces);
	QUERY_DEBUG_INTERFACE(IDebugRegisters, &this->m_debugRegisters);
	QUERY_DEBUG_INTERFACE(IDebugSymbols3, &this->m_debugSymbols);
	QUERY_DEBUG_INTERFACE(IDebugSystemObjects, &this->m_debugSystemObjects);

	constexpr size_t CONNECTION_MAX_TRY = 300;
	for (size_t i = 0; i < CONNECTION_MAX_TRY; i++)
	{
		auto result = m_debugClient->ConnectProcessServer(connectionString.c_str(), &m_server);
		if (result == S_OK)
		{
			m_connectedToDebugServer = true;
			return true;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	LogWarn("ConnectToDebugServerInternal timeout");
	return false;
}

bool DbgEngAdapter::Start()
{
	if (this->m_debugActive)
		this->Reset();

	if (!m_connectedToDebugServer)
	{
		auto pipeName = GenerateRandomPipeName();
		auto connectString = fmt::format("npipe:pipe={},Server=localhost", pipeName);
		auto arch = m_defaultArchitecture == "x86" ? "x86" : "amd64";
		auto enginePath = GetDbgEngPath(arch);
		if (enginePath.empty())
			return false;

		auto dbgsrvCommandLine = fmt::format("\"{}\\dbgsrv.exe\" -t {}", enginePath, connectString);
		if (!LaunchDbgSrv(dbgsrvCommandLine))
		{
			LogWarn("Command %s failed", dbgsrvCommandLine.c_str());
			return false;
		}

		if (!ConnectToDebugServerInternal(connectString))
		{
			LogWarn("Failed to connect process server");
			return false;
		}
	}

	m_debugEventCallbacks.SetAdapter(this);
	if (const auto result = this->m_debugClient->SetEventCallbacks(&this->m_debugEventCallbacks); result != S_OK)
	{
		LogWarn("Failed to set event callbacks");
		return false;
	}

	m_outputCallbacks.SetAdapter(this);
	if (const auto result = this->m_debugClient->SetOutputCallbacks(&this->m_outputCallbacks); result != S_OK)
	{
		LogWarn("Failed to set output callbacks");
		return false;
	}

    m_inputCallbacks.SetDbgControl(m_debugControl);
    if (const auto result = this->m_debugClient->SetInputCallbacks(&this->m_inputCallbacks); result != S_OK)
	{
		LogWarn("Failed to set input callbacks");
		return false;
	}

	this->m_debugActive = true;
	return true;
}


void DbgEngAdapter::Reset()
{
	m_aboutToBeKilled = false;

	if (!this->m_debugActive)
		return;

	// Free up the resources if the dbgsrv is launched by the adapter. Otherwise, the dbgsrv is launched outside BN,
	// we should keep everything active.
	if (m_dbgSrvLaunchedByAdapter)
	{
		SAFE_RELEASE(this->m_debugControl);
		SAFE_RELEASE(this->m_debugDataSpaces);
		SAFE_RELEASE(this->m_debugRegisters);
		SAFE_RELEASE(this->m_debugSymbols);
		SAFE_RELEASE(this->m_debugSystemObjects);

		if (this->m_debugClient)
		{
			this->m_debugClient->EndSession(DEBUG_END_PASSIVE);
			this->m_debugClient->EndProcessServer(m_server);
			m_dbgSrvLaunchedByAdapter = false;
			m_connectedToDebugServer = false;
			m_server = 0;
		}

		SAFE_RELEASE(this->m_debugClient);
	}

	this->m_debugActive = false;
}


DbgEngAdapter::DbgEngAdapter(BinaryView* data) : DebugAdapter(data)
{
    auto metadata = data->QueryMetadata("PDB_FILENAME");
    if (metadata && metadata->IsString())
        m_pdbFileName = metadata->GetString();
}

DbgEngAdapter::~DbgEngAdapter()
{
}


bool DbgEngAdapter::Init()
{
	return true;
}


bool DbgEngAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return this->ExecuteWithArgs(path, "", "", {});
}


bool DbgEngAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
	const LaunchConfigurations& configs)
{
	std::atomic_bool ret = false;
	std::atomic_bool finished = false;
	// Doing the operation on a different thread ensures the same thread starts the session and runs EngineLoop().
	// This is required by DngEng. Although things sometimes work even if it is violated, it can fail randomly.
	std::thread([=, &ret, &finished]() {
		ret = ExecuteWithArgsInternal(path, args, workingDir, configs);
		finished = true;
		if (ret)
			EngineLoop();
	}).detach();

	while (!finished)
	{}
	return ret;
}


bool DbgEngAdapter::ExecuteWithArgsInternal(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	m_aboutToBeKilled = false;

	if (this->m_debugActive)
	{
		this->Reset();
	}

	if (!Start())
	{
		this->Reset();
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("Failed to initialize DbgEng");
		event.data.errorData.shortError = fmt::format("Failed to initialize DbgEng");
		PostDebuggerEvent(event);
		return false;
	}

	if (const auto result = this->m_debugControl->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK); result != S_OK)
	{
		this->Reset();
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("Failed to engine option DEBUG_ENGOPT_INITIAL_BREAK");
		event.data.errorData.shortError = fmt::format("Failed to engine option");
		PostDebuggerEvent(event);
		return false;
	}

	/* TODO: parse args better */
	std::string path_with_args {path};
	if (!args.empty())
	{
		path_with_args.append(" ");
		path_with_args.append(args);
	}

	DEBUG_CREATE_PROCESS_OPTIONS options;
	options.CreateFlags = DEBUG_ONLY_THIS_PROCESS;
	options.EngCreateFlags = 0;
	options.VerifierFlags = 0;
	options.Reserved = 0;

	// CreateProcess2() is picky about the InitialDirectory parameter. It is OK to send in a NULL, but if a non-NULL
	// string which is empty gets passed in, the call fails.
	char* directory = _strdup(workingDir.c_str());
	if (workingDir.empty())
		directory = nullptr;

	if (const auto result = this->m_debugClient->CreateProcess2(m_server, const_cast<char*>(path_with_args.c_str()),
			&options, sizeof(DEBUG_CREATE_PROCESS_OPTIONS), directory, nullptr);
		result != S_OK)
	{
		this->Reset();
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("CreateProcess2 failed: 0x{:x}", result);
		event.data.errorData.shortError = fmt::format("CreateProcess2 failed: 0x{:x}", result);
		PostDebuggerEvent(event);
		return false;
	}

	// The WaitForEvent() must be called once before the engine fully attaches to the target.
	if (!Wait())
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("WaitForEvent failed");
		event.data.errorData.shortError = fmt::format("WaitForEvent failed");
		PostDebuggerEvent(event);
	}

	// Apply the breakpoints added before the m_debugClient is created
	ApplyBreakpoints();

	auto settings = Settings::Instance();
	if (settings->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction)
	{
		AddBreakpoint(ModuleNameAndOffset(configs.inputFile, m_entryPoint - m_start));
	}

	if (!settings->Get<bool>("debugger.stopAtSystemEntryPoint"))
	{
		if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK)
		{
			this->Reset();
			DebuggerEvent event;
			event.type = LaunchFailureEventType;
			event.data.errorData.error = fmt::format("Failed to resume the target after the system entry point");
			event.data.errorData.shortError = fmt::format("Failed to resume target");
			PostDebuggerEvent(event);
			return false;
		}
	}

	return true;
}


void DbgEngAdapter::EngineLoop()
{
	auto settings = Settings::Instance();
	bool outputStateOnStop = settings->Get<bool>("debugger.dbgEngOutputStateOnStop");

	m_lastExecutionStatus = DEBUG_STATUS_NO_DEBUGGEE;
	bool finished = false;
	while (true)
	{
		if (finished)
			break;

		//Wait();
		unsigned long execution_status {};
		while (true)
		{
			if (this->m_debugControl->GetExecutionStatus(&execution_status) != S_OK)
			{}

			if (execution_status == DEBUG_STATUS_BREAK)
			{
				if (m_lastExecutionStatus != DEBUG_STATUS_BREAK)
				{
					if (outputStateOnStop)
					{
						// m_debugRegisters->OutputRegisters(DEBUG_OUTCTL_THIS_CLIENT, DEBUG_REGISTERS_DEFAULT);
						m_debugControl->OutputCurrentState(DEBUG_OUTCTL_THIS_CLIENT, DEBUG_CURRENT_DEFAULT);
					}
					DebuggerEvent event;
					event.type = AdapterStoppedEventType;
					event.data.targetStoppedData.reason = StopReason();
					PostDebuggerEvent(event);
				}

				// This is NOT actually dispatching callback, since the callbacks are already dispatched in
				// WaitForEvent(). The real purpose of this call is to wait until the UI/API initiates another control
				// operation, which then calls ExitDispatch(), which causes the DispatchCallbacks() to return.
				m_debugClient->DispatchCallbacks(INFINITE);
			}
			// TODO: add step branch and step backs
			else if ((execution_status == DEBUG_STATUS_GO) || (execution_status == DEBUG_STATUS_STEP_INTO)
				|| (execution_status == DEBUG_STATUS_STEP_OVER) || (execution_status == DEBUG_STATUS_GO_HANDLED)
				|| (execution_status == DEBUG_STATUS_STEP_BRANCH)
				|| (execution_status == DEBUG_STATUS_GO_NOT_HANDLED) || (execution_status == DEBUG_STATUS_REVERSE_GO)
				|| (execution_status == DEBUG_STATUS_REVERSE_STEP_OVER)
				|| (execution_status == DEBUG_STATUS_REVERSE_STEP_INTO)
				|| (execution_status == DEBUG_STATUS_REVERSE_STEP_BRANCH))
			{
				DebuggerEvent dbgevt;
				if ((execution_status == DEBUG_STATUS_GO) || (execution_status == DEBUG_STATUS_REVERSE_GO)
					|| ((execution_status == DEBUG_STATUS_GO_HANDLED))
					|| (execution_status == DEBUG_STATUS_GO_NOT_HANDLED))
				{
					dbgevt.type = ResumeEventType;
					PostDebuggerEvent(dbgevt);
				}
				else if ((execution_status == DEBUG_STATUS_STEP_INTO) || (execution_status == DEBUG_STATUS_STEP_OVER)
					|| (execution_status == DEBUG_STATUS_STEP_BRANCH)
					|| (execution_status == DEBUG_STATUS_REVERSE_STEP_OVER)
					|| (execution_status == DEBUG_STATUS_REVERSE_STEP_INTO)
					|| (execution_status == DEBUG_STATUS_REVERSE_STEP_BRANCH))
				{
					dbgevt.type = StepIntoEventType;
					PostDebuggerEvent(dbgevt);
				}
				break;
			}
			else if (execution_status == DEBUG_STATUS_NO_DEBUGGEE)
			{
				finished = true;
				DebuggerEvent event;
				event.type = TargetExitedEventType;
				event.data.exitData.exitCode = ExitCode();
				PostDebuggerEvent(event);
				Reset();
				break;
			}
			m_lastExecutionStatus = execution_status;
		}
		m_lastExecutionStatus = execution_status;

		if (finished)
			break;

		Wait();
	}

	m_lastExecutionStatus = DEBUG_STATUS_NO_DEBUGGEE;
}

bool DbgEngAdapter::AttachInternal(std::uint32_t pid)
{
	m_aboutToBeKilled = false;

	if (this->m_debugActive)
		this->Reset();

	this->Start();

	if (const auto result = this->m_debugControl->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK); result != S_OK)
	{
		this->Reset();
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("Failed to engine option DEBUG_ENGOPT_INITIAL_BREAK");
		event.data.errorData.shortError = fmt::format("Failed to engine option");
		PostDebuggerEvent(event);
		return false;
	}

	if (const auto result = this->m_debugClient->AttachProcess(m_server, pid, 0); result != S_OK)
	{
		this->Reset();
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("AttachProcess failed: 0x{:x}", result);
		event.data.errorData.shortError = fmt::format("AttachProcess failed: 0x{:x}", result);
		PostDebuggerEvent(event);
		return false;
	}

	if (!Wait())
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("WaitForEvent failed");
		event.data.errorData.shortError = fmt::format("WaitForEvent failed");
		PostDebuggerEvent(event);
	}

	ApplyBreakpoints();

	return true;
}

bool DbgEngAdapter::Attach(std::uint32_t pid)
{
	std::atomic_bool ret = false;
	std::atomic_bool finished = false;
	// Doing the operation on a different thread ensures the same thread starts the session and runs EngineLoop().
	// This is required by DngEng. Although things sometimes work even if it is violated, it can fail randomly.
	std::thread([=, &ret, &finished]() {
		ret = AttachInternal(pid);
		finished = true;
		if (ret)
			EngineLoop();
	}).detach();

	while (!finished)
	{}
	return ret;
}

bool DbgEngAdapter::Connect(const std::string& server, std::uint32_t port)
{
	DebuggerEvent event;
	event.type = LaunchFailureEventType;
	event.data.errorData.error = fmt::format("Connect() is not implemented in DbgEng");
	event.data.errorData.shortError = fmt::format("Connect() is not implemented in DbgEng");
	PostDebuggerEvent(event);
	return false;
}

bool DbgEngAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port)
{
	std::string connectionString = fmt::format("tcp:port={}, Server={}", port, server);
	return ConnectToDebugServerInternal(connectionString);
}

bool DbgEngAdapter::DisconnectDebugServer()
{
	if (!m_connectedToDebugServer)
		return true;

	auto ret = m_debugClient->DisconnectProcessServer(m_server);
	m_connectedToDebugServer = false;
	m_server = 0;

	return ret == S_OK;
}

bool DbgEngAdapter::Detach()
{
	m_aboutToBeKilled = true;
	m_lastOperationIsStepInto = false;
	if (!this->m_debugClient)
		return false;

	if (this->m_debugClient->DetachProcesses() != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}

bool DbgEngAdapter::Quit()
{
	m_aboutToBeKilled = true;
	m_lastOperationIsStepInto = false;
	if (!this->m_debugClient)
		return false;

	if (this->m_debugClient->TerminateProcesses() != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}

std::vector<DebugProcess> DbgEngAdapter::GetProcessList()
{
	// we need to start dbgserver in order to get process list
	
	if (!m_debugActive)
	{
		if (!Start())
			return {};
	}

	ULONG Count = 0;
	if (m_debugClient->GetRunningProcessSystemIds(m_server, 0, 0, &Count) != S_OK)
	{
		LogError("Failed to get system process count.");
		return {};
	}

	auto procIds = std::make_unique<unsigned long[]>(Count);
	if (m_debugClient->GetRunningProcessSystemIds(m_server, procIds.get(), Count, &Count) != S_OK)
	{
		LogError("Failed to get system process ids.");
		return {};
	}

	std::vector<DebugProcess> debug_processes {};
	for (int i = 0; i < Count; i++)
	{
		char processName[MAX_PATH];
		ZeroMemory(processName, MAX_PATH);

		if (m_debugClient->GetRunningProcessDescription(
			m_server, 
			procIds[i], 
			DEBUG_PROC_DESC_DEFAULT, 
			processName,
			sizeof(processName), 
			NULL, 
			NULL, 
			0, 
			NULL) != S_OK)
		{
			strcpy_s(processName, MAX_PATH, "<could not get process name>");
		}	

		debug_processes.emplace_back(procIds[i], processName);
	}

	return debug_processes;
}

std::vector<DebugThread> DbgEngAdapter::GetThreadList()
{
	if (!m_debugSystemObjects)
		return {};

	unsigned long number_threads {};
	if (this->m_debugSystemObjects->GetNumberThreads(&number_threads) != S_OK)
		return {};

	auto tids = std::make_unique<unsigned long[]>(number_threads);
	auto sysids = std::make_unique<unsigned long[]>(number_threads);
	if (this->m_debugSystemObjects->GetThreadIdsByIndex(0, number_threads, tids.get(), sysids.get()) != S_OK)
		return {};

	std::vector<DebugThread> debug_threads {};
	DebugThread activeThead = GetActiveThread();
	for (std::size_t index {}; index < number_threads; index++)
	{
		SetActiveThreadId(tids[index]);
		uint64_t pc = GetInstructionOffset();
		debug_threads.emplace_back(tids[index], pc);
	}
	SetActiveThread(activeThead);

	return debug_threads;
}

// Note, on Windows, we use engine thread ID, but on Linux/macOS, we use system thread ID.
// System thread ID is also available on Windows, We should later add a new field to the DebugThread struct
DebugThread DbgEngAdapter::GetActiveThread() const
{
	// Temporary hacky to get the code compile without changing everything
	if (!m_debugRegisters)
		return DebugThread {};
	return DebugThread(this->GetActiveThreadId(), ((DbgEngAdapter*)this)->GetInstructionOffset());
}

std::uint32_t DbgEngAdapter::GetActiveThreadId() const
{
	unsigned long current_tid {};
	if (this->m_debugSystemObjects->GetCurrentThreadId(&current_tid) != S_OK)
		return {};

	return current_tid;
}

bool DbgEngAdapter::SetActiveThread(const DebugThread& thread)
{
	return this->SetActiveThreadId(thread.m_tid);
}

bool DbgEngAdapter::SetActiveThreadId(std::uint32_t tid)
{
	if (this->m_debugSystemObjects->SetCurrentThreadId(tid) != S_OK)
		return false;

	return true;
}


bool DbgEngAdapter::SuspendThread(std::uint32_t tid)
{
	std::string suspendCmd = fmt::format("~{}f", tid);
	InvokeBackendCommand(suspendCmd);
	return true;
}

bool DbgEngAdapter::ResumeThread(std::uint32_t tid)
{
	std::string resumeCmd = fmt::format("~{}u", tid);
	InvokeBackendCommand(resumeCmd);
	return true;
}


DebugBreakpoint DbgEngAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags)
{
	IDebugBreakpoint2* debug_breakpoint {};

	/* attempt to read at breakpoint location to confirm its valid */
	/* DbgEng won't tell us if its valid until continue/go so this is a hacky fix */
    /* Note we cannot write to it if we are replaying TTD trace */
	auto val = this->ReadMemory(address, 1);
	if (val.GetLength() != 1)
		return {};

	if (const auto result =
			this->m_debugControl->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &debug_breakpoint);
		result != S_OK)
		return {};

	/* these will all work even on invalid addresses hence the previous checks */
	unsigned long id {};
	if (debug_breakpoint->GetId(&id) != S_OK)
		return {};

	if (debug_breakpoint->SetOffset(address) != S_OK)
		return {};

	if (debug_breakpoint->SetFlags(DEBUG_BREAKPOINT_ENABLED | breakpoint_flags) != S_OK)
		return {};

	const auto new_breakpoint = DebugBreakpoint(address, id, true);
	this->m_debug_breakpoints.push_back(new_breakpoint);

	return new_breakpoint;
}

static std::string EscapeModuleName(const std::string& name)
{
	std::string result = name;
	const std::string charsToEscape = " -'~`.";
	auto shouldReplace = [&](char c) -> bool {
		return charsToEscape.find(c) != std::string::npos;
	};
	std::replace_if(result.begin(), result.end(), shouldReplace, '_');
	return result;
}

DebugBreakpoint DbgEngAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	// If the backend has been created, we add the breakpoints directly. Otherwise, keep track of the breakpoints,
	// and add them when we launch/attach the target.
	if (m_debugActive)
	{
        auto moduleToUse = address.module;
        if (DebugModule::IsSameBaseModule(moduleToUse, m_originalFileName))
        {
            if (m_usePDBFileName && (!m_pdbFileName.empty()))
                moduleToUse = m_pdbFileName;
        }

		// DbgEng does not take a full path. It can take "hello.exe", or simply "hello". E.g., "bp helloworld+0x1338"
		auto fileName = std::filesystem::path(moduleToUse).stem();
		std::string breakpointCommand =
			fmt::format("bp @!\"{}\"+0x{:x}", EscapeModuleName(fileName.string()), address.offset);
        LogDebug("Breakpoint command: %s", breakpointCommand.c_str());
		auto ret = InvokeBackendCommand(breakpointCommand);
	}
	else
	{
		if (std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end())
			m_pendingBreakpoints.push_back(address);
	}

	return DebugBreakpoint {};
}

bool DbgEngAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	bool done = false;
	ULONG numBreakpoints {};
	if (m_debugControl->GetNumberBreakpoints(&numBreakpoints) != S_OK)
		return false;

	for (size_t i = 0; i < numBreakpoints; i++)
	{
		IDebugBreakpoint2* bp {};
		if (m_debugControl->GetBreakpointByIndex2(i, &bp) != S_OK)
			continue;

		ULONG64 address {};
		if (bp->GetOffset(&address) != S_OK)
			continue;

		// Right now, only the address info of the breakpoint is valid.
		// Once the ID info is also valid, we can call GetBreakpointById2() to get the breakpoint by ID.
		if (address == breakpoint.m_address)
		{
			m_debugControl->RemoveBreakpoint2(bp);
			done = true;
			break;
		}
	}
	return done;
}

bool DbgEngAdapter::RemoveBreakpoint(const ModuleNameAndOffset& breakpoint)
{
	// If the backend has been created, we remove the breakpoints directly. Otherwise, remove it from the list of
	// pending breakpoints.
	if (m_debugActive)
	{
		// TODO. This is not used by the controller right now.
	}
	else
	{
		auto it = std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), breakpoint);
		if (it != m_pendingBreakpoints.end())
			m_pendingBreakpoints.erase(it);
	}
}

std::vector<DebugBreakpoint> DbgEngAdapter::GetBreakpointList() const
{
	// TODO: this list is maintained properly and can become outdated. Also, it is not used by the controller
	//    return this->m_debug_breakpoints;
	return {};
}

void DbgEngAdapter::ApplyBreakpoints()
{
	for (const auto bp : m_pendingBreakpoints)
	{
		AddBreakpoint(bp);
	}
	m_pendingBreakpoints.clear();
}

DebugRegister DbgEngAdapter::ReadRegister(const std::string& reg)
{
	if (!m_debugRegisters)
		return DebugRegister {};

	unsigned long reg_index {};
	DEBUG_VALUE debug_value {};
	DEBUG_REGISTER_DESCRIPTION register_descriptor {};

	if (this->m_debugRegisters->GetIndexByName(reg.c_str(), &reg_index) != S_OK)
		return {};

	if (this->m_debugRegisters->GetValue(reg_index, &debug_value) != S_OK)
		return {};

	char buf[256];
	unsigned long reg_length {};
	if (this->m_debugRegisters->GetDescription(reg_index, buf, 256, &reg_length, &register_descriptor) != S_OK)
		return {};

	std::size_t width {};
	switch (register_descriptor.Type)
	{
	case DEBUG_VALUE_INT8:
		width = 8;
		break;
	case DEBUG_VALUE_INT16:
		width = 16;
		break;
	case DEBUG_VALUE_INT32:
		width = 32;
		break;
	case DEBUG_VALUE_INT64:
		width = 64;
		break;
	case DEBUG_VALUE_FLOAT32:
		width = 32;
		break;
	case DEBUG_VALUE_FLOAT64:
		width = 64;
		break;
	case DEBUG_VALUE_FLOAT80:
		width = 80;
		break;
	case DEBUG_VALUE_FLOAT128:
		width = 128;
		break;
	case DEBUG_VALUE_VECTOR64:
		width = 64;
		break;
	case DEBUG_VALUE_VECTOR128:
		width = 128;
		break;
	default:
		break;
	}

	return DebugRegister {reg, debug_value.I64, width, reg_index};
}

bool DbgEngAdapter::WriteRegister(const std::string& reg, std::uintptr_t value)
{
	unsigned long reg_index {};

	if (this->m_debugRegisters->GetIndexByName(reg.c_str(), &reg_index) != S_OK)
		return false;

	DEBUG_VALUE debug_value {};
	debug_value.I64 = value;
	debug_value.Type = DEBUG_VALUE_INT64;

	if (this->m_debugRegisters->SetValue(reg_index, &debug_value) != S_OK)
		return false;

	return true;
}


std::string DbgEngAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
	if (!m_debugRegisters)
		return {};

	unsigned long reg_length {};
	DEBUG_REGISTER_DESCRIPTION reg_description {};

	std::array<char, 256> out {'\0'};
	if (this->m_debugRegisters->GetDescription(index, out.data(), 256, &reg_length, &reg_description) != S_OK)
		return {};

	return std::string(out.data());
}


std::vector<std::string> DbgEngAdapter::GetRegisterList() const
{
	if (!this->m_debugRegisters)
		return {};

	unsigned long register_count {};
	if (this->m_debugRegisters->GetNumberRegisters(&register_count) != S_OK)
		return {};

	std::vector<std::string> register_list {};
	for (std::size_t reg_index {}; reg_index < register_count; reg_index++)
		register_list.push_back(this->GetRegisterNameByIndex(reg_index));

	return register_list;
}


std::vector<DebugModule> DbgEngAdapter::GetModuleList()
{
	if (!this->m_debugSymbols)
		return {};

	unsigned long loaded_module_count {}, unloaded_module_count {};

	if (this->m_debugSymbols->GetNumberModules(&loaded_module_count, &unloaded_module_count) != S_OK)
		return {};

	if (!loaded_module_count)
		return {};

	std::vector<DebugModule> modules {};

	const auto total_modules = loaded_module_count + unloaded_module_count;
	auto module_parameters = std::make_unique<DEBUG_MODULE_PARAMETERS[]>(total_modules);
	if (this->m_debugSymbols->GetModuleParameters(total_modules, nullptr, 0, module_parameters.get()) != S_OK)
		return {};

	for (std::size_t module_index {}; module_index < total_modules; module_index++)
	{
		const auto& parameters = module_parameters[module_index];

		char name[1024];
		char short_name[1024];
		char loaded_image_name[1024];
		if (this->m_debugSymbols->GetModuleNames(
				module_index, 0, name, 1024, nullptr, short_name, 1024, nullptr, loaded_image_name, 1024, nullptr)
			!= S_OK)
			continue;

		if (m_usePDBFileName &&(!m_pdbFileName.empty()) &&
			DebugModule::IsSameBaseModule(short_name, m_pdbFileName))
		{
			strcpy_s(name, 1024, m_originalFileName.c_str());
		}

		modules.emplace_back(
			name, short_name, parameters.Base, parameters.Size, !(parameters.Flags & DEBUG_MODULE_UNLOADED));
	}

	return modules;
}

bool DbgEngAdapter::BreakInto()
{
	if (ExecStatus() == DEBUG_STATUS_BREAK)
		return false;

	m_lastOperationIsStepInto = false;
	//	After we call SetInterrupt(), the WaitForEvent() function will return due to a breakpoint exception
	if (this->m_debugControl->SetInterrupt(DEBUG_INTERRUPT_ACTIVE) != S_OK)
		return false;

	return true;
}

bool DbgEngAdapter::Go()
{
	// TODO: we should have the debugger core to detect the failure and notify the user about it.
	// Currently, LLDB directly notifies such errors, which needs to be changed in the future.
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	m_lastOperationIsStepInto = false;
	if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}

bool DbgEngAdapter::StepInto()
{
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	m_lastOperationIsStepInto = true;
	if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}

bool DbgEngAdapter::StepOver()
{
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	m_lastOperationIsStepInto = false;
	if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}

bool DbgEngAdapter::StepReturn()
{
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	InvokeBackendCommand("gu");
	return true;
}

bool DbgEngAdapter::Wait(std::chrono::milliseconds timeout)
{
	std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint));
	std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_lastException, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_lastException));

	const auto wait_result = this->m_debugControl->WaitForEvent(0, INFINITE);
	return wait_result == S_OK;
}

std::unordered_map<std::string, DebugRegister> DbgEngAdapter::ReadAllRegisters()
{
	std::unordered_map<std::string, DebugRegister> all_regs {};

	for (const auto& reg : this->GetRegisterList())
	{
		const auto regRead = this->ReadRegister(reg);
		// During TTD replay, some registers are present in the list, but their values are unavailable, e.g., ymm0.
		// A better way is to have ReadRegister() fail for them. However, here I am doing it in a simple and dirty way
		// by checking whether the name of the returned register is empty.
		if (!regRead.m_name.empty())
			all_regs[reg] = regRead;
	}

	return all_regs;
}

std::string DbgEngAdapter::GetTargetArchitecture()
{
	if (!m_debugControl)
		return "";

	unsigned long processor_type {};

	if (this->m_debugControl->GetExecutingProcessorType(&processor_type) != S_OK)
		return "";

	switch (processor_type)
	{
	case IMAGE_FILE_MACHINE_I386:
		return "x86";
	case IMAGE_FILE_MACHINE_AMD64:
		return "x86_64";
	default:
		return "";
	}
}

DebugStopReason DbgEngAdapter::StopReason()
{
	const auto exec_status = this->ExecStatus();
	if (exec_status == DEBUG_STATUS_BREAK)
	{
		const auto instruction_ptr = this->ReadRegister(this->GetTargetArchitecture() == "x86" ? "eip" : "rip").m_value;

		if (instruction_ptr == DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint.m_address)
			return DebugStopReason::Breakpoint;

		const auto& last_exception = DbgEngAdapter::ProcessCallbackInfo.m_lastException;
		if (instruction_ptr == last_exception.ExceptionAddress)
		{
			switch (last_exception.ExceptionCode)
			{
			case STATUS_BREAKPOINT:
			case STATUS_WX86_BREAKPOINT:
				return DebugStopReason::Breakpoint;
			case STATUS_SINGLE_STEP:
			case STATUS_WX86_SINGLE_STEP:
				return DebugStopReason::SingleStep;
			case STATUS_ACCESS_VIOLATION:
				return DebugStopReason::AccessViolation;
			case STATUS_INTEGER_DIVIDE_BY_ZERO:
			case STATUS_FLOAT_DIVIDE_BY_ZERO:
				return DebugStopReason::Calculation;
			default:
				return DebugStopReason::UnknownReason;
			}
		}

		if (m_lastOperationIsStepInto)
			return DebugStopReason::SingleStep;
	}
	else if (exec_status == DEBUG_STATUS_NO_DEBUGGEE)
	{
		return DebugStopReason::ProcessExited;
	}

	return DebugStopReason::UnknownReason;
}

unsigned long DbgEngAdapter::ExecStatus()
{
	if (!m_debugControl)
		return DEBUG_STATUS_NO_DEBUGGEE;

	unsigned long execution_status {};
	if (this->m_debugControl->GetExecutionStatus(&execution_status) != S_OK)
		return 0;

	return execution_status;
}

uint64_t DbgEngAdapter::ExitCode()
{
	return DbgEngAdapter::ProcessCallbackInfo.m_exitCode;
}

std::string DbgEngAdapter::InvokeBackendCommand(const std::string& command)
{
	if (m_debugControl)
	{
		m_outputCallbacks.StartOutput();
		this->m_debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, command.c_str(), DEBUG_EXECUTE_NO_REPEAT);
		m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
		// The output is handled by DbgEngOutputCallbacks::Output(), and Execute() would not return until all output
		// has been dumped, so we can get the full output here
		auto ret = m_outputCallbacks.EndOutput();
		return ret;
	}
	return "";
}

uint64_t DbgEngAdapter::GetInstructionOffset()
{
	if (!m_debugRegisters)
		return -1;
	std::uintptr_t register_offset {};
	this->m_debugRegisters->GetInstructionOffset(&register_offset);

	return register_offset;
}

uint64_t DbgEngAdapter::GetStackPointer()
{
	if (!m_debugRegisters)
		return 0;

	uint64_t stackPointer {};
	m_debugRegisters->GetStackOffset(&stackPointer);
	return stackPointer;
}

unsigned long DbgEngEventCallbacks::AddRef()
{
	return 1;
}

unsigned long DbgEngEventCallbacks::Release()
{
	return 0;
}

HRESULT DbgEngEventCallbacks::GetInterestMask(unsigned long* mask)
{
	*mask = 0;
	*mask |= DEBUG_EVENT_BREAKPOINT;
	*mask |= DEBUG_EVENT_EXCEPTION;
	*mask |= DEBUG_EVENT_CREATE_THREAD;
	*mask |= DEBUG_EVENT_EXIT_THREAD;
	*mask |= DEBUG_EVENT_CREATE_PROCESS;
	*mask |= DEBUG_EVENT_EXIT_PROCESS;
	*mask |= DEBUG_EVENT_LOAD_MODULE;
	*mask |= DEBUG_EVENT_UNLOAD_MODULE;
	*mask |= DEBUG_EVENT_SYSTEM_ERROR;
	*mask |= DEBUG_EVENT_SESSION_STATUS;
	*mask |= DEBUG_EVENT_CHANGE_DEBUGGEE_STATE;
	*mask |= DEBUG_EVENT_CHANGE_ENGINE_STATE;
	*mask |= DEBUG_EVENT_CHANGE_SYMBOL_STATE;

	return S_OK;
}

HRESULT DbgEngEventCallbacks::Breakpoint(IDebugBreakpoint* breakpoint)
{
	std::uintptr_t address {};
	if (breakpoint->GetOffset(&address) == S_OK)
		DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint = DebugBreakpoint(address);

	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::Exception(EXCEPTION_RECORD64* exception, unsigned long first_chance)
{
	DbgEngAdapter::ProcessCallbackInfo.m_lastException = *exception;

	// If we are debugging a 32-bit program, we get STATUS_WX86_BREAKPOINT followed by STATUS_WX86_BREAKPOINT
	// However, returning DEBUG_STATUS_GO here does not work. This might be a dbgeng bug.
	//if (exception->ExceptionCode == STATUS_WX86_BREAKPOINT)
	//	return DEBUG_STATUS_GO;

	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::CreateThread(uint64_t handle, uint64_t data_offset, uint64_t start_offset)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::ExitThread(unsigned long exit_code)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::CreateProcess(uint64_t image_file_handle, uint64_t handle, uint64_t base_offset,
	unsigned long module_size, const char* module_name, const char* image_name, unsigned long check_sum,
	unsigned long time_date_stamp, uint64_t initial_thread_handle, uint64_t thread_data_offset, uint64_t start_offset)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::ExitProcess(unsigned long exit_code)
{
	DbgEngAdapter::ProcessCallbackInfo.m_exitCode = exit_code;
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::LoadModule(uint64_t image_file_handle, uint64_t base_offset, unsigned long module_size,
	const char* module_name, const char* image_name, unsigned long check_sum, unsigned long time_date_stamp)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::UnloadModule(const char* image_base_name, uint64_t base_offset)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::SystemError(unsigned long error, unsigned long level)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::SessionStatus(unsigned long session_status)
{
	return S_OK;
}

HRESULT DbgEngEventCallbacks::ChangeDebuggeeState(unsigned long flags, uint64_t argument)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::ChangeEngineState(unsigned long flags, uint64_t argument)
{
	//if (flags == DEBUG_CES_EXECUTION_STATUS)
	//{
	//	if (argument == DEBUG_STATUS_STEP_OVER)
	//	{
	//	}
	//}
	return S_OK;
}

HRESULT DbgEngEventCallbacks::ChangeSymbolState(unsigned long flags, uint64_t argument)
{
	return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngOutputCallbacks::Output(unsigned long mask, const char* text)
{
	DebuggerEvent event;
	event.type = BackendMessageEventType;
	event.data.messageData.message = text;
	m_adapter->PostDebuggerEvent(event);
	m_output += text;
	return S_OK;
}

unsigned long DbgEngOutputCallbacks::AddRef()
{
	return 1;
}

unsigned long DbgEngOutputCallbacks::Release()
{
	return 0;
}

void DbgEngOutputCallbacks::StartOutput()
{
	m_output.clear();
}

std::string DbgEngOutputCallbacks::EndOutput()
{
	return m_output;
}

HRESULT DbgEngOutputCallbacks::QueryInterface(const IID& interface_id, void** _interface)
{
	return S_OK;
}

void DbgEngOutputCallbacks::SetAdapter(DebugAdapter* adapter)
{
	m_adapter = adapter;
}

HRESULT DbgEngInputCallbacks::StartInput(ULONG BufferSize)
{
    // TODO: we should let the user type in some input when asked to. For now, we simply return an empty string,
    // otherwise, the debugger will hang.
    PCSTR input = "";
    if (m_control)
        m_control->ReturnInput(input);
    return S_OK;
}

HRESULT DbgEngInputCallbacks::EndInput()
{
    return S_OK;
}

unsigned long DbgEngInputCallbacks::AddRef()
{
    return 1;
}

unsigned long DbgEngInputCallbacks::Release()
{
    return 0;
}

HRESULT DbgEngInputCallbacks::QueryInterface(const IID& interface_id, void** _interface)
{
    return S_OK;
}

void DbgEngInputCallbacks::SetDbgControl(IDebugControl7* control)
{
    m_control = control;
}

bool DbgEngAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	switch (feature)
	{
	case DebugAdapterSupportStepOver:
		return true;
	case DebugAdapterSupportModules:
		return true;
	case DebugAdapterSupportThreads:
		return true;
	default:
		return false;
	}
}


DataBuffer DbgEngAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	const auto source = std::make_unique<std::uint8_t[]>(size);

	unsigned long bytesRead {};
	const auto success =
		this->m_debugDataSpaces->ReadVirtual(address, source.get(), size, &bytesRead) == S_OK && bytesRead == size;
	if (!success)
		return {};

	return {source.get(), size};
}

bool DbgEngAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	unsigned long bytes_written {};
	return this->m_debugDataSpaces->WriteVirtual(address, const_cast<void*>(buffer.GetData()), buffer.GetLength(), &bytes_written) == S_OK
		&& bytes_written == buffer.GetLength();
}


std::vector<DebugFrame> DbgEngAdapter::GetFramesOfThread(uint32_t tid)
{
	std::vector<DebugFrame> result;
	// Due to https://github.com/Vector35/debugger/issues/304 and that we pause the target before killing it, we would
	// not be able to even kill or restart a GUI app on Windows. That is really bad. To mitigate the issue, I created
	// this boolean, which help skip any update on thread information when the target is about to be killed, thus
	// allowing the target to be killed or restarted normally. This needs to be reworked later.
	if (m_aboutToBeKilled)
		return result;

	DebugThread activeThead = GetActiveThread();

	SetActiveThreadId(tid);

	const size_t numFrames = 100;
	PDEBUG_STACK_FRAME_EX frames = new DEBUG_STACK_FRAME_EX[numFrames];
	unsigned long framesFilled = 0;
	if (m_debugControl->GetStackTraceEx(0, 0, 0, frames, numFrames, &framesFilled) != S_OK)
	{
		delete []frames;
		return result;
	}

	for (size_t i = 0; i < framesFilled; i++)
	{
		DebugFrame frame;
		auto engineFrame = frames[i];
		frame.m_index = i;
		frame.m_fp = engineFrame.FrameOffset;
		frame.m_sp = engineFrame.StackOffset;
		frame.m_pc = engineFrame.InstructionOffset;
		// FuncTableEntry is always 0x0, so it cannot be used
		//frame.m_functionStart = engineFrame.FuncTableEntry;

		// Get module info
		ULONG moduleIndex = 0;
		uint64_t moduleBase = 0;
		m_debugSymbols->GetModuleByOffset(engineFrame.InstructionOffset, 0, &moduleIndex, &moduleBase);

		char name[1024];
		char short_name[1024];
		char loaded_image_name[1024];
		if (this->m_debugSymbols->GetModuleNames(moduleIndex, 0,
				name, 1024, nullptr,
				short_name, 1024, nullptr,
				loaded_image_name, 1024, nullptr) == S_OK)
		{
			frame.m_module = short_name;
		}

		// Get function info
		char functionName[1024];
		unsigned long functionNameLen = 0;
		uint64_t displacement = 0;
		if (S_OK == m_debugSymbols->GetNameByOffset(engineFrame.InstructionOffset,
				functionName, sizeof(functionName),
				&functionNameLen, &displacement))
		{
			frame.m_functionName = functionName;
			frame.m_functionStart = engineFrame.InstructionOffset - displacement;
		}

		result.push_back(frame);
	}

	SetActiveThread(activeThead);

	delete []frames;
	return result;
}


LocalDbgEngAdapterType::LocalDbgEngAdapterType() : DebugAdapterType("DBGENG") {}


DebugAdapter* LocalDbgEngAdapterType::Create(BinaryNinja::BinaryView* data)
{
	// TODO: someone should free this.
	return new DbgEngAdapter(data);
}


bool LocalDbgEngAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool LocalDbgEngAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	return true;
}


bool LocalDbgEngAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
	return true;
#endif
	return false;
}

void BinaryNinjaDebugger::InitDbgEngAdapterType()
{
	static LocalDbgEngAdapterType localType;
	DebugAdapterType::Register(&localType);
}
