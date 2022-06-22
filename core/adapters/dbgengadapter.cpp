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
#include "queuedadapter.h"
#include "../debuggerevent.h"
#include "shlobj_core.h"
#pragma warning(push)
// warning C40005, macro redefinition
#pragma warning(disable: 5)
#include "ntstatus.h"
#pragma warning(pop)

using namespace BinaryNinjaDebugger;
using namespace std;

#define QUERY_DEBUG_INTERFACE(query, out) \
    if ( const auto result = this->m_debugClient->QueryInterface(__uuidof(query), reinterpret_cast<void**>(out) ); \
            result != S_OK) \
        throw std::runtime_error("Failed to create "#query)

std::string DbgEngAdapter::GetDbgEngPath(const std::string& arch)
{
    std::string path;
    if (arch == "x64")
        path = Settings::Instance()->Get<string>("debugger.x64dbgEngPath");
    else
        path = Settings::Instance()->Get<string>("debugger.x86dbgEngPath");

    if (path.empty())
    {
        char appData[MAX_PATH];
        if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData)))
            return "";
        auto debuggerRoot = filesystem::path(appData) / "Binary Ninja" / "dbgeng" / "Windows Kits" / "10" / "Debuggers" / arch;
        if (!filesystem::exists(debuggerRoot))
            return "";

        path = debuggerRoot.string();
    }

    auto enginePath = filesystem::path(path);
    if (!filesystem::exists(enginePath))
        return "";

    if (!filesystem::exists(enginePath / "dbgeng.dll"))
        return "";

    if (!filesystem::exists(enginePath / "dbghelp.dll"))
        return "";

    if (!filesystem::exists(enginePath / "dbgmodel.dll"))
        return "";

    if (!filesystem::exists(enginePath / "dbgcore.dll"))
        return "";

    if (!filesystem::exists(enginePath / "dbgsrv.exe"))
        return "";

    return enginePath.string();
}

bool DbgEngAdapter::LoadDngEngLibraries()
{
    auto enginePath = GetDbgEngPath();
    if (!enginePath.empty())
    {
        if (!SetDllDirectoryA(enginePath.c_str()))
            LogWarn("Failed to set DLL directory to %s. The debugger is going to load the system dbgeng DLLs and they may"
                    "not work as expected", enginePath.c_str());
    }
    else
    {
        LogWarn("debugger.x64dbgEngPath is empty or invalid. The debugger is going to load the system dbgeng DLLs and they may"
                "not work as expected");
    }

    HMODULE handle;
    handle = LoadLibraryA("dbgcore.dll");
    if (handle == nullptr)
    {
        LogWarn("fail to load dbgcore.dll, %d", GetLastError());
        return false;
    }

    handle = LoadLibraryA("dbghelp.dll");
    if (handle == nullptr)
    {
        LogWarn("fail to load dbghelp.dll, %d", GetLastError());
        return false;
    }

    handle = LoadLibraryA("dbgmodel.dll");
    if (handle == nullptr)
    {
        LogWarn("fail to load dbgmodel.dll, %d", GetLastError());
        return false;
    }

    handle = LoadLibraryA("dbgeng.dll");
    if (handle == nullptr)
    {
        LogWarn("fail to load dbgeng.dll, %d", GetLastError());
        return false;
    }
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
    if (!CreateProcessA(NULL,
                        (LPSTR)commandLine.c_str(),
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        NULL,
                        &si,
                        &pi))
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
        false;

    //    HRESULT DebugCreate(
    //    [in]  REFIID InterfaceId,
    //    [out] PVOID  *Interface
    //    );
    typedef HRESULT(__stdcall *pfunDebugCreate)(REFIID, PVOID*);
    auto DebugCreate = (pfunDebugCreate)GetProcAddress(handle, "DebugCreate");
    if (DebugCreate == nullptr)
        return false;

    if (const auto result = DebugCreate(__uuidof(IDebugClient5), reinterpret_cast<void**>(&this->m_debugClient));
            result != S_OK)
        throw std::runtime_error("Failed to create IDebugClient5");

    QUERY_DEBUG_INTERFACE(IDebugControl5, &this->m_debugControl);
    QUERY_DEBUG_INTERFACE(IDebugDataSpaces, &this->m_debugDataSpaces);
    QUERY_DEBUG_INTERFACE(IDebugRegisters, &this->m_debugRegisters);
    QUERY_DEBUG_INTERFACE(IDebugSymbols, &this->m_debugSymbols);
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

    return false;
}

bool DbgEngAdapter::Start()
{
    if ( this->m_debugActive )
        this->Reset();

    if (!m_connectedToDebugServer)
    {
        auto pipeName = GenerateRandomPipeName();
        auto connectString = fmt::format("npipe:pipe={},Server=localhost", pipeName);
        auto arch = m_data->GetDefaultArchitecture()->GetName() == "x86_64" ? "x64" : "x86";
        auto dbgsrvCommandLine = fmt::format("\"{}\\dbgsrv.exe\" -t {}", GetDbgEngPath(arch), connectString);
        if (!LaunchDbgSrv(dbgsrvCommandLine)) {
            LogWarn("Command %s failed", dbgsrvCommandLine.c_str());
            return false;
        }

        if (!ConnectToDebugServerInternal(connectString)) {
            LogWarn("Failed to connect process server");
            return false;
        }
    }

	m_debugEventCallbacks.SetAdapter(this);
    if (const auto result = this->m_debugClient->SetEventCallbacks(&this->m_debugEventCallbacks);
            result != S_OK)
        throw std::runtime_error("Failed to set event callbacks");

	m_outputCallbacks.SetAdapter(this);
    if (const auto result = this->m_debugClient->SetOutputCallbacks(&this->m_outputCallbacks);
            result != S_OK)
        throw std::runtime_error("Failed to set output callbacks");

    this->m_debugActive = true;
    return true;
}

#undef QUERY_DEBUG_INTERFACE

#define SAFE_RELEASE(ptr) \
    if (ptr)\
    { \
        ptr->Release(); \
        ptr = nullptr; \
    }

void DbgEngAdapter::Reset()
{
    if ( !this->m_debugActive )
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

        if ( this->m_debugClient )
        {
            this->m_debugClient->EndSession(DEBUG_END_PASSIVE);
            this->m_debugClient->EndProcessServer(m_server);
            m_dbgSrvLaunchedByAdapter = false;
            m_connectedToDebugServer = false;
            m_server = 0;
        }
        this->m_debugClient->Release();
        this->m_debugClient = nullptr;
    }

    this->m_debugActive = false;
}

#undef SAFE_RELEASE

DbgEngAdapter::DbgEngAdapter(BinaryView* data): DebugAdapter(data)
{
    LoadDngEngLibraries();
}

DbgEngAdapter::~DbgEngAdapter()
{
    this->Reset();
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
	std::thread([=, &ret, &finished](){
		ret = ExecuteWithArgsInternal(path, args, workingDir, configs);
		finished = true;
		if (ret)
			EngineLoop();
	}).detach();

	while (!finished) {}
	return ret;
}


bool DbgEngAdapter::ExecuteWithArgsInternal(const std::string& path, const std::string &args, const std::string& workingDir,
                                    const LaunchConfigurations& configs)
{
    if ( this->m_debugActive ) {
        this->Reset();
    }

    if (!Start())
        return false;

    if (const auto result = this->m_debugControl->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
            result != S_OK)
    {
        LogError("Failed to set engine options...");
        this->Reset();
        return false;
    }

    /* TODO: parse args better */
    std::string path_with_args{ path };
    if ( !args.empty())
    {
        path_with_args.append( " " );
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

	if (const auto result = this->m_debugClient->CreateProcess2(m_server,
			const_cast<char*>( path_with_args.c_str() ), &options, sizeof(DEBUG_CREATE_PROCESS_OPTIONS),
			directory, nullptr);
            result != S_OK)
    {
		LogWarn("failed to launch");
        this->Reset();
        return false;
    }

	// The WaitForEvent() must be called once before the engine fully attaches to the target.
	Wait();

    // Apply the breakpoints added before the m_debugClient is created
    ApplyBreakpoints();

    auto settings = Settings::Instance();
    if (settings->Get<bool>("debugger.stopAtEntryPoint")) {
        AddBreakpoint(ModuleNameAndOffset(path, m_data->GetEntryPoint() - m_data->GetStart()));
        if (!settings->Get<bool>("debugger.stopAtSystemEntryPoint"))
        {
            if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK)
                return false;
            Wait();
        }
    }

	return true;
}


void DbgEngAdapter::EngineLoop()
{
	bool finished = false;
	while (true)
	{
		if (finished)
			break;

//		Wait();
        unsigned long execution_status {};
		while (true)
		{
			if (this->m_debugControl->GetExecutionStatus(&execution_status) != S_OK)
			{}

			if (execution_status == DEBUG_STATUS_BREAK)
			{
                if (m_lastExecutionStatus != DEBUG_STATUS_BREAK)
                {
                    DebuggerEvent event;
                    event.type = AdapterStoppedEventType;
                    event.data.targetStoppedData.reason = StopReason();
                    PostDebuggerEvent(event);
                }

				// This is NOT actually dispatching callback, since the callbacks are already dispatched in WaitForEvent().
				// The real purpose of this call is to wait until the UI/API initiates another control operation,
				// which then calls ExitDispatch(), which causes the DispatchCallbacks() to return.
				m_debugClient->DispatchCallbacks(INFINITE);
			}
			// TODO: add step branch and step backs
			else if ((execution_status == DEBUG_STATUS_GO) || (execution_status == DEBUG_STATUS_STEP_INTO) ||
				(execution_status == DEBUG_STATUS_STEP_OVER) || (execution_status == DEBUG_STATUS_GO_HANDLED)
				|| (execution_status == DEBUG_STATUS_GO_NOT_HANDLED))
			{
				DebuggerEvent dbgevt;
				if (execution_status == DEBUG_STATUS_GO)
				{
					dbgevt.type = ResumeEventType;
					PostDebuggerEvent(dbgevt);
				}
				else if ((execution_status == DEBUG_STATUS_STEP_INTO) || (execution_status == DEBUG_STATUS_STEP_OVER))
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

    m_lastExecutionStatus = DEBUG_STATUS_BREAK;
}

bool DbgEngAdapter::AttachInternal(std::uint32_t pid)
{
    if ( this->m_debugActive )
        this->Reset();

    this->Start();

    if (const auto result = this->m_debugControl->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
            result != S_OK)
    {
        this->Reset();
        return false;
    }

    if (const auto result = this->m_debugClient->AttachProcess(m_server, pid, 0);
        result != S_OK )
    {
        this->Reset();
        return false;
    }

	Wait();
	return true;
}

bool DbgEngAdapter::Attach(std::uint32_t pid)
{
	std::atomic_bool ret = false;
	std::atomic_bool finished = false;
	// Doing the operation on a different thread ensures the same thread starts the session and runs EngineLoop().
	// This is required by DngEng. Although things sometimes work even if it is violated, it can fail randomly.
	std::thread([=, &ret, &finished](){
		ret = AttachInternal(pid);
		finished = true;
		if (ret)
			EngineLoop();
	}).detach();

	while (!finished) {}
	return ret;
}

bool DbgEngAdapter::Connect(const std::string &server, std::uint32_t port)
{
    static_assert("not implemented");
    return false;
}

bool DbgEngAdapter::ConnectToDebugServer(const std::string &server, std::uint32_t port)
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

void DbgEngAdapter::Detach()
{
    m_lastOperationIsStepInto = false;
    if ( this->m_debugClient )
        this->m_debugClient->DetachProcesses();

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
}

void DbgEngAdapter::Quit()
{
    m_lastOperationIsStepInto = false;
    if ( this->m_debugClient )
    {
        HRESULT result = this->m_debugClient->TerminateProcesses();
    }

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
}

std::vector<DebugThread> DbgEngAdapter::GetThreadList()
{
    if (!m_debugSystemObjects)
        return {};

    unsigned long number_threads{};
    if (this->m_debugSystemObjects->GetNumberThreads(&number_threads) != S_OK )
        return {};

    auto tids = std::make_unique<unsigned long[]>( number_threads );
    auto sysids = std::make_unique<unsigned long[]>( number_threads );
    if (this->m_debugSystemObjects->GetThreadIdsByIndex(0, number_threads, tids.get(), sysids.get()) != S_OK )
        return {};

    std::vector<DebugThread> debug_threads{};
    DebugThread activeThead = GetActiveThread();
    for ( std::size_t index{}; index < number_threads; index++ )
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
    return DebugThread(this->GetActiveThreadId(), ((DbgEngAdapter*)this)->GetInstructionOffset());
}

std::uint32_t DbgEngAdapter::GetActiveThreadId() const
{
    unsigned long current_tid{};
    if (this->m_debugSystemObjects->GetCurrentThreadId(&current_tid) != S_OK )
        return {};

    return current_tid;
}

bool DbgEngAdapter::SetActiveThread(const DebugThread& thread)
{
    return this->SetActiveThreadId(thread.m_tid);
}

bool DbgEngAdapter::SetActiveThreadId(std::uint32_t tid)
{
    if (this->m_debugSystemObjects->SetCurrentThreadId(tid) != S_OK )
        return false;

    return true;
}

DebugBreakpoint DbgEngAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags)
{
    IDebugBreakpoint2* debug_breakpoint{};

    /* attempt to read/write at breakpoint location to confirm its valid */
    /* DbgEng won't tell us if its valid until continue/go so this is a hacky fix */
    auto val = this->ReadMemory(address, sizeof(std::uint16_t));
    if (!this->WriteMemory(address, val))
        return {};

    if (const auto result = this->m_debugControl->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID,
                                                                 &debug_breakpoint);
            result != S_OK)
        return {};

    /* these will all work even on invalid addresses hence the previous checks */
    unsigned long id{};
    if ( debug_breakpoint->GetId(&id) != S_OK )
        return {};

    if ( debug_breakpoint->SetOffset(address) != S_OK )
        return {};

    if ( debug_breakpoint->SetFlags(DEBUG_BREAKPOINT_ENABLED | breakpoint_flags) != S_OK )
        return {};

    const auto new_breakpoint = DebugBreakpoint(address, id, true);
    this->m_debug_breakpoints.push_back(new_breakpoint);

    return new_breakpoint;
}

DebugBreakpoint DbgEngAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
    // If the backend has been created, we add the breakpoints directly. Otherwise, keep track of the breakpoints,
    // and add them when we launch/attach the target.
    if (m_debugActive)
    {
        // DbgEng does not take a full path. It can take "hello.exe", or simply "hello". E.g., "bp helloworld+0x1338"
        auto fileName = std::filesystem::path(address.module).filename();
        std::string breakpointCommand = fmt::format("bp {}+0x{:x}", fileName.string(), address.offset);
        auto ret = InvokeBackendCommand(breakpointCommand);
    }
    else
    {
        if (std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end())
            m_pendingBreakpoints.push_back(address);
    }

    return DebugBreakpoint{};
}

bool DbgEngAdapter::RemoveBreakpoint(const DebugBreakpoint &breakpoint)
{
    bool done = false;
    ULONG numBreakpoints{};
    if (m_debugControl->GetNumberBreakpoints(&numBreakpoints) != S_OK)
        return false;

    for (size_t i = 0; i < numBreakpoints; i++)
    {
        IDebugBreakpoint2* bp{};
        if (m_debugControl->GetBreakpointByIndex2(i, &bp) != S_OK)
            continue;

        ULONG64 address{};
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

bool DbgEngAdapter::RemoveBreakpoint(const ModuleNameAndOffset &breakpoint)
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
    for (const auto bp: m_pendingBreakpoints)
    {
        AddBreakpoint(bp);
    }
}

DebugRegister DbgEngAdapter::ReadRegister(const std::string &reg)
{
    if (!m_debugRegisters)
        return DebugRegister{};

    unsigned long reg_index{};
    DEBUG_VALUE debug_value{};
    DEBUG_REGISTER_DESCRIPTION register_descriptor{};

    if (this->m_debugRegisters->GetIndexByName(reg.c_str(), &reg_index) != S_OK )
        return {};

    if (this->m_debugRegisters->GetValue(reg_index, &debug_value) != S_OK )
        return {};

    char buf[256];
    unsigned long reg_length{};
    if (this->m_debugRegisters->GetDescription(reg_index, buf, 256, &reg_length, &register_descriptor) != S_OK )
        return {};

    std::size_t width{};
    switch(register_descriptor.Type) {
        case DEBUG_VALUE_INT8: width = 8; break;
        case DEBUG_VALUE_INT16: width = 16; break;
        case DEBUG_VALUE_INT32: width = 32; break;
        case DEBUG_VALUE_INT64: width = 64; break;
        case DEBUG_VALUE_FLOAT32: width = 32; break;
        case DEBUG_VALUE_FLOAT64: width = 64; break;
        case DEBUG_VALUE_FLOAT80: width = 80; break;
        case DEBUG_VALUE_FLOAT128: width = 128; break;
        case DEBUG_VALUE_VECTOR64: width = 64; break;
        case DEBUG_VALUE_VECTOR128: width = 128; break;
        default: break;
    }

    return DebugRegister{ reg, debug_value.I64, width, reg_index };
}

bool DbgEngAdapter::WriteRegister(const std::string &reg, std::uintptr_t value)
{
    unsigned long reg_index{};

    if (this->m_debugRegisters->GetIndexByName(reg.c_str(), &reg_index) != S_OK )
        return false;

    DEBUG_VALUE debug_value{};
    debug_value.I64 = value;
    debug_value.Type = DEBUG_VALUE_INT64;

    if (this->m_debugRegisters->SetValue(reg_index, &debug_value ) != S_OK )
        return false;

    return true;
}



std::string DbgEngAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
	if (!m_debugRegisters)
		return {};

	unsigned long reg_length{};
	DEBUG_REGISTER_DESCRIPTION reg_description{};

	std::array<char, 256> out{'\0'};
	if (this->m_debugRegisters->GetDescription(index, out.data(), 256, &reg_length, &reg_description) != S_OK )
		return {};

	return std::string(out.data());
}


std::vector<std::string> DbgEngAdapter::GetRegisterList() const
{
	if ( !this->m_debugRegisters )
		return{};

	unsigned long register_count{};
	if (this->m_debugRegisters->GetNumberRegisters(&register_count) != S_OK )
		return {};

	std::vector<std::string> register_list{};
	for ( std::size_t reg_index{}; reg_index < register_count; reg_index++ )
		register_list.push_back(this->GetRegisterNameByIndex(reg_index));

	return register_list;
}


std::vector<DebugModule> DbgEngAdapter::GetModuleList()
{
    if (!this->m_debugSymbols)
        return {};

    unsigned long loaded_module_count{}, unloaded_module_count{};

    if (this->m_debugSymbols->GetNumberModules(&loaded_module_count, &unloaded_module_count) != S_OK )
        return {};

    if ( !loaded_module_count )
        return {};

    std::vector<DebugModule> modules{};

    const auto total_modules = loaded_module_count + unloaded_module_count;
    auto module_parameters = std::make_unique<DEBUG_MODULE_PARAMETERS[]>(total_modules);
    if (this->m_debugSymbols->GetModuleParameters(total_modules, nullptr, 0, module_parameters.get()) != S_OK )
        return {};

    for ( std::size_t module_index{}; module_index < total_modules; module_index++ )
    {
        const auto& parameters = module_parameters[module_index];

        char name[1024];
        char short_name[1024];
        char loaded_image_name[1024];
        if ( this->m_debugSymbols->GetModuleNames(module_index, 0,
                                                  name, 1024, nullptr,
                                                  short_name, 1024, nullptr,
                                                  loaded_image_name, 1024, nullptr ) != S_OK )
            continue;

        modules.emplace_back(name, short_name, parameters.Base, parameters.Size, !(parameters.Flags & DEBUG_MODULE_UNLOADED) );
    }

    return modules;
}

bool DbgEngAdapter::BreakInto()
{
    m_lastOperationIsStepInto = false;
//	After we call SetInterrupt(), the WaitForEvent() function will return due to a breakpoint exception
    if (this->m_debugControl->SetInterrupt(DEBUG_INTERRUPT_ACTIVE) != S_OK )
        return false;

    return true;
}

DebugStopReason DbgEngAdapter::Go()
{
    m_lastOperationIsStepInto = false;
    if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK )
        return DebugStopReason::InternalError;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return UnknownReason;
}

DebugStopReason DbgEngAdapter::StepInto()
{
    m_lastOperationIsStepInto = true;
    if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK )
        return DebugStopReason::InternalError;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return UnknownReason;
}

DebugStopReason DbgEngAdapter::StepOver()
{
    m_lastOperationIsStepInto = false;
    if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK )
        return DebugStopReason::InternalError;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return UnknownReason;
}

DebugStopReason DbgEngAdapter::StepReturn()
{
	InvokeBackendCommand("gu");
	return UnknownReason;
}

bool DbgEngAdapter::Wait(std::chrono::milliseconds timeout)
{
    std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint));
    std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_lastException, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_lastException));

    const auto wait_result = this->m_debugControl->WaitForEvent(0, timeout.count());
    return wait_result == S_OK;
}

std::unordered_map<std::string, DebugRegister> DbgEngAdapter::ReadAllRegisters() {
    std::unordered_map<std::string, DebugRegister> all_regs{};

    for (const auto& reg : this->GetRegisterList())
        all_regs[reg] = this->ReadRegister(reg);

    return all_regs;
}

std::string DbgEngAdapter::GetTargetArchitecture()
{
    if (!m_debugControl)
        return "";

    unsigned long processor_type{};

    if (this->m_debugControl->GetExecutingProcessorType(&processor_type) != S_OK )
        return "";

    switch (processor_type)
    {
        case IMAGE_FILE_MACHINE_I386: return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x86_64";
        default: return "";
    }
}

DebugStopReason DbgEngAdapter::StopReason()
{
    const auto exec_status = this->ExecStatus();
    if (exec_status == DEBUG_STATUS_BREAK)
    {
        const auto instruction_ptr = this->ReadRegister(this->GetTargetArchitecture() == "x86" ? "eip" : "rip").m_value;

        if (instruction_ptr == DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint.m_address )
            return DebugStopReason::Breakpoint;

        const auto& last_exception = DbgEngAdapter::ProcessCallbackInfo.m_lastException;
        if ( instruction_ptr == last_exception.ExceptionAddress )
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

    unsigned long execution_status{};
    if (this->m_debugControl->GetExecutionStatus(&execution_status) != S_OK )
        return 0;

    return execution_status;
}

uint64_t DbgEngAdapter::ExitCode()
{
	return DbgEngAdapter::ProcessCallbackInfo.m_exitCode;
}

std::string DbgEngAdapter::InvokeBackendCommand(const std::string& command)
{
    this->m_debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, command.c_str(), DEBUG_EXECUTE_NO_REPEAT);
	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	// The output is handled by DbgEngOutputCallbacks::Output()
	return "";
}

std::uintptr_t DbgEngAdapter::GetInstructionOffset()
{
    std::uintptr_t register_offset{};
    this->m_debugRegisters->GetInstructionOffset(&register_offset);

    return register_offset;
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
    std::uintptr_t address{};
    if (breakpoint->GetOffset(&address) == S_OK )
        DbgEngAdapter::ProcessCallbackInfo.m_lastBreakpoint = DebugBreakpoint(address );

    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::Exception(EXCEPTION_RECORD64* exception, unsigned long first_chance)
{
    DbgEngAdapter::ProcessCallbackInfo.m_lastException = *exception;

    // If we are debugging a 32-bit program, we get STATUS_WX86_BREAKPOINT followed by STATUS_WX86_BREAKPOINT
    // However, returning DEBUG_STATUS_GO here does not work. This might be a dbgeng bug.
//    if (exception->ExceptionCode == STATUS_WX86_BREAKPOINT)
//        return DEBUG_STATUS_GO;

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
                                             unsigned long module_size, const char* module_name, const char* image_name,
                                             unsigned long check_sum, unsigned long time_date_stamp,
                                             uint64_t initial_thread_handle, uint64_t thread_data_offset,
                                             uint64_t start_offset)
{
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::ExitProcess(unsigned long exit_code)
{
    DbgEngAdapter::ProcessCallbackInfo.m_exitCode = exit_code;
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::LoadModule(uint64_t image_file_handle, uint64_t base_offset, unsigned long module_size,
                                         const char* module_name, const char* image_name, unsigned long check_sum,
                                         unsigned long time_date_stamp)
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
//	if (flags == DEBUG_CES_EXECUTION_STATUS)
//	{
//		if (argument == DEBUG_STATUS_STEP_OVER)
//		{
//		}
//	}
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

HRESULT DbgEngOutputCallbacks::QueryInterface(const IID& interface_id, void** _interface)
{
    return S_OK;
}

void DbgEngOutputCallbacks::SetAdapter(DebugAdapter* adapter)
{
	m_adapter = adapter;
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

    unsigned long bytesRead{};
    const auto success = this->m_debugDataSpaces->ReadVirtual(address, source.get(), size, &bytesRead) == S_OK && bytesRead == size;
    if (!success)
        return {};

    return {source.get(), size};
}

bool DbgEngAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
    unsigned long bytes_written{};
    return this->m_debugDataSpaces->WriteVirtual(address, const_cast<void*>(buffer.GetData()), buffer.GetLength(), &bytes_written) == S_OK && bytes_written == buffer.GetLength();
}


std::vector<DebugFrame> DbgEngAdapter::GetFramesOfThread(uint32_t tid)
{
	std::vector<DebugFrame> result;
	DebugThread activeThead = GetActiveThread();

	SetActiveThreadId(tid);

	const size_t numFrames = 16;
	PDEBUG_STACK_FRAME frames = new DEBUG_STACK_FRAME[numFrames];
	unsigned long framesFilled = 0;
	if (m_debugControl->GetStackTrace(0, 0, 0, frames, numFrames, &framesFilled) != S_OK)
		return result;

	for (size_t i = 0; i < framesFilled; i++)
	{
		DebugFrame frame;
		auto engineFrame = frames[i];
		frame.m_fp = engineFrame.FrameOffset;
		frame.m_sp = engineFrame.StackOffset;
		frame.m_pc = engineFrame.InstructionOffset;
		frame.m_functionStart = engineFrame.FuncTableEntry;

		// Get module info
		ULONG moduleIndex = 0;
		uint64_t moduleBase = 0;
		m_debugSymbols->GetModuleByOffset(engineFrame.InstructionOffset, 0, &moduleIndex, &moduleBase);

		char name[1024];
		char short_name[1024];
		char loaded_image_name[1024];
		if ( this->m_debugSymbols->GetModuleNames(moduleIndex, 0,
				name, 1024, nullptr,
				short_name, 1024, nullptr,
				loaded_image_name, 1024, nullptr ) == S_OK )
		{
			frame.m_module = short_name;
		}

		// Get function info
		char functionName[1024];
		unsigned long functionNameLen = 0;
		uint64_t displacement = 0;
		if (S_OK == m_debugSymbols->GetNameByOffset(engineFrame.FuncTableEntry, functionName, sizeof(functionName),
						  &functionNameLen, &displacement))
		{
			frame.m_functionName = functionName;
		}

		result.push_back(frame);
	}

	SetActiveThread(activeThead);
	return result;
}


LocalDbgEngAdapterType::LocalDbgEngAdapterType(): DebugAdapterType("DBGENG")
{

}


DebugAdapter* LocalDbgEngAdapterType::Create(BinaryNinja::BinaryView *data)
{
    // TODO: someone should free this.
    return new DbgEngAdapter(data);
}


bool LocalDbgEngAdapterType::IsValidForData(BinaryNinja::BinaryView *data)
{
    return data->GetTypeName() == "PE";
}


bool LocalDbgEngAdapterType::CanConnect(BinaryNinja::BinaryView *data)
{
    return true;
}


bool LocalDbgEngAdapterType::CanExecute(BinaryNinja::BinaryView *data)
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