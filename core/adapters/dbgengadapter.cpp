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
#include "dbgengadapter.h"
#include "../../cli/log.h"
#include "queuedadapter.h"
#include "../debuggerevent.h"
#include "ntstatus.h"

using namespace BinaryNinjaDebugger;


#define QUERY_DEBUG_INTERFACE(query, out) \
    if ( const auto result = this->m_debugClient->QueryInterface(__uuidof(query), reinterpret_cast<void**>(out) ); \
            result != S_OK) \
        throw std::runtime_error("Failed to create "#query)

void DbgEngAdapter::Start()
{
    if ( this->m_debugActive )
        this->Reset();

    if (const auto result = DebugCreate(__uuidof(IDebugClient5), reinterpret_cast<void**>(&this->m_debugClient));
            result != S_OK)
        throw std::runtime_error("Failed to create IDebugClient5");

    QUERY_DEBUG_INTERFACE(IDebugControl5, &this->m_debugControl);
    QUERY_DEBUG_INTERFACE(IDebugDataSpaces, &this->m_debugDataSpaces);
    QUERY_DEBUG_INTERFACE(IDebugRegisters, &this->m_debugRegisters);
    QUERY_DEBUG_INTERFACE(IDebugSymbols, &this->m_debugSymbols);
    QUERY_DEBUG_INTERFACE(IDebugSystemObjects, &this->m_debugSystemObjects);

    if (const auto result = this->m_debugClient->SetEventCallbacks(&this->m_debugEventCallbacks);
            result != S_OK)
        throw std::runtime_error("Failed to set event callbacks");

    if (const auto result = this->m_debugClient->SetOutputCallbacks(&this->m_outputCallbacks);
            result != S_OK)
        throw std::runtime_error("Failed to set output callbacks");

    this->m_debugActive = true;
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

    SAFE_RELEASE(this->m_debugControl);
    SAFE_RELEASE(this->m_debugDataSpaces);
    SAFE_RELEASE(this->m_debugRegisters);
    SAFE_RELEASE(this->m_debugSymbols);
    SAFE_RELEASE(this->m_debugSystemObjects);

    if ( this->m_debugClient )
    {
        this->m_debugClient->EndSession(DEBUG_END_PASSIVE);
        this->m_debugClient->Release();
        this->m_debugClient = nullptr;
    }

    this->m_debugActive = false;
}

#undef SAFE_RELEASE

DbgEngAdapter::DbgEngAdapter(BinaryView* data): DebugAdapter(data)
{
    this->Start();
}

DbgEngAdapter::~DbgEngAdapter()
{
    this->Reset();
}

bool DbgEngAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
    return this->ExecuteWithArgs(path, "", {});
}

bool DbgEngAdapter::ExecuteWithArgs(const std::string& path, const std::string &args,
                                    const LaunchConfigurations& configs)
{
    auto& ProcessInfo = DbgEngAdapter::ProcessCallbackInfo;
    ProcessInfo.m_created = false;
    ProcessInfo.m_exited = false;
    ProcessInfo.m_hasOneBreakpoint = false;
    ProcessInfo.m_lastSessionStatus = DEBUG_SESSION_FAILURE;

    if ( this->m_debugActive ) {
        this->Reset();
    }

    this->Start();

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

    if (const auto result = this->m_debugClient->CreateProcess(0, const_cast<char*>( path_with_args.c_str() ), DEBUG_ONLY_THIS_PROCESS);
            result != S_OK)
    {
        this->Reset();
        return false;
    }

    for (std::size_t timeout_attempts{}; timeout_attempts < 10; timeout_attempts++) {
        LogInfo("timeout attempt @ 0x%x", timeout_attempts);
        if (this->Wait(std::chrono::milliseconds(100)))
            if (ProcessInfo.m_created && ProcessInfo.m_hasOneBreakpoint)
            {
                if (m_data->GetDefaultArchitecture()->GetName() == "x86")
                {
                    Go();
                }
                return true;
            }
    }

    return false;
}

bool DbgEngAdapter::Attach(std::uint32_t pid)
{
    auto& ProcessInfo = DbgEngAdapter::ProcessCallbackInfo;
    ProcessInfo.m_created = false;
    ProcessInfo.m_exited = false;
    ProcessInfo.m_hasOneBreakpoint = false;
    ProcessInfo.m_lastSessionStatus = DEBUG_SESSION_FAILURE;

    if ( this->m_debugActive )
        this->Reset();

    this->Start();

    if (const auto result = this->m_debugControl->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
            result != S_OK)
    {
        this->Reset();
        return false;
    }

    if (const auto result = this->m_debugClient->AttachProcess(0, pid, 0);
        result != S_OK )
    {
        this->Reset();
        return false;
    }

    for (std::size_t timeout_attempts{}; timeout_attempts < 10; timeout_attempts++)
        if (this->Wait(std::chrono::milliseconds(100)))
            if (ProcessInfo.m_lastSessionStatus == DEBUG_SESSION_ACTIVE )
                return this->m_debugActive;

    return false;
}

bool DbgEngAdapter::Connect(const std::string &server, std::uint32_t port)
{
    static_assert("not implemented");
    return false;
}

void DbgEngAdapter::Detach()
{
    m_lastOperationIsStepInto = false;
    if ( this->m_debugClient )
        this->m_debugClient->DetachProcesses();

    this->Reset();
}

void DbgEngAdapter::Quit()
{
    m_lastOperationIsStepInto = false;
    if ( this->m_debugClient )
    {
        HRESULT result = this->m_debugClient->TerminateProcesses();
    }

    this->Reset();
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

std::vector<DebugBreakpoint> DbgEngAdapter::AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints)
{
    std::vector<DebugBreakpoint> debug_breakpoints{};
    debug_breakpoints.reserve(breakpoints.size());

    for ( const auto& breakpoint : breakpoints )
        debug_breakpoints.push_back(this->AddBreakpoint(breakpoint));

    return debug_breakpoints;
}

bool DbgEngAdapter::RemoveBreakpoint(const DebugBreakpoint &breakpoint)
{
    IDebugBreakpoint2* debug_breakpoint{};

    const auto remove_breakpoint_from_list = [&]
    {
        if (auto location = std::find(this->m_debug_breakpoints.begin(), this->m_debug_breakpoints.end(), breakpoint);
                location != this->m_debug_breakpoints.end())
            this->m_debug_breakpoints.erase(location);
    };

    if (this->m_debugControl->GetBreakpointById2(breakpoint.m_id, &debug_breakpoint) != S_OK )
    {
        remove_breakpoint_from_list();
        return false;
    }

    if (this->m_debugControl->RemoveBreakpoint2(debug_breakpoint) != S_OK )
    {
        remove_breakpoint_from_list();
        return false;
    }

    remove_breakpoint_from_list();

    return true;
}

std::vector<DebugBreakpoint> DbgEngAdapter::GetBreakpointList() const
{
    return this->m_debug_breakpoints;
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
    if (this->m_debugControl->SetInterrupt(DEBUG_INTERRUPT_ACTIVE) != S_OK )
        return false;

    return true;
}

DebugStopReason DbgEngAdapter::Go()
{
    m_lastOperationIsStepInto = false;
    if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK )
        return DebugStopReason::InternalError;

    this->Wait();
    return StopReason();
}

DebugStopReason DbgEngAdapter::StepInto()
{
    m_lastOperationIsStepInto = true;
    if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK )
        return DebugStopReason::InternalError;

    this->Wait();
    return StopReason();
}

DebugStopReason DbgEngAdapter::StepOver()
{
    m_lastOperationIsStepInto = false;
    if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK )
        return DebugStopReason::InternalError;

    this->Wait();
    return StopReason();
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
	// TODO: get the output
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

    if ( exception->ExceptionCode == EXCEPTION_BREAKPOINT )
    {
        DbgEngAdapter::ProcessCallbackInfo.m_hasOneBreakpoint = true;
    }

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
    DbgEngAdapter::ProcessCallbackInfo.m_imageBase = base_offset;
    DbgEngAdapter::ProcessCallbackInfo.m_created = true;

    return DEBUG_STATUS_GO;
}

HRESULT DbgEngEventCallbacks::ExitProcess(unsigned long exit_code)
{
    DbgEngAdapter::ProcessCallbackInfo.m_exited = true;
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
    DbgEngAdapter::ProcessCallbackInfo.m_lastSessionStatus = session_status;

    return S_OK;
}

HRESULT DbgEngEventCallbacks::ChangeDebuggeeState(unsigned long flags, uint64_t argument)
{
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::ChangeEngineState(unsigned long flags, uint64_t argument)
{
    return S_OK;
}

HRESULT DbgEngEventCallbacks::ChangeSymbolState(unsigned long flags, uint64_t argument)
{
    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngOutputCallbacks::Output(unsigned long mask, const char* text)
{
    const auto blue_style = Log::Style(25, 25, 255);
    const auto white_style = Log::Style(255, 255, 255);

    //if ( std::string(text).find('\n') != std::string::npos )
    //    Log::print("{}WIN{}DBG{}> {}{}", blue_style, white_style, blue_style, white_style, text );
    //else
    //    Log::print("{}WIN{}DBG{}> {}{}\n", blue_style, white_style, blue_style, white_style, text );

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

LocalDbgEngAdapterType::LocalDbgEngAdapterType(): DebugAdapterType("Local DBGENG")
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
    return false;
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