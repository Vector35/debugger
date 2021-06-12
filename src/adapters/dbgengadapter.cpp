#include <thread>
#include <chrono>
#include "dbgengadapter.h"

#define QUERY_DEBUG_INTERFACE(query, out) \
    if ( const auto result = this->m_debug_client->QueryInterface(__uuidof(query), reinterpret_cast<void**>(out) ); \
            result != S_OK) \
        throw std::runtime_error("Failed to create "#query)

void DbgEngAdapter::Start()
{
    if ( this->m_debug_active )
        this->Reset();

    if (const auto result = DebugCreate(__uuidof(IDebugClient5), reinterpret_cast<void**>(&this->m_debug_client));
            result != S_OK)
        throw std::runtime_error("Failed to create IDebugClient5");

    QUERY_DEBUG_INTERFACE(IDebugControl, &this->m_debug_control);
    QUERY_DEBUG_INTERFACE(IDebugDataSpaces, &this->m_debug_data_spaces);
    QUERY_DEBUG_INTERFACE(IDebugSymbols, &this->m_debug_symbols);
    QUERY_DEBUG_INTERFACE(IDebugSystemObjects, &this->m_debug_system_objects);

    if (const auto result = this->m_debug_client->SetEventCallbacks(&this->m_debug_event_callbacks);
            result != S_OK)
        throw std::runtime_error("Failed to set event callbacks");

    this->m_debug_active = true;
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
    if ( !this->m_debug_active )
        return;

    SAFE_RELEASE(this->m_debug_control);
    SAFE_RELEASE(this->m_debug_data_spaces);
    SAFE_RELEASE(this->m_debug_registers);
    SAFE_RELEASE(this->m_debug_symbols);
    SAFE_RELEASE(this->m_debug_system_objects);

    if ( this->m_debug_client )
    {
        this->m_debug_client->EndSession(DEBUG_END_PASSIVE);
        this->m_debug_client->Release();
        this->m_debug_client = nullptr;
    }

    this->m_debug_active = false;
}

#undef SAFE_RELEASE

DbgEngAdapter::DbgEngAdapter()
{
    this->Start();
}

DbgEngAdapter::~DbgEngAdapter()
{
    this->Reset();
}

bool DbgEngAdapter::Execute(const std::string &path)
{
    return this->ExecuteWithArgs(path, {});
}

bool DbgEngAdapter::ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args)
{
    auto& ProcessInfo = DbgEngAdapter::ProcessCallbackInfo;
    ProcessInfo.m_process_created = false;
    ProcessInfo.m_process_exited = false;
    ProcessInfo.m_process_has_one_breakpoint = false;
    ProcessInfo.m_last_session_status = DEBUG_SESSION_FAILURE;

    if ( this->m_debug_active )
        this->Reset();

    this->Start();

    if (const auto result = this->m_debug_control->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
            result != S_OK)
        throw std::runtime_error("Failed to set engine options");

    /* TODO: parse args better */
    std::string path_with_args{ path };
    if ( !args.empty())
    {
        path_with_args.append( " " );

        for ( const auto& arg : args )
            path_with_args.append( arg + " " );
    }

    if (const auto result = this->m_debug_client->CreateProcess(0, const_cast<char*>( path_with_args.c_str() ), DEBUG_ONLY_THIS_PROCESS);
            result != S_OK)
        throw std::runtime_error( "Failed to create process" );

    /* hold execution for testing if debugger creates process */
    std::this_thread::sleep_for(std::chrono::seconds(100));

    return false;
}

bool DbgEngAdapter::Attach(std::uint32_t pid) const
{
    return false;
}

bool DbgEngAdapter::Connect(const std::string &server, std::uint32_t port) const
{
    return false;
}

void DbgEngAdapter::Detach() const
{

}

void DbgEngAdapter::Quit() const
{

}

std::vector<DebugThread> DbgEngAdapter::GetThreadList() const
{
    return std::vector<DebugThread>();
}

DebugThread DbgEngAdapter::GetActiveThread() const
{
    return DebugThread();
}

std::uint32_t DbgEngAdapter::GetActiveThreadId() const
{
    return 0;
}

bool DbgEngAdapter::SetActiveThread(const DebugThread &thread)
{
    return false;
}

bool DbgEngAdapter::SetActiveThreadId(std::uint32_t)
{
    return false;
}

bool DbgEngAdapter::AddBreakpoint(const DebugBreakpoint &breakpoint)
{
    return false;
}

bool DbgEngAdapter::AddBreakpoints(const std::vector<DebugBreakpoint> &breakpoints)
{
    return false;
}

bool DbgEngAdapter::RemoveBreakpoint(const DebugBreakpoint &breakpoint)
{
    return false;
}

bool DbgEngAdapter::RemoveBreakpoints(const std::vector<DebugBreakpoint> &breakpoints)
{
    return false;
}

bool DbgEngAdapter::ClearAllBreakpoints()
{
    return false;
}

std::vector<DebugBreakpoint> DbgEngAdapter::GetBreakpointList() const
{
    return std::vector<DebugBreakpoint>();
}

DebugRegister DbgEngAdapter::ReadRegister(const std::string &reg) const
{
    return DebugRegister();
}

bool DbgEngAdapter::WriteRegister(const std::string &reg, std::uintptr_t value)
{
    return false;
}

bool DbgEngAdapter::WriteRegister(const DebugRegister &reg)
{
    return false;
}

std::vector<DebugRegister> DbgEngAdapter::GetRegisterList() const
{
    return std::vector<DebugRegister>();
}

bool DbgEngAdapter::ReadMemory(std::uintptr_t address, void* out, std::size_t size)
{
    return false;
}

bool DbgEngAdapter::WriteMemory(std::uintptr_t address, void* out, std::size_t size)
{
    return false;
}

std::vector<DebugModule> DbgEngAdapter::GetModuleList() const
{
    return std::vector<DebugModule>();
}

bool DbgEngAdapter::BreakInto()
{
    return false;
}

bool DbgEngAdapter::Go()
{
    return false;
}

bool DbgEngAdapter::StepInto()
{
    return false;
}

bool DbgEngAdapter::StepOver()
{
    return false;
}

bool DbgEngAdapter::StepTo(std::uintptr_t address)
{
    return false;
}
bool DbgEngAdapter::Wait(std::int32_t timeout)
{
    std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_last_breakpoint, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_last_breakpoint));
    std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_last_exception, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_last_exception));
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
    std::uint64_t address{};
    if (breakpoint->GetOffset(&address) == S_OK )
        DbgEngAdapter::ProcessCallbackInfo.m_last_breakpoint = DebugBreakpoint( address );

    return DEBUG_STATUS_NO_CHANGE;
}

HRESULT DbgEngEventCallbacks::Exception(EXCEPTION_RECORD64* exception, unsigned long first_chance)
{
    DbgEngAdapter::ProcessCallbackInfo.m_last_exception = *exception;

    if ( exception->ExceptionCode == EXCEPTION_BREAKPOINT )
        DbgEngAdapter::ProcessCallbackInfo.m_process_has_one_breakpoint = true;

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
    DbgEngAdapter::ProcessCallbackInfo.m_image_base = base_offset;
    DbgEngAdapter::ProcessCallbackInfo.m_process_created = true;

    return DEBUG_STATUS_GO;
}

HRESULT DbgEngEventCallbacks::ExitProcess(unsigned long exit_code)
{
    DbgEngAdapter::ProcessCallbackInfo.m_process_exited = true;
    DbgEngAdapter::ProcessCallbackInfo.m_process_exit_code = exit_code;
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
    DbgEngAdapter::ProcessCallbackInfo.m_last_session_status = session_status;

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
