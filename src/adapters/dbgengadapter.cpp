#include <thread>
#include <chrono>
#include <algorithm>
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

    QUERY_DEBUG_INTERFACE(IDebugControl4, &this->m_debug_control);
    QUERY_DEBUG_INTERFACE(IDebugDataSpaces, &this->m_debug_data_spaces);
    QUERY_DEBUG_INTERFACE(IDebugRegisters, &this->m_debug_registers);
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
    ProcessInfo.m_created = false;
    ProcessInfo.m_exited = false;
    ProcessInfo.m_has_one_breakpoint = false;
    ProcessInfo.m_last_session_status = DEBUG_SESSION_FAILURE;

    if ( this->m_debug_active )
        this->Reset();

    this->Start();

    if (const auto result = this->m_debug_control->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
            result != S_OK)
    {
        this->Reset();
        return false;
    }
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
    {
        this->Reset();
        return false;
    }

    for (std::size_t timeout_attempts{}; timeout_attempts < 10; timeout_attempts++)
        if (this->Wait(std::chrono::milliseconds(100)))
            if ( ProcessInfo.m_created && ProcessInfo.m_has_one_breakpoint )
                return this->m_debug_active;

    return false;
}

bool DbgEngAdapter::Attach(std::uint32_t pid)
{
    auto& ProcessInfo = DbgEngAdapter::ProcessCallbackInfo;
    ProcessInfo.m_created = false;
    ProcessInfo.m_exited = false;
    ProcessInfo.m_has_one_breakpoint = false;
    ProcessInfo.m_last_session_status = DEBUG_SESSION_FAILURE;

    if ( this->m_debug_active )
        this->Reset();

    this->Start();

    if (const auto result = this->m_debug_control->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
            result != S_OK)
    {
        this->Reset();
        return false;
    }

    if (const auto result = this->m_debug_client->AttachProcess(0, pid, 0);
        result != S_OK )
    {
        this->Reset();
        return false;
    }

    for (std::size_t timeout_attempts{}; timeout_attempts < 10; timeout_attempts++)
        if (this->Wait(std::chrono::milliseconds(100)))
            if ( ProcessInfo.m_last_session_status == DEBUG_SESSION_ACTIVE )
                return this->m_debug_active;

    return false;
}

bool DbgEngAdapter::Connect(const std::string &server, std::uint32_t port)
{
    static_assert("not implemented");
    return false;
}

void DbgEngAdapter::Detach()
{
    if ( this->m_debug_client )
        this->m_debug_client->DetachProcesses();

    this->Reset();
}

void DbgEngAdapter::Quit()
{
    if ( this->m_debug_client )
        this->m_debug_client->TerminateProcesses();

    this->Reset();
}

std::vector<DebugThread> DbgEngAdapter::GetThreadList() const
{
    return {};
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

DebugBreakpoint DbgEngAdapter::AddBreakpoint(const std::uintptr_t address)
{
    IDebugBreakpoint2* debug_breakpoint{};

    /* attempt to read/write at breakpoint location to confirm its valid */
    /* DbgEng won't tell us if its valid until continue/go so this is a hacky fix */
    auto val = this->ReadMemoryTy<std::uint16_t>(address);
    if (!val.has_value())
        return {};

    if (!this->WriteMemoryTy(address, val.value()))
        return {};

    if (const auto result = this->m_debug_control->AddBreakpoint2(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID,
                                                                 &debug_breakpoint);
            result != S_OK)
        return {};

    /* these will all work even on invalid addresses hence the previous checks */
    unsigned long id{};
    if ( debug_breakpoint->GetId(&id) != S_OK )
        return {};

    if ( debug_breakpoint->SetOffset(address) != S_OK )
        return {};

    if ( debug_breakpoint->SetFlags(DEBUG_BREAKPOINT_ENABLED) != S_OK )
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

    if ( this->m_debug_control->GetBreakpointById2(breakpoint.m_id, &debug_breakpoint) != S_OK )
    {
        remove_breakpoint_from_list();
        return false;
    }

    if ( this->m_debug_control->RemoveBreakpoint2(debug_breakpoint) != S_OK )
    {
        remove_breakpoint_from_list();
        return false;
    }

    remove_breakpoint_from_list();

    return true;
}

bool DbgEngAdapter::RemoveBreakpoints(const std::vector<DebugBreakpoint> &breakpoints)
{
    for ( const auto& breakpoint : breakpoints )
        this->RemoveBreakpoint(breakpoint);

    return true;
}

bool DbgEngAdapter::ClearAllBreakpoints()
{
    return this->RemoveBreakpoints(this->m_debug_breakpoints);
}

std::vector<DebugBreakpoint> DbgEngAdapter::GetBreakpointList() const
{
    return this->m_debug_breakpoints;
}

DebugRegister DbgEngAdapter::ReadRegister(const std::string &reg) const
{
    unsigned long reg_index{};
    DEBUG_VALUE debug_value{};
    DEBUG_REGISTER_DESCRIPTION register_descriptor{};

    if ( this->m_debug_registers->GetIndexByName(reg.c_str(), &reg_index) != S_OK )
        return {};

    if ( this->m_debug_registers->GetValue(reg_index, &debug_value) != S_OK )
        return {};

    char buf[256];
    unsigned long reg_length{};
    if ( this->m_debug_registers->GetDescription(reg_index, buf, 256, &reg_length, &register_descriptor) != S_OK )
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

    return DebugRegister{ reg, debug_value.I64, width };
}

bool DbgEngAdapter::WriteRegister(const std::string &reg, std::uintptr_t value)
{
    unsigned long reg_index{};

    if ( this->m_debug_registers->GetIndexByName(reg.c_str(), &reg_index) != S_OK )
        return false;

    DEBUG_VALUE debug_value{};
    debug_value.I64 = value;
    debug_value.Type = DEBUG_VALUE_INT64;

    if ( this->m_debug_registers->SetValue(reg_index, &debug_value ) != S_OK )
        return false;

    return true;
}

bool DbgEngAdapter::WriteRegister(const DebugRegister& reg, std::uintptr_t value)
{
    return this->WriteRegister(reg.m_name, value);
}

std::vector<std::string> DbgEngAdapter::GetRegisterList() const
{
    if ( !this->m_debug_registers )
        return{};

    unsigned long register_count{};
    if ( this->m_debug_registers->GetNumberRegisters(&register_count) != S_OK )
        return {};

    std::vector<std::string> register_list{};
    for ( std::size_t reg_index{}; reg_index < register_count; reg_index++ )
        register_list.push_back( this->GetRegisterNameByIndex(reg_index) );

    return register_list;
}

bool DbgEngAdapter::ReadMemory(std::uintptr_t address, void* out, std::size_t size)
{
    unsigned long bytes_read{};
    return this->m_debug_data_spaces->ReadVirtual(address, out, size, &bytes_read) == S_OK && bytes_read == size;
}

bool DbgEngAdapter::WriteMemory(std::uintptr_t address, void* out, std::size_t size)
{
    unsigned long bytes_written{};
    return this->m_debug_data_spaces->WriteVirtual(address, out, size, &bytes_written) == S_OK && bytes_written == size;
}

std::vector<DebugModule> DbgEngAdapter::GetModuleList() const
{
    unsigned long loaded_module_count{}, unloaded_module_count{};

    if ( this->m_debug_symbols->GetNumberModules(&loaded_module_count, &unloaded_module_count) != S_OK )
        return {};

    if ( !loaded_module_count )
        return {};

    std::vector<DebugModule> modules{};

    const auto total_modules = loaded_module_count + unloaded_module_count;
    auto module_parameters = new DEBUG_MODULE_PARAMETERS[total_modules];
    if ( this->m_debug_symbols->GetModuleParameters(total_modules, nullptr, 0, module_parameters) != S_OK )
        return {};

    for ( std::size_t module_index{}; module_index < total_modules; module_index++ )
    {
        const auto& parameters = module_parameters[module_index];

        char name[1024];
        char short_name[1024];
        char loaded_image_name[1024];
        if ( this->m_debug_symbols->GetModuleNames(module_index, 0,
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
    if ( this->m_debug_control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE) != S_OK )
        return false;

    this->Wait();

    return true;
}

bool DbgEngAdapter::Go()
{
    if ( this->m_debug_control->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK )
        return false;

    this->Wait();

    return true;
}

bool DbgEngAdapter::StepInto()
{
    return false;
}

bool DbgEngAdapter::StepOver()
{
    if ( this->m_debug_control->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK )
        return false;

    this->Wait();

    return false;
}

bool DbgEngAdapter::StepTo(std::uintptr_t address)
{
    return false;
}
bool DbgEngAdapter::Wait(std::chrono::milliseconds timeout)
{
    std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_last_breakpoint, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_last_breakpoint));
    std::memset(&DbgEngAdapter::ProcessCallbackInfo.m_last_exception, 0, sizeof(DbgEngAdapter::ProcessCallbackInfo.m_last_exception));

    const auto wait_result = this->m_debug_control->WaitForEvent(0, timeout.count());
    return wait_result == S_OK;
}

std::string DbgEngAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
    unsigned long reg_length{};
    DEBUG_REGISTER_DESCRIPTION reg_description{};

    std::string out{};
    if ( this->m_debug_registers->GetDescription(index, out.data(), 256, &reg_length, &reg_description) != S_OK )
        return {};

    return out;
}
std::string DbgEngAdapter::GetTargetArchitecture()
{
    unsigned long processor_type{};

    if ( this->m_debug_control->GetExecutingProcessorType(&processor_type) != S_OK )
        return "";

    switch (processor_type)
    {
        case IMAGE_FILE_MACHINE_I386: return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x86_64";
        default: return "";
    }
}
unsigned long DbgEngAdapter::StopReason()
{
    const auto exec_status = this->ExecStatus();

    if (exec_status == DEBUG_STATUS_BREAK)
    {
        const auto instruction_ptr = this->ReadRegister(this->GetTargetArchitecture() == "x86" ? "eip" : "rip").m_value;

        if (instruction_ptr == DbgEngAdapter::ProcessCallbackInfo.m_last_breakpoint.m_address )
            return 0x100;

        const auto& last_exception = DbgEngAdapter::ProcessCallbackInfo.m_last_exception;
        if ( instruction_ptr == last_exception.ExceptionAddress )
            return last_exception.ExceptionCode;
    }

    return 0x200;
}

unsigned long DbgEngAdapter::ExecStatus()
{
    unsigned long execution_status{};
    if ( this->m_debug_control->GetExecutionStatus(&execution_status) != S_OK )
        return 0;

    return execution_status;
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
        DbgEngAdapter::ProcessCallbackInfo.m_has_one_breakpoint = true;

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
    DbgEngAdapter::ProcessCallbackInfo.m_created = true;

    return DEBUG_STATUS_GO;
}

HRESULT DbgEngEventCallbacks::ExitProcess(unsigned long exit_code)
{
    DbgEngAdapter::ProcessCallbackInfo.m_exited = true;
    DbgEngAdapter::ProcessCallbackInfo.m_exit_code = exit_code;
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
