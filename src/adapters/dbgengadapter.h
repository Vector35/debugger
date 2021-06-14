#pragma once
#include "debugadapter.h"
#define NOMINMAX
#include <windows.h>
#include <dbgeng.h>
#include <chrono>

struct ProcessCallbackInformation
{
    bool m_created{false};
    bool m_exited{false};
    bool m_has_one_breakpoint{false};
    DebugBreakpoint m_last_breakpoint{};
    EXCEPTION_RECORD64 m_last_exception{};
    std::uint64_t m_image_base{};
    unsigned long m_exit_code{};
    unsigned long m_last_session_status{DEBUG_SESSION_FAILURE};
};

class DbgEngEventCallbacks : public DebugBaseEventCallbacks
{
public:
#define CALLBACK_METHOD(return_type) __declspec(nothrow) __stdcall return_type

    CALLBACK_METHOD(unsigned long) AddRef() override;
    CALLBACK_METHOD(unsigned long) Release() override;
    CALLBACK_METHOD(HRESULT) GetInterestMask(unsigned long* mask) override;
    CALLBACK_METHOD(HRESULT) Breakpoint(IDebugBreakpoint* breakpoint) override;
    CALLBACK_METHOD(HRESULT) Exception(EXCEPTION_RECORD64* exception, unsigned long first_chance) override;
    CALLBACK_METHOD(HRESULT) CreateThread(std::uint64_t handle, std::uint64_t data_offset, std::uint64_t start_offset) override;
    CALLBACK_METHOD(HRESULT) ExitThread(unsigned long exit_code) override;
    CALLBACK_METHOD(HRESULT) CreateProcess(
            std::uint64_t image_file_handle,
            std::uint64_t handle,
            std::uint64_t base_offset,
            unsigned long module_size,
            const char* module_name,
            const char* image_name,
            unsigned long check_sum,
            unsigned long time_date_stamp,
            std::uint64_t initial_thread_handle,
            std::uint64_t thread_data_offset,
            std::uint64_t start_offset
    ) override;
    CALLBACK_METHOD(HRESULT) ExitProcess(unsigned long exit_code) override;
    CALLBACK_METHOD(HRESULT) LoadModule(
            std::uint64_t image_file_handle,
            std::uint64_t base_offset,
            unsigned long module_size,
            const char* module_name,
            const char* image_name,
            unsigned long check_sum,
            unsigned long time_date_stamp
    ) override;
    CALLBACK_METHOD(HRESULT) UnloadModule(const char* image_base_name, std::uint64_t base_offset) override;
    CALLBACK_METHOD(HRESULT) SystemError(unsigned long error, unsigned long level) override;
    CALLBACK_METHOD(HRESULT) SessionStatus(unsigned long session_status) override;
    CALLBACK_METHOD(HRESULT) ChangeDebuggeeState(unsigned long flags, std::uint64_t argument) override;
    CALLBACK_METHOD(HRESULT) ChangeEngineState(unsigned long flags, std::uint64_t argument) override;
    CALLBACK_METHOD(HRESULT) ChangeSymbolState(unsigned long flags, std::uint64_t argument) override;

#undef CALLBACK_METHOD
};

class DbgEngAdapter : public DebugAdapter
{
    DbgEngEventCallbacks m_debug_event_callbacks{};
    IDebugClient5* m_debug_client{nullptr};
    IDebugControl* m_debug_control{nullptr};
    IDebugDataSpaces* m_debug_data_spaces{nullptr};
    IDebugRegisters* m_debug_registers{nullptr};
    IDebugSymbols* m_debug_symbols{nullptr};
    IDebugSystemObjects* m_debug_system_objects{nullptr};
    bool m_debug_active{false};

    void Start();
    void Reset();
    bool Wait(std::chrono::milliseconds timeout = std::chrono::milliseconds::max());

    std::vector<DebugBreakpoint> m_debug_breakpoints{};

public:
    inline static ProcessCallbackInformation ProcessCallbackInfo{};

    DbgEngAdapter();
    ~DbgEngAdapter();

    [[nodiscard]] bool Execute(const std::string &path) override;
    [[nodiscard]] bool ExecuteWithArgs(const std::string &path, const std::vector<std::string> &args) override;
    [[nodiscard]] bool Attach(std::uint32_t pid) override;
    [[nodiscard]] bool Connect(const std::string &server, std::uint32_t port) override;

    void Detach() override;
    void Quit() override;

    std::vector<DebugThread> GetThreadList() const override;
    DebugThread GetActiveThread() const override;
    std::uint32_t GetActiveThreadId() const override;
    bool SetActiveThread(const DebugThread &thread) override;
    bool SetActiveThreadId(std::uint32_t) override;

    DebugBreakpoint AddBreakpoint(const std::uintptr_t address) override;
    std::vector<DebugBreakpoint> AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints) override;
    bool RemoveBreakpoint(const DebugBreakpoint &breakpoint) override;
    bool RemoveBreakpoints(const std::vector<DebugBreakpoint> &breakpoints) override;
    bool ClearAllBreakpoints() override;
    std::vector<DebugBreakpoint> GetBreakpointList() const override;

    std::string GetRegisterNameByIndex(std::uint32_t index) const override;
    DebugRegister ReadRegister(const std::string &reg) const override;
    bool WriteRegister(const std::string &reg, std::uintptr_t value) override;
    bool WriteRegister(const DebugRegister& reg, std::uintptr_t value) override;
    std::vector<std::string> GetRegisterList() const override;

    bool ReadMemory(std::uintptr_t address, void* out, std::size_t size) override;
    bool WriteMemory(std::uintptr_t address, void* out, std::size_t size) override;
    std::vector<DebugModule> GetModuleList() const override;

    bool BreakInto() override;
    bool Go() override;
    bool StepInto() override;
    bool StepOver() override;
    bool StepTo(std::uintptr_t address) override;
};