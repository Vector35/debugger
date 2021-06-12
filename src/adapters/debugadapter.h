#pragma once
#include <cstdint>
#include <vector>
#include <optional>
#include <string>
#include <stdexcept>

struct DebugThread
{
    std::uint32_t m_index{};
    std::uint32_t m_tid{};
    bool m_is_executing{};
    bool m_is_selected{};
};

struct DebugBreakpoint
{
    std::uintptr_t m_address{};
    bool m_is_active{};

    DebugBreakpoint(std::uintptr_t address) : m_address(address) {}
    DebugBreakpoint() {}
};

struct DebugRegister
{
    std::string m_name{};
    std::uintptr_t m_address{};
    std::uintptr_t m_value{};
    std::size_t m_width{};
};

struct DebugModule
{
    std::uintptr_t m_address{};
    std::size_t m_size{};
};

class DebugAdapter
{
    std::string m_path{};
    std::uint32_t m_pid{};
    std::uintptr_t m_target_base{};
    bool m_is_attached = false;

public:
    [[nodiscard]] virtual bool Execute(const std::string& path ) = 0;
    [[nodiscard]] virtual bool ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args ) = 0;

    [[nodiscard]] virtual bool Attach(std::uint32_t pid) const = 0;
    [[nodiscard]] virtual bool Connect(const std::string& server, std::uint32_t port) const = 0;

    virtual void Detach() const = 0;
    virtual void Quit() const = 0;

    virtual std::vector<DebugThread> GetThreadList() const = 0;
    virtual DebugThread GetActiveThread() const = 0;
    virtual std::uint32_t GetActiveThreadId() const = 0;
    virtual bool SetActiveThread(const DebugThread& thread) = 0;
    virtual bool SetActiveThreadId(std::uint32_t) = 0;

    virtual bool AddBreakpoint(const DebugBreakpoint& breakpoint) = 0;
    virtual bool AddBreakpoints(const std::vector<DebugBreakpoint>& breakpoints) = 0;
    virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) = 0;
    virtual bool RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints) = 0;
    virtual bool ClearAllBreakpoints() = 0;
    virtual std::vector<DebugBreakpoint> GetBreakpointList() const = 0;

    virtual DebugRegister ReadRegister(const std::string& reg) const = 0;
    virtual bool WriteRegister(const std::string& reg, std::uintptr_t value) = 0;
    virtual bool WriteRegister(const DebugRegister& reg) = 0;
    virtual std::vector<DebugRegister> GetRegisterList() const = 0;

    virtual bool ReadMemory(std::uintptr_t address, void* out, std::size_t size) = 0;
    virtual bool WriteMemory(std::uintptr_t address, void* out, std::size_t size) = 0;
    virtual std::vector<DebugModule> GetModuleList() const = 0;

    virtual bool BreakInto() = 0;
    virtual bool Go() = 0;
    virtual bool StepInto() = 0;
    virtual bool StepOver() = 0;
    virtual bool StepTo(std::uintptr_t address) = 0;

    std::string GetPath() const;
    std::uint32_t GetPid() const;
    std::uintptr_t TargetBase() const;
};