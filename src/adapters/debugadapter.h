#pragma once
#include <cstdint>
#include <utility>
#include <vector>
#include <optional>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <array>

struct DebugThread
{
    std::uint32_t m_tid{};
    std::uint32_t m_index{};

    DebugThread() {}
    DebugThread(std::uint32_t tid) : m_tid(tid) {}
    DebugThread(std::uint32_t tid, std::uint32_t index) : m_tid(tid), m_index(index) {}
};

struct DebugBreakpoint
{
    std::uintptr_t m_address{};
    unsigned long m_id{};
    bool m_is_active{};

    DebugBreakpoint(std::uintptr_t address, unsigned long id, bool active) : m_address(address), m_id(id), m_is_active(active) {}
    DebugBreakpoint(std::uintptr_t address) : m_address(address) {}
    DebugBreakpoint() {}

    bool operator==(const DebugBreakpoint& rhs) const
    {
        return this->m_address == rhs.m_address;
    }
};

struct DebugRegister
{
    std::string m_name{};
    std::uintptr_t m_value{};
    std::size_t m_width{};
};

struct DebugModule
{
    std::string m_name{}, m_short_name{};
    std::uintptr_t m_address{};
    std::size_t m_size{};
    bool m_loaded{};

    DebugModule(std::string name, std::string short_name, std::uintptr_t address, std::size_t size, bool loaded) :
        m_name(std::move(name)), m_short_name(std::move(short_name)), m_address(address), m_size(size), m_loaded(loaded) {}
};

class DebugAdapter
{
public:
    [[nodiscard]] virtual bool Execute(const std::string& path ) = 0;
    [[nodiscard]] virtual bool ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args ) = 0;

    [[nodiscard]] virtual bool Attach(std::uint32_t pid) = 0;
    [[nodiscard]] virtual bool Connect(const std::string& server, std::uint32_t port) = 0;

    virtual void Detach() = 0;
    virtual void Quit() = 0;

    virtual std::vector<DebugThread> GetThreadList() const = 0;
    virtual DebugThread GetActiveThread() const = 0;
    virtual std::uint32_t GetActiveThreadId() const = 0;
    virtual bool SetActiveThread(const DebugThread& thread) = 0;
    virtual bool SetActiveThreadId(std::uint32_t tid) = 0;

    virtual DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type = 0) = 0;
    virtual std::vector<DebugBreakpoint> AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints) = 0;
    virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) = 0;
    virtual bool RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints) = 0;
    virtual bool ClearAllBreakpoints() = 0;
    virtual std::vector<DebugBreakpoint> GetBreakpointList() const = 0;

    virtual std::string GetRegisterNameByIndex(std::uint32_t index) const = 0;
    virtual DebugRegister ReadRegister(const std::string& reg) const = 0;
    virtual bool WriteRegister(const std::string& reg, std::uintptr_t value) = 0;
    virtual bool WriteRegister(const DebugRegister& reg, std::uintptr_t value) = 0;
    virtual std::vector<std::string> GetRegisterList() const = 0;

    virtual bool ReadMemory(std::uintptr_t address, void* out, std::size_t size) = 0;
    virtual bool WriteMemory(std::uintptr_t address, void* out, std::size_t size) = 0;

    template <typename Ty = std::uintptr_t, typename PtrTy = std::uintptr_t>
    std::optional<Ty> ReadMemoryTy(PtrTy address)
    {
        Ty Buf{};
        if ( !this->ReadMemory((std::uintptr_t)address, (void*)&Buf, sizeof(Ty)) )
            return std::nullopt;

        return std::make_optional<Ty>( Buf );
    }

    template <typename Ty = std::uintptr_t, typename PtrTy = std::uintptr_t>
    bool WriteMemoryTy(PtrTy address, const Ty& value)
    {
        return this->WriteMemory((std::uintptr_t)address, (void*)&value, sizeof(Ty));
    }

    virtual std::vector<DebugModule> GetModuleList() const = 0;

    virtual std::string GetTargetArchitecture() = 0;

    virtual unsigned long StopReason() = 0;
    virtual unsigned long ExecStatus() = 0;

    virtual bool BreakInto() = 0;
    virtual bool Go() = 0;
    virtual bool StepInto() = 0;
    virtual bool StepOver() = 0;
    virtual bool StepOut() = 0;
    virtual bool StepTo(std::uintptr_t address) = 0;

    virtual void Invoke(const std::string& command) = 0;
    virtual std::uintptr_t GetInstructionOffset() = 0;
};