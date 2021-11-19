#pragma once
#include <cstdint>
#include <utility>
#include <vector>
#include <optional>
#include <string>
#include <stdexcept>
#include <functional>
#include <unordered_map>
#include <array>
#include <fmt/format.h>
#include "binaryninjaapi.h"
#include "debuggercommon.h"
#include "debuggerevent.h"

using namespace BinaryNinja;

enum StopReason
{
    UnknownStopReason,
    StdoutMessageReason,
    ProcessExitedReason,
    BackendDisconnectedReason,
    SingleStepStopReason,
    BreakpointStopReason,
    ExceptionStopReason
};


// Used by the DebuggerState to query the capacities of the DebugAdapter, and take different actions accordingly.
enum DebugAdapterCapacity
{
    DebugAdapterSupportStepOver,
    DebugAdapterSupportModules,
    DebugAdapterSupportThreads,
};


struct DebugThread
{
    std::uint32_t m_tid{};
    std::uint32_t m_index{};
    std::uintptr_t m_rip{};

    DebugThread() {}
    DebugThread(std::uint32_t tid) : m_tid(tid) {}
    DebugThread(std::uint32_t tid, std::uint32_t index) : m_tid(tid), m_index(index) {}
    DebugThread(std::uint32_t tid, std::uint32_t index, std::uintptr_t rip) : m_tid(tid), m_index(index), m_rip(rip) {}

    bool operator==(const DebugThread& rhs) const
    {
        return (m_tid == rhs.m_tid) && (m_index == rhs.m_index);
    }
    bool operator!=(const DebugThread& rhs) const
    {
        return !(*this == rhs);
    }
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

    bool operator!() const {
        return !this->m_address && !this->m_id && !this->m_is_active;
    }
};

struct DebugRegister
{
    std::string m_name{};
    std::uintptr_t m_value{};
    std::size_t m_width{}, m_registerIndex{};
    std::string m_hint{};

    DebugRegister() = default;
    DebugRegister(std::string name, std::uintptr_t value, std::size_t width, std::size_t register_index) :
        m_name(std::move(name)), m_value(value), m_width(width), m_registerIndex(register_index) {}
};

struct DebugModule
{
    std::string m_name{}, m_short_name{};
    std::uintptr_t m_address{};
    std::size_t m_size{};
    bool m_loaded{};

    DebugModule(): m_name(""), m_short_name(""), m_address(0), m_size(0) {}
    DebugModule(std::string name, std::string short_name, std::uintptr_t address, std::size_t size, bool loaded) :
        m_name(std::move(name)), m_short_name(std::move(short_name)), m_address(address), m_size(size), m_loaded(loaded) {}
};

class DebugAdapter
{
private:
    // Function to call when the DebugAdapter wants to notify the front-end of certain events
    // TODO: we should not use a vector here; only the DebuggerController should register one here;
    // Other components should register their callbacks to the controller, who is responsible for notify them.
    std::vector<std::function<void(DebuggerEventType event, void* data)>> m_eventCallbacks;

public:
    void RegisterEventCallback(std::function<void(DebuggerEventType event, void* data)> function)
    {
        m_eventCallbacks.push_back(function);
    }

    [[nodiscard]] virtual bool Execute(const std::string& path ) = 0;
    [[nodiscard]] virtual bool ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args ) = 0;

    [[nodiscard]] virtual bool Attach(std::uint32_t pid) = 0;
    [[nodiscard]] virtual bool Connect(const std::string& server, std::uint32_t port) = 0;

    virtual void Detach() = 0;
    virtual void Quit() = 0;

    virtual std::vector<DebugThread> GetThreadList() = 0;
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
    virtual std::unordered_map<std::string, DebugRegister> ReadAllRegisters() = 0;
    virtual DebugRegister ReadRegister(const std::string& reg) = 0;
    virtual bool WriteRegister(const std::string& reg, std::uintptr_t value) = 0;
    virtual bool WriteRegister(const DebugRegister& reg, std::uintptr_t value) = 0;
    virtual std::vector<std::string> GetRegisterList() const = 0;

    virtual DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) = 0;
    virtual bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) = 0;

//    template <typename Ty = std::uintptr_t, typename PtrTy = std::uintptr_t>
//    std::optional<Ty> ReadMemoryTy(PtrTy address)
//    {
//        Ty Buf{};
//        if ( !this->ReadMemory((std::uintptr_t)address, (void*)&Buf, sizeof(Ty)) )
//            return std::nullopt;
//
//        return std::make_optional<Ty>( Buf );
//    }
//
//    template <typename Ty = std::uintptr_t, typename PtrTy = std::uintptr_t>
//    bool WriteMemoryTy(PtrTy address, const Ty& value)
//    {
//        return this->WriteMemory((std::uintptr_t)address, (void*)&value, sizeof(Ty));
//    }

    virtual std::vector<DebugModule> GetModuleList() = 0;

    virtual std::string GetTargetArchitecture() = 0;

    virtual DebugStopReason StopReason() = 0;
    virtual unsigned long ExecStatus() = 0;

    virtual bool BreakInto() = 0;
    virtual bool Go() = 0;
    virtual bool StepInto() = 0;
    virtual bool StepOver() = 0;
    virtual bool StepOut();
    virtual bool StepTo(std::uintptr_t address) = 0;

    virtual void Invoke(const std::string& command) = 0;
    virtual std::uintptr_t GetInstructionOffset() = 0;

    virtual bool SupportFeature(DebugAdapterCapacity feature) = 0;

    // These are implemented by the (base) DebugAdapter class.
    // Sub-classes should use these to communicate changes of the target.
    void NotifyDebuggerEvent(DebuggerEventType event, void* data = nullptr);

    void NotifyStopped(DebugStopReason reason, void* data= nullptr);
    void NotifyError(const std::string& error, void* data = nullptr);
    void NotifyEvent(const std::string& event, void* data = nullptr);
};