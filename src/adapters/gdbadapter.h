#pragma once
#include "../debugadapter.h"
#include "rspconnector.h"
#include <map>

class GdbAdapter : public DebugAdapter
{
    struct RegisterInfo
    {
        std::uint32_t m_bitSize{};
        std::uint32_t m_regNum{};
    };

    int m_socket{};
    int m_port{};
    RspConnector m_rspConnector{};

    std::map<std::string, RegisterInfo> m_registerInfo{};

    int m_internalBreakpointId{};
    std::vector<DebugBreakpoint> m_debugBreakpoint{};

    std::string ExecuteShellCommand(const std::string& command);
    bool LoadRegisterInfo();

public:
    GdbAdapter();
    ~GdbAdapter();

    bool Execute(const std::string& path) override;
    bool ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args) override;
    bool Attach(std::uint32_t pid) override;
    bool Connect(const std::string& server, std::uint32_t port) override;

    void Detach() override;
    void Quit() override;

    std::vector<DebugThread> GetThreadList() const override;
    DebugThread GetActiveThread() const override;
    std::uint32_t GetActiveThreadId() const override;
    bool SetActiveThread(const DebugThread& thread) override;
    bool SetActiveThreadId(std::uint32_t tid) override;

    DebugBreakpoint AddBreakpoint(std::uintptr_t address, unsigned long breakpoint_type = 0) override;
    std::vector<DebugBreakpoint> AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints) override;
    bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;
    bool RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints) override;
    bool ClearAllBreakpoints() override;
    std::vector<DebugBreakpoint> GetBreakpointList() const override;

    std::string GetRegisterNameByIndex(std::uint32_t index) const override;
    DebugRegister ReadRegister(const std::string& reg) override;
    bool WriteRegister(const std::string& reg, std::uintptr_t value) override;
    bool WriteRegister(const DebugRegister& reg, std::uintptr_t value) override;
    std::vector<std::string> GetRegisterList() const override;

    bool ReadMemory(std::uintptr_t address, void* out, std::size_t size) override;
    bool WriteMemory(std::uintptr_t address, void* out, std::size_t size) override;
    std::vector<DebugModule> GetModuleList() const override;

    std::string GetTargetArchitecture() override;

    unsigned long StopReason() override;
    unsigned long ExecStatus() override;

    bool BreakInto() override;
    bool Go() override;
    bool StepInto() override;
    bool StepOver() override;
    bool StepOut() override;
    bool StepTo(std::uintptr_t address) override;

    void Invoke(const std::string& command) override;
    std::uintptr_t GetInstructionOffset() override;
};