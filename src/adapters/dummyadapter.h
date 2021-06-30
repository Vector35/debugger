#include "../debugadapter.h"
#include "binaryninjaapi.h"

class DummyAdapter: public DebugAdapter
{
private:
    virtual bool Attach(uint32_t pid);
    virtual bool Connect(const std::string& server, uint32_t port);

    virtual void Detach();
    virtual void Quit();

    virtual bool Execute(const std::string& path);
    virtual bool ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args);

    virtual std::vector<DebugThread> GetThreadList() const;
    virtual DebugThread GetActiveThread() const;
    virtual uint32_t GetActiveThreadId() const;
    virtual bool SetActiveThread(const DebugThread& thread);
    virtual bool SetActiveThreadId(uint32_t);

    virtual DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type);
    virtual std::vector<DebugBreakpoint> AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints);
    virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint);
    virtual bool RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints);
    virtual bool ClearAllBreakpoints();
    virtual std::vector<DebugBreakpoint> GetBreakpointList() const;

    virtual std::string GetRegisterNameByIndex(std::uint32_t index) const;
    virtual DebugRegister ReadRegister(const std::string& reg);
    virtual bool WriteRegister(const std::string& reg, std::uintptr_t value);
    virtual bool WriteRegister(const DebugRegister& reg, std::uintptr_t value);
    virtual std::vector<std::string> GetRegisterList() const;

    virtual bool ReadMemory(std::uintptr_t address, void* out, std::size_t size);
    virtual bool WriteMemory(std::uintptr_t address, void* out, std::size_t size);

    virtual std::vector<DebugModule> GetModuleList() const;

    virtual std::string GetTargetArchitecture();
    virtual unsigned long StopReason();
    virtual unsigned long ExecStatus();

    virtual bool BreakInto();
    virtual bool Go();
    virtual bool StepInto();
    virtual bool StepOver();
    virtual bool StepOut();
    virtual bool StepTo(std::uintptr_t address);

    virtual void Invoke(const std::string& command);
    virtual std::uintptr_t GetInstructionOffset();

    virtual bool IsValidForPlatform(BinaryNinja::Platform* platform);

public:
    DummyAdapter();
};
