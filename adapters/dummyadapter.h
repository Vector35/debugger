#include "debugadapter.h"
#include "binaryninjaapi.h"

class DummyAdapter: public DebugAdapter
{
    DummyAdapter();
    virtual bool Attach(uint32_t pid);
    virtual bool Connect(const std::string& server, uint32_t port);

    virtual void Detech();
    virtual void Quit();

    virtual std::vector<DebugThread> GetThreadList();
    virtual DebugThread GetActiveThread();
    virtual uint32_t GetActiveThreadId();
    virtual bool SetActiveThread(const DebugThread& thread);
    virtual bool SetActiveThreadId(uint32_t);

    virtual DebugBreakpoint AddBreakpoint(const std::uintptr_t address);
    virtual std::vector<DebugBreakpoint> AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints);
    virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint);
    virtual bool RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints);
    virtual bool ClearAllBreakpoints();
    virtual std::vector<DebugBreakpoint> GetBreakpointList() const;

    virtual std::string GetRegisterNameByIndex(std::uint32_t index) const;
    virtual DebugRegister ReadRegister(const std::string& reg) const;
    virtual bool WriteRegister(const std::string& reg, std::uintptr_t value);
    virtual bool WriteRegister(const DebugRegister& reg, std::uintptr_t value);
    virtual std::vector<std::string> GetRegisterList() const;

    virtual bool ReadMemory(std::uintptr_t address, void* out, std::size_t size);
    virtual bool WriteMemory(std::uintptr_t address, void* out, std::size_t size);

    virtual std::string GetTargetArchitecture();

    virtual bool BreakInto();
    virtual bool Go();
    virtual bool StepInto();
    virtual bool StepOver();
    virtual bool StepOut();
    virtual bool StepTo(std::uintptr_t address);

    virtual void Invoke(const std::string& command);
    virtual std::uintptr_t GetInstructionOffset();

    virtual bool IsValidForPlatform(BinaryNinja::Platform* platform);
};
