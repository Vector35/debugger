#include "dummyadapter.h"

using namespace BinaryNinja;

DummyAdapter::DummyAdapter()
{
    // SetName("Dummy Adapter");
    LogWarn("Hello from a dummy DebugAdapter");
}


bool DummyAdapter::Execute(const std::string& path)
{
    return true;
}


bool DummyAdapter::ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args)
{
    return true;
}


bool DummyAdapter::Attach(uint32_t pid)
{
    LogWarn("Attaching to process: %d", pid);
    return true;
}


bool DummyAdapter::Connect(const std::string& server, uint32_t port)
{
    LogWarn("Connecting to %s:%d", server.c_str(), port);
    return true;
}


void DummyAdapter::Detach()
{

}


void DummyAdapter::Quit()
{

}


std::vector<DebugThread> DummyAdapter::GetThreadList()
{
    std::vector<DebugThread> result;
    return result;
}


DebugThread DummyAdapter::GetActiveThread() const
{
    DebugThread result;
    return result;    
}


uint32_t DummyAdapter::GetActiveThreadId() const
{
    return 0;
}


bool DummyAdapter::SetActiveThread(const DebugThread& thread)
{
    return true;
}


bool DummyAdapter::SetActiveThreadId(uint32_t)
{
    return true;
}


DebugBreakpoint DummyAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
    DebugBreakpoint result;
    return result;
}

std::vector<DebugBreakpoint> DummyAdapter::AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints)
{
    std::vector<DebugBreakpoint> result;
    return result;
}


bool DummyAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
    return true;
}


bool DummyAdapter::RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints)
{
    return true;
}


bool DummyAdapter::ClearAllBreakpoints()
{
    return true;
}

std::vector<DebugBreakpoint> DummyAdapter::GetBreakpointList() const
{
    std::vector<DebugBreakpoint> result;
    return result;
}


std::string DummyAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
    return std::string();
}


DebugRegister DummyAdapter::ReadRegister(const std::string& reg)
{
    DebugRegister result;
    return result;
}


bool DummyAdapter::WriteRegister(const std::string& reg, std::uintptr_t value)
{
    return true;
}


bool DummyAdapter::WriteRegister(const DebugRegister& reg, std::uintptr_t value)
{
    return true;
}

std::vector<std::string> DummyAdapter::GetRegisterList() const
{
    std::vector<std::string> result;
    return result;
}

bool DummyAdapter::ReadMemory(std::uintptr_t address, void* out, std::size_t size)
{
    return true;
}


bool DummyAdapter::WriteMemory(std::uintptr_t address, void* out, std::size_t size)
{
    return true;
}


std::vector<DebugModule> DummyAdapter::GetModuleList()
{
    std::vector<DebugModule> result;
    return result;
}


std::string DummyAdapter::GetTargetArchitecture()
{
    return std::string();
}


unsigned long DummyAdapter::StopReason()
{
    return 0;
}


unsigned long DummyAdapter::ExecStatus()
{
    return 0;
}


bool DummyAdapter::BreakInto()
{
    return true;
}


bool DummyAdapter::Go()
{
    return true;
}

bool DummyAdapter::StepInto()
{
    return true;
}


bool DummyAdapter::StepOver()
{
    return true;
}


bool DummyAdapter::StepOut()
{
    return true;
}


bool DummyAdapter::StepTo(std::uintptr_t address)
{
    return true;
}


void DummyAdapter::Invoke(const std::string& command)
{

}


std::uintptr_t DummyAdapter::GetInstructionOffset()
{
    return 0x1234;
}


bool DummyAdapter::IsValidForPlatform(Platform* platform)
{
    return true;
}