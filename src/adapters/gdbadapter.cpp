#include "gdbadapter.h"

GdbAdapter::GdbAdapter()
{

}

GdbAdapter::~GdbAdapter()
{

}

bool GdbAdapter::Execute(const std::string& path)
{
    return false;
}

bool GdbAdapter::ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args)
{
    return false;
}

bool GdbAdapter::Attach(std::uint32_t pid)
{
    return true;
}

bool GdbAdapter::Connect(const std::string& server, std::uint32_t port)
{
    return false;
}

void GdbAdapter::Detach()
{

}

void GdbAdapter::Quit()
{

}

std::vector<DebugThread> GdbAdapter::GetThreadList() const
{
    return std::vector<DebugThread>();
}

DebugThread GdbAdapter::GetActiveThread() const
{
    return DebugThread();
}

std::uint32_t GdbAdapter::GetActiveThreadId() const
{
    return 0;
}

bool GdbAdapter::SetActiveThread(const DebugThread& thread)
{
    return false;
}

bool GdbAdapter::SetActiveThreadId(std::uint32_t tid)
{
    return false;
}

DebugBreakpoint GdbAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
    return DebugBreakpoint();
}

std::vector<DebugBreakpoint> GdbAdapter::AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints)
{
    return std::vector<DebugBreakpoint>();
}

bool GdbAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
    return false;
}

bool GdbAdapter::RemoveBreakpoints(const std::vector<DebugBreakpoint>& breakpoints)
{
    return false;
}

bool GdbAdapter::ClearAllBreakpoints()
{
    return false;
}

std::vector<DebugBreakpoint> GdbAdapter::GetBreakpointList() const
{
    return std::vector<DebugBreakpoint>();
}

std::string GdbAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
    return std::string();
}

DebugRegister GdbAdapter::ReadRegister(const std::string& reg) const
{
    return DebugRegister();
}

bool GdbAdapter::WriteRegister(const std::string& reg, std::uintptr_t value)
{
    return false;
}

bool GdbAdapter::WriteRegister(const DebugRegister& reg, std::uintptr_t value)
{
    return false;
}

std::vector<std::string> GdbAdapter::GetRegisterList() const
{
    return std::vector<std::string>();
}

bool GdbAdapter::ReadMemory(std::uintptr_t address, void* out, std::size_t size)
{
    return false;
}

bool GdbAdapter::WriteMemory(std::uintptr_t address, void* out, std::size_t size)
{
    return false;
}

std::vector<DebugModule> GdbAdapter::GetModuleList() const
{
    return std::vector<DebugModule>();
}

std::string GdbAdapter::GetTargetArchitecture()
{
    return std::string();
}

bool GdbAdapter::BreakInto()
{
    return false;
}

bool GdbAdapter::Go()
{
    return false;
}

bool GdbAdapter::StepInto()
{
    return false;
}

bool GdbAdapter::StepOver()
{
    return false;
}

bool GdbAdapter::StepOut()
{
    return false;
}

bool GdbAdapter::StepTo(std::uintptr_t address)
{
    return false;
}

void GdbAdapter::Invoke(const std::string& command)
{

}

std::uintptr_t GdbAdapter::GetInstructionOffset()
{
    return 0;
}

unsigned long GdbAdapter::StopReason()
{
    return 0;
}

unsigned long GdbAdapter::ExecStatus()
{
    return 0;
}
