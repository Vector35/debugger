#include "gdbadapter.h"
#include "rspconnector.h"
#include <memory>
#include <cstring>
#include <unistd.h>
#include <algorithm>
#include <string>
#include <chrono>
#include <thread>

GdbAdapter::GdbAdapter()
{

}

GdbAdapter::~GdbAdapter()
{

}

std::string GdbAdapter::ExecuteShellCommand(const std::string& command)
{
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe)
        return {};

    std::string result{};
    std::array<char, 128> buffer{};
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
        result += buffer.data();

    if (result.empty())
        return {};

    return result;
}

bool GdbAdapter::Execute(const std::string& path)
{
    auto gdb_server_path = this->ExecuteShellCommand("which gdbserver");
    if ( gdb_server_path.empty() )
        return false;
    gdb_server_path.erase(std::remove(gdb_server_path.begin(), gdb_server_path.end(), '\n'), gdb_server_path.end());

    for ( int index = 31337; index < 31337 + 256; index++ )
    {
        this->m_socket = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(index);

        if (bind(this->m_socket, (const sockaddr*) &addr, sizeof(addr)) >= 0)
        {
            this->m_port = index;
            close(this->m_socket);
            break;
        }
    }

    if ( !this->m_port )
        return false;

    std::array<char, 256> buffer{};
    std::sprintf(buffer.data(), "%s --once --no-startup-with-shell localhost:%d %s > /dev/null 2>&1 &",
                 gdb_server_path.c_str(), this->m_port, path.c_str());

    std::system(buffer.data());
    std::system((path + " > /dev/null 2>&1").c_str());

    for ( std::uint8_t index{}; index < 4; index++ )
    {
        this->m_socket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(this->m_port);
        if (connect(this->m_socket, (const sockaddr*) &addr, sizeof(addr)) >= 0)
        {
            auto rsp_connector = RspConnector(this->m_socket);
            printf("%s\n", rsp_connector.TransmitAndReceive(RspData("Hg0")).AsString().c_str() );
            //printf("%s\n", rsp_connector.TransmitAndReceive(RspData("?")).AsString().c_str() );
            return true;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

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
