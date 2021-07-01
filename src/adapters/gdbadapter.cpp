#include "gdbadapter.h"
#include <memory>
#include <cstring>
#include <unistd.h>
#include <algorithm>
#include <string>
#include <chrono>
#include <thread>
#include <pugixml/pugixml.hpp>
#include <spawn.h>

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
    std::sprintf(buffer.data(), "localhost:%d", this->m_port);
    setsid();
    pid_t pid;
    char* arg[] = {(char*) gdb_server_path.c_str(), "--once", "--no-startup-with-shell", buffer.data(),
                   (char*) path.c_str()};
    posix_spawn(&pid, gdb_server_path.c_str(), nullptr, nullptr, arg, environ);

    /*
    pid_t pid = fork();
    switch (pid)
    {
    case -1:
        perror("fork()\n");
        return false;
    case 0:
    {
        // This is done in the Python implementation, but I am not sure what it is intended for
        // setpgrp();

        // This will detach the gdbserver from the current terminal, so that we can continue interacting with it.
        // Otherwise, gdbserver will set itself to the foreground process and the cli will become background.
        // TODO: we should redirect the stdin/stdout to a different FILE so that we can see the debuggee's output
        // and send input to it
        FILE *newOut = freopen("/dev/null", "w", stdout);
        if (!newOut)
        {
            perror("freopen");
            return false;
        }
        stdout = newOut;

        FILE *newIn = freopen("/dev/null", "r", stdin);
        if (!newIn)
        {
            perror("freopen");
            return false;
        }
        stdin = newIn;

        FILE *newErr = freopen("/dev/null", "w", stderr);
        if (!newErr)
        {
            perror("freopen");
            return false;
        }
        stderr = newErr;

        if (execv(gdb_server_path.c_str(), arg) == -1)
        {
            perror("execv()\n");
            return false;
        }
    }
    default:
        break;
    }*/

    return this->Connect("127.0.0.1", this->m_port);
}

bool GdbAdapter::ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args)
{
    return false;
}

bool GdbAdapter::Attach(std::uint32_t pid)
{
    return true;
}

bool GdbAdapter::LoadRegisterInfo()
{
    const auto xml = this->m_rspConnector.GetXml("target.xml");

    pugi::xml_document doc{};
    const auto parse_result = doc.load_string(xml.c_str());
    if (!parse_result)
        return false;

    std::string architecture{};
    std::string os_abi{};
    for (auto node = doc.first_child().child("architecture"); node; node = node.next_sibling())
    {
        using namespace std::literals::string_literals;

        if ( node.name() == "architecture"s )
            architecture = node.child_value();
        if ( node.name() == "osabi"s )
            os_abi = node.child_value();

        if ( node.name() == "feature"s )
        {
            for (auto reg_child = node.child("reg"); reg_child; reg_child = reg_child.next_sibling())
            {
                std::string register_name{};
                RegisterInfo register_info{};

                for (auto reg_attribute = reg_child.attribute("name"); reg_attribute; reg_attribute = reg_attribute.next_attribute())
                {
                    if (reg_attribute.name() == "name"s )
                        register_name = reg_attribute.value();
                    else if (reg_attribute.name() == "bitsize"s )
                        register_info.m_bitSize = reg_attribute.as_uint();
                    else if (reg_attribute.name() == "regnum"s)
                        register_info.m_regNum = reg_attribute.as_uint();
                }

                this->m_registerInfo[register_name] = register_info;
            }
        }
    }

    return true;
}

bool GdbAdapter::Connect(const std::string& server, std::uint32_t port)
{
    bool connected = false;
    for ( std::uint8_t index{}; index < 4; index++ )
    {
        this->m_socket = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(this->m_port);
        if (connect(this->m_socket, (const sockaddr*) &addr, sizeof(addr)) >= 0)
        {
            connected = true;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if ( !connected ) {
        printf("failed to connect!\n");
        return false;
    }

    this->m_rspConnector = RspConnector(this->m_socket);
    printf("FINAL RESPONSE -> %s\n", this->m_rspConnector.TransmitAndReceive(RspData("Hg0")).AsString().c_str() );
    this->m_rspConnector.NegotiateCapabilities(
            { "swbreak+", "hwbreak+", "qRelocInsn+", "fork-events+", "vfork-events+", "exec-events+",
                         "vContSupported+", "QThreadEvents+", "no-resumed+", "xmlRegisters=i386" } );
    if ( !this->LoadRegisterInfo() )
        return false;

    auto reply = this->m_rspConnector.TransmitAndReceive(RspData("?"));
    printf("RESPONSE -> %s\n", reply.AsString().c_str() );
    auto map = RspConnector::PacketToUnorderedMap(reply);
    for ( const auto& [key, val] : map ) {
        printf("[%s] = 0x%llx\n", key.c_str(), val );
    }

    return true;
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
    if ( std::find(this->m_debugBreakpoint.begin(), this->m_debugBreakpoint.end(),
                   DebugBreakpoint(address)) != this->m_debugBreakpoint.end())
        return {};

    /* TODO: replace %d with the actual breakpoint size as it differs per architecture */
    if (this->m_rspConnector.TransmitAndReceive(RspData("Z0,%llx,%d", address, 1)).AsString() != "OK" )
        throw std::runtime_error("rsp reply failure on breakpoint");

    const auto new_breakpoint = DebugBreakpoint(address, this->m_internalBreakpointId++, true);
    this->m_debugBreakpoint.push_back(new_breakpoint);

    return new_breakpoint;
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
    return this->m_debugBreakpoint;
}

std::string GdbAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
    return std::string();
}

/* TODO: register cache, no point in spamming gdb with requests when we get all the info we need in one  */
DebugRegister GdbAdapter::ReadRegister(const std::string& reg)
{
    if ( this->m_registerInfo.find(reg) == this->m_registerInfo.end() )
        throw std::runtime_error("register does not exist in target");

    using register_pair = std::pair<std::string, RegisterInfo>;
    std::vector<register_pair> register_info_vec{};
    for ( const auto& [register_name, register_info] : this->m_registerInfo ) {
        register_info_vec.emplace_back(register_name, register_info);
    }

    std::sort(register_info_vec.begin(), register_info_vec.end(),
              [](const register_pair& lhs, const register_pair& rhs) {
                    return lhs.second.m_regNum < rhs.second.m_regNum;
              });

    char request{'g'};
    const auto register_info_reply = this->m_rspConnector.TransmitAndReceive(RspData(&request, sizeof(request)));
    auto register_info_reply_string = register_info_reply.AsString();

    std::unordered_map<std::string, DebugRegister> test_out{};
    for ( const auto& [register_name, register_info] : register_info_vec ) {
        const auto number_of_chars = 2 * ( register_info.m_bitSize / 8 );
        const auto value_string = register_info_reply_string.substr(0, number_of_chars);
        const auto value = RspConnector::SwapEndianness(std::stoull(value_string, nullptr, 16));
        test_out[register_name] = DebugRegister(register_name, value, register_info.m_bitSize);
        register_info_reply_string.erase(0, number_of_chars);
    }

    return test_out[reg];
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
    std::vector<std::string> registers{};

    for ( const auto& [register_name, register_info] : this->m_registerInfo )
        registers.push_back(register_name);

    return registers;
}

bool GdbAdapter::ReadMemory(std::uintptr_t address, void* out, std::size_t size)
{
    auto reply = this->m_rspConnector.TransmitAndReceive(RspData("m%llx,%x", address, size));
    if (reply.m_data[0] == 'E')
        return false;

    const auto source = std::make_unique<std::uint8_t[]>(size + 1);
    const auto dest = std::make_unique<std::uint8_t[]>(size + 1);
    std::memset(source.get(), '\0', size + 1);
    std::memset(dest.get(), '\0', size + 1);
    std::memcpy(source.get(), reply.m_data, size);

    [](const std::uint8_t* src, std::uint8_t* dst) {
        const auto char_to_int = [](std::uint8_t input) -> int {
            if(input >= '0' && input <= '9')
                return input - '0';
            if(input >= 'A' && input <= 'F')
                return input - 'A' + 10;
            if(input >= 'a' && input <= 'f')
                return input - 'a' + 10;
            throw std::invalid_argument("Invalid input string");
        };

        while(*src && src[1]) {
            *(dst++) = char_to_int(*src) * 16 + char_to_int(src[1]);
            src += 2;
        }
    }(source.get(), dest.get());

    std::memcpy(out, dest.get(), size);

    return true;
}

bool GdbAdapter::WriteMemory(std::uintptr_t address, void* out, std::size_t size)
{
    const auto dest = std::make_unique<char[]>(size + 1);
    std::memset(dest.get(), '\0', size + 1);

    for ( std::size_t index{}; index < size; index++ )
        std::sprintf(dest.get(), "%s%02x", dest.get(), ((std::uint8_t*)out)[index]);

    auto reply = this->m_rspConnector.TransmitAndReceive(RspData("M%llx,%x:%s", address, size, dest.get()));
    if (reply.AsString() != "OK")
        return false;

    return true;
}

std::vector<DebugModule> GdbAdapter::GetModuleList() const
{
    return std::vector<DebugModule>();
}

std::string GdbAdapter::GetTargetArchitecture()
{
    const auto xml = this->m_rspConnector.GetXml("target.xml");

    pugi::xml_document doc{};
    const auto parse_result = doc.load_string(xml.c_str());
    if (!parse_result)
        throw std::runtime_error("failed to parse target.xml");

    std::string architecture{};
    for (auto node = doc.first_child().child("architecture"); node; node = node.next_sibling()) {
        using namespace std::literals::string_literals;
        if (node.name() == "architecture"s) {
            architecture = node.child_value();
            break;
        }
    }

    if (architecture.empty())
        throw std::runtime_error("failed to find architecture");

    architecture.erase(0, architecture.find(':') + 1);
    architecture.replace(architecture.find('-'), 1, "_");

    return architecture;
}

bool GdbAdapter::BreakInto()
{
    char var = '\x03';
    this->m_rspConnector.SendRaw(RspData(&var, sizeof(var)));
    return true;
}

bool GdbAdapter::GenericGo(const std::string& go_type) {
    const auto go_reply =
            this->m_rspConnector.TransmitAndReceive(
                    RspData(go_type), "mixed_output_ack_then_reply", true);

    if ( go_reply.m_data[0] == 'T' ) {
        auto map = RspConnector::PacketToUnorderedMap(go_reply);
        const auto tid = map["thread"];
        printf("%lx\n", tid);
    } else if ( go_reply.m_data[0] == 'W' ) {
        /* exit status, substr */
    } else {
        printf("[generic go failed?]\n");
        printf("%s\n", go_reply.AsString().c_str());
        return false;
    }

    return true;
}

bool GdbAdapter::Go()
{
    return this->GenericGo("vCont;c:-1");
}

bool GdbAdapter::StepInto()
{
    return this->GenericGo("vCont;s");
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
    return this->ReadRegister(this->GetTargetArchitecture() == "x86" ? "eip" : "rip").m_value;
}

unsigned long GdbAdapter::StopReason()
{
    return 0;
}

unsigned long GdbAdapter::ExecStatus()
{
    return 0;
}