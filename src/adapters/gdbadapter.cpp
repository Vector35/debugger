#include "gdbadapter.h"
#include <memory>
#include <cstring>
#ifdef WIN32
#include <windows.h>
#undef min
#undef max
#else
#include <unistd.h>
#include <spawn.h>
#include <csignal>
#endif
#include <algorithm>
#include <string>
#include <chrono>
#include <thread>
#include <cstdio>
#include <iostream>
#include <string_view>
#include <regex>
#include <stdexcept>
#include <pugixml/pugixml.hpp>
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>

using namespace BinaryNinja;
using namespace std;

GdbAdapter::GdbAdapter(bool redirectGDBServer): m_redirectGDBServer(redirectGDBServer)
{
}

GdbAdapter::~GdbAdapter()
{
}

std::string GdbAdapter::ExecuteShellCommand(const std::string& command)
{
#ifdef WIN32
    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(command.c_str(), "r"), _pclose);
#else
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
#endif

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
    return this->ExecuteWithArgs(path, {});
}

bool GdbAdapter::ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args)
{
    const auto file_exists = fopen(path.c_str(), "r");
    if (!file_exists)
        return false;
    fclose(file_exists);

#ifdef WIN32
    auto gdb_server_path = this->ExecuteShellCommand("where gdbserver");
#else
    auto gdb_server_path = this->ExecuteShellCommand("which gdbserver");
#endif
    if ( gdb_server_path.empty() )
        return false;

    gdb_server_path = gdb_server_path.substr(0, gdb_server_path.find('\n'));

    this->m_socket = Socket(AF_INET, SOCK_STREAM, 0);

    const auto host_with_port = fmt::format("127.0.0.1:{}", this->m_socket.GetPort());

#ifdef WIN32
    std::string final_args{};
    for (const auto& arg : args) {
        final_args.append(arg);
        if (&arg != &args.back())
            final_args.append(" ");
    }

    const auto arguments = fmt::format("--once --no-startup-with-shell {} {} {}", host_with_port, path, final_args);

    STARTUPINFOA startup_info{};
    PROCESS_INFORMATION process_info{};
    if (CreateProcessA(gdb_server_path.c_str(), const_cast<char*>( arguments.c_str() ),
                       nullptr, nullptr,
                       true, CREATE_NEW_CONSOLE, nullptr, nullptr,
                       &startup_info, &process_info)) {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    } else {
        throw std::runtime_error("failed to create gdb process");
    }
#else
    pid_t pid = fork();
    switch (pid)
    {
    case -1:
        perror("fork");
        return false;
    case 0:
    {
        // This is done in the Python implementation, but I am not sure what it is intended for
        // setpgrp();

        // This will detach the gdbserver from the current terminal, so that we can continue interacting with it.
        // Otherwise, gdbserver will set itself to the foreground process and the cli will become background.
        // TODO: we should redirect the stdin/stdout to a different FILE so that we can see the debuggee's output
        // and send input to it
        if (m_redirectGDBServer)
        {
            FILE *newOut = freopen("/dev/null", "w", stdout);
            if (!newOut)
            {
                perror("freopen");
                return false;
            }

            FILE *newIn = freopen("/dev/null", "r", stdin);
            if (!newIn)
            {
                perror("freopen");
                return false;
            }

            FILE *newErr = freopen("/dev/null", "w", stderr);
            if (!newErr)
            {
                perror("freopen");
                return false;
            }
        }
        // TODO: this works, but its not good. We are casting const char* to char*
        std::string final_args{};
        for (const auto& arg : args) {
            final_args.append(arg);
            if (&arg != &args.back())
                final_args.append(" ");
        }

        char* arg[] = {"--once", "--no-startup-with-shell", (char*)host_with_port.c_str(),
                    (char*) path.c_str(), (char*)final_args.c_str(), NULL};

        if (execv(gdb_server_path.c_str(), arg) == -1)
        {
            perror("execv");
            return false;
        }
    }
    default:
        break;
    }
#endif

    return this->Connect("127.0.0.1", this->m_socket.GetPort());
}

bool GdbAdapter::Attach(std::uint32_t pid)
{
    throw std::runtime_error("gdb attach is not supported");
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

    std::unordered_map<std::uint32_t, std::string> id_name{};
    std::unordered_map<std::uint32_t, std::uint32_t> id_width{};

    for ( auto [key, value] : this->m_registerInfo ) {
        id_name[value.m_regNum] = key;
        id_width[value.m_regNum] = value.m_bitSize;
    }

    std::size_t max_id{};
    for ( auto [key, value] : this->m_registerInfo )
        max_id += value.m_regNum;

    std::size_t offset{};
    for ( std::size_t index{}; index < max_id; index++ ) {
        if ( !id_width[index] )
            break;

        const auto name = id_name[index];
        this->m_registerInfo[name].m_offset = offset;
        offset += id_width[index];
    }

    return true;
}

bool GdbAdapter::Connect(const std::string& server, std::uint32_t port)
{
    bool connected = false;
    for ( std::uint8_t index{}; index < 4; index++ ) {
        this->m_socket = Socket(AF_INET, SOCK_STREAM, 0, port);

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = inet_addr("127.0.0.1");
        address.sin_port = htons(port);

        if (this->m_socket.Connect(address)) {
            connected = true;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if ( !connected ) {
        printf("failed to connect!\n");
        return false;
    }

    this->m_rspConnector = RspConnector(&this->m_socket);
    this->m_rspConnector.TransmitAndReceive(RspData("Hg0"));
    this->m_rspConnector.NegotiateCapabilities(
            { "swbreak+", "hwbreak+", "qRelocInsn+", "fork-events+", "vfork-events+", "exec-events+",
                         "vContSupported+", "QThreadEvents+", "no-resumed+", "xmlRegisters=i386" } );
    if ( !this->LoadRegisterInfo() )
        return false;

    const auto reply = this->m_rspConnector.TransmitAndReceive(RspData("?"));
    auto map = RspConnector::PacketToUnorderedMap(reply);

    this->m_lastActiveThreadId = map["thread"];

    return true;
}

void GdbAdapter::Detach()
{
    char detach{'D'};
    this->m_rspConnector.SendRaw(RspData(&detach, sizeof(detach)));
    this->m_socket.Kill();
}

void GdbAdapter::Quit()
{
    char send{'\x03'};
    char kill{'k'};
    this->m_rspConnector.SendRaw(RspData(&send, sizeof(send)));
    this->m_rspConnector.SendRaw(RspData(&kill, sizeof(kill)));
    this->m_socket.Kill();
}

std::vector<DebugThread> GdbAdapter::GetThreadList()
{
    int internal_thread_index{};
    std::vector<DebugThread> threads{};

    auto reply = this->m_rspConnector.TransmitAndReceive(RspData("qfThreadInfo"));
    while(reply.m_data[0] != 'l') {
        if (reply.m_data[0] != 'm')
            throw std::runtime_error("thread list failed?");

        const auto shortened_string =
                reply.AsString().substr(1);
        const auto tids = RspConnector::Split(shortened_string, ",");
        for ( const auto& tid : tids )
            threads.emplace_back(std::stoi(tid, nullptr, 16), internal_thread_index++);

        reply = this->m_rspConnector.TransmitAndReceive(RspData("qsThreadInfo"));
    }

    const auto current_thread = this->GetActiveThread();
    for (auto& thread : threads) {
        this->SetActiveThread(thread);
        thread.m_rip = GetInstructionOffset();
    }
    this->SetActiveThread(current_thread);

    return threads;
}

DebugThread GdbAdapter::GetActiveThread() const
{
    return DebugThread(this->GetActiveThreadId(), 0);
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
    if ( this->m_rspConnector.TransmitAndReceive(RspData("T{:x}", tid)).AsString() != "OK" )
        throw std::runtime_error("thread does not exist!");

    if ( this->m_rspConnector.TransmitAndReceive(RspData("Hc{:x}", tid)).AsString() != "OK")
        throw std::runtime_error("failed to set thread");

    if ( this->m_rspConnector.TransmitAndReceive(RspData("Hg{:x}", tid)).AsString() != "OK")
        throw std::runtime_error("failed to set thread");

    this->m_lastActiveThreadId = tid;

    return true;
}

DebugBreakpoint GdbAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
    if ( std::find(this->m_debugBreakpoints.begin(), this->m_debugBreakpoints.end(),
                   DebugBreakpoint(address)) != this->m_debugBreakpoints.end())
        return {};

    /* TODO: replace %d with the actual breakpoint size as it differs per architecture */
    if (this->m_rspConnector.TransmitAndReceive(RspData("Z0,{:x},{}", address, 1)).AsString() != "OK" )
        throw std::runtime_error("rsp reply failure on breakpoint");

    const auto new_breakpoint = DebugBreakpoint(address, this->m_internalBreakpointId++, true);
    this->m_debugBreakpoints.push_back(new_breakpoint);

    return new_breakpoint;
}

std::vector<DebugBreakpoint> GdbAdapter::AddBreakpoints(const std::vector<std::uintptr_t>& breakpoints)
{
    return std::vector<DebugBreakpoint>();
}

bool GdbAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
    if (auto location = std::find(this->m_debugBreakpoints.begin(), this->m_debugBreakpoints.end(), breakpoint);
            location == this->m_debugBreakpoints.end()) {
        printf("breakpoint does not exist!\n");
        return false;
    }

    /* TODO: replace %d with the actual breakpoint size as it differs per architecture */
    if (this->m_rspConnector.TransmitAndReceive(RspData("z0,{:x},{}", breakpoint.m_address, 1)).AsString() != "OK" )
        throw std::runtime_error("rsp reply failure on remove breakpoint");

    if (auto location = std::find(this->m_debugBreakpoints.begin(), this->m_debugBreakpoints.end(), breakpoint);
            location != this->m_debugBreakpoints.end())
        this->m_debugBreakpoints.erase(location);

    return true;
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
    return this->m_debugBreakpoints;
}

std::string GdbAdapter::GetRegisterNameByIndex(std::uint32_t index) const
{
    for (const auto& [key, val] : this->m_registerInfo)
        if (val.m_regNum == index)
            return key;

    throw std::runtime_error("failed to find register by index");
}

std::unordered_map<std::string, DebugRegister> GdbAdapter::ReadAllRegisters() {
    if ( this->m_registerInfo.empty() )
        throw std::runtime_error("register info empty");

    std::vector<register_pair> register_info_vec{};
    for ( const auto& [register_name, register_info] : this->m_registerInfo )
        register_info_vec.emplace_back(register_name, register_info);

    std::sort(register_info_vec.begin(), register_info_vec.end(),
              [](const register_pair& lhs, const register_pair& rhs) {
                  return lhs.second.m_regNum < rhs.second.m_regNum;
              });

    char request{'g'};
    const auto register_info_reply = this->m_rspConnector.TransmitAndReceive(RspData(&request, sizeof(request)));
    auto register_info_reply_string = register_info_reply.AsString();
    if ( register_info_reply_string.empty() )
        throw std::runtime_error("register request reply empty");

    std::unordered_map<std::string, DebugRegister> all_regs{};
    for ( const auto& [register_name, register_info] : register_info_vec ) {
        const auto number_of_chars = 2 * ( register_info.m_bitSize / 8 );
        const auto value_string = register_info_reply_string.substr(0, number_of_chars);
        if (number_of_chars <= 0x10 && !value_string.empty()) {
            const auto value = RspConnector::SwapEndianness(std::stoull(value_string, nullptr, 16));
            all_regs[register_name] = DebugRegister(register_name, value, register_info.m_bitSize);
            #warning "ignoring registers with a larger size than 0x10"
            /* TODO: ^fix this^ */
        }
        register_info_reply_string.erase(0, number_of_chars);
    }

    return all_regs;
}

DebugRegister GdbAdapter::ReadRegister(const std::string& reg)
{
    if ( this->m_registerInfo.find(reg) == this->m_registerInfo.end() )
        throw std::runtime_error(fmt::format("register {} does not exist in target", reg));

    return this->ReadAllRegisters()[reg];
}

bool GdbAdapter::WriteRegister(const std::string& reg, std::uintptr_t value)
{
    const auto reply = this->m_rspConnector.TransmitAndReceive(RspData("P{}={:016X}",
                                       this->m_registerInfo[reg].m_regNum, RspConnector::SwapEndianness(value)));
    if (reply.m_data[0])
        return true;

    char query{'g'};
    const auto generic_query = this->m_rspConnector.TransmitAndReceive(RspData(&query, sizeof(query)));
    const auto register_offset = this->m_registerInfo[reg].m_offset;

    const auto first_half = generic_query.AsString().substr(0, 2 * (register_offset / 8));
    const auto second_half = generic_query.AsString().substr(2 * ((register_offset + this->m_registerInfo[reg].m_bitSize) / 8) );
    const auto payload = "G" + first_half + fmt::format("{:016X}", RspConnector::SwapEndianness(value)) + second_half;

    if ( this->m_rspConnector.TransmitAndReceive(RspData(payload)).AsString() != "OK" )
        return false;

    return true;
}

bool GdbAdapter::WriteRegister(const DebugRegister& reg, std::uintptr_t value)
{
    return this->WriteRegister(reg.m_name, value);
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
    auto reply = this->m_rspConnector.TransmitAndReceive(RspData("m{:x},{:x}", address, size));
    if (reply.m_data[0] == 'E')
        return false;

    const auto source = std::make_unique<std::uint8_t[]>(2 * size + 1);
    const auto dest = std::make_unique<std::uint8_t[]>(size + 1);
    std::memset(source.get(), '\0', 2 * size + 1);
    std::memset(dest.get(), '\0', size + 1);
    std::memcpy(source.get(), reply.m_data, 2 * size + 1);

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

bool GdbAdapter::WriteMemory(std::uintptr_t address, const void* out, std::size_t size)
{
    const auto dest = std::make_unique<char[]>(2 * size + 1);
    std::memset(dest.get(), '\0', 2 * size + 1);

    for ( std::size_t index{}; index < size; index++ )
        fmt::format_to(dest.get(), "{}{:02X}", dest.get(), ((std::uint8_t*)out)[index]);

    auto reply = this->m_rspConnector.TransmitAndReceive(RspData("M{:x},{:x}:{}", address, size, dest.get()));
    if (reply.AsString() != "OK")
        return false;

    return true;
}


std::string GdbAdapter::GetRemoteFile(const std::string& path)
{
    RspData output;
    int32_t error;
    int32_t ret = this->m_rspConnector.HostFileIO(RspData("vFile:setfs:0"), output, error);
    if (ret < 0)
        throw runtime_error("could not set remote filesystem");

    std::string path_hex_string{};
    for ( const auto& ch : path )
        path_hex_string += fmt::format("{:02X}", ch);

    ret = this->m_rspConnector.HostFileIO(
                    RspData("vFile:open:{},{:X},{:X}", path_hex_string.c_str(), 0, 0), output, error);
    if (ret < 0)
        throw runtime_error("unable to open file with host I/O");

    int32_t fd = ret;

    std::string data;
    size_t offset = 0;
    const size_t blockSize = 1024;

    while(true)
    {
        ret = this->m_rspConnector.HostFileIO(
                    RspData("vFile:pread:{:X},{:X},{:X}", fd, blockSize, offset), output, error);
        if (ret < 0)
            throw runtime_error(fmt::format("host i/o pread() failed, result=%d, errno=%d", ret, error));
        if (ret == 0)
            // EOF
            break;
        if (ret != (int32_t)output.AsString().length())
            throw runtime_error(fmt::format("host i/o pread() returned {:X} but decoded binary attachment is size {:X}",
                    ret, output.AsString().length()));
        
        data += output.AsString();
        offset += output.AsString().length();
    }

    ret = this->m_rspConnector.HostFileIO(RspData(fmt::format("vFile:close:{:X}", fd)), output, error);
    if (ret)
        throw runtime_error(fmt::format("host i/o close() failed, result={}, errno={}", ret, error));

    return data;
}

std::vector<DebugModule> GdbAdapter::GetModuleList()
{
    std::map<std::string, BNAddressRange> moduleRanges;

    const auto path = "/proc/" + std::to_string(this->m_lastActiveThreadId) + "/maps";
    std::string data = GetRemoteFile(path);
    for (const std::string& line: RspConnector::Split(data, "\n"))
    {
        std::string_view v = line;
        v.remove_prefix(std::min(v.find_first_not_of(" "), v.size()));
        auto trimPosition = v.find_last_not_of(" ");
        if (trimPosition != v.npos)
            v.remove_suffix(v.size() - trimPosition - 1);

        // regex_match() requires the first argument to be const
        const std::string trimmedLine = std::string(v);

        std::smatch match;
        const std::regex module_regex("^([0-9a-f]+)-([0-9a-f]+) [rwxp-]{4} .* (/.*)$");
        bool found = std::regex_match(trimmedLine, match, module_regex);
        if (found)
        {
            if (match.size() == 4) {
                std::string startString = match[1].str();
                uint64_t start = std::strtoull(startString.c_str(), nullptr, 16);
                std::string endString = match[2].str();
                uint64_t end = std::strtoull(endString.c_str(), nullptr, 16);
                std::string path = match[3].str();

                auto iter = moduleRanges.find(path);
                if (iter != moduleRanges.end())
                {
                    BNAddressRange currentRange = iter->second;
                    BNAddressRange newRange;
                    newRange.start = std::min<uint64_t>(currentRange.start, start);
                    newRange.end = std::max<uint64_t>(currentRange.end, end);
                    iter->second = newRange;
                }
                else
                {
                    moduleRanges[path] = {start, end};
                }
            }
        }
    }

    std::vector<DebugModule> result;
    for (auto& iter: moduleRanges)
    {
        DebugModule module;
        module.m_address = iter.second.start;
        module.m_size = iter.second.end - iter.second.start;
        module.m_name = iter.first;
        module.m_short_name = iter.first;
        module.m_loaded = true;
        result.push_back(module);
    }
    return result;
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

    if (architecture.find(':') != std::string::npos) {
        architecture.erase(0, architecture.find(':') + 1);
        architecture.replace(architecture.find('-'), 1, "_");
    }
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
        this->m_lastActiveThreadId = tid;
        if (map["signal"] == 5) {
            this->m_lastStopReason = DebugStopReason::Breakpoint;
        } else if (map["signal"] == 11) {
            this->m_lastStopReason = DebugStopReason::AccessViolation;
        }
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
    // GdbAdapter does not support StepOver(), it relies on DebuggerState to do a breakpoint and continue execution
    return false;
}

bool GdbAdapter::StepTo(std::uintptr_t address)
{
    const auto breakpoints = this->m_debugBreakpoints;

    this->RemoveBreakpoints(this->m_debugBreakpoints);

    const auto bp = this->AddBreakpoint(address);
    if ( !bp.m_address )
        return false;

    this->Go();

    this->RemoveBreakpoint(bp);

    for ( const auto& breakpoint : breakpoints )
        this->AddBreakpoint(breakpoint.m_address);

    return true;
}

void GdbAdapter::Invoke(const std::string& command)
{
}

std::uintptr_t GdbAdapter::GetInstructionOffset()
{
    // TODO: obviously this will only support x86/x86_64, so we need a more systematic way for it
    return this->ReadRegister(this->GetTargetArchitecture() == "x86" ? "eip" : "rip").m_value;
}

DebugStopReason GdbAdapter::StopReason()
{
    return this->m_lastStopReason;
}

unsigned long GdbAdapter::ExecStatus()
{
    return 0;
}


bool GdbAdapter::SupportFeature(DebugAdapterCapacity feature)
{
    switch (feature)
    {
    case DebugAdapterSupportStepOver:
        return false;
    case DebugAdapterSupportModules:
        return true;
    case DebugAdapterSupportThreads:
        return true;
    default:
        return false;
    }
}
