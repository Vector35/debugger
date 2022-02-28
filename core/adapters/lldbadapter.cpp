#include <thread>
#include <regex>
#ifndef WIN32
#include <spawn.h>
#endif
#include <pugixml/pugixml.hpp>
#include "lldbadapter.h"
#include "queuedadapter.h"


//https://opensource.apple.com/source/lldb/lldb-310.2.36/docs/lldb-gdb-remote.txt.auto.html

using namespace BinaryNinjaDebugger;

bool LldbAdapter::LoadRegisterInfo() {
    const auto xml = this->m_rspConnector.GetXml("target.xml");

    pugi::xml_document doc{};
    const auto parse_result = doc.load_string(xml.c_str());
    if (!parse_result)
        return false;

    for (auto node = doc.first_child().child("feature"); node; node = node.next_sibling())
    {
        using namespace std::literals::string_literals;

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


std::unordered_map<std::string, DebugRegister> LldbAdapter::ReadAllRegisters()
{
    if ( this->m_registerInfo.empty() )
        throw std::runtime_error("register info empty");

    std::vector<register_pair> register_info_vec{};
    for ( const auto& [register_name, register_info] : this->m_registerInfo )
        register_info_vec.emplace_back(register_name, register_info);

    std::sort(register_info_vec.begin(), register_info_vec.end(),
              [](const register_pair& lhs, const register_pair& rhs) {
                  return lhs.second.m_regNum < rhs.second.m_regNum;
              });

    std::unordered_map<std::string, DebugRegister> all_regs{};
    for ( const auto& [register_name, register_info] : register_info_vec )
    {
        DebugRegister value = ReadRegister(register_name);
        all_regs[register_name] = value;
    }

    return all_regs;
}


DebugRegister LldbAdapter::ReadRegister(const std::string& reg)
{
//    if (!m_isTargetRunning)
//        return DebugRegister{};

    auto iter = m_registerInfo.find(reg);
    if (iter == m_registerInfo.end())
        throw std::runtime_error(fmt::format("register {} does not exist in target", reg));

    const auto reply = this->m_rspConnector.TransmitAndReceive(RspData(
            fmt::format("p{:02x}", iter->second.m_regNum)));

    // TODO: handle exceptions in parsing
    uint64_t value = RspConnector::SwapEndianness(strtoull(reply.AsString().c_str(), nullptr, 16));
    DebugRegister result;
    result.m_name = iter->first;
    result.m_value = value;
    result.m_registerIndex = iter->second.m_regNum;
    result.m_width = iter->second.m_bitSize;
    return result;
}


bool LldbAdapter::ExecuteWithArgs(const std::string& path, const std::string &args, const LaunchConfigurations& configs)
{
#ifndef __APPLE__
    return false;
#else
    const auto file_exists = fopen(path.c_str(), "r");
    if (!file_exists)
        return false;
    fclose(file_exists);

    auto lldb_server_path = this->ExecuteShellCommand("which debugserver");

    if ( lldb_server_path.empty() )
        lldb_server_path = "/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver";

    const auto lldb_server_exists = fopen(lldb_server_path.c_str(), "r");
    if (!lldb_server_exists)
        return false;
    fclose(lldb_server_exists);

    lldb_server_path = lldb_server_path.substr(0, lldb_server_path.find('\n'));

    this->m_socket = new Socket(AF_INET, SOCK_STREAM, 0);

    const auto host_with_port = fmt::format("127.0.0.1:{}", this->m_socket->GetPort());

    char* arg[] = {(char*)lldb_server_path.c_str(),
				   "--stdio-path", "/dev/stdin",
				   "--stdout-path", "/dev/stdout",
				   "--stderr-path", "/dev/stderr",
				   (char*)host_with_port.c_str(), (char*) path.c_str(), "--", (char*)args.c_str(), NULL};

	pid_t serverPid;
	if (!configs.requestTerminalEmulator)
	{
		int s = posix_spawn(&serverPid, lldb_server_path.c_str(), nullptr, nullptr, arg, nullptr);
		if (s != 0)
		{
			LogWarn("posix_spawn failed");
			return false;
		}
	}
	else
	{
		std::string cmd{};
		for (const auto& s : arg)
		{
			if (s != NULL)
			{
				cmd.append(s);
				cmd.append(" ");
			}
		}
		std::string fullCmd = fmt::format("osascript -e 'tell app \"Terminal\" to do script \"{}\"'  -e 'activate application \"Terminal\"'", cmd);
		system(fullCmd.c_str());
	}

    return this->Connect("127.0.0.1", this->m_socket->GetPort());
#endif
}


bool LldbAdapter::Attach(std::uint32_t pid)
{
#ifndef __APPLE__
    return false;
#else
    auto lldb_server_path = this->ExecuteShellCommand("which debugserver");

    if ( lldb_server_path.empty() )
        lldb_server_path = "/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver";

    const auto lldb_server_exists = fopen(lldb_server_path.c_str(), "r");
    if (!lldb_server_exists)
        return false;
    fclose(lldb_server_exists);

    lldb_server_path = lldb_server_path.substr(0, lldb_server_path.find('\n'));

    this->m_socket = new Socket(AF_INET, SOCK_STREAM, 0);

    const auto host_with_port = fmt::format("127.0.0.1:{}", this->m_socket->GetPort());

    char* arg[] = {(char*)lldb_server_path.c_str(),
				   "--stdio-path", "/dev/stdin",
				   "--stdout-path", "/dev/stdout",
				   "--stderr-path", "/dev/stderr",
				   (char*)host_with_port.c_str(), "--attach", (char*)fmt::format("{}", pid).c_str(), NULL};

	pid_t serverPid;
	int s = posix_spawn(&serverPid, lldb_server_path.c_str(), nullptr, nullptr, arg, nullptr);
	if (s != 0)
	{
		LogWarn("posix_spawn failed");
		return false;
	}

    return this->Connect("127.0.0.1", this->m_socket->GetPort());
#endif
}


DebugStopReason LldbAdapter::Go()
{
    return GenericGo("c");
}


std::string LldbAdapter::GetTargetArchitecture() {
    // hardcoded this for m1 mac
    // A better way is to parse the target.xml returned by lldb, which has
    // <feature name="com.apple.debugserver.arm64">
    // We will need to translate the arch name returned by lldb into name used by BN archs
    m_remoteArch = "aarch64";
    return "aarch64";
}


std::vector<DebugModule> LldbAdapter::GetModuleList()
{
    std::vector<DebugModule> result;

    const auto reply = m_rspConnector.TransmitAndReceive(
            RspData("jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}"));
    std::string replyString = reply.AsString();

    std::smatch match;
    // "load_address":(\d+).*?"pathname":"([^"]+)"
    const std::regex module_regex("\"load_address\":(\\d+).*?\"pathname\":\"([^\"]+)\"");
    while (std::regex_search(replyString, match, module_regex))
    {
        std::string startString = match[1].str();
        uint64_t start = std::strtoull(startString.c_str(), nullptr, 10);
        std::string path = match[2].str();
        DebugModule module;
        module.m_address = start;
        // we do not know the size of the module
        module.m_size = 0;
        module.m_name = path;
        module.m_short_name = path;
        module.m_loaded = true;
        result.push_back(module);

        replyString = match.suffix();
    }

    return result;
}


DebugStopReason LldbAdapter::SignalToStopReason(std::unordered_map<std::string, std::uint64_t>& dict)
{
//	metype:6;mecount:2;medata:1;medata:0;memory:0x16f5ba940=d0ad5b6f0100000068a8b60001801c5e;
//	memory:0x16f5badd0=90b65b6f01000000f416b600018006f6;#00
//	When there is a metype in the reply, use that; Otherwise, use the signal.
//	metype means "mach exception type"

//	TODO: The current implementation does not differentiate stop caused by breakpoint and single stepping.
//	This is because either the target hits a breakpoint, or single steps, the stop reply is the same and
//	it contains a metype of 6, i.e., which maps to DebugStopReason::Breakpoint.
//	However, if I attach lldb to debugserver, then we can see it knows the difference in the two stops.
//	I am not sure how lldb does it.
//	As a result, the unit test has to special case for macOS see code in expect_single_step().

/*
(lldb) c
Process 51374 resuming
Process 51374 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000104af7f20 commandline_test`main
commandline_test`main:
->  0x104af7f20 <+0>:  sub    sp, sp, #0x30             ; =0x30
    0x104af7f24 <+4>:  stp    x29, x30, [sp, #0x20]
    0x104af7f28 <+8>:  add    x29, sp, #0x20            ; =0x20
    0x104af7f2c <+12>: stur   wzr, [x29, #-0x4]
Target 0: (commandline_test) stopped.
(lldb) si
Process 51374 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = instruction step into
    frame #0: 0x0000000104af7f24 commandline_test`main + 4
commandline_test`main:
->  0x104af7f24 <+4>:  stp    x29, x30, [sp, #0x20]
    0x104af7f28 <+8>:  add    x29, sp, #0x20            ; =0x20
    0x104af7f2c <+12>: stur   wzr, [x29, #-0x4]
    0x104af7f30 <+16>: stur   w0, [x29, #-0x8]
Target 0: (commandline_test) stopped.
*/

    static std::unordered_map<std::uint64_t, DebugStopReason> signal_lookup =
	{
		{ 1,  DebugStopReason::SignalHup},
		{ 2 , DebugStopReason::SignalInt },
		{ 3 , DebugStopReason::SignalQuit },
		{ 4 , DebugStopReason::SignalIll },
		{ 5 , DebugStopReason::SingleStep },
		{ 6 , DebugStopReason::SignalAbrt },
		{ 7 , DebugStopReason::SignalEmt },
		{ 8 , DebugStopReason::SignalFpe },
		{ 9 , DebugStopReason::SignalKill },
		{ 10, DebugStopReason::SignalBus },
		{ 11, DebugStopReason::SignalSegv },
		{ 12, DebugStopReason::SignalSys },
		{ 13, DebugStopReason::SignalPipe },
		{ 14, DebugStopReason::SignalAlrm },
		{ 15, DebugStopReason::SignalTerm },
		{ 16, DebugStopReason::SignalUrg },
		{ 17, DebugStopReason::SignalStop },
		{ 18, DebugStopReason::SignalTstp },
		{ 19, DebugStopReason::SignalCont },
		{ 20, DebugStopReason::SignalChld },
		{ 21, DebugStopReason::SignalTtin },
		{ 22, DebugStopReason::SignalTtou },
		{ 23, DebugStopReason::SignalIo },
		{ 24, DebugStopReason::SignalXcpu },
		{ 25, DebugStopReason::SignalXfsz },
		{ 26, DebugStopReason::SignalVtalrm },
		{ 27, DebugStopReason::SignalProf },
		{ 28, DebugStopReason::SignalWinch },
		{ 29, DebugStopReason::SignalInfo },
		{ 30, DebugStopReason::SignalUsr1 },
		{ 31, DebugStopReason::SignalUsr2 }
    };

	static std::unordered_map<std::uint64_t, DebugStopReason> metype_lookup =
	{
		{1, DebugStopReason::AccessViolation},
		{2, DebugStopReason::IllegalInstruction},
		{3, DebugStopReason::Calculation},
		{4, DebugStopReason::ExcEmulation},
		{5, DebugStopReason::ExcSoftware},
		{6, DebugStopReason::Breakpoint},
		{7, DebugStopReason::ExcSyscall},
		{8, DebugStopReason::ExcMachSyscall},
		{9, DebugStopReason::ExcRpcAlert},
		{10, DebugStopReason::ExcCrash}
	};

	if (dict.find("metype") != dict.end())
	{
		uint64_t metype = dict["metype"];
		if (metype_lookup.find(metype) != metype_lookup.end())
			return metype_lookup[metype];
	}

	if (dict.find("signal") != dict.end())
	{
		uint64_t signal = dict["signal"];
		if (signal_lookup.find(signal) != signal_lookup.end())
			return signal_lookup[signal];
	}

	return DebugStopReason::UnknownReason;
}


LocalLldbAdapterType::LocalLldbAdapterType(): DebugAdapterType("Local LLDB")
{

}


DebugAdapter* LocalLldbAdapterType::Create(BinaryNinja::BinaryView *data)
{
	// TODO: someone should feel this.
    return new QueuedAdapter(new LldbAdapter());
}


bool LocalLldbAdapterType::IsValidForData(BinaryNinja::BinaryView *data)
{
	return data->GetTypeName() == "Mach-O";
}


bool LocalLldbAdapterType::CanConnect(BinaryNinja::BinaryView *data)
{
    return false;
}


bool LocalLldbAdapterType::CanExecute(BinaryNinja::BinaryView *data)
{
//	TODO: LLDB actually works fine on Linux, should we return true for it?
//  Note: LLDB does not work well on Windows.
#ifdef __clang__
	return true;
#else
	return false;
#endif
}


RemoteLldbAdapterType::RemoteLldbAdapterType(): DebugAdapterType("Remote LLDB")
{

}


DebugAdapter* RemoteLldbAdapterType::Create(BinaryNinja::BinaryView *data)
{
	// TODO: someone should feel this.
    return new QueuedAdapter(new LldbAdapter());
}


bool RemoteLldbAdapterType::IsValidForData(BinaryNinja::BinaryView *data)
{
//	it does not matter what the BinaryViewType is -- as long as we can connect to it, it is fine.
	return true;
}


bool RemoteLldbAdapterType::CanConnect(BinaryNinja::BinaryView *data)
{
//	We can connect to remote lldb on any host system
    return true;
}


bool RemoteLldbAdapterType::CanExecute(BinaryNinja::BinaryView *data)
{
    return false;
}


void BinaryNinjaDebugger::InitLldbAdapterType()
{
    static LocalLldbAdapterType localType;
    DebugAdapterType::Register(&localType);
    static RemoteLldbAdapterType remoteType;
    DebugAdapterType::Register(&remoteType);
}
