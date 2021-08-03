#include <thread>
#include <pugixml/pugixml.hpp>
#include "lldbadapter.h"

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


bool LldbAdapter::ExecuteWithArgs(const std::string& path, const std::vector<std::string>& args) {
#ifdef WIN32
    auto lldb_server_path = this->ExecuteShellCommand("where lldb-server");
#else
    auto lldb_server_path = this->ExecuteShellCommand("which debugserver");
#endif

    if ( lldb_server_path.empty() )
        return false;

    lldb_server_path = lldb_server_path.substr(0, lldb_server_path.find('\n'));

    this->m_socket = new Socket(AF_INET, SOCK_STREAM, 0);

    const auto host_with_port = fmt::format("127.0.0.1:{}", this->m_socket->GetPort());

#ifdef WIN32
    std::string final_args{};
    for (const auto& arg : args) {
        final_args.append(arg);
        if (&arg != &args.back())
            final_args.append(" ");
    }

    const auto arguments = fmt::format("--once --no-startup-with-shell {} {} {}", host_with_port, path, final_args);

    STARTUPINFO startup_info{};
    PROCESS_INFORMATION process_info{};
    if (CreateProcessA(lldb_server_path.c_str(), const_cast<char*>( arguments.c_str() ),
                       nullptr, nullptr,
                       true, CREATE_NEW_CONSOLE, nullptr, nullptr,
                       &startup_info, &process_info)) {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    } else {
        throw std::runtime_error("failed to create lldb process");
    }
#else
    std::string final_args{};
    for (const auto& arg : args) {
        final_args.append(arg);
        if (&arg != &args.back())
            final_args.append(" ");
    }

    char* arg[] = {(char*)lldb_server_path.c_str(), (char*)host_with_port.c_str(),
                   (char*) path.c_str(), (char*)final_args.c_str(), NULL};

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

            if (execv(lldb_server_path.c_str(), arg) == -1)
            {
                perror("execv");
                return false;
            }
        }
        default:
            break;
    }
#endif

    return this->Connect("127.0.0.1", this->m_socket->GetPort());
}

bool LldbAdapter::Go() {
    return this->GenericGo("c");
}

std::string LldbAdapter::GetTargetArchitecture() {
    return "x86_64";
}