#include <thread>
#include "lldbadapter.h"

bool LldbAdapter::Execute(const std::string& path) {
#ifdef WIN32
    auto lldb_server_path = this->ExecuteShellCommand("where lldb-server");
#else
    auto lldb_server_path = this->ExecuteShellCommand("which debugserver");
#endif

    if ( lldb_server_path.empty() )
        return false;

    lldb_server_path = lldb_server_path.substr(0, lldb_server_path.find('\n'));

    this->m_socket = Socket(AF_INET, SOCK_STREAM, 0);

    const auto host_with_port = fmt::format("127.0.0.1:{}", this->m_socket.GetPort());

#ifdef WIN32
    const auto arguments = fmt::format("{} {}", host_with_port, path);
    fmt::print("{} {}\n", lldb_server_path, arguments);

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
    char* arg[] = {(char*)host_with_port.c_str(), (char*) path.c_str(), NULL};
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

    return this->Connect("127.0.0.1", this->m_socket.GetPort());
}

bool LldbAdapter::Go() {
    return this->GenericGo("c");
}
