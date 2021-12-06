#pragma once
#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#else
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#endif

class Socket {
    using socket_type =
#ifdef WIN32
        SOCKET;
#else
    std::int32_t;
#endif

    socket_type m_socket{};
    std::int32_t m_addressFamily{}, m_type{}, m_protocol{};
    std::uint32_t m_port{};

public:
    Socket() = default;

    /* if port is zero it will be bruteforced */
    Socket(std::int32_t address_family, std::int32_t type, std::int32_t protocol, std::uint32_t port = 0)
    : m_addressFamily(address_family), m_type(type), m_protocol(protocol), m_port(port) {

        if (port) {
            this->m_socket = ::socket(address_family, type, protocol);
        } else {
            for (std::int32_t index = 31337; index < 31337 + 256; index++) {
                this->m_socket = ::socket(address_family, type, protocol);

                sockaddr_in address{};
                address.sin_family = AF_INET;
                address.sin_addr.s_addr = ::inet_addr("127.0.0.1");
                address.sin_port = htons(index);

                if (this->Bind(address)) {
                    this->m_port = index;
                    this->Close();
                    break;
                }
            }
        }

        if ( !this->m_port )
            throw std::runtime_error("failed to locate port");
    }

    [[nodiscard]] std::uint32_t GetPort() const {
        return this->m_port;
    }

    [[nodiscard]] socket_type GetSocket() const {
        return this->m_socket;
    }

    bool Bind(sockaddr_in& address) const {
        return ::bind(this->m_socket, (const sockaddr*)&address, sizeof(address)) >= 0;
    }

    bool Connect(sockaddr_in& address) const {
        return ::connect(this->m_socket, (const sockaddr*)&address, sizeof(address)) >= 0;
    }

    intptr_t Recv(char* data, std::int32_t size, std::int32_t flags = 0) const {
        return ::recv(this->m_socket, data, size, flags);
    }

    intptr_t Send(char* data, std::int32_t size, std::int32_t flags = 0) const {
        return ::send(this->m_socket, data, size, flags);
    }

    bool Close() const {
        return
            #ifdef WIN32
            ::closesocket(this->m_socket)
            #else
            ::close(this->m_socket)
            #endif
            >= 0;
    }

    bool Kill() const {
        return
            #ifdef WIN32
            ::shutdown(this->m_socket, 2) >= 0
            #else
            ::shutdown(this->m_socket, SHUT_RDWR) >= 0
            #endif
            && this->Close();
    }
};