#pragma once

#include <winsock2.h>

class SocketHandle{
    SOCKET m_socket = INVALID_SOCKET;

    public:
    SocketHandle() = default;
    explicit SocketHandle(SOCKET s) : m_socket(s){}
    ~SocketHandle() {reset();}

    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle(SocketHandle&& other) noexcept : m_socket(other.m_socket){
        other.m_socket = INVALID_SOCKET;
    }
    SocketHandle& operator=(SocketHandle&& other) noexcept{
        if(this != &other){
            reset();
            m_socket = other.m_socket;
            other.m_socket = INVALID_SOCKET;
        }
        return *this;
    }

    SOCKET get() const { return m_socket; }

    void reset(SOCKET s = INVALID_SOCKET){
        if(m_socket != INVALID_SOCKET){
            closesocket(m_socket);
        }
        m_socket = s;
    }
};