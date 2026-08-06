#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdexcept>
#include <string>

class WinsockLibrary{
    public:
    WinsockLibrary(){
        WSADATA wsaData;
        int result =WSAStartup(MAKEWORD(2, 2), &wsaData);
        if(result != 0){
            throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
        }
    }

    ~WinsockLibrary(){
        WSACleanup();
    }

    WinsockLibrary(const WinsockLibrary&) = delete;
    WinsockLibrary& operator=(const WinsockLibrary&) = delete;
    WinsockLibrary(WinsockLibrary&&) = delete;
    WinsockLibrary& operator=(WinsockLibrary&&) = delete;
};