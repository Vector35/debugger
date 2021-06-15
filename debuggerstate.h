#pragma once

#include "binaryninjaapi.h"
#include "uitypes.h"


class DebugerRegisters
{
    struct RegisterCache
    {
        std::vector<std::string> registerList;
    }
private:
    DebuggerState* m_state;

};


class DebuggerState
{
private:
    BinaryViewRef m_data;
    bool m_connecting;
    bool m_running;

    std::vector<std::string> m_commandLineArge;
    // DebugerAdapterType m_debugAdapterType;
    std::string m_remoteHost;
    uint32_t m_remotePort;
    bool m_requestTerminalEmulator;


public:
    DebuggerState(BinaryViewRef data);
};
