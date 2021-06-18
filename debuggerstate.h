#pragma once

#include "binaryninjaapi.h"
#include "uitypes.h"

class DebuggerState;


class DebugerRegisters
{
    struct RegisterCache
    {
        std::vector<std::string> registerList;
    };
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

    BinaryViewRef getData() const { return m_data; }
    inline static std::vector<DebuggerState*> g_debuggerStates;
    static DebuggerState* getState(BinaryViewRef data);
    void deleteState(BinaryViewRef data);


public:
    DebuggerState(BinaryViewRef data);
    void run();
    void restart();
    void quit();
    void attach();
    void detach();
    void pause();
    void resume();
    void stepIntoAsm();
    void stepIntoIL();
    void stepOverAsm();
    void stepOverIL();
    void stepReturn();

    bool canExec();
    bool canConnect();
};
