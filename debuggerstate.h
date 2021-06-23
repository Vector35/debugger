#pragma once

#include "binaryninjaapi.h"
#include "uitypes.h"
#include "processview.h"
#include "adapters/dummyadapter.h"

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


class DebugModulesCache
{
private:
    DebuggerState* m_state;
    std::vector<DebugModule> m_modules;

public:
    DebugModulesCache(DebuggerState* state, std::vector<DebugModule> modules);
    void markDirty();
    void update();

    bool GetModuleBase(const std::string& name, uint64_t& address);
    DebugModule resolvePath(std::string fpathExe);
    

};


class DebuggerState
{
private:
    BinaryViewRef m_data;
    bool m_connecting;
    bool m_running;
    DebugAdapter* m_adapter;
    // TODO: This really should be called m_processView, but for ease of porting I am keeping it
    DebugProcessView* m_memoryView;
    DebugModulesCache* m_modulesCache;

    std::vector<std::string> m_commandLineArge;
    // DebugerAdapterType m_debugAdapterType;
    std::string m_remoteHost;
    uint32_t m_remotePort;
    bool m_requestTerminalEmulator;

    BinaryViewRef getData() const { return m_data; }
    inline static std::vector<DebuggerState*> g_debuggerStates;
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

    static DebuggerState* getState(BinaryViewRef data);
    DebugAdapter* getAdapter() { return m_adapter; }

    DebugModulesCache* getModulesCache() { return m_modulesCache; }
    DebugProcessView* getMemoryView() { return m_memoryView; }
};
