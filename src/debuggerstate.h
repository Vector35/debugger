#pragma once

#include "binaryninjaapi.h"
#include "uitypes.h"
#include "ui/processview.h"
#include "debugadaptertype.h"
#include "adapters/dummyadapter.h"

class DebuggerState;


class DebuggerRegisters
{
    struct RegisterCache
    {
        std::vector<std::string> registerList;
    };
private:
    DebuggerState* m_state;
    std::vector<std::string> m_cachedRgisterList;
    std::map<std::string, DebugRegister> m_registerCache;

public:
    DebuggerRegisters(DebuggerState* state);
    // DebugRegister operator[](std::string name);
    uint64_t getRegisterValue(const std::string& name);
    void updateRegisterValue(const std::string& name, uint64_t value);
    void markDirty();
    void update();
};


class DebuggerModules
{
private:
    DebuggerState* m_state;
    std::vector<DebugModule> m_modules;

public:
    DebuggerModules(DebuggerState* state, std::vector<DebugModule> modules);
    void markDirty();
    void update();

    bool GetModuleBase(const std::string& name, uint64_t& address);
    DebugModule resolvePath(std::string fpathExe);
    

};


class DebuggerState
{
private:
    BinaryViewRef m_data;
    bool m_connecting, m_connected;
    bool m_running;
    DebugAdapter* m_adapter;
    // TODO: This really should be called m_processView, but for ease of porting I am keeping it
    DebugProcessView* m_memoryView;
    DebuggerModules* m_modules;
    DebuggerRegisters* m_registers;

    std::vector<std::string> m_commandLineArgs;
    // DebugerAdapterType m_debugAdapterType;
    std::string m_remoteHost;
    uint32_t m_remotePort;
    bool m_requestTerminalEmulator;
    ArchitectureRef m_remoteArch;

    // std::string m_pcRegister;

    DebugAdapterType::AdapterType m_adapterType;

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

    DebuggerModules* getModulesCache() { return m_modules; }
    DebugProcessView* getMemoryView() { return m_memoryView; }

    uint64_t ip();
    uint64_t localIp();
};
