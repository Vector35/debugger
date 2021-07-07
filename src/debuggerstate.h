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

    std::string m_executablePath;
    std::vector<std::string> m_commandLineArgs;
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
    void exec();
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

    DebugAdapterType::AdapterType getAdapterType() const { return m_adapterType; }
    std::string getExecutablePath() const { return m_executablePath; }
    std::vector<std::string> getCommandLineArguments() const { return m_commandLineArgs; }
    std::string getRemoteHost() const { return m_remoteHost; }
    uint32_t getRemotePort() const { return m_remotePort; }

    void SetAdapterType(DebugAdapterType::AdapterType adapter) { m_adapterType = adapter; }
    void SetExecutablePath(const std::string& path) { m_executablePath = path; }
    void SetCommandLineArguments(const std::vector<std::string> arguments) { m_commandLineArgs = arguments; }
    void SetRemoteHost(const std::string& host) { m_remoteHost = host; }
    void SetRemotePort(uint32_t port) { m_remotePort = port; }

    uint64_t ip();
    uint64_t localIp();
};
