#pragma once

#include "binaryninjaapi.h"
#include "uitypes.h"
#include "ui/processview.h"
#include "debugadaptertype.h"
#include "adapters/dummyadapter.h"


class DebuggerUI;
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

struct DebuggerThreadCache
{
    DebugThread thread;
    uint64_t ip;
    // TODO: this does not seem to me the correct way to mark the selected thread. Instead, the
    // DebuggerThreads class should simply have a field called selectedThread
    bool selected;
};


class DebuggerThreads
{
private:
    DebuggerState* m_state;
    std::vector<DebuggerThreadCache> m_threads;
    bool m_cacheValid;

public:
    DebuggerThreads(DebuggerState* state);
    void MarkDirty();
    void Update();
    DebugThread GetActiveThread() const;
    bool SetActiveThread(const DebugThread& thread);
    bool IsValid() const { return m_cacheValid; }
    size_t size() const { return m_threads.size(); }
    // Note, the caller of this function is responsible for ensuring the cache is valid
    std::vector<DebuggerThreadCache> GetThreads() const { return m_threads; }
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
    DebuggerThreads* m_threads;

    DebuggerUI* m_ui;

    std::string m_executablePath;
    std::vector<std::string> m_commandLineArgs;
    std::string m_remoteHost;
    uint32_t m_remotePort;
    bool m_requestTerminalEmulator;
    ArchitectureRef m_remoteArch;

    // std::string m_pcRegister;

    DebugAdapterType::AdapterType m_adapterType;

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
    DebugAdapter* getAdapter() const { return m_adapter; }
    BinaryViewRef getData() const { return m_data; }

    DebuggerModules* getModulesCache() const { return m_modules; }
    DebugProcessView* getMemoryView() const { return m_memoryView; }

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

    bool IsConnected() const { return m_connected; }
    bool IsConnecting() const { return m_connecting; }
    bool IsRunning() const { return m_running; }

    // This is slightly different from the Python implementation. The caller does not need to first
    // retrieve the DebuggerThreads object and then call SetActiveThread() on it. They call this function.
    bool SetActiveThread(const DebugThread& thread);

    void OnStep();
};
