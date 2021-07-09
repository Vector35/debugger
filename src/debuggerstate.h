#pragma once

#include "binaryninjaapi.h"
#include "uitypes.h"
#include "processview.h"
#include "debugadaptertype.h"
#include "adapters/dummyadapter.h"


class DebuggerUI;
class DebuggerState;

enum DebugAdapterConnectionStatus
{
    DebugAdapterNotConnectedStatus,
    DebugAdapterConnectingStatus,
    DebugAdapterConnectedStatus,
};


enum DebugAdapterTargetStatus
{
    DeubgAdapterUnknownStatus,
    DebugAdapterRunningStatus,
    DebugAdapterPausedStatus,
};


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
    bool m_dirty;

public:
    DebuggerRegisters(DebuggerState* state);
    // DebugRegister operator[](std::string name);
    uint64_t GetRegisterValue(const std::string& name);
    void UpdateRegisterValue(const std::string& name, uint64_t value);
    void MarkDirty();
    bool IsDirty() const { return m_dirty; }
    void Update();
};


class DebuggerModules
{
private:
    DebuggerState* m_state;
    std::vector<DebugModule> m_modules;
    bool m_dirty;

public:
    DebuggerModules(DebuggerState* state);
    void MarkDirty();
    void Update();
    bool IsDirty() const { return m_dirty; }

    bool GetModuleBase(const std::string& name, uint64_t& address);
    DebugModule ResolvePath(std::string fpathExe);
    

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
    bool m_dirty;

public:
    DebuggerThreads(DebuggerState* state);
    void MarkDirty();
    void Update();
    DebugThread GetActiveThread() const;
    bool SetActiveThread(const DebugThread& thread);
    bool IsDirty() const { return m_dirty; }
    size_t GetSize() const { return m_threads.size(); }
    // Note, the caller of this function is responsible for ensuring the cache is valid
    std::vector<DebuggerThreadCache> GetThreads() const { return m_threads; }
};


class DebuggerState
{
private:
    BinaryViewRef m_data;
    DebugAdapterConnectionStatus m_connectionStatus;
    DebugAdapterTargetStatus m_targetStatus;

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
    void DeleteState(BinaryViewRef data);

public:
    DebuggerState(BinaryViewRef data);
    void Run();
    void Restart();
    void Quit();
    void Exec();
    void Attach();
    void Detach();
    void Pause();
    void Go();
    void StepIntoAsm();
    void StepIntoIL();
    void StepOverAsm();
    void StepOverIL();
    void StepReturn();

    bool CanExec();
    bool CanConnect();

    static DebuggerState* GetState(BinaryViewRef data);
    DebugAdapter* GetAdapter() const { return m_adapter; }
    BinaryViewRef GetData() const { return m_data; }

    DebuggerModules* GetModulesCache() const { return m_modules; }
    DebugProcessView* GetMemoryView() const { return m_memoryView; }
    DebuggerUI* GetDebuggerUI() const { return m_ui; }

    DebugAdapterType::AdapterType GetAdapterType() const { return m_adapterType; }
    std::string GetExecutablePath() const { return m_executablePath; }
    std::vector<std::string> GetCommandLineArguments() const { return m_commandLineArgs; }
    std::string GetRemoteHost() const { return m_remoteHost; }
    uint32_t GetRemotePort() const { return m_remotePort; }

    void SetAdapterType(DebugAdapterType::AdapterType adapter) { m_adapterType = adapter; }
    void SetExecutablePath(const std::string& path) { m_executablePath = path; }
    void SetCommandLineArguments(const std::vector<std::string> arguments) { m_commandLineArgs = arguments; }
    void SetRemoteHost(const std::string& host) { m_remoteHost = host; }
    void SetRemotePort(uint32_t port) { m_remotePort = port; }

    uint64_t IP();
    uint64_t LocalIP();

    bool IsConnected() const { return m_connectionStatus == DebugAdapterConnectedStatus; }
    bool IsConnecting() const { return m_connectionStatus == DebugAdapterConnectingStatus; }
    bool IsRunning() const { return m_targetStatus == DebugAdapterRunningStatus; }

    // This is slightly different from the Python implementation. The caller does not need to first
    // retrieve the DebuggerThreads object and then call SetActiveThread() on it. They call this function.
    bool SetActiveThread(const DebugThread& thread);

    void OnStep();
    void MarkDirty();
    void UpdateCaches();

    ArchitectureRef DetectRemoteArch();
};
