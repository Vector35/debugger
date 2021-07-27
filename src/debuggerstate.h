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
private:
    DebuggerState* m_state;
    std::unordered_map<std::string, DebugRegister> m_registerCache;
    bool m_dirty;

public:
    DebuggerRegisters(DebuggerState* state);
    // DebugRegister operator[](std::string name);
    uint64_t GetRegisterValue(const std::string& name);
    bool UpdateRegisterValue(const std::string& name, uint64_t value);
    void MarkDirty();
    bool IsDirty() const { return m_dirty; }
    void Update();
    std::vector<DebugRegister> GetAllRegisters() const;
};


struct ModuleNameAndOffset
{
    // TODO: maybe we should use DebugModule instead of its name
    // Update: We are not using a DebugModule here because the base adress information of it can be outdated;
    // instead, we only keep a name and an offset.
    std::string module;
    uint64_t offset;

    ModuleNameAndOffset(): module(""), offset(0) {}
    ModuleNameAndOffset(std::string mod, uint64_t off): module(mod), offset(off) {}
    bool operator==(const ModuleNameAndOffset& other) const
    {
        return (module == other.module) && (offset == other.offset);
    }
    bool operator<(const ModuleNameAndOffset& other) const
    {
        if (module < other.module)
            return true;
        if (module > other.module)
            return false;
        return offset < other.offset;
    }
    bool operator>(const ModuleNameAndOffset& other) const
    {
        if (module > other.module)
            return true;
        if (module < other.module)
            return false;
        return offset > other.offset;
    }
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

    std::vector<DebugModule> GetAllModules() const { return m_modules; }
    DebugModule ResolvePath(const std::string& fpathExe) const;

    // TODO: These conversion functions are not very robust for lookup failures. They need to be improved for it.
    DebugModule GetModuleByName(const std::string& module) const;
    uint64_t GetModuleBase(const std::string& name) const;
    DebugModule GetModuleForAddress(uint64_t remoteAddress) const;
    ModuleNameAndOffset AbsoluteAddressToRelative(uint64_t absoluteAddress) const;
    uint64_t RelativeAddressToAbsolute(ModuleNameAndOffset relativeAddress) const;
};




class DebuggerBreakpoints
{
private:
    DebuggerState* m_state;
    std::vector<ModuleNameAndOffset> m_breakpoints;

public:
    DebuggerBreakpoints(DebuggerState* state, std::vector<ModuleNameAndOffset> initial = {});
    bool AddAbsolute(uint64_t remoteAddress);
    bool AddOffset(const ModuleNameAndOffset& address);
    bool RemoveAbsolute(uint64_t remoteAddress);
    bool RemoveOffset(const ModuleNameAndOffset& address);
    bool ContainsAbsolute(uint64_t address);
    bool ContainsOffset(const ModuleNameAndOffset& address);
    void Apply();
    void SerializeMetadata();
    void UnserializedMetadata();
    std::vector<ModuleNameAndOffset> GetBreakpointList() const { return m_breakpoints; }
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
    // Note, the caller of this function is responsible for ensuring the cache is valid
    std::vector<DebuggerThreadCache> GetAllThreads() const { return m_threads; }
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
    DebuggerBreakpoints* m_breakpoints;

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
    void StepTo(std::vector<uint64_t> remoteAddresses);

    bool CanExec();
    bool CanConnect();

    static DebuggerState* GetState(BinaryViewRef data);
    DebugAdapter* GetAdapter() const { return m_adapter; }
    BinaryViewRef GetData() const { return m_data; }

    DebuggerModules* GetModules() const { return m_modules; }
    DebugProcessView* GetMemoryView() const { return m_memoryView; }
    DebuggerUI* GetDebuggerUI() const { return m_ui; }
    DebuggerBreakpoints* GetBreakpoints() const { return m_breakpoints; }
    DebuggerRegisters* GetRegisters() const { return m_registers; }
    DebuggerThreads* GetThreads() const { return m_threads; }
    ArchitectureRef GetRemoteArchitecture() const { return m_remoteArch; }

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
    uint64_t StackPointer();

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

    uint64_t GetRemoteBase(BinaryViewRef relativeView = nullptr);
    bool IsCodeASLR(BinaryViewRef relativeView = nullptr);
    uint64_t LocalAddressToRemote(uint64_t localAddr, BinaryViewRef relativeView = nullptr);
    uint64_t RemoteAddressToLocal(uint64_t remoteAddr, BinaryViewRef relativeView = nullptr);
    bool IsLocalAddress(uint64_t remoteAddr, BinaryViewRef relativeView = nullptr);

    std::string ResolveTargetBase();
};
