#pragma once
#include <optional>
#include "gdbmiconnector.h"
#include "../debugadapter.h"
#include "../debugadaptertype.h"
#include "../../vendor/intx/intx.hpp"

class GdbMiAdapter : public BinaryNinjaDebugger::DebugAdapter
{
private:
    std::unique_ptr<GdbMiConnector> m_mi;
    uint64_t m_lastStopTid = 1;
    uint64_t m_currentTid = 1;
    bool m_connected = false;
    std::string m_remoteArch;
    std::vector<std::string> m_registerNames; // In GDB's order
    BinaryNinjaDebugger::DebugStopReason m_lastStopReason;
    std::atomic<bool> m_targetRunningAtomic{false};
    uint64_t m_exitCode = 0;

    std::mutex m_eventMutex;
    std::mutex m_gdbCommandMutex;
    std::condition_variable m_eventCV;

    // Console output buffering for console commands
    std::mutex m_consoleBufferMutex;
    std::string m_consoleOutputBuffer;
    bool m_captureConsoleOutput = false;
    
    // --- Cached Target State ---
    std::mutex m_cacheMutex; // To protect access to cached data
    std::vector<BinaryNinjaDebugger::DebugThread> m_cachedThreads;
    std::unordered_map<std::string, BinaryNinjaDebugger::DebugRegister> m_cachedRegisters;
    std::map<uint32_t, std::vector<BinaryNinjaDebugger::DebugFrame>> m_cachedFrames; // tid -> frames
    std::optional<std::vector<BinaryNinjaDebugger::DebugModule>> m_moduleCache;

    void UpdateThreadList();
    void UpdateAllRegisters();
    void UpdateStackFrames(uint32_t tid);

    void InvalidateCache(); // Helper to clear the cache when the target runs

    void AsyncRecordHandler(const MiRecord& record);
    void ScheduleStateRefresh();
    BinaryNinjaDebugger::DebugStopReason GetStopReason(const MiRecord& record);
	static intx::uint512 ParseGdbValue(const std::string& valueStr);

	bool RunMonitorCommand(const std::string& command) const;
	void ApplyBreakpoints();
	void ApplyPendingHardwareBreakpoints();
	bool GetModuleBase(const std::string& moduleName, uint64_t& base);
	std::vector<BinaryNinjaDebugger::ModuleNameAndOffset> m_pendingBreakpoints {};
	std::vector<BinaryNinjaDebugger::PendingHardwareBreakpoint> m_pendingHardwareBreakpoints {};

public:
    GdbMiAdapter(BinaryView* data);
    ~GdbMiAdapter() override;

    // --- Overridden Virtual Functions ---
    // All functions that override a virtual function in DebugAdapter should have `override`.

    bool Execute(const std::string& path, const BinaryNinjaDebugger::LaunchConfigurations& configs) override;
    bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir, const BinaryNinjaDebugger::LaunchConfigurations& configs) override;
    bool Attach(uint32_t pid) override;
    bool Connect(const std::string& server, uint32_t port) override;
    bool Detach() override;
    bool Quit() override;
	void Stop();

    std::vector<BinaryNinjaDebugger::DebugProcess> GetProcessList() override;
    std::vector<BinaryNinjaDebugger::DebugThread> GetThreadList() override;
    BinaryNinjaDebugger::DebugThread GetActiveThread() const override;
    uint32_t GetActiveThreadId() const override;
    bool SetActiveThread(const BinaryNinjaDebugger::DebugThread& thread) override;
    bool SetActiveThreadId(uint32_t tid) override;
    bool SuspendThread(uint32_t tid) override;
    bool ResumeThread(uint32_t tid) override;

    std::vector<BinaryNinjaDebugger::DebugFrame> GetFramesOfThread(uint32_t tid) override;
    BinaryNinjaDebugger::DebugBreakpoint AddBreakpoint(std::uintptr_t address, unsigned long breakpoint_type) override;
    BinaryNinjaDebugger::DebugBreakpoint AddBreakpoint(const BinaryNinjaDebugger::ModuleNameAndOffset& address, unsigned long breakpoint_type) override;
    bool RemoveBreakpoint(const BinaryNinjaDebugger::DebugBreakpoint& breakpoint) override;
    std::vector<BinaryNinjaDebugger::DebugBreakpoint> GetBreakpointList() const override;

    std::unordered_map<std::string, BinaryNinjaDebugger::DebugRegister> ReadAllRegisters() override;
    BinaryNinjaDebugger::DebugRegister ReadRegister(const std::string& reg) override;
    bool WriteRegister(const std::string& reg, intx::uint512 value) override;

    BinaryNinja::DataBuffer ReadMemory(std::uintptr_t address, size_t size) override;
    bool WriteMemory(std::uintptr_t address, const BinaryNinja::DataBuffer& buffer) override;
    
    std::vector<BinaryNinjaDebugger::DebugModule> GetModuleList() override;
    std::string GetTargetArchitecture() override;
    BinaryNinjaDebugger::DebugStopReason StopReason() override;
    uint64_t ExitCode() override;

    bool BreakInto() override;
    bool Go() override;
    bool StepInto() override;
    bool StepOver() override;
	bool StepReturn() override;

	std::uint32_t GetActivePID() override { return 0; }

    std::string InvokeBackendCommand(const std::string& command) override;
    uint64_t GetInstructionOffset() override;
    uint64_t GetStackPointer() override;
    bool SupportFeature(BinaryNinjaDebugger::DebugAdapterCapacity feature) override;

	// Hardware breakpoint support - not implemented
	bool AddHardwareBreakpoint(uint64_t address, BinaryNinjaDebugger::DebugBreakpointType type, size_t size = 1) override;
	bool RemoveHardwareBreakpoint(uint64_t address, BinaryNinjaDebugger::DebugBreakpointType type, size_t size = 1) override;
	bool AddHardwareBreakpoint(const BinaryNinjaDebugger::ModuleNameAndOffset& location, BinaryNinjaDebugger::DebugBreakpointType type, size_t size = 1) override;
	bool RemoveHardwareBreakpoint(const BinaryNinjaDebugger::ModuleNameAndOffset& location, BinaryNinjaDebugger::DebugBreakpointType type, size_t size = 1) override;

	void GenerateDefaultAdapterSettings(BinaryView* data);
    Ref<Settings> GetAdapterSettings() override;
};


// --- GdbMiAdapterType Declaration ---
class GdbMiAdapterType : public BinaryNinjaDebugger::DebugAdapterType
    {
    public:
        GdbMiAdapterType();
		BinaryNinjaDebugger::DebugAdapter* Create(BinaryView* data) override;
        bool IsValidForData(BinaryView* data) override { return true; }
        bool CanConnect(BinaryView* data) override { return true; }
        bool CanExecute(BinaryView* data) override { return false; }
        static Ref<Settings> GetAdapterSettings();

    private:
        static Ref<Settings> RegisterAdapterSettings();
    };

namespace BinaryNinjaDebugger {
    void InitGdbMiAdapterType();
}
