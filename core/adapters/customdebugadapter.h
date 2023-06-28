#include "../debugadapter.h"

namespace BinaryNinjaDebugger
{
	class CustomDebugAdapter : public DebugAdapter
	{
		BNDebuggerCustomDebugAdapter m_adapter;

	public:
		CustomDebugAdapter(BinaryView* data);
		virtual ~CustomDebugAdapter();

		virtual bool Init() override;

		virtual bool ExecuteWithArgs(const std::string &path, const std::string &args,
									 const std::string &workingDir, const LaunchConfigurations &configs = {}) override;

		[[nodiscard]] virtual bool Attach(uint32_t pid) override;

		[[nodiscard]] virtual bool Connect(const std::string& server, uint32_t port) override;

		virtual bool ConnectToDebugServer(const std::string& server, uint32_t port) override;

		virtual bool DisconnectDebugServer() override;

		virtual bool Detach() override;

		virtual bool Quit() override;

		virtual std::vector<DebugProcess> GetProcessList() override;

		virtual std::vector<DebugThread> GetThreadList() override;

		virtual DebugThread GetActiveThread() const override;

		virtual uint32_t GetActiveThreadId() const override;

		virtual bool SetActiveThread(const DebugThread& thread) override;

		virtual bool SetActiveThreadId(uint32_t tid) override;

		virtual bool SuspendThread(uint32_t tid) override;

		virtual bool ResumeThread(uint32_t tid) override;

		virtual std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;

		virtual DebugBreakpoint AddBreakpoint(const uint64_t address, unsigned long breakpoint_type = 0) override;

		virtual DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;

		virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;

		virtual bool RemoveBreakpoint(const ModuleNameAndOffset& address) override;

		virtual std::vector<DebugBreakpoint> GetBreakpointList() const override;

		virtual std::map<std::string, DebugRegister> ReadAllRegisters() override;

		virtual DebugRegister ReadRegister(const std::string& reg) override;

		virtual bool WriteRegister(const std::string& reg, uint64_t value) override;

		virtual DataBuffer ReadMemory(uint64_t address, size_t size) override;

		virtual bool WriteMemory(uint64_t address, const DataBuffer& buffer) override;

		virtual std::vector<DebugModule> GetModuleList() override;

		virtual std::string GetTargetArchitecture() override;

		virtual DebugStopReason StopReason() override;

		virtual uint64_t ExitCode() override;

		virtual bool BreakInto() override;

		virtual bool Go() override;

		virtual bool StepInto() override;

		virtual bool StepOver() override;

		virtual bool StepReturn() override;

		virtual std::string InvokeBackendCommand(const std::string& command) override;

		virtual uint64_t GetInstructionOffset() override;

		virtual uint64_t GetStackPointer() override;

		virtual bool SupportFeature(DebugAdapterCapacity feature) override;

		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
		void PostDebuggerEvent(const DebuggerEvent& event);

		virtual void WriteStdin(const std::string& msg) override;

		virtual BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name) override;

		virtual bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value) override;

//		virtual void AddRef() override;
//		virtual void Release() override;
	};
};
