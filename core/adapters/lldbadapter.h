#include "../debugadapter.h"
#include "../debugadaptertype.h"
#ifdef __APPLE__
#include "LLDB.h"
#else
#include "lldb/API/LLDB.h"
#endif

namespace BinaryNinjaDebugger {
	class LldbAdapter: public DebugAdapter
	{
	private:
		lldb::SBDebugger m_debugger;
		lldb::SBTarget m_target;
		lldb::SBProcess m_process;

	public:

		LldbAdapter(BinaryView* data);

		bool Execute(const std::string &path, const LaunchConfigurations &configs) override;

		bool
		ExecuteWithArgs(const std::string &path, const std::string &args, const LaunchConfigurations &configs) override;

		bool Attach(std::uint32_t pid) override;

		bool Connect(const std::string &server, std::uint32_t port) override;

		void Detach() override;

		void Quit() override;

		std::vector<DebugThread> GetThreadList() override;

		DebugThread GetActiveThread() const override;

		uint32_t GetActiveThreadId() const override;

		bool SetActiveThread(const DebugThread &thread) override;

		bool SetActiveThreadId(std::uint32_t tid) override;

		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;

		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type) override;

		bool RemoveBreakpoint(const DebugBreakpoint &breakpoint) override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;

		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;

		DebugRegister ReadRegister(const std::string &reg) override;

		bool WriteRegister(const std::string &reg, std::uintptr_t value) override;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;

		bool WriteMemory(std::uintptr_t address, const DataBuffer &buffer) override;

		std::vector<DebugModule> GetModuleList() override;

		std::string GetTargetArchitecture() override;

		DebugStopReason StopReason() override;

		uint64_t ExitCode() override;

		bool BreakInto() override;

		DebugStopReason Go() override;

		DebugStopReason StepInto() override;

		DebugStopReason StepOver() override;

		DebugStopReason StepReturn() override;

		std::string InvokeBackendCommand(const std::string &command) override;

		uintptr_t GetInstructionOffset() override;

		uint64_t GetStackPointer() override;

		bool SupportFeature(DebugAdapterCapacity feature) override;

		void EventListener();

		void WriteStdin(const std::string& msg) override;
	};

	class LldbAdapterType: public DebugAdapterType
	{
	public:
		LldbAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	void InitLldbAdapterType();
}
