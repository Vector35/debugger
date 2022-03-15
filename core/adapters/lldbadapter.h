#include "../debugadapter.h"
#include "../debugadaptertype.h"

namespace BinaryNinjaDebugger {
	class LldbAdapter: public DebugAdapter
	{
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

		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type) override;

		std::vector<DebugBreakpoint> AddBreakpoints(const std::vector<std::uintptr_t> &breakpoints) override;

		bool RemoveBreakpoint(const DebugBreakpoint &breakpoint) override;

		bool RemoveBreakpoints(const std::vector<DebugBreakpoint> &breakpoints) override;

		bool ClearAllBreakpoints() override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;

		std::string GetRegisterNameByIndex(std::uint32_t index) const override;

		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;

		DebugRegister ReadRegister(const std::string &reg) override;

		bool WriteRegister(const std::string &reg, std::uintptr_t value) override;

		bool WriteRegister(const DebugRegister &reg, std::uintptr_t value) override;

		std::vector<std::string> GetRegisterList() const override;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;

		bool WriteMemory(std::uintptr_t address, const DataBuffer &buffer) override;

		std::vector<DebugModule> GetModuleList() override;

		std::string GetTargetArchitecture() override;

		DebugStopReason StopReason() override;

		unsigned long ExecStatus() override;

		uint64_t ExitCode() override;

		bool BreakInto() override;

		DebugStopReason Go() override;

		DebugStopReason StepInto() override;

		DebugStopReason StepOver() override;

		void Invoke(const std::string &command) override;

		uintptr_t GetInstructionOffset() override;

		bool SupportFeature(DebugAdapterCapacity feature) override;
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
