#pragma once
#include "../debugadapter.h"
#include "../debugadaptertype.h"
#include "rspconnector.h"
#include <map>
#include <queue>
#include "../semaphore.h"
#include "gdbadapter.h"

namespace BinaryNinjaDebugger
{
	class QueuedAdapter : public DebugAdapter
	{
		DebugAdapter* m_adapter;
		mutable std::mutex m_queueMutex;
		mutable std::queue<std::function<void()>> m_queue;

	public:
		QueuedAdapter(DebugAdapter* adapter);
		~QueuedAdapter();

		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string& path, const std::string &args, const LaunchConfigurations& configs) override;
		bool Attach(std::uint32_t pid) override;
		bool Connect(const std::string& server, std::uint32_t port) override;

		void Detach() override;
		void Quit() override;

		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;

		DebugBreakpoint AddBreakpoint(std::uintptr_t address, unsigned long breakpoint_type = 0) override;

		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;

		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& reg) override;
		bool WriteRegister(const std::string& reg, std::uintptr_t value) override;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;

		std::vector<DebugModule> GetModuleList() override;

		std::string GetTargetArchitecture() override;

		DebugStopReason StopReason() override;

		uint64_t ExitCode() override;

		bool GenericGo(const std::string& go_type);
		bool GenericGoAsync(const std::string& go_type);

		bool BreakInto() override;
		DebugStopReason Go() override;
		DebugStopReason StepInto() override;
		DebugStopReason StepOver() override;
		DebugStopReason StepReturn() override;

		std::string InvokeBackendCommand(const std::string& command) override;
		std::uintptr_t GetInstructionOffset() override;
		uint64_t GetStackPointer() override;

		bool SupportFeature(DebugAdapterCapacity feature) override;

		void Worker();

		virtual void SetEventCallback(std::function<void(const DebuggerEvent &)> function) override;

		virtual void WriteStdin(const std::string& msg) override;
	};
};
