/*
Copyright 2020-2023 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "../debugadapter.h"
#include "../debugadaptertype.h"
#ifdef WIN32
	#pragma warning(push)
	#pragma warning(disable : 4251)
	#include "lldb/API/LLDB.h"
	#pragma warning(pop)
#else
	#include "lldb/API/LLDB.h"
#endif

namespace BinaryNinjaDebugger {
	class LldbAdapter : public DebugAdapter
	{
	private:
		lldb::SBDebugger m_debugger;
		lldb::SBTarget m_target;
		lldb::SBProcess m_process;

		bool m_targetActive;
		std::vector<ModuleNameAndOffset> m_pendingBreakpoints {};

		// Since when SBProcess::Kill() and SBProcess::ReadMemory() are called at the same time, LLDB will hang,
		// we must use this mutex to prevent the quit operation and read memory operation to happen at the same time.
		std::mutex m_quitingMutex;

		// To launch an ELF without dynamic loader, we must set `debugger.stopAtSystemEntryPoint`.
		// Otherwise, the process will run freely on its own and not stop.
		bool m_isElFWithoutDynamicLoader = false;
		bool IsELFWithoutDynamicLoader(BinaryView* data);

	public:
		LldbAdapter(BinaryView* data);
		virtual ~LldbAdapter();

		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;

		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;

		bool Attach(std::uint32_t pid) override;

		bool Connect(const std::string& server, std::uint32_t port) override;

		bool Detach() override;

		bool Quit() override;

		std::vector<DebugProcess> GetProcessList() override;

		std::vector<DebugThread> GetThreadList() override;

		DebugThread GetActiveThread() const override;

		uint32_t GetActiveThreadId() const override;

		bool SetActiveThread(const DebugThread& thread) override;

		bool SetActiveThreadId(std::uint32_t tid) override;

		bool SuspendThread(std::uint32_t tid) override;
		bool ResumeThread(std::uint32_t tid) override;

		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;

		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type) override;

		virtual DebugBreakpoint AddBreakpoint(
			const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;

		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;

		virtual bool RemoveBreakpoint(const ModuleNameAndOffset& address) override;

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

		bool BreakInto() override;

		bool Go() override;

		bool StepInto() override;

		bool StepOver() override;

		bool StepReturn() override;

		std::string InvokeBackendCommand(const std::string& command) override;

		uint64_t GetInstructionOffset() override;

		uint64_t GetStackPointer() override;

		bool SupportFeature(DebugAdapterCapacity feature) override;

		void EventListener();

		void WriteStdin(const std::string& msg) override;

		void FixActiveThread();

		Ref<Metadata> GetProperty(const std::string& name) override;

		bool SetProperty(const std::string& name, const Ref<Metadata>& value) override;

		bool ConnectToDebugServer(const std::string& server, std::uint32_t port) override;

		bool DisconnectDebugServer() override;

		std::string m_processPlugin;

		void ApplyBreakpoints();
	};

	class LldbAdapterType : public DebugAdapterType
	{
	public:
		LldbAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	void InitLldbAdapterType();
}  // namespace BinaryNinjaDebugger
