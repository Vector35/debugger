/*
Copyright 2020-2026 Vector 35 Inc.

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

#pragma once
#include <atomic>
#include <memory>
#include "../debugadapter.h"
#include "../debugadaptertype.h"
#include "ptracearch.h"
#include "ptraceengine.h"

namespace BinaryNinjaDebugger {
	class PtraceAdapter : public DebugAdapter
	{
	private:
		std::unique_ptr<PtraceEngine> m_engine;
		std::atomic<bool> m_targetActive;
		std::atomic<uint32_t> m_activeThreadId {0};
		std::atomic<DebugStopReason> m_lastStopReason {UnknownReason};
		std::atomic<uint64_t> m_exitCode {0};
		std::atomic<const PtraceArch*> m_arch {nullptr};
		bool m_firstStop = false;
		bool m_stopAtSystemEntry = false;

		std::vector<ModuleNameAndOffset> m_pendingBreakpoints {};
		std::vector<PendingHardwareBreakpoint> m_pendingHardwareBreakpoints {};

		void HandleEngineEvent(const PtraceEngine::Event& event);
		uint64_t ReadArchRegister(const std::string& name);

		// Helper to resolve module+offset to absolute address
		// Returns true if the module was found in the loaded module list and address was resolved
		// Returns false if the module was not found (caller should fall back to module+offset handling)
		bool ResolveModuleAddress(const ModuleNameAndOffset& location, uint64_t& address);

	public:
		PtraceAdapter(BinaryView* data);
		virtual ~PtraceAdapter();

		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;

		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;

		bool Attach(std::uint32_t pid) override;

		bool Connect(const std::string& server, std::uint32_t port) override;

		bool Detach() override;

		bool Quit() override;

		std::vector<DebugProcess> GetProcessList() override;

		std::uint32_t GetActivePID() override;

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

		// Hardware breakpoint and watchpoint support
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;

		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;

		DebugRegister ReadRegister(const std::string& reg) override;

		bool WriteRegister(const std::string& reg, intx::uint512 value) override;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;

		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;

		std::vector<DebugModule> GetModuleList() override;

		std::vector<DebugMemoryRegion> GetMemoryMap() override;

		std::vector<DebugSymbol> GetSymbolsForModule(const DebugModule& module) override;

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

		void ApplyBreakpoints();

		void GenerateDefaultAdapterSettings(BinaryView* data);
		Ref<Settings> GetAdapterSettings() override;
	};

	class PtraceAdapterType : public DebugAdapterType
	{
		static Ref<Settings> RegisterAdapterSettings();

	public:
		PtraceAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
		static Ref<Settings> GetAdapterSettings();
	};


	void InitPtraceAdapterType();

}  // namespace BinaryNinjaDebugger
