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

#include "../debugadapter.h"
#include "../debugadaptertype.h"
#include "binaryninjaapi.h"
#include "emulatorapi.h"  // BinaryNinja::LLILEmulator, from the bnil-emulator plugin
#include <mutex>
#include <condition_variable>

namespace BinaryNinjaDebugger {

	class EmulatorAdapter : public DebugAdapter
	{
		BinaryNinja::Ref<BinaryNinja::LLILEmulator> m_emulator;
		BinaryNinja::Ref<BinaryNinja::BinaryView> m_view;
		BinaryNinja::Ref<BinaryNinja::Architecture> m_arch;
		bool m_running = false;
		uint64_t m_exitCode = 0;

		// Snapshot of original segments captured before the debugger memory overlay is installed.
		// This is a workaround for a quick PoC of the emulator — we need to figure out the proper
		// way to deal with this later.
		struct SegmentSnapshot
		{
			uint64_t virtualAddr;
			uint64_t dataOffset;
			size_t dataLen;
			size_t segLen;
		};
		std::vector<SegmentSnapshot> m_originalSegments;

		// Breakpoint tracking
		std::vector<DebugBreakpoint> m_breakpoints;
		unsigned long m_nextBreakpointId = 1;

		// Stdin buffer for target console input
		std::mutex m_stdinMutex;
		std::condition_variable m_stdinCV;
		std::string m_stdinBuffer;
		bool m_stdinClosed = false;

		void PostStopEvent(DebugStopReason reason);
		DebugStopReason MapStopReason(BNILEmulatorStopReason reason);
		void HandleStopReason(BNILEmulatorStopReason reason);

		void GenerateDefaultAdapterSettings(BinaryNinja::BinaryView* data);

	public:
		EmulatorAdapter(BinaryNinja::BinaryView* data);
		~EmulatorAdapter() override;

		BinaryNinja::Ref<BinaryNinja::Settings> GetAdapterSettings() override;

		// Lifecycle
		bool Execute(const std::string& path, const LaunchConfigurations& configs = {}) override;
		bool ExecuteWithArgs(const std::string& path, const std::string& args,
			const std::string& workingDir, const LaunchConfigurations& configs = {}) override;
		bool Attach(std::uint32_t pid) override;
		bool Connect(const std::string& server, std::uint32_t port) override;
		bool Detach() override;
		bool Quit() override;

		// Process / Thread
		std::vector<DebugProcess> GetProcessList() override;
		std::uint32_t GetActivePID() override;
		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;
		bool SuspendThread(std::uint32_t tid) override;
		bool ResumeThread(std::uint32_t tid) override;
		std::vector<DebugFrame> GetFramesOfThread(std::uint32_t tid) override;

		// Breakpoints
		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type = 0) override;
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;
		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;
		std::vector<DebugBreakpoint> GetBreakpointList() const override;
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;

		// Registers
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& reg) override;
		bool WriteRegister(const std::string& reg, intx::uint512 value) override;

		// Memory
		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;

		// Modules
		std::vector<DebugModule> GetModuleList() override;

		// Architecture
		std::string GetTargetArchitecture() override;

		// Execution control
		DebugStopReason StopReason() override;
		uint64_t ExitCode() override;
		bool BreakInto() override;
		bool Go() override;
		bool StepInto() override;
		bool StepOver() override;

		// State
		uint64_t GetInstructionOffset() override;
		uint64_t GetStackPointer() override;
		std::string InvokeBackendCommand(const std::string& command) override;
		bool SupportFeature(DebugAdapterCapacity feature) override;
		void WriteStdin(const std::string& msg) override;
		bool DumpTargetState(const std::string& filePath) override;
	};


	class EmulatorAdapterType : public DebugAdapterType
	{
		static BinaryNinja::Ref<BinaryNinja::Settings> RegisterAdapterSettings();

	public:
		EmulatorAdapterType();
		DebugAdapter* Create(BinaryNinja::BinaryView* data) override;
		bool IsValidForData(BinaryNinja::BinaryView* data) override;
		bool CanExecute(BinaryNinja::BinaryView* data) override;
		bool CanConnect(BinaryNinja::BinaryView* data) override;

		static BinaryNinja::Ref<BinaryNinja::Settings> GetAdapterSettings();
	};

	void InitEmulatorAdapterType();

}  // namespace BinaryNinjaDebugger
