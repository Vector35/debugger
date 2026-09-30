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
#include <mach/mach.h>
#include <mach/exception_types.h>
#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>

namespace BinaryNinjaDebugger {
	class MacOSNativeAdapter : public DebugAdapter
	{
		struct Breakpoint
		{
			uint32_t original;
			unsigned long id;
			bool installed;
		};
		struct HardwareBreakpoint
		{
			uint64_t address;
			DebugBreakpointType type;
			size_t size;
			unsigned slot;
		};
		struct Exception
		{
			std::array<uint8_t, 4096> reply {};
			thread_t thread = MACH_PORT_NULL;
			task_t task = MACH_PORT_NULL;
			int signal = 0;
		};
		mutable std::recursive_mutex m_mutex;
		std::thread m_worker;
		std::atomic<bool> m_shutdown {false};
		pid_t m_pid = 0;
		task_t m_task = MACH_PORT_NULL;
		mach_port_t m_exceptionPort = MACH_PORT_NULL;
		bool m_traced = false;
		bool m_child = false;
		bool m_inspectionOnly = false;
		bool m_running = false;
		bool m_suspended = false;
		bool m_initial = false;
		bool m_initialRunToEntry = false;
		bool m_detaching = false;
		std::condition_variable_any m_stateChanged;
		DebugStopReason m_reason = UnknownReason;
		uint64_t m_exitCode = 0;
		std::map<uint32_t, thread_t> m_threads;
		std::map<uint32_t, unsigned> m_userSuspends;
		uint32_t m_activeThread = 0;
		std::map<uint64_t, Breakpoint> m_breakpoints;
		std::vector<ModuleNameAndOffset> m_pendingBreakpoints;
		std::vector<PendingHardwareBreakpoint> m_pendingHardware;
		std::vector<HardwareBreakpoint> m_hardware;
		unsigned long m_nextBreakpointId = 1;
		std::vector<Exception> m_exceptions;
		std::vector<DebuggerEvent> m_events;
		Exception* m_receiving = nullptr;
		exception_type_t m_exceptionType = 0;
		std::vector<mach_exception_data_type_t> m_exceptionCodes;
		std::vector<thread_t> m_stepSuspends;
		thread_t m_stepThread = MACH_PORT_NULL;
		std::vector<HardwareBreakpoint> m_stepHardware;
		bool m_watchpointStop = false;
		uint64_t m_reinsertAddress = 0;
		bool m_continueAfterStep = false;
		uint64_t m_temporaryBreakpoint = 0;
		bool m_temporaryOwned = false;
		std::string m_executable;
		int m_stdin = -1;
		int m_stdout = -1;
		int m_stderr = -1;
		std::string m_stdinQueue;
		static constexpr exception_mask_t ExceptionMask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION
			| EXC_MASK_ARITHMETIC | EXC_MASK_BREAKPOINT | EXC_MASK_SOFTWARE;
		exception_mask_t m_savedMasks[EXC_TYPES_COUNT] {};
		mach_port_t m_savedPorts[EXC_TYPES_COUNT] {};
		exception_behavior_t m_savedBehaviors[EXC_TYPES_COUNT] {};
		thread_state_flavor_t m_savedFlavors[EXC_TYPES_COUNT] {};
		mach_msg_type_number_t m_savedCount = 0;

		bool Start(pid_t pid, bool child);
		void Worker();
		void Cleanup();
		void RestoreExceptionPorts();
		void RefreshThreads();
		thread_t ActiveThread() const;
		bool Resume(bool step, bool notify = true);
		bool ReplyExceptions(bool preserveStop = false);
		void EndSingleStep();
		DataBuffer ReadRaw(uint64_t address, size_t size);
		bool WriteRaw(uint64_t address, const void* data, size_t size);
		uint64_t Resolve(const ModuleNameAndOffset& location);
		void ApplyPendingBreakpoints();
		bool TemporaryBreakpoint(uint64_t address);
		void Error(const std::string& message, bool launch = false);
		void StopEvent(DebugStopReason reason);
		std::string ReadString(uint64_t address);

	public:
		MacOSNativeAdapter(BinaryView* data);
		~MacOSNativeAdapter() override;
		bool InspectTask(pid_t pid);
		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
		bool Attach(uint32_t pid) override;
		bool Connect(const std::string&, uint32_t) override { return false; }
		bool Detach() override;
		bool Quit() override;
		std::vector<DebugProcess> GetProcessList() override;
		uint32_t GetActivePID() override;
		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(uint32_t tid) override;
		bool SuspendThread(uint32_t tid) override;
		bool ResumeThread(uint32_t tid) override;
		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;
		DebugBreakpoint AddBreakpoint(uintptr_t address, unsigned long type = 0) override;
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& location, unsigned long type = 0) override;
		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;
		bool RemoveBreakpoint(const ModuleNameAndOffset& location) override;
		std::vector<DebugBreakpoint> GetBreakpointList() const override;
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool AddHardwareBreakpoint(
			const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(
			const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& name) override;
		bool WriteRegister(const std::string& name, intx::uint512 value) override;
		DataBuffer ReadMemory(uintptr_t address, size_t size) override;
		bool WriteMemory(uintptr_t address, const DataBuffer& data) override;
		std::vector<DebugModule> GetModuleList() override;
		std::vector<DebugSymbol> GetSymbolsForModule(const DebugModule& module) override;
		std::vector<DebugMemoryRegion> GetMemoryMap() override;
		std::string GetTargetArchitecture() override { return "aarch64"; }
		DebugStopReason StopReason() override;
		uint64_t ExitCode() override;
		bool BreakInto() override;
		bool Go() override;
		bool StepInto() override;
		bool StepOver() override;
		bool StepReturn() override;
		std::string InvokeBackendCommand(const std::string&) override;
		uint64_t GetInstructionOffset() override;
		uint64_t GetStackPointer() override;
		bool SupportFeature(DebugAdapterCapacity feature) override;
		void WriteStdin(const std::string& message) override;
		Ref<Settings> GetAdapterSettings() override;
		Ref<Metadata> GetProperty(const std::string& name) override;
		bool SetProperty(const std::string& name, const Ref<Metadata>& value) override;
		kern_return_t ReceiveException(thread_t thread, task_t task, exception_type_t type, mach_exception_data_t code,
			mach_msg_type_number_t count);
	};

	class MacOSNativeAdapterType : public DebugAdapterType
	{
	public:
		MacOSNativeAdapterType() : DebugAdapterType("macOS Native") {}
		DebugAdapter* Create(BinaryView* data) override;
		bool IsValidForData(BinaryView* data) override;
		bool CanExecute(BinaryView* data) override { return IsValidForData(data); }
		bool CanConnect(BinaryView*) override { return false; }
		static Ref<Settings> GetAdapterSettings();
	};
	void InitMacOSNativeAdapterType();
}  // namespace BinaryNinjaDebugger
