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

#define NOMINMAX
#include <windows.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace BinaryNinjaDebugger {

	// Internal breakpoint tracking structure
	struct InternalBreakpoint
	{
		uint64_t address;
		uint8_t originalByte;
		bool isActive;
		unsigned long id;

		InternalBreakpoint() : address(0), originalByte(0), isActive(false), id(0) {}
		InternalBreakpoint(uint64_t addr, uint8_t orig, bool active, unsigned long bpId)
			: address(addr), originalByte(orig), isActive(active), id(bpId) {}
	};

	// Internal hardware breakpoint tracking
	struct InternalHardwareBreakpoint
	{
		uint64_t address;
		DebugBreakpointType type;
		size_t size;
		int drIndex;  // Which debug register (0-3)
		bool isActive;

		InternalHardwareBreakpoint() : address(0), type(HardwareExecuteBreakpoint), size(1), drIndex(-1), isActive(false) {}
		InternalHardwareBreakpoint(uint64_t addr, DebugBreakpointType t, size_t s, int idx)
			: address(addr), type(t), size(s), drIndex(idx), isActive(false) {}
	};

	class WindowsNativeAdapter : public DebugAdapter
	{
	private:
		// Process and thread handles
		HANDLE m_processHandle = nullptr;
		HANDLE m_threadHandle = nullptr;
		DWORD m_processId = 0;
		DWORD m_threadId = 0;

		// Debug event handling
		DEBUG_EVENT m_lastDebugEvent {};
		bool m_hasLastDebugEvent = false;

		// State tracking
		std::atomic<bool> m_activelyDebugging {false};
		std::atomic<bool> m_targetRunning {false};
		std::atomic<bool> m_shouldStop {false};
		DebugStopReason m_stopReason = UnknownReason;
		unsigned long m_exitCode = 0;

		// Thread management
		std::thread m_debugThread;
		std::mutex m_debugMutex;
		std::condition_variable m_debugCondition;

		// Thread tracking
		std::map<DWORD, HANDLE> m_threads;
		DWORD m_activeThreadId = 0;

		// Module tracking
		std::vector<DebugModule> m_modules;
		std::mutex m_modulesMutex;

		// Breakpoint tracking
		std::vector<InternalBreakpoint> m_breakpoints;
		std::vector<ModuleNameAndOffset> m_pendingBreakpoints;
		unsigned long m_nextBreakpointId = 1;
		std::mutex m_breakpointsMutex;

		// Hardware breakpoints
		std::vector<InternalHardwareBreakpoint> m_hardwareBreakpoints;
		std::vector<PendingHardwareBreakpoint> m_pendingHardwareBreakpoints;
		std::mutex m_hwBreakpointsMutex;

		// Single step tracking
		bool m_singleStepping = false;
		uint64_t m_stepOverBreakpointAddress = 0;
		bool m_hasStepOverBreakpoint = false;
		bool m_stepOverBreakpointContinue = false;  // If true, continue after re-applying breakpoint

		// Hardware breakpoint step-over tracking
		int m_stepOverHwBreakpointIndex = -1;  // DR index of hardware breakpoint being stepped over
		bool m_hasStepOverHwBreakpoint = false;
		bool m_stepOverHwBreakpointContinue = false;

		// Temporary breakpoint for step over/return (removed after hit)
		uint64_t m_tempBreakpointAddress = 0;
		uint8_t m_tempBreakpointOriginalByte = 0;
		bool m_hasTempBreakpoint = false;

		// Architecture info
		bool m_is64Bit = false;
		bool m_isTargetWow64 = false;  // True if debugging a 32-bit process on 64-bit Windows

		// Settings
		bool m_verboseLogging = false;  // Enable verbose debug logging

		// Initial breakpoint tracking
		bool m_initialBreakpointSeen = false;
		bool m_wow64InitialBreakpointSeen = false;  // WOW64 processes have a second system breakpoint

		// Launch/attach parameters (for passing to debug thread)
		std::string m_launchExecutable;
		std::string m_launchWorkingDir;
		std::string m_launchCommandLine;
		DWORD m_attachPID = 0;
		bool m_isAttaching = false;
		std::atomic<bool> m_launchResult {false};
		std::string m_launchError;
		std::condition_variable m_launchCondition;
		std::mutex m_launchMutex;

		// Internal methods
		void DebugLoop();
		bool StartDebugging();  // Called from debug thread to create/attach process
		void Reset();  // Reset state for a new debug session
		bool HandleDebugEvent(const DEBUG_EVENT& event);
		bool HandleException(const EXCEPTION_DEBUG_INFO& info);
		bool HandleCreateProcess(const CREATE_PROCESS_DEBUG_INFO& info);
		bool HandleExitProcess(const EXIT_PROCESS_DEBUG_INFO& info);
		bool HandleCreateThread(const CREATE_THREAD_DEBUG_INFO& info, DWORD threadId);
		bool HandleExitThread(const EXIT_THREAD_DEBUG_INFO& info, DWORD threadId);
		bool HandleLoadDll(const LOAD_DLL_DEBUG_INFO& info);
		bool HandleUnloadDll(const UNLOAD_DLL_DEBUG_INFO& info);
		bool HandleOutputDebugString(const OUTPUT_DEBUG_STRING_INFO& info);

		std::string GetModuleNameFromHandle(HANDLE fileHandle, LPVOID baseAddress);
		bool ApplyBreakpoint(uint64_t address, unsigned long id);
		bool RemoveBreakpointInternal(uint64_t address);
		void ApplyPendingBreakpoints();
		void RemoveAllBreakpoints();
		bool ApplyHardwareBreakpointsToThread(HANDLE threadHandle);
		int FindFreeDebugRegister();
		bool SetHardwareBreakpointInContext(CONTEXT& ctx, int drIndex, uint64_t address, DebugBreakpointType type, size_t size);
		bool SetHardwareBreakpointInContext(WOW64_CONTEXT& ctx, int drIndex, uint64_t address, DebugBreakpointType type, size_t size);
		bool ClearHardwareBreakpointInContext(CONTEXT& ctx, int drIndex);
		bool ClearHardwareBreakpointInContext(WOW64_CONTEXT& ctx, int drIndex);

		uint64_t ResolveModuleOffset(const ModuleNameAndOffset& location);

		// Verbose logging helper
		template<typename... Args>
		void LogVerbose(const char* fmt, Args&&... args)
		{
			if (m_verboseLogging)
				LogWarn(fmt, std::forward<Args>(args)...);
		}

		// Temporary breakpoint helpers for step over/return
		bool SetTempBreakpoint(uint64_t address);
		bool RemoveTempBreakpoint();

		// Instruction helpers
		bool IsCallInstruction(uint64_t address, size_t& instrLength);
		uint64_t GetReturnAddress();

	public:
		WindowsNativeAdapter(BinaryView* data);
		~WindowsNativeAdapter();

		bool Init() override;

		[[nodiscard]] bool Execute(const std::string& path, const LaunchConfigurations& configs = {}) override;
		[[nodiscard]] bool ExecuteWithArgs(const std::string& path, const std::string& args,
			const std::string& workingDir, const LaunchConfigurations& configs = {}) override;
		[[nodiscard]] bool Attach(std::uint32_t pid) override;
		[[nodiscard]] bool Connect(const std::string& server, std::uint32_t port) override;

		bool Detach() override;
		bool Quit() override;

		std::vector<DebugProcess> GetProcessList() override;

		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;

		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags = 0) override;
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;

		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;
		bool RemoveBreakpoint(const ModuleNameAndOffset& breakpoint) override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;

		// Hardware breakpoint support
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
		std::uint32_t GetActivePID() override;

		bool SupportFeature(DebugAdapterCapacity feature) override;

		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;

		bool SuspendThread(std::uint32_t tid) override;
		bool ResumeThread(std::uint32_t tid) override;

		void GenerateDefaultAdapterSettings(BinaryView* data);
		Ref<Settings> GetAdapterSettings() override;
	};

	class WindowsNativeAdapterType : public DebugAdapterType
	{
		static Ref<Settings> RegisterAdapterSettings();

	public:
		WindowsNativeAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
		static Ref<Settings> GetAdapterSettings();
	};

	void InitWindowsNativeAdapterType();

}  // namespace BinaryNinjaDebugger
