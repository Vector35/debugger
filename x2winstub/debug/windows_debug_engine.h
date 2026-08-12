/*
Ported from core/adapters/windowsnativeadapter.cpp/.h (BinaryNinjaDebugger::WindowsNativeAdapter).
This is the same Windows debug engine (Win32 debug-loop, software/hardware breakpoints, stepping,
registers, memory map, WOW64 handling) with the Binary Ninja dependencies removed: no BinaryView,
no Settings, no BN logging, no DebugAdapter base class.
*/
#pragma once
#include "debug_types.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>

namespace x2win {

	// Minimal printf-style logging, replacing BN's global LogWarn()/LogError() free functions.
	// Declared here (not just in the .cpp) so WindowsDebugEngine::LogVerbose, a member template
	// defined inline below, sees them at its point of definition.
	void LogWarn(const char* fmt, ...);
	void LogError(const char* fmt, ...);

	// Internal breakpoint tracking structure
	struct InternalBreakpoint
	{
		uint64_t address;
		uint8_t originalByte;
		bool hasOriginalByte;  // true once originalByte holds a real saved value (0x00 is a valid byte, so we can't use originalByte itself as the sentinel)
		bool isActive;
		unsigned long id;

		InternalBreakpoint() : address(0), originalByte(0), hasOriginalByte(false), isActive(false), id(0) {}
		InternalBreakpoint(uint64_t addr, uint8_t orig, bool active, unsigned long bpId)
			: address(addr), originalByte(orig), hasOriginalByte(true), isActive(active), id(bpId) {}
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

	class WindowsDebugEngine
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

		// Architecture info (WOW64 is runtime-detected once attached; see StartDebugging())
		bool m_isTargetWow64 = false;  // True if debugging a 32-bit process on 64-bit Windows

		// Settings (plain local flags, replacing BN's Settings::Instance() lookups -- defaults
		// match the BN debugger.* settings' registered defaults, see core/debugger.cpp)
		bool m_verboseLogging = false;          // was "common.verboseLogging" (default false)
		bool m_stopAtSystemEntryPoint = true;   // was "debugger.stopAtSystemEntryPoint" (default false)
												// In here we set default as true, because we removed binaryview
												// so that there is no more break point at program entry.

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

		// Event delivery -- replaces DebugAdapter::PostDebuggerEvent()/m_eventCallback.
		std::function<void(const EngineEvent&)> m_eventCallback;
		void PostEngineEvent(const EngineEvent& event);

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
		WindowsDebugEngine();
		~WindowsDebugEngine();

		void SetEventCallback(std::function<void(const EngineEvent&)> callback) { m_eventCallback = std::move(callback); }

		[[nodiscard]] bool Execute(const std::string& path, const LaunchConfigurations& configs = {});
		[[nodiscard]] bool ExecuteWithArgs(const std::string& path, const std::string& args,
			const std::string& workingDir, const LaunchConfigurations& configs = {});
		[[nodiscard]] bool Attach(std::uint32_t pid);

		bool Detach();
		bool Quit();

		std::vector<DebugProcess> GetProcessList();

		std::vector<DebugThread> GetThreadList();
		DebugThread GetActiveThread() const;
		std::uint32_t GetActiveThreadId() const;
		bool SetActiveThread(const DebugThread& thread);
		bool SetActiveThreadId(std::uint32_t tid);

		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags = 0);
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0);

		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint);
		bool RemoveBreakpoint(const ModuleNameAndOffset& breakpoint);

		std::vector<DebugBreakpoint> GetBreakpointList() const;

		// Hardware breakpoint support
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1);
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1);
		bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1);
		bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1);

		std::unordered_map<std::string, DebugRegister> ReadAllRegisters();
		DebugRegister ReadRegister(const std::string& reg);
		bool WriteRegister(const std::string& reg, uint64_t value);

		std::vector<uint8_t> ReadMemory(std::uintptr_t address, std::size_t size);
		bool WriteMemory(std::uintptr_t address, const std::vector<uint8_t>& buffer);

		std::vector<DebugModule> GetModuleList();

		std::vector<DebugMemoryRegion> GetMemoryMap();

		std::string GetTargetArchitecture();

		DebugStopReason StopReason();
		uint64_t ExitCode();

		bool BreakInto();
		bool Go();
		bool StepInto();
		bool StepOver();
		bool StepReturn();

		uint64_t GetInstructionOffset();
		uint64_t GetStackPointer();
		std::uint32_t GetActivePID();

		// True once Attach()/Execute() has actually started a debug session, false again after
		// Detach()/Quit() (or the debuggee exits on its own) -- unlike GetActivePID(), which keeps
		// returning the last-known pid even after the session has ended, this is the right signal for
		// "is there still something to supervise right now".
		bool IsActivelyDebugging() const { return m_activelyDebugging; }

		bool SupportFeature(DebugAdapterCapacity feature);

		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid);

		bool SuspendThread(std::uint32_t tid);
		bool ResumeThread(std::uint32_t tid);
	};

}  // namespace x2win
