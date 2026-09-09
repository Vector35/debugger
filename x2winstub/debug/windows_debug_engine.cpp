/*
Ported from core/adapters/windowsnativeadapter.cpp (BinaryNinjaDebugger::WindowsNativeAdapter).
See windows_debug_engine.h for what changed and why. Summary of the non-mechanical changes (beyond
renaming the class and dropping BN-only code):
  - The dbghelp.dll delay-load hook (originally there to avoid a DLL-version clash with the DbgEng
    adapter *running in the same BN process*) is dropped entirely -- x2winstub is its own process,
    so that clash can't happen; dbghelp.dll is now just linked normally.
  - Settings::Instance() lookups become plain local fields (see header) with the same defaults as
    the BN debugger.* settings they replace.
  - The "auto-breakpoint at the BinaryView's analyzed entry function" part of the initial-breakpoint
    handling is dropped -- it required BinaryView analysis data this standalone engine doesn't have.
    The rest of that logic (the stopAtSystemEntryPoint check, which needs no analysis data) is kept.
  - DataBuffer becomes std::vector<uint8_t>; DebuggerEvent/PostDebuggerEvent become EngineEvent/
    PostEngineEvent (see debug_types.h for the mapping, checked against all 8 original call sites).
  - ExecuteWithArgs() now actually uses its path/args/workingDir parameters (the original read them
    from BN Settings instead and ignored the parameters -- a BN-GUI-specific quirk that doesn't
    apply here; the proto LaunchRequest already carries these explicitly).
*/
#include "windows_debug_engine.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <algorithm>
#include <cstdio>
#include <cstdarg>

namespace x2win {

	void LogWarn(const char* fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		fprintf(stderr, "[x2winstub][WARN] ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}

	void LogError(const char* fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		fprintf(stderr, "[x2winstub][ERROR] ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}

	// INT3 instruction opcode
	constexpr uint8_t INT3_OPCODE = 0xCC;

	WindowsDebugEngine::WindowsDebugEngine()
	{
	}


	WindowsDebugEngine::~WindowsDebugEngine()
	{
		if (m_activelyDebugging)
			Quit();

		// If the target exited on its own, HandleExitProcess cleared m_activelyDebugging and the
		// debug loop returned, but nobody joined the thread. Destroying a joinable std::thread
		// calls std::terminate, so join here to cover that path.
		if (m_debugThread.joinable())
			m_debugThread.join();
	}


	void WindowsDebugEngine::PostEngineEvent(const EngineEvent& event)
	{
		if (m_eventCallback)
			m_eventCallback(event);
	}


	bool WindowsDebugEngine::Execute(const std::string& path, const LaunchConfigurations& configs)
	{
		return ExecuteWithArgs(path, "", "", configs);
	}


	bool WindowsDebugEngine::ExecuteWithArgs(const std::string& path, const std::string& args,
		const std::string& workingDir, const LaunchConfigurations& configs)
	{
		// Reset any previous state
		Reset();

		m_launchExecutable = path;
		m_launchWorkingDir = workingDir;
		m_launchCommandLine = path;
		if (!args.empty())
			m_launchCommandLine += " " + args;
		m_isAttaching = false;
		m_launchResult = false;
		m_launchError.clear();

		// Start the debug loop thread - it will create the process
		m_debugThread = std::thread(&WindowsDebugEngine::DebugLoop, this);

		// Wait for the debug thread to signal success or failure
		{
			std::unique_lock<std::mutex> lock(m_launchMutex);
			m_launchCondition.wait(lock, [this] { return m_launchResult.load() || !m_launchError.empty(); });
		}

		if (!m_launchError.empty())
		{
			LogError("Failed to create process: %s", m_launchError.c_str());
			EngineEvent event;
			event.type = EngineEventType::LaunchFailure;
			event.error = m_launchError;
			event.shortError = "CreateProcess failed";
			PostEngineEvent(event);

			// Wait for debug thread to finish
			if (m_debugThread.joinable())
				m_debugThread.join();
			return false;
		}

		return true;
	}


	bool WindowsDebugEngine::Attach(std::uint32_t pid)
	{
		// Reset any previous state
		Reset();

		m_attachPID = static_cast<DWORD>(pid);
		m_isAttaching = true;
		m_launchResult = false;
		m_launchError.clear();

		// Start the debug loop thread - it will attach to the process
		m_debugThread = std::thread(&WindowsDebugEngine::DebugLoop, this);

		// Wait for the debug thread to signal success or failure
		{
			std::unique_lock<std::mutex> lock(m_launchMutex);
			m_launchCondition.wait(lock, [this] { return m_launchResult.load() || !m_launchError.empty(); });
		}

		if (!m_launchError.empty())
		{
			LogError("Failed to attach to process: %s", m_launchError.c_str());
			EngineEvent event;
			event.type = EngineEventType::LaunchFailure;
			event.error = m_launchError;
			event.shortError = "Attach failed";
			PostEngineEvent(event);

			// Wait for debug thread to finish
			if (m_debugThread.joinable())
				m_debugThread.join();
			return false;
		}

		return true;
	}


	bool WindowsDebugEngine::Detach()
	{
		if (!m_activelyDebugging)
			return true;

		// Set the stop flag under m_debugMutex so the DebugLoop's condition_variable wait
		// (whose predicate reads m_shouldStop) can't miss the wakeup if it is between evaluating
		// the predicate and parking. Modifying the flag without the lock races with that window
		// and can lose the notify, hanging the join() below forever even though m_shouldStop is
		// atomic.
		{
			std::lock_guard<std::mutex> lock(m_debugMutex);
			m_shouldStop = true;
		}

		// Wake up the debug thread if it's waiting
		m_debugCondition.notify_one();

		if (m_debugThread.joinable())
			m_debugThread.join();

		// Thread handles in m_threads come from debug events (CREATE_PROCESS/CREATE_THREAD);
		// Windows closes those automatically when debugging ends, so we must not close them
		// here (see HandleExitThread). Doing so raises STATUS_INVALID_HANDLE under a debugger.
		m_threads.clear();

		// The initial thread handle from CreateProcess is owned by us.
		if (m_threadHandle)
		{
			CloseHandle(m_threadHandle);
			m_threadHandle = nullptr;
		}

		if (m_processHandle)
		{
			CloseHandle(m_processHandle);
			m_processHandle = nullptr;
		}

		m_activelyDebugging = false;
		m_targetRunning = false;

		EngineEvent event;
		event.type = EngineEventType::TargetExited;
		event.exitCode = 0;
		PostEngineEvent(event);

		return true;
	}


	bool WindowsDebugEngine::Quit()
	{
		if (!m_activelyDebugging)
			return true;

		// Set the stop flag under m_debugMutex so the DebugLoop's condition_variable wait
		// (whose predicate reads m_shouldStop) can't miss the wakeup if it is between evaluating
		// the predicate and parking. Modifying the flag without the lock races with that window
		// and can lose the notify, hanging the join() below forever even though m_shouldStop is
		// atomic.
		{
			std::lock_guard<std::mutex> lock(m_debugMutex);
			m_shouldStop = true;
		}

		// Wake up the debug thread if it's waiting
		m_debugCondition.notify_one();

		// Terminate the process
		if (m_processHandle)
			TerminateProcess(m_processHandle, 0);

		if (m_debugThread.joinable())
			m_debugThread.join();

		// Thread handles in m_threads come from debug events (CREATE_PROCESS/CREATE_THREAD);
		// Windows closes those automatically when debugging ends, so we must not close them
		// here (see HandleExitThread). Doing so raises STATUS_INVALID_HANDLE under a debugger.
		m_threads.clear();

		// The initial thread handle from CreateProcess is owned by us.
		if (m_threadHandle)
		{
			CloseHandle(m_threadHandle);
			m_threadHandle = nullptr;
		}

		if (m_processHandle)
		{
			CloseHandle(m_processHandle);
			m_processHandle = nullptr;
		}

		m_activelyDebugging = false;
		m_targetRunning = false;

		EngineEvent event;
		event.type = EngineEventType::TargetExited;
		event.exitCode = m_exitCode;
		PostEngineEvent(event);

		return true;
	}


	void WindowsDebugEngine::Reset()
	{
		// Wait for any existing debug thread to finish
		if (m_debugThread.joinable())
			m_debugThread.join();

		// Thread handles in m_threads come from debug events (CREATE_PROCESS/CREATE_THREAD);
		// Windows closes those automatically when debugging ends, so we must not close them
		// here (see HandleExitThread). Doing so raises STATUS_INVALID_HANDLE under a debugger.
		m_threads.clear();

		// The initial thread handle from CreateProcess is owned by us.
		if (m_threadHandle)
		{
			CloseHandle(m_threadHandle);
			m_threadHandle = nullptr;
		}

		// Close process handle
		if (m_processHandle)
		{
			CloseHandle(m_processHandle);
			m_processHandle = nullptr;
		}

		// Reset state variables
		m_threadHandle = nullptr;
		m_processId = 0;
		m_threadId = 0;
		m_activeThreadId = 0;
		m_hasLastDebugEvent = false;
		m_activelyDebugging = false;
		m_targetRunning = false;
		m_shouldStop = false;
		m_stopReason = UnknownReason;
		m_exitCode = 0;

		// Clear modules
		{
			std::lock_guard<std::mutex> lock(m_modulesMutex);
			m_modules.clear();
		}

		// Fully clear breakpoint state instead of only marking it inactive. Keeping the old address
		// around let ApplyPendingBreakpoints() silently re-apply it (by the stored raw address) to
		// whatever process gets attached/launched next -- correct when restarting the *same* binary,
		// wrong once this engine instance is reused for an unrelated target on a reused stub
		// connection. Safe to drop entirely: X2WinRpcAdapter (BN-core side) already re-sends every
		// breakpoint it cares about via AddBreakpoint()/AddHardwareBreakpoint() on every successful
		// Attach/Launch/ConnectToDebugServer (see its ApplyBreakPoints()), so nothing is lost.
		{
			std::lock_guard<std::mutex> lock(m_breakpointsMutex);
			m_breakpoints.clear();
			m_pendingBreakpoints.clear();
		}

		// Same reasoning for hardware breakpoints -- their addresses (and any not-yet-resolved pending
		// ones, e.g. queued because no free debug register was available) are just as process-specific.
		{
			std::lock_guard<std::mutex> lock(m_hwBreakpointsMutex);
			m_hardwareBreakpoints.clear();
			m_pendingHardwareBreakpoints.clear();
		}

		// Reset step tracking
		m_singleStepping = false;
		m_stepOverBreakpointAddress = 0;
		m_hasStepOverBreakpoint = false;
		m_stepOverBreakpointContinue = false;

		// Reset hardware breakpoint step-over tracking
		m_stepOverHwBreakpointIndex = -1;
		m_hasStepOverHwBreakpoint = false;
		m_stepOverHwBreakpointContinue = false;

		// Reset temp breakpoint
		m_hasTempBreakpoint = false;
		m_tempBreakpointAddress = 0;
		m_tempBreakpointOriginalByte = 0;

		// Reset initial breakpoint tracking
		m_initialBreakpointSeen = false;
		m_wow64InitialBreakpointSeen = false;

		// Reset WOW64 flag (will be re-detected on next process start)
		m_isTargetWow64 = false;

		// Reset launch state
		m_launchResult = false;
		m_launchError.clear();
	}


	bool WindowsDebugEngine::StartDebugging()
	{
		LogVerbose("WindowsDebugEngine::StartDebugging - isAttaching=%d", m_isAttaching);

		if (m_isAttaching)
		{
			// Attach to existing process
			if (!DebugActiveProcess(m_attachPID))
			{
				char buf[256];
				snprintf(buf, sizeof(buf), "Failed to attach to process %lu: %lu", m_attachPID, GetLastError());
				m_launchError = buf;
				LogError("%s", m_launchError.c_str());
				return false;
			}

			m_processId = m_attachPID;
			m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_attachPID);
			if (!m_processHandle)
			{
				char buf[256];
				snprintf(buf, sizeof(buf), "Failed to open process %lu: %lu", m_attachPID, GetLastError());
				m_launchError = buf;
				LogError("%s", m_launchError.c_str());
				DebugActiveProcessStop(m_attachPID);
				return false;
			}
		}
		else
		{
			// Launch new process
			STARTUPINFOA si {};
			PROCESS_INFORMATION pi {};
			si.cb = sizeof(si);

			DWORD creationFlags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;

			LogVerbose("CreateProcessA: %s, workingDir=%s",
				m_launchCommandLine.c_str(), m_launchWorkingDir.c_str());

			if (!CreateProcessA(
				nullptr,
				const_cast<char*>(m_launchCommandLine.c_str()),
				nullptr,
				nullptr,
				FALSE,
				creationFlags,
				nullptr,
				m_launchWorkingDir.empty() ? nullptr : m_launchWorkingDir.c_str(),
				&si,
				&pi))
			{
				char buf[256];
				snprintf(buf, sizeof(buf), "Failed to create process: %lu", GetLastError());
				m_launchError = buf;
				LogError("%s", m_launchError.c_str());
				return false;
			}

			m_processHandle = pi.hProcess;
			m_threadHandle = pi.hThread;
			m_processId = pi.dwProcessId;
			m_threadId = pi.dwThreadId;
			m_activeThreadId = pi.dwThreadId;

			// Add the initial thread to our tracking
			m_threads[pi.dwThreadId] = pi.hThread;

			LogVerbose("Process created: PID=%d, TID=%d", m_processId, m_threadId);
		}

		// Detect if the target is a WOW64 (32-bit) process
		BOOL isWow64 = FALSE;
		if (IsWow64Process(m_processHandle, &isWow64))
		{
			m_isTargetWow64 = (isWow64 != FALSE);
			LogVerbose("Target process WOW64 status: %s", m_isTargetWow64 ? "32-bit (WOW64)" : "64-bit");
		}

		m_activelyDebugging = true;
		m_targetRunning = true;

		return true;
	}


	void WindowsDebugEngine::DebugLoop()
	{
		LogVerbose("WindowsDebugEngine::DebugLoop started");

		// Create/attach to process on this thread (required by Windows debug API)
		if (!StartDebugging())
		{
			// Signal failure to the calling thread
			{
				std::lock_guard<std::mutex> lock(m_launchMutex);
				// m_launchError is already set by StartDebugging
			}
			m_launchCondition.notify_one();
			return;
		}

		// Signal success to the calling thread
		{
			std::lock_guard<std::mutex> lock(m_launchMutex);
			m_launchResult = true;
		}
		m_launchCondition.notify_one();

		DEBUG_EVENT debugEvent;

		while (m_activelyDebugging && !m_shouldStop)
		{
			if (!WaitForDebugEvent(&debugEvent, 100))
			{
				if (GetLastError() == ERROR_SEM_TIMEOUT)
					continue;
				LogWarn("WaitForDebugEvent failed with error: %d", GetLastError());
				break;
			}

			LogVerbose("Received debug event: code=%d, pid=%d, tid=%d",
				debugEvent.dwDebugEventCode, debugEvent.dwProcessId, debugEvent.dwThreadId);

			m_lastDebugEvent = debugEvent;
			m_hasLastDebugEvent = true;

			DWORD continueStatus = DBG_CONTINUE;

			bool shouldBreak = HandleDebugEvent(debugEvent);
			LogVerbose("HandleDebugEvent returned shouldBreak=%d", shouldBreak);

			if (shouldBreak)
			{
				m_targetRunning = false;

				// Notify the controller that we've stopped
				LogVerbose("Posting TargetStopped with reason=%d, thread=%d", m_stopReason, m_activeThreadId);
				EngineEvent event;
				event.type = EngineEventType::TargetStopped;
				event.stopReason = m_stopReason;
				event.lastActiveThread = m_activeThreadId;
				event.exitCode = 0;
				PostEngineEvent(event);

				// Wait for Go() or other commands
				LogVerbose("Waiting for Go() or stop signal...");
				std::unique_lock<std::mutex> lock(m_debugMutex);
				m_debugCondition.wait(lock, [this] { return m_targetRunning || m_shouldStop; });
				LogVerbose("Wait completed: m_targetRunning=%d, m_shouldStop=%d", m_targetRunning.load(), m_shouldStop.load());

				if (m_shouldStop)
				{
					RemoveAllBreakpoints();
					ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);

					// If more than one thread hit this breakpoint at the same time, the ContinueDebugEvent()
					// above only accounts for the one debug event WaitForDebugEvent() actually retrieved --
					// any other thread's debug event is still sitting in the kernel's queue for this process,
					// never continued. DebugActiveProcessStop() below requires every outstanding debug event
					// to be continued before it will detach cleanly; leaving one pending makes it fail, and the
					// fallback below then kills the target -- which is exactly the multi-threaded-detach bug
					// this is fixing. A zero-millisecond WaitForDebugEvent() returns immediately once the
					// queue is empty, so this doesn't add any real delay in the common (single pending event)
					// case.
					DEBUG_EVENT pendingEvent;
					while (WaitForDebugEvent(&pendingEvent, 0))
					{
						LogVerbose("Detach: draining pending debug event code=%d, pid=%d, tid=%d",
							pendingEvent.dwDebugEventCode, pendingEvent.dwProcessId, pendingEvent.dwThreadId);
						ContinueDebugEvent(pendingEvent.dwProcessId, pendingEvent.dwThreadId, DBG_CONTINUE);
					}

					// DebugActiveProcessStop must be called from the same thread that started debugging
					if (!DebugActiveProcessStop(m_processId))
					{
						LogWarn("DebugActiveProcessStop failed (error %d) -- killing target", GetLastError());
						TerminateProcess(m_processHandle, 1);
					}

					// Mark detach as already handled so the post-loop cleanup below (which exists for
					// the "still running, never stopped" case) doesn't see m_activelyDebugging still
					// true and redundantly call DebugActiveProcessStop a second time -- that second
					// call would fail (already detached) and trip its own TerminateProcess fallback,
					// killing the target even on a plain Detach().
					m_activelyDebugging = false;

					break;
				}
			}

			// Handle exception continue status
			if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
			{
				DWORD exCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
				if (exCode == EXCEPTION_BREAKPOINT ||
					exCode == EXCEPTION_SINGLE_STEP ||
					exCode == 0x4000001F ||  // STATUS_WX86_BREAKPOINT
					exCode == 0x4000001E)    // STATUS_WX86_SINGLE_STEP
				{
					continueStatus = DBG_CONTINUE;
				}
				else if (!debugEvent.u.Exception.dwFirstChance)
				{
					continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
			}

			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
		}

		// If we exited the loop due to m_shouldStop while the target was running (not stopped at a
		// breakpoint), we still need to detach. The stopped-at-breakpoint case is handled inside the loop.
		if (m_shouldStop && m_activelyDebugging)
		{
			RemoveAllBreakpoints();

			// Same rationale as the drain in the shouldBreak branch above -- make sure nothing is left
			// pending before detaching here too.
			DEBUG_EVENT pendingEvent;
			while (WaitForDebugEvent(&pendingEvent, 0))
			{
				LogVerbose("Detach: draining pending debug event code=%d, pid=%d, tid=%d",
					pendingEvent.dwDebugEventCode, pendingEvent.dwProcessId, pendingEvent.dwThreadId);
				ContinueDebugEvent(pendingEvent.dwProcessId, pendingEvent.dwThreadId, DBG_CONTINUE);
			}

			if (!DebugActiveProcessStop(m_processId))
			{
				LogWarn("DebugActiveProcessStop failed (error %d) -- killing target", GetLastError());
				TerminateProcess(m_processHandle, 1);
			}
		}

		m_activelyDebugging = false;
	}


	bool WindowsDebugEngine::HandleDebugEvent(const DEBUG_EVENT& event)
	{
		switch (event.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			return HandleException(event.u.Exception);

		case CREATE_PROCESS_DEBUG_EVENT:
			return HandleCreateProcess(event.u.CreateProcessInfo);

		case EXIT_PROCESS_DEBUG_EVENT:
			return HandleExitProcess(event.u.ExitProcess);

		case CREATE_THREAD_DEBUG_EVENT:
			return HandleCreateThread(event.u.CreateThread, event.dwThreadId);

		case EXIT_THREAD_DEBUG_EVENT:
			return HandleExitThread(event.u.ExitThread, event.dwThreadId);

		case LOAD_DLL_DEBUG_EVENT:
			return HandleLoadDll(event.u.LoadDll);

		case UNLOAD_DLL_DEBUG_EVENT:
			return HandleUnloadDll(event.u.UnloadDll);

		case OUTPUT_DEBUG_STRING_EVENT:
			return HandleOutputDebugString(event.u.DebugString);

		default:
			return false;
		}
	}


	bool WindowsDebugEngine::HandleException(const EXCEPTION_DEBUG_INFO& info)
	{
		m_activeThreadId = m_lastDebugEvent.dwThreadId;

		LogVerbose("HandleException: code=0x%08X, address=0x%llX, firstChance=%d",
			info.ExceptionRecord.ExceptionCode,
			(uint64_t)info.ExceptionRecord.ExceptionAddress,
			info.dwFirstChance);

		switch (info.ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_BREAKPOINT:
		case 0x4000001F:  // STATUS_WX86_BREAKPOINT - WOW64 breakpoint exception
		{
			uint64_t address = (uint64_t)info.ExceptionRecord.ExceptionAddress;

			// Check if this is a temporary breakpoint (from StepOver/StepReturn)
			if (m_hasTempBreakpoint && address == m_tempBreakpointAddress)
			{
				// Remove the temporary breakpoint
				RemoveTempBreakpoint();

				// Set IP back to the breakpoint address so the instruction executes
				HANDLE threadHandle = m_threads[m_activeThreadId];
				if (threadHandle)
				{
					if (m_isTargetWow64)
					{
						WOW64_CONTEXT ctx {};
						ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
						if (Wow64GetThreadContext(threadHandle, &ctx))
						{
							ctx.Eip = static_cast<DWORD>(address);
							Wow64SetThreadContext(threadHandle, &ctx);
						}
					}
					else
					{
						CONTEXT ctx {};
						ctx.ContextFlags = CONTEXT_CONTROL;
						if (GetThreadContext(threadHandle, &ctx))
						{
							ctx.Rip = address;
							SetThreadContext(threadHandle, &ctx);
						}
					}
				}

				m_stopReason = SingleStep;  // Report as step completion
				return true;
			}

			// Check if this is one of our breakpoints
			{
				std::lock_guard<std::mutex> lock(m_breakpointsMutex);
				for (auto& bp : m_breakpoints)
				{
					if (bp.address == address && bp.isActive)
					{
						// Restore the original byte
						WriteMemory(address, std::vector<uint8_t>{bp.originalByte});

						// Set IP back to the breakpoint address
						HANDLE threadHandle = m_threads[m_activeThreadId];
						if (threadHandle)
						{
							if (m_isTargetWow64)
							{
								WOW64_CONTEXT ctx {};
								ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
								if (Wow64GetThreadContext(threadHandle, &ctx))
								{
									ctx.Eip = static_cast<DWORD>(address);
									Wow64SetThreadContext(threadHandle, &ctx);
								}
							}
							else
							{
								CONTEXT ctx {};
								ctx.ContextFlags = CONTEXT_CONTROL;
								if (GetThreadContext(threadHandle, &ctx))
								{
									ctx.Rip = address;
									SetThreadContext(threadHandle, &ctx);
								}
							}
						}

						m_stopReason = Breakpoint;
						return true;
					}
				}
			}

			// Initial breakpoint (system breakpoint)
			if (!m_initialBreakpointSeen)
			{
				m_initialBreakpointSeen = true;

				// Note: the original WindowsNativeAdapter also placed a breakpoint at the
				// BinaryView's analyzed entry function here when "debugger.stopAtEntryPoint" was
				// enabled. That requires BinaryView analysis data this standalone engine
				// deliberately doesn't have -- dropped for this port.

				// When attaching to a running process, always stop at the attach breakpoint.
				// When launching a new process, respect m_stopAtSystemEntryPoint.
				if (!m_isAttaching && !m_stopAtSystemEntryPoint)
				{
					return false;  // Don't stop, continue running
				}

				m_stopReason = InitialBreakpoint;
				return true;
			}

			// WOW64 processes have a second system breakpoint (LdrpDoDebuggerBreak in 32-bit ntdll)
			if (m_isTargetWow64 && !m_wow64InitialBreakpointSeen)
			{
				m_wow64InitialBreakpointSeen = true;

				// When attaching, always stop at the attach breakpoint (even for WOW64 second breakpoint)
				if (!m_isAttaching && !m_stopAtSystemEntryPoint)
				{
					return false;  // Don't stop, continue running
				}

				m_stopReason = InitialBreakpoint;
				return true;
			}

			// Unknown breakpoint - stop and report
			m_stopReason = Breakpoint;
			return true;
		}

		case EXCEPTION_SINGLE_STEP:
		case 0x4000001E:  // STATUS_WX86_SINGLE_STEP - WOW64 single step exception
		{
			// If we were stepping over a software breakpoint, re-apply it
			if (m_hasStepOverBreakpoint)
			{
				std::lock_guard<std::mutex> lock(m_breakpointsMutex);
				for (auto& bp : m_breakpoints)
				{
					if (bp.address == m_stepOverBreakpointAddress)
					{
						ApplyBreakpoint(bp.address, bp.id);
						break;
					}
				}
				m_hasStepOverBreakpoint = false;

				// Resume all other threads that we suspended
				for (const auto& [tid, handle] : m_threads)
				{
					if (tid != m_activeThreadId && handle)
					{
						::ResumeThread(handle);
					}
				}

				// If this was from Go(), continue execution; if from StepInto(), stop
				if (m_stepOverBreakpointContinue)
				{
					m_stepOverBreakpointContinue = false;
					return false;  // Don't stop, continue execution
				}
				// Fall through to normal single step handling (will stop)
			}

			// If we were stepping over a hardware breakpoint, re-enable it
			if (m_hasStepOverHwBreakpoint)
			{
				HANDLE threadHandle = m_threads[m_activeThreadId];
				if (threadHandle && m_stepOverHwBreakpointIndex >= 0)
				{
					if (m_isTargetWow64)
					{
						WOW64_CONTEXT ctx {};
						ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
						if (Wow64GetThreadContext(threadHandle, &ctx))
						{
							ctx.Dr7 |= (1UL << (m_stepOverHwBreakpointIndex * 2));
							Wow64SetThreadContext(threadHandle, &ctx);
						}
					}
					else
					{
						CONTEXT ctx {};
						ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
						if (GetThreadContext(threadHandle, &ctx))
						{
							ctx.Dr7 |= (1ULL << (m_stepOverHwBreakpointIndex * 2));
							SetThreadContext(threadHandle, &ctx);
						}
					}
				}
				m_hasStepOverHwBreakpoint = false;

				// If this was from Go(), continue execution
				if (m_stepOverHwBreakpointContinue)
				{
					m_stepOverHwBreakpointContinue = false;
					m_stepOverHwBreakpointIndex = -1;
					return false;  // Don't stop, continue execution
				}
				m_stepOverHwBreakpointIndex = -1;
				// Fall through to normal single step handling (will stop)
			}

			// Check if a hardware breakpoint was hit
			HANDLE threadHandle = m_threads[m_activeThreadId];
			if (threadHandle)
			{
				int hitIndex = -1;
				bool hwBpHit = false;

				if (m_isTargetWow64)
				{
					WOW64_CONTEXT ctx {};
					ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
					if (Wow64GetThreadContext(threadHandle, &ctx))
					{
						if (ctx.Dr6 & 0xF)
						{
							hwBpHit = true;
							for (int i = 0; i < 4; i++)
							{
								if (ctx.Dr6 & (1 << i))
								{
									hitIndex = i;
									break;
								}
							}
							ctx.Dr6 = 0;
							Wow64SetThreadContext(threadHandle, &ctx);
						}
					}
				}
				else
				{
					CONTEXT ctx {};
					ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
					if (GetThreadContext(threadHandle, &ctx))
					{
						if (ctx.Dr6 & 0xF)
						{
							hwBpHit = true;
							for (int i = 0; i < 4; i++)
							{
								if (ctx.Dr6 & (1 << i))
								{
									hitIndex = i;
									break;
								}
							}
							ctx.Dr6 = 0;
							SetThreadContext(threadHandle, &ctx);
						}
					}
				}

				if (hwBpHit)
				{
					m_stepOverHwBreakpointIndex = hitIndex;
					m_stopReason = Breakpoint;
					return true;
				}
			}

			// Resume all other threads that were suspended during stepping
			for (const auto& [tid, handle] : m_threads)
			{
				if (tid != m_activeThreadId && handle)
				{
					::ResumeThread(handle);
				}
			}

			m_stopReason = SingleStep;
			m_singleStepping = false;
			return true;
		}

		// Calculation exceptions (divide by zero, overflow, etc.)
		case EXCEPTION_FLT_DENORMAL_OPERAND:
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		case EXCEPTION_FLT_INEXACT_RESULT:
		case EXCEPTION_FLT_INVALID_OPERATION:
		case EXCEPTION_FLT_OVERFLOW:
		case EXCEPTION_FLT_STACK_CHECK:
		case EXCEPTION_FLT_UNDERFLOW:
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
		case EXCEPTION_INT_OVERFLOW:
			m_stopReason = Calculation;
			return true;

		// Illegal instruction
		case EXCEPTION_ILLEGAL_INSTRUCTION:
		case EXCEPTION_PRIV_INSTRUCTION:
			m_stopReason = IllegalInstruction;
			return true;

		// Memory access violations and other fatal exceptions
		case EXCEPTION_ACCESS_VIOLATION:
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		case EXCEPTION_DATATYPE_MISALIGNMENT:
		case EXCEPTION_IN_PAGE_ERROR:
		case EXCEPTION_INVALID_DISPOSITION:
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		case EXCEPTION_STACK_OVERFLOW:
			m_stopReason = AccessViolation;
			return true;

		default:
			// First chance exceptions that we don't handle
			if (info.dwFirstChance)
				return false;
			m_stopReason = AccessViolation;
			return true;
		}
	}


	bool WindowsDebugEngine::HandleCreateProcess(const CREATE_PROCESS_DEBUG_INFO& info)
	{
		LogVerbose("HandleCreateProcess: baseOfImage=0x%llX, startAddress=0x%llX",
			(uint64_t)info.lpBaseOfImage, (uint64_t)info.lpStartAddress);

		// Store the initial thread handle
		m_threads[m_lastDebugEvent.dwThreadId] = info.hThread;
		m_activeThreadId = m_lastDebugEvent.dwThreadId;

		// Get module name
		std::string moduleName = GetModuleNameFromHandle(info.hFile, info.lpBaseOfImage);

		// Add main module to module list
		{
			std::lock_guard<std::mutex> lock(m_modulesMutex);
			DebugModule module;
			module.m_name = moduleName;
			module.m_short_name = DebugModule::GetPathBaseName(moduleName);
			module.m_address = (uintptr_t)info.lpBaseOfImage;

			// Get module size from PE header
			IMAGE_DOS_HEADER dosHeader;
			if (ReadProcessMemory(m_processHandle, info.lpBaseOfImage, &dosHeader, sizeof(dosHeader), nullptr))
			{
				IMAGE_NT_HEADERS ntHeaders;
				if (ReadProcessMemory(m_processHandle,
					(LPVOID)((BYTE*)info.lpBaseOfImage + dosHeader.e_lfanew),
					&ntHeaders, sizeof(ntHeaders), nullptr))
				{
					module.m_size = ntHeaders.OptionalHeader.SizeOfImage;
				}
			}
			module.m_loaded = true;
			m_modules.push_back(module);
		}

		if (info.hFile)
			CloseHandle(info.hFile);

		// Apply pending breakpoints
		ApplyPendingBreakpoints();

		return false;  // Don't stop on process creation
	}


	bool WindowsDebugEngine::HandleExitProcess(const EXIT_PROCESS_DEBUG_INFO& info)
	{
		m_exitCode = info.dwExitCode;
		m_activelyDebugging = false;
		m_stopReason = ProcessExited;

		EngineEvent event;
		event.type = EngineEventType::TargetExited;
		event.exitCode = info.dwExitCode;
		PostEngineEvent(event);

		return false;
	}


	bool WindowsDebugEngine::HandleCreateThread(const CREATE_THREAD_DEBUG_INFO& info, DWORD threadId)
	{
		m_threads[threadId] = info.hThread;

		// Apply hardware breakpoints to the new thread
		ApplyHardwareBreakpointsToThread(info.hThread);

		return false;
	}


	bool WindowsDebugEngine::HandleExitThread(const EXIT_THREAD_DEBUG_INFO& info, DWORD threadId)
	{
		auto it = m_threads.find(threadId);
		if (it != m_threads.end())
		{
			// Don't close the handle - Windows will do it
			m_threads.erase(it);
		}

		if (m_activeThreadId == threadId && !m_threads.empty())
			m_activeThreadId = m_threads.begin()->first;

		return false;
	}


	bool WindowsDebugEngine::HandleLoadDll(const LOAD_DLL_DEBUG_INFO& info)
	{
		std::string moduleName = GetModuleNameFromHandle(info.hFile, info.lpBaseOfDll);
		LogVerbose("HandleLoadDll: %s at 0x%llX", moduleName.c_str(), (uint64_t)info.lpBaseOfDll);

		{
			std::lock_guard<std::mutex> lock(m_modulesMutex);
			DebugModule module;
			module.m_name = moduleName;
			module.m_short_name = DebugModule::GetPathBaseName(moduleName);
			module.m_address = (uintptr_t)info.lpBaseOfDll;

			// Get module size
			IMAGE_DOS_HEADER dosHeader;
			if (ReadProcessMemory(m_processHandle, info.lpBaseOfDll, &dosHeader, sizeof(dosHeader), nullptr))
			{
				IMAGE_NT_HEADERS ntHeaders;
				if (ReadProcessMemory(m_processHandle,
					(LPVOID)((BYTE*)info.lpBaseOfDll + dosHeader.e_lfanew),
					&ntHeaders, sizeof(ntHeaders), nullptr))
				{
					module.m_size = ntHeaders.OptionalHeader.SizeOfImage;
				}
			}
			module.m_loaded = true;
			m_modules.push_back(module);
		}

		if (info.hFile)
			CloseHandle(info.hFile);

		// Try to apply pending breakpoints
		ApplyPendingBreakpoints();

		return false;
	}


	bool WindowsDebugEngine::HandleUnloadDll(const UNLOAD_DLL_DEBUG_INFO& info)
	{
		std::lock_guard<std::mutex> lock(m_modulesMutex);
		auto it = std::remove_if(m_modules.begin(), m_modules.end(),
			[&info](const DebugModule& m) { return m.m_address == (uintptr_t)info.lpBaseOfDll; });
		m_modules.erase(it, m_modules.end());
		return false;
	}


	bool WindowsDebugEngine::HandleOutputDebugString(const OUTPUT_DEBUG_STRING_INFO& info)
	{
		std::vector<char> buffer(info.nDebugStringLength);
		SIZE_T bytesRead;
		if (ReadProcessMemory(m_processHandle, info.lpDebugStringData, buffer.data(),
			info.nDebugStringLength, &bytesRead))
		{
			std::string message(buffer.data(), bytesRead);
			LogVerbose("Debug output: %s", message.c_str());
		}
		return false;
	}


	std::string WindowsDebugEngine::GetModuleNameFromHandle(HANDLE fileHandle, LPVOID baseAddress)
	{
		char filename[MAX_PATH] = {};

		if (fileHandle)
		{
			if (GetFinalPathNameByHandleA(fileHandle, filename, MAX_PATH, 0) > 0)
			{
				// Remove the "\\?\" prefix if present
				std::string result = filename;
				if (result.substr(0, 4) == "\\\\?\\")
					result = result.substr(4);
				return result;
			}
		}

		// Fallback: try to get from process memory
		if (GetMappedFileNameA(m_processHandle, baseAddress, filename, MAX_PATH) > 0)
		{
			// Convert device path to DOS path
			char drives[256];
			if (GetLogicalDriveStringsA(sizeof(drives), drives))
			{
				char* drive = drives;
				while (*drive)
				{
					char driveLetter[3] = { drive[0], ':', 0 };
					char devicePath[MAX_PATH];
					if (QueryDosDeviceA(driveLetter, devicePath, MAX_PATH))
					{
						size_t len = strlen(devicePath);
						if (_strnicmp(filename, devicePath, len) == 0)
						{
							std::string result = driveLetter;
							result += (filename + len);
							return result;
						}
					}
					drive += strlen(drive) + 1;
				}
			}
			return filename;
		}

		return "<unknown>";
	}


	// winternl.h provides forward declarations but not full definitions
	// Define a local structure for command line info to avoid conflicts
	struct CommandLineInfo {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	};

	// Helper function to get command line of a process
	static std::string GetProcessCommandLine(DWORD pid, const std::string& exeName)
	{
		// Can't get command line for system processes, fallback to executable name
		if (pid == 0 || pid == 4)
			return exeName;

		// Try with PROCESS_QUERY_LIMITED_INFORMATION first (less intrusive, works on more processes)
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (!hProcess)
		{
			// Fallback to executable name if we can't open the process
			return exeName;
		}

		// Get NtQueryInformationProcess from ntdll
		// Use the declaration from winternl.h
		typedef NTSTATUS (NTAPI *NtQueryInformationProcessFn)(
			HANDLE ProcessHandle,
			PROCESSINFOCLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength,
			PULONG ReturnLength
		);

		static NtQueryInformationProcessFn NtQueryInformationProcess = nullptr;
		if (!NtQueryInformationProcess)
		{
			HMODULE ntdll = GetModuleHandleA("ntdll.dll");
			if (ntdll)
				NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(ntdll, "NtQueryInformationProcess");
		}

		if (!NtQueryInformationProcess)
		{
			CloseHandle(hProcess);
			return exeName;
		}

		// ProcessCommandLineInformation = 60 (available since Windows 8.1)
		// Cast to PROCESSINFOCLASS from winternl.h
		const PROCESSINFOCLASS ProcessCommandLineInformation = static_cast<PROCESSINFOCLASS>(60);

		// First call to get required buffer size
		ULONG returnLength = 0;
		NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, nullptr, 0, &returnLength);

		if (returnLength == 0)
		{
			CloseHandle(hProcess);
			return exeName;
		}

		// Allocate buffer and query again
		std::vector<BYTE> buffer(returnLength);
		status = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, buffer.data(), returnLength, &returnLength);

		if (status != 0)
		{
			CloseHandle(hProcess);
			return exeName;
		}

		// The buffer contains a UNICODE_STRING-like structure (same layout as CommandLineInfo)
		CommandLineInfo* cmdLine = reinterpret_cast<CommandLineInfo*>(buffer.data());
		if (cmdLine->Length > 0 && cmdLine->Buffer)
		{
			// Convert wide string to UTF-8
			int size = WideCharToMultiByte(CP_UTF8, 0, cmdLine->Buffer, cmdLine->Length / sizeof(WCHAR), nullptr, 0, nullptr, nullptr);
			if (size > 0)
			{
				std::string result(size, '\0');
				WideCharToMultiByte(CP_UTF8, 0, cmdLine->Buffer, cmdLine->Length / sizeof(WCHAR), &result[0], size, nullptr, nullptr);
				CloseHandle(hProcess);
				return result;
			}
		}

		CloseHandle(hProcess);
		return exeName;
	}


	std::vector<DebugProcess> WindowsDebugEngine::GetProcessList()
	{
		std::vector<DebugProcess> processes;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return processes;

		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapshot, &pe32))
		{
			do
			{
				DebugProcess proc;
				proc.m_pid = pe32.th32ProcessID;
				proc.m_processName = pe32.szExeFile;
				proc.m_commandLine = GetProcessCommandLine(pe32.th32ProcessID, pe32.szExeFile);
				processes.push_back(proc);
			} while (Process32Next(snapshot, &pe32));
		}

		CloseHandle(snapshot);
		return processes;
	}


	std::vector<DebugThread> WindowsDebugEngine::GetThreadList()
	{
		std::vector<DebugThread> threads;

		for (const auto& [tid, handle] : m_threads)
		{
			DebugThread thread;
			thread.m_tid = tid;

			// Get thread instruction pointer
			if (handle)
			{
				if (m_isTargetWow64)
				{
					WOW64_CONTEXT ctx {};
					ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
					if (Wow64GetThreadContext(handle, &ctx))
						thread.m_rip = ctx.Eip;
				}
				else
				{
					CONTEXT ctx {};
					ctx.ContextFlags = CONTEXT_CONTROL;
					if (GetThreadContext(handle, &ctx))
						thread.m_rip = ctx.Rip;
				}
			}
			threads.push_back(thread);
		}

		return threads;
	}


	DebugThread WindowsDebugEngine::GetActiveThread() const
	{
		DebugThread thread;
		thread.m_tid = m_activeThreadId;

		auto it = m_threads.find(m_activeThreadId);
		if (it != m_threads.end() && it->second)
		{
			if (m_isTargetWow64)
			{
				WOW64_CONTEXT ctx {};
				ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
				if (Wow64GetThreadContext(it->second, &ctx))
					thread.m_rip = ctx.Eip;
			}
			else
			{
				CONTEXT ctx {};
				ctx.ContextFlags = CONTEXT_CONTROL;
				if (GetThreadContext(it->second, &ctx))
					thread.m_rip = ctx.Rip;
			}
		}

		return thread;
	}


	std::uint32_t WindowsDebugEngine::GetActiveThreadId() const
	{
		return m_activeThreadId;
	}


	bool WindowsDebugEngine::SetActiveThread(const DebugThread& thread)
	{
		return SetActiveThreadId(thread.m_tid);
	}


	bool WindowsDebugEngine::SetActiveThreadId(std::uint32_t tid)
	{
		if (m_threads.find(tid) == m_threads.end())
			return false;

		m_activeThreadId = tid;
		return true;
	}


	bool WindowsDebugEngine::SuspendThread(std::uint32_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
			return false;

		return ::SuspendThread(it->second) != (DWORD)-1;
	}


	bool WindowsDebugEngine::ResumeThread(std::uint32_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
			return false;

		return ::ResumeThread(it->second) != (DWORD)-1;
	}


	DebugBreakpoint WindowsDebugEngine::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags)
	{
		std::lock_guard<std::mutex> lock(m_breakpointsMutex);

		// Check if breakpoint already exists
		for (auto& bp : m_breakpoints)
		{
			if (bp.address == address)
			{
				// If the breakpoint exists but isn't active yet, try to apply it now
				if (!bp.isActive && m_processHandle)
				{
					ApplyBreakpoint(address, bp.id);
				}
				return DebugBreakpoint(address, bp.id, bp.isActive);
			}
		}

		unsigned long id = m_nextBreakpointId++;

		InternalBreakpoint bp;
		bp.address = address;
		bp.id = id;
		bp.isActive = false;
		bp.originalByte = 0;

		// Add to vector first so ApplyBreakpoint can update it
		m_breakpoints.push_back(bp);

		// Try to apply the breakpoint if we're attached
		if (m_processHandle)
		{
			if (!ApplyBreakpoint(address, id))
			{
				LogWarn("Failed to apply breakpoint at 0x%llX", address);
			}
			else
			{
				LogVerbose("Successfully applied breakpoint at 0x%llX", address);
			}
		}

		// Return the updated state
		for (const auto& b : m_breakpoints)
		{
			if (b.address == address)
				return DebugBreakpoint(address, b.id, b.isActive);
		}
		return DebugBreakpoint(address, id, false);
	}


	DebugBreakpoint WindowsDebugEngine::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
	{
		// Try to resolve the address immediately
		uint64_t resolved = ResolveModuleOffset(address);

		if (resolved != 0)
		{
			return AddBreakpoint(resolved, breakpoint_type);
		}

		// Add to pending breakpoints
		std::lock_guard<std::mutex> lock(m_breakpointsMutex);
		m_pendingBreakpoints.push_back(address);

		// Return a placeholder breakpoint
		return DebugBreakpoint(0, m_nextBreakpointId++, false);
	}


	bool WindowsDebugEngine::ApplyBreakpoint(uint64_t address, unsigned long id)
	{
		// Find the breakpoint record first
		InternalBreakpoint* targetBp = nullptr;
		for (auto& bp : m_breakpoints)
		{
			if (bp.address == address)
			{
				targetBp = &bp;
				break;
			}
		}

		if (!targetBp)
			return false;

		// Read the current byte from memory - this is the actual original byte we need to save
		uint8_t currentByte;
		SIZE_T bytesRead;
		if (!ReadProcessMemory(m_processHandle, (LPCVOID)address, &currentByte, 1, &bytesRead) || bytesRead != 1)
		{
			LogWarn("ApplyBreakpoint: Failed to read memory at 0x%llX, error=%d", address, GetLastError());
			return false;
		}

		// If the byte is already INT3, the breakpoint is already applied
		if (currentByte == INT3_OPCODE)
		{
			// If we already have a saved original byte, we're good - just ensure isActive is set
			if (targetBp->hasOriginalByte)
			{
				targetBp->isActive = true;
				return true;
			}
			// Otherwise we have a problem - INT3 is there but we don't know the original byte
			// This shouldn't happen in normal operation
			LogWarn("ApplyBreakpoint: INT3 already at 0x%llX but no original byte saved", address);
			return false;
		}

		// Save the original byte read from memory (the actual byte, not from binary view)
		targetBp->originalByte = currentByte;
		targetBp->hasOriginalByte = true;

		// Write INT3
		DWORD oldProtect;
		if (!VirtualProtectEx(m_processHandle, (LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			LogWarn("ApplyBreakpoint: Failed to change protection at 0x%llX, error=%d", address, GetLastError());
			return false;
		}

		SIZE_T bytesWritten;
		uint8_t int3 = INT3_OPCODE;
		bool success = WriteProcessMemory(m_processHandle, (LPVOID)address, &int3, 1, &bytesWritten) && bytesWritten == 1;

		if (!success)
		{
			LogWarn("ApplyBreakpoint: Failed to write INT3 at 0x%llX, error=%d", address, GetLastError());
		}
		else
		{
			// WriteProcessMemory() only guarantees the byte lands in the target's memory, not that a
			// thread already executing (or about to fetch) this address sees it -- unlike same-thread
			// self-modifying code, x86/x64 doesn't automatically keep a cross-process data write
			// coherent with the instruction stream. FlushInstructionCache() is what MSDN's
			// WriteProcessMemory docs say is required after writing to code; without it, a breakpoint
			// set on a target that's already running (as opposed to one set before Launch/Attach, before
			// this address was ever fetched) can silently never trigger even though the write itself
			// succeeded.
			FlushInstructionCache(m_processHandle, (LPCVOID)address, 1);
		}

		VirtualProtectEx(m_processHandle, (LPVOID)address, 1, oldProtect, &oldProtect);

		if (success)
		{
			targetBp->isActive = true;
		}

		return success;
	}


	bool WindowsDebugEngine::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
	{
		std::lock_guard<std::mutex> lock(m_breakpointsMutex);

		for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); ++it)
		{
			if (it->address == breakpoint.m_address || it->id == breakpoint.m_id)
			{
				if (it->isActive)
					RemoveBreakpointInternal(it->address);

				m_breakpoints.erase(it);
				return true;
			}
		}

		return false;
	}


	bool WindowsDebugEngine::RemoveBreakpoint(const ModuleNameAndOffset& breakpoint)
	{
		uint64_t address = ResolveModuleOffset(breakpoint);
		if (address == 0)
		{
			// Remove from pending
			std::lock_guard<std::mutex> lock(m_breakpointsMutex);
			auto it = std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), breakpoint);
			if (it != m_pendingBreakpoints.end())
			{
				m_pendingBreakpoints.erase(it);
				return true;
			}
			return false;
		}

		return RemoveBreakpoint(DebugBreakpoint(address));
	}


	void WindowsDebugEngine::RemoveAllBreakpoints()
	{
		// Remove software breakpoints
		{
			std::lock_guard<std::mutex> lock(m_breakpointsMutex);
			for (auto& bp : m_breakpoints)
			{
				if (bp.isActive)
					RemoveBreakpointInternal(bp.address);
			}
			m_breakpoints.clear();
		}

		// Remove hardware breakpoints from all threads
		{
			std::lock_guard<std::mutex> lock(m_hwBreakpointsMutex);
			for (const auto& hwbp : m_hardwareBreakpoints)
			{
				if (hwbp.isActive)
				{
					for (auto& [tid, handle] : m_threads)
					{
						if (!handle)
							continue;
						if (m_isTargetWow64)
						{
							WOW64_CONTEXT ctx {};
							ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
							if (Wow64GetThreadContext(handle, &ctx))
							{
								if (ClearHardwareBreakpointInContext(ctx, hwbp.drIndex))
									Wow64SetThreadContext(handle, &ctx);
							}
						}
						else
						{
							CONTEXT ctx {};
							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							if (GetThreadContext(handle, &ctx))
							{
								if (ClearHardwareBreakpointInContext(ctx, hwbp.drIndex))
									SetThreadContext(handle, &ctx);
							}
						}
					}
				}
			}
			m_hardwareBreakpoints.clear();
		}
	}


	bool WindowsDebugEngine::RemoveBreakpointInternal(uint64_t address)
	{
		// Find the breakpoint to get the original byte
		uint8_t originalByte = 0;
		for (const auto& bp : m_breakpoints)
		{
			if (bp.address == address)
			{
				originalByte = bp.originalByte;
				break;
			}
		}

		DWORD oldProtect;
		if (!VirtualProtectEx(m_processHandle, (LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
			return false;

		SIZE_T bytesWritten;
		bool success = WriteProcessMemory(m_processHandle, (LPVOID)address, &originalByte, 1, &bytesWritten) && bytesWritten == 1;

		// Same reasoning as ApplyBreakpoint() -- flush so a thread already running near this address
		// picks up the restored original byte instead of a stale cached INT3.
		if (success)
			FlushInstructionCache(m_processHandle, (LPCVOID)address, 1);

		VirtualProtectEx(m_processHandle, (LPVOID)address, 1, oldProtect, &oldProtect);

		return success;
	}


	void WindowsDebugEngine::ApplyPendingBreakpoints()
	{
		std::lock_guard<std::mutex> lock(m_breakpointsMutex);

		// Re-apply existing breakpoints that are inactive (e.g., from a previous debug session)
		for (auto& bp : m_breakpoints)
		{
			if (!bp.isActive)
			{
				ApplyBreakpoint(bp.address, bp.id);
			}
		}

		// Apply pending breakpoints (ModuleNameAndOffset style that need resolution)
		auto it = m_pendingBreakpoints.begin();
		while (it != m_pendingBreakpoints.end())
		{
			uint64_t address = ResolveModuleOffset(*it);
			if (address != 0)
			{
				// Create and apply the breakpoint
				InternalBreakpoint bp;
				bp.address = address;
				bp.id = m_nextBreakpointId++;
				bp.isActive = false;
				bp.originalByte = 0;

				// Add to vector first so ApplyBreakpoint can update it
				m_breakpoints.push_back(bp);

				ApplyBreakpoint(address, bp.id);

				it = m_pendingBreakpoints.erase(it);
			}
			else
			{
				++it;
			}
		}

		// Re-apply existing hardware breakpoints that are inactive (e.g., from a previous debug session)
		{
			std::lock_guard<std::mutex> hwLock(m_hwBreakpointsMutex);
			for (auto& hwbp : m_hardwareBreakpoints)
			{
				if (!hwbp.isActive)
				{
					// Find a free debug register
					int drIndex = FindFreeDebugRegister();
					if (drIndex < 0)
					{
						LogError("No free debug registers available for hardware breakpoint re-apply");
						continue;
					}

					hwbp.drIndex = drIndex;
					hwbp.isActive = true;

					// Apply to all threads
					for (auto& [tid, handle] : m_threads)
					{
						if (handle)
						{
							if (m_isTargetWow64)
							{
								WOW64_CONTEXT ctx {};
								ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
								if (Wow64GetThreadContext(handle, &ctx))
								{
									if (SetHardwareBreakpointInContext(ctx, drIndex, hwbp.address, hwbp.type, hwbp.size))
									{
										Wow64SetThreadContext(handle, &ctx);
									}
								}
							}
							else
							{
								CONTEXT ctx {};
								ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
								if (GetThreadContext(handle, &ctx))
								{
									if (SetHardwareBreakpointInContext(ctx, drIndex, hwbp.address, hwbp.type, hwbp.size))
									{
										SetThreadContext(handle, &ctx);
									}
								}
							}
						}
					}
				}
			}
		}

		// Also try pending hardware breakpoints - collect them first, then apply outside the lock
		std::vector<PendingHardwareBreakpoint> toApply;
		{
			std::lock_guard<std::mutex> hwLock(m_hwBreakpointsMutex);
			auto hwIt = m_pendingHardwareBreakpoints.begin();
			while (hwIt != m_pendingHardwareBreakpoints.end())
			{
				if (hwIt->isRelative)
				{
					uint64_t address = ResolveModuleOffset(hwIt->location);
					if (address != 0)
					{
						PendingHardwareBreakpoint resolved(address, hwIt->type, hwIt->size);
						toApply.push_back(resolved);
						hwIt = m_pendingHardwareBreakpoints.erase(hwIt);
						continue;
					}
				}
				++hwIt;
			}
		}

		// Apply the resolved pending hardware breakpoints outside the lock
		for (const auto& pending : toApply)
		{
			AddHardwareBreakpoint(pending.address, pending.type, pending.size);
		}
	}


	uint64_t WindowsDebugEngine::ResolveModuleOffset(const ModuleNameAndOffset& location)
	{
		std::lock_guard<std::mutex> lock(m_modulesMutex);

		for (const auto& module : m_modules)
		{
			if (module.IsSameBaseModule(location.module))
			{
				return module.m_address + location.offset;
			}
		}

		return 0;
	}


	bool WindowsDebugEngine::SetTempBreakpoint(uint64_t address)
	{
		if (m_hasTempBreakpoint)
			RemoveTempBreakpoint();

		// Read original byte
		SIZE_T bytesRead;
		if (!ReadProcessMemory(m_processHandle, (LPCVOID)address, &m_tempBreakpointOriginalByte, 1, &bytesRead) || bytesRead != 1)
			return false;

		// Write INT3
		DWORD oldProtect;
		if (!VirtualProtectEx(m_processHandle, (LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
			return false;

		SIZE_T bytesWritten;
		uint8_t int3 = INT3_OPCODE;
		bool success = WriteProcessMemory(m_processHandle, (LPVOID)address, &int3, 1, &bytesWritten) && bytesWritten == 1;

		// Same reasoning as ApplyBreakpoint() -- this temp breakpoint is written while the target is
		// actively running (that's the whole point of a run-to/step-over temp breakpoint), so it needs
		// the flush at least as much as a regular breakpoint set before launch would.
		if (success)
			FlushInstructionCache(m_processHandle, (LPCVOID)address, 1);

		VirtualProtectEx(m_processHandle, (LPVOID)address, 1, oldProtect, &oldProtect);

		if (success)
		{
			m_tempBreakpointAddress = address;
			m_hasTempBreakpoint = true;
		}

		return success;
	}


	bool WindowsDebugEngine::RemoveTempBreakpoint()
	{
		if (!m_hasTempBreakpoint)
			return true;

		// Restore original byte
		DWORD oldProtect;
		if (!VirtualProtectEx(m_processHandle, (LPVOID)m_tempBreakpointAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
			return false;

		SIZE_T bytesWritten;
		bool success = WriteProcessMemory(m_processHandle, (LPVOID)m_tempBreakpointAddress,
			&m_tempBreakpointOriginalByte, 1, &bytesWritten) && bytesWritten == 1;

		// Same reasoning as ApplyBreakpoint() -- the target resumes executing right after this restore,
		// at the address whose byte just changed back.
		if (success)
			FlushInstructionCache(m_processHandle, (LPCVOID)m_tempBreakpointAddress, 1);

		VirtualProtectEx(m_processHandle, (LPVOID)m_tempBreakpointAddress, 1, oldProtect, &oldProtect);

		m_hasTempBreakpoint = false;
		m_tempBreakpointAddress = 0;

		return success;
	}


	bool WindowsDebugEngine::IsCallInstruction(uint64_t address, size_t& instrLength)
	{
		uint8_t bytes[16];
		SIZE_T bytesRead;

		if (!ReadProcessMemory(m_processHandle, (LPCVOID)address, bytes, sizeof(bytes), &bytesRead) || bytesRead < 2)
			return false;

		// Check for various call instruction encodings
		// E8 xx xx xx xx - near relative call (5 bytes)
		if (bytes[0] == 0xE8)
		{
			instrLength = 5;
			return true;
		}

		// 9A xx xx xx xx xx xx - far absolute call (7 bytes, rare in 64-bit)
		if (bytes[0] == 0x9A)
		{
			instrLength = 7;
			return true;
		}

		// FF /2 - call r/m (variable length)
		if (bytes[0] == 0xFF)
		{
			uint8_t modrm = bytes[1];
			uint8_t reg = (modrm >> 3) & 7;
			if (reg == 2)  // /2 = CALL
			{
				uint8_t mod = modrm >> 6;
				uint8_t rm = modrm & 7;

				instrLength = 2;  // opcode + modrm

				if (mod == 3)
				{
					// Register direct - just 2 bytes
					return true;
				}

				// Handle SIB byte
				if (rm == 4 && mod != 3)
					instrLength++;

				// Handle displacement
				if (mod == 1)
					instrLength += 1;  // disp8
				else if (mod == 2 || (mod == 0 && rm == 5))
					instrLength += 4;  // disp32

				return true;
			}
		}

		// REX prefix + FF /2 (64-bit)
		if ((bytes[0] >= 0x40 && bytes[0] <= 0x4F) && bytes[1] == 0xFF)
		{
			uint8_t modrm = bytes[2];
			uint8_t reg = (modrm >> 3) & 7;
			if (reg == 2)  // /2 = CALL
			{
				uint8_t mod = modrm >> 6;
				uint8_t rm = modrm & 7;

				instrLength = 3;  // rex + opcode + modrm

				if (mod == 3)
					return true;

				// Handle SIB byte
				if (rm == 4 && mod != 3)
					instrLength++;

				// Handle displacement
				if (mod == 1)
					instrLength += 1;
				else if (mod == 2 || (mod == 0 && rm == 5))
					instrLength += 4;

				return true;
			}
		}

		return false;
	}


	uint64_t WindowsDebugEngine::GetReturnAddress()
	{
		auto it = m_threads.find(m_activeThreadId);
		if (it == m_threads.end() || !it->second)
			return 0;

		uint64_t sp;
		SIZE_T bytesRead;
		uint64_t returnAddr = 0;

		if (m_isTargetWow64)
		{
			// 32-bit process
			WOW64_CONTEXT ctx {};
			ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
			if (!Wow64GetThreadContext(it->second, &ctx))
				return 0;

			sp = ctx.Esp;

			// Read 32-bit return address from stack
			uint32_t addr32;
			if (!ReadProcessMemory(m_processHandle, (LPCVOID)sp, &addr32, 4, &bytesRead) || bytesRead != 4)
				return 0;
			returnAddr = addr32;
		}
		else
		{
			// 64-bit process
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(it->second, &ctx))
				return 0;

			sp = ctx.Rsp;

			// Read 64-bit return address from stack
			if (!ReadProcessMemory(m_processHandle, (LPCVOID)sp, &returnAddr, 8, &bytesRead) || bytesRead != 8)
				return 0;
		}

		return returnAddr;
	}


	std::vector<DebugBreakpoint> WindowsDebugEngine::GetBreakpointList() const
	{
		std::vector<DebugBreakpoint> result;

		// Note: Can't lock mutex in const method, but this is called from the session layer
		// which should ensure proper synchronization.
		for (const auto& bp : m_breakpoints)
		{
			result.emplace_back(bp.address, bp.id, bp.isActive);
		}

		return result;
	}


	bool WindowsDebugEngine::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
	{
		std::lock_guard<std::mutex> lock(m_hwBreakpointsMutex);

		// Check if we already have this breakpoint
		for (auto& bp : m_hardwareBreakpoints)
		{
			if (bp.address == address && bp.type == type && bp.size == size)
			{
				// If already active, nothing to do
				if (bp.isActive)
					return true;

				// Re-apply the inactive breakpoint
				int drIndex = FindFreeDebugRegister();
				if (drIndex < 0)
				{
					LogError("No free debug registers available");
					return false;
				}

				bp.drIndex = drIndex;
				bp.isActive = true;

				// Apply to all threads
				for (auto& [tid, handle] : m_threads)
				{
					if (handle)
					{
						if (m_isTargetWow64)
						{
							WOW64_CONTEXT ctx {};
							ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
							if (Wow64GetThreadContext(handle, &ctx))
							{
								if (SetHardwareBreakpointInContext(ctx, drIndex, address, type, size))
								{
									Wow64SetThreadContext(handle, &ctx);
								}
							}
						}
						else
						{
							CONTEXT ctx {};
							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							if (GetThreadContext(handle, &ctx))
							{
								if (SetHardwareBreakpointInContext(ctx, drIndex, address, type, size))
								{
									SetThreadContext(handle, &ctx);
								}
							}
						}
					}
				}
				return true;
			}
		}

		// Find a free debug register
		int drIndex = FindFreeDebugRegister();
		if (drIndex < 0)
		{
			LogError("No free debug registers available");
			return false;
		}

		InternalHardwareBreakpoint hwBp(address, type, size, drIndex);
		hwBp.isActive = true;

		// Apply to all threads
		for (auto& [tid, handle] : m_threads)
		{
			if (handle)
			{
				if (m_isTargetWow64)
				{
					WOW64_CONTEXT ctx {};
					ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
					if (Wow64GetThreadContext(handle, &ctx))
					{
						if (SetHardwareBreakpointInContext(ctx, drIndex, address, type, size))
						{
							Wow64SetThreadContext(handle, &ctx);
						}
					}
				}
				else
				{
					CONTEXT ctx {};
					ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
					if (GetThreadContext(handle, &ctx))
					{
						if (SetHardwareBreakpointInContext(ctx, drIndex, address, type, size))
						{
							SetThreadContext(handle, &ctx);
						}
					}
				}
			}
		}

		m_hardwareBreakpoints.push_back(hwBp);
		return true;
	}


	bool WindowsDebugEngine::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
	{
		std::lock_guard<std::mutex> lock(m_hwBreakpointsMutex);

		for (auto it = m_hardwareBreakpoints.begin(); it != m_hardwareBreakpoints.end(); ++it)
		{
			if (it->address == address && it->type == type && it->size == size)
			{
				int drIndex = it->drIndex;

				// Remove from all threads
				for (auto& [tid, handle] : m_threads)
				{
					if (handle)
					{
						if (m_isTargetWow64)
						{
							WOW64_CONTEXT ctx {};
							ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
							if (Wow64GetThreadContext(handle, &ctx))
							{
								if (ClearHardwareBreakpointInContext(ctx, drIndex))
								{
									Wow64SetThreadContext(handle, &ctx);
								}
							}
						}
						else
						{
							CONTEXT ctx {};
							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							if (GetThreadContext(handle, &ctx))
							{
								if (ClearHardwareBreakpointInContext(ctx, drIndex))
								{
									SetThreadContext(handle, &ctx);
								}
							}
						}
					}
				}

				m_hardwareBreakpoints.erase(it);
				return true;
			}
		}

		return false;
	}


	bool WindowsDebugEngine::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
	{
		uint64_t address = ResolveModuleOffset(location);
		if (address != 0)
		{
			return AddHardwareBreakpoint(address, type, size);
		}

		// Add to pending
		std::lock_guard<std::mutex> lock(m_hwBreakpointsMutex);
		m_pendingHardwareBreakpoints.emplace_back(location, type, size);
		return true;
	}


	bool WindowsDebugEngine::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
	{
		uint64_t address = ResolveModuleOffset(location);
		if (address != 0)
		{
			return RemoveHardwareBreakpoint(address, type, size);
		}

		// Remove from pending
		std::lock_guard<std::mutex> lock(m_hwBreakpointsMutex);
		for (auto it = m_pendingHardwareBreakpoints.begin(); it != m_pendingHardwareBreakpoints.end(); ++it)
		{
			if (it->isRelative && it->location == location && it->type == type && it->size == size)
			{
				m_pendingHardwareBreakpoints.erase(it);
				return true;
			}
		}

		return false;
	}


	int WindowsDebugEngine::FindFreeDebugRegister()
	{
		bool used[4] = { false, false, false, false };

		for (const auto& bp : m_hardwareBreakpoints)
		{
			if (bp.drIndex >= 0 && bp.drIndex < 4)
				used[bp.drIndex] = true;
		}

		for (int i = 0; i < 4; ++i)
		{
			if (!used[i])
				return i;
		}

		return -1;
	}


	bool WindowsDebugEngine::SetHardwareBreakpointInContext(CONTEXT& ctx, int drIndex, uint64_t address, DebugBreakpointType type, size_t size)
	{
		// Set the address in the debug register
		switch (drIndex)
		{
		case 0: ctx.Dr0 = address; break;
		case 1: ctx.Dr1 = address; break;
		case 2: ctx.Dr2 = address; break;
		case 3: ctx.Dr3 = address; break;
		default: return false;
		}

		// Calculate condition bits (RW field)
		// 00 = Execute, 01 = Write, 10 = I/O (not used), 11 = Read/Write
		DWORD64 condition;
		switch (type)
		{
		case HardwareExecuteBreakpoint: condition = 0; break;
		case HardwareWriteBreakpoint: condition = 1; break;
		case HardwareReadBreakpoint: condition = 3; break;  // Use R/W for read
		case HardwareAccessBreakpoint: condition = 3; break;
		default: return false;
		}

		// Calculate size bits (LEN field)
		// 00 = 1 byte, 01 = 2 bytes, 10 = 8 bytes (x64), 11 = 4 bytes
		DWORD64 len;
		switch (size)
		{
		case 1: len = 0; break;
		case 2: len = 1; break;
		case 4: len = 3; break;
		case 8: len = 2; break;
		default: return false;
		}

		// Clear existing bits for this breakpoint
		int shift = drIndex * 4 + 16;
		ctx.Dr7 &= ~(0xFULL << shift);
		ctx.Dr7 &= ~(3ULL << (drIndex * 2));

		// Set the new bits
		ctx.Dr7 |= (condition << shift);
		ctx.Dr7 |= (len << (shift + 2));
		ctx.Dr7 |= (1ULL << (drIndex * 2));  // Enable local breakpoint

		return true;
	}


	bool WindowsDebugEngine::ClearHardwareBreakpointInContext(CONTEXT& ctx, int drIndex)
	{
		// Clear the address
		switch (drIndex)
		{
		case 0: ctx.Dr0 = 0; break;
		case 1: ctx.Dr1 = 0; break;
		case 2: ctx.Dr2 = 0; break;
		case 3: ctx.Dr3 = 0; break;
		default: return false;
		}

		// Clear the control bits
		int shift = drIndex * 4 + 16;
		ctx.Dr7 &= ~(0xFULL << shift);
		ctx.Dr7 &= ~(3ULL << (drIndex * 2));

		return true;
	}


	// WOW64 overload for SetHardwareBreakpointInContext
	bool WindowsDebugEngine::SetHardwareBreakpointInContext(WOW64_CONTEXT& ctx, int drIndex, uint64_t address, DebugBreakpointType type, size_t size)
	{
		// Set the address in the debug register (32-bit for WOW64)
		DWORD addr32 = static_cast<DWORD>(address);
		switch (drIndex)
		{
		case 0: ctx.Dr0 = addr32; break;
		case 1: ctx.Dr1 = addr32; break;
		case 2: ctx.Dr2 = addr32; break;
		case 3: ctx.Dr3 = addr32; break;
		default: return false;
		}

		// Calculate condition bits (RW field)
		DWORD condition;
		switch (type)
		{
		case HardwareExecuteBreakpoint: condition = 0; break;
		case HardwareWriteBreakpoint: condition = 1; break;
		case HardwareReadBreakpoint: condition = 3; break;
		case HardwareAccessBreakpoint: condition = 3; break;
		default: return false;
		}

		// Calculate size bits (LEN field)
		// 00 = 1 byte, 01 = 2 bytes, 11 = 4 bytes (no 8-byte for 32-bit)
		DWORD len;
		switch (size)
		{
		case 1: len = 0; break;
		case 2: len = 1; break;
		case 4: len = 3; break;
		default: len = 0; break;  // Default to 1 byte
		}

		// Update DR7
		int shift = drIndex * 4 + 16;
		ctx.Dr7 &= ~(0xFUL << shift);
		ctx.Dr7 |= (condition << shift);
		ctx.Dr7 |= (len << (shift + 2));
		ctx.Dr7 |= (1UL << (drIndex * 2));  // Enable local breakpoint

		return true;
	}


	// WOW64 overload for ClearHardwareBreakpointInContext
	bool WindowsDebugEngine::ClearHardwareBreakpointInContext(WOW64_CONTEXT& ctx, int drIndex)
	{
		// Clear the address
		switch (drIndex)
		{
		case 0: ctx.Dr0 = 0; break;
		case 1: ctx.Dr1 = 0; break;
		case 2: ctx.Dr2 = 0; break;
		case 3: ctx.Dr3 = 0; break;
		default: return false;
		}

		// Clear the control bits
		int shift = drIndex * 4 + 16;
		ctx.Dr7 &= ~(0xFUL << shift);
		ctx.Dr7 &= ~(3UL << (drIndex * 2));

		return true;
	}


	bool WindowsDebugEngine::ApplyHardwareBreakpointsToThread(HANDLE threadHandle)
	{
		if (m_hardwareBreakpoints.empty())
			return true;

		if (m_isTargetWow64)
		{
			WOW64_CONTEXT ctx {};
			ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
			if (!Wow64GetThreadContext(threadHandle, &ctx))
				return false;

			for (const auto& bp : m_hardwareBreakpoints)
			{
				if (bp.isActive)
				{
					SetHardwareBreakpointInContext(ctx, bp.drIndex, bp.address, bp.type, bp.size);
				}
			}

			return Wow64SetThreadContext(threadHandle, &ctx) != 0;
		}
		else
		{
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (!GetThreadContext(threadHandle, &ctx))
				return false;

			for (const auto& bp : m_hardwareBreakpoints)
			{
				if (bp.isActive)
				{
					SetHardwareBreakpointInContext(ctx, bp.drIndex, bp.address, bp.type, bp.size);
				}
			}

			return SetThreadContext(threadHandle, &ctx) != 0;
		}
	}


	std::unordered_map<std::string, DebugRegister> WindowsDebugEngine::ReadAllRegisters()
	{
		std::unordered_map<std::string, DebugRegister> registers;

		auto it = m_threads.find(m_activeThreadId);
		if (it == m_threads.end() || !it->second)
			return registers;

		if (m_isTargetWow64)
		{
			// 32-bit process on 64-bit Windows - use Wow64 API
			WOW64_CONTEXT ctx {};
			ctx.ContextFlags = WOW64_CONTEXT_ALL;
			if (!Wow64GetThreadContext(it->second, &ctx))
				return registers;

			registers["eax"] = DebugRegister("eax", ctx.Eax, 4, 0);
			registers["ebx"] = DebugRegister("ebx", ctx.Ebx, 4, 1);
			registers["ecx"] = DebugRegister("ecx", ctx.Ecx, 4, 2);
			registers["edx"] = DebugRegister("edx", ctx.Edx, 4, 3);
			registers["esi"] = DebugRegister("esi", ctx.Esi, 4, 4);
			registers["edi"] = DebugRegister("edi", ctx.Edi, 4, 5);
			registers["ebp"] = DebugRegister("ebp", ctx.Ebp, 4, 6);
			registers["esp"] = DebugRegister("esp", ctx.Esp, 4, 7);
			registers["eip"] = DebugRegister("eip", ctx.Eip, 4, 8);
			registers["eflags"] = DebugRegister("eflags", ctx.EFlags, 4, 9);
			registers["cs"] = DebugRegister("cs", ctx.SegCs, 2, 10);
			registers["ds"] = DebugRegister("ds", ctx.SegDs, 2, 11);
			registers["es"] = DebugRegister("es", ctx.SegEs, 2, 12);
			registers["fs"] = DebugRegister("fs", ctx.SegFs, 2, 13);
			registers["gs"] = DebugRegister("gs", ctx.SegGs, 2, 14);
			registers["ss"] = DebugRegister("ss", ctx.SegSs, 2, 15);
		}
		else
		{
			// 64-bit process
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_ALL;
			if (!GetThreadContext(it->second, &ctx))
				return registers;

			registers["rax"] = DebugRegister("rax", ctx.Rax, 8, 0);
			registers["rbx"] = DebugRegister("rbx", ctx.Rbx, 8, 1);
			registers["rcx"] = DebugRegister("rcx", ctx.Rcx, 8, 2);
			registers["rdx"] = DebugRegister("rdx", ctx.Rdx, 8, 3);
			registers["rsi"] = DebugRegister("rsi", ctx.Rsi, 8, 4);
			registers["rdi"] = DebugRegister("rdi", ctx.Rdi, 8, 5);
			registers["rbp"] = DebugRegister("rbp", ctx.Rbp, 8, 6);
			registers["rsp"] = DebugRegister("rsp", ctx.Rsp, 8, 7);
			registers["r8"] = DebugRegister("r8", ctx.R8, 8, 8);
			registers["r9"] = DebugRegister("r9", ctx.R9, 8, 9);
			registers["r10"] = DebugRegister("r10", ctx.R10, 8, 10);
			registers["r11"] = DebugRegister("r11", ctx.R11, 8, 11);
			registers["r12"] = DebugRegister("r12", ctx.R12, 8, 12);
			registers["r13"] = DebugRegister("r13", ctx.R13, 8, 13);
			registers["r14"] = DebugRegister("r14", ctx.R14, 8, 14);
			registers["r15"] = DebugRegister("r15", ctx.R15, 8, 15);
			registers["rip"] = DebugRegister("rip", ctx.Rip, 8, 16);
			registers["rflags"] = DebugRegister("rflags", ctx.EFlags, 4, 17);
			registers["cs"] = DebugRegister("cs", ctx.SegCs, 2, 18);
			registers["ds"] = DebugRegister("ds", ctx.SegDs, 2, 19);
			registers["es"] = DebugRegister("es", ctx.SegEs, 2, 20);
			registers["fs"] = DebugRegister("fs", ctx.SegFs, 2, 21);
			registers["gs"] = DebugRegister("gs", ctx.SegGs, 2, 22);
			registers["ss"] = DebugRegister("ss", ctx.SegSs, 2, 23);
		}

		return registers;
	}


	DebugRegister WindowsDebugEngine::ReadRegister(const std::string& reg)
	{
		auto registers = ReadAllRegisters();
		auto it = registers.find(reg);
		if (it != registers.end())
			return it->second;

		return DebugRegister();
	}


	bool WindowsDebugEngine::WriteRegister(const std::string& reg, uint64_t value)
	{
		auto it = m_threads.find(m_activeThreadId);
		if (it == m_threads.end() || !it->second)
			return false;

		uint64_t val64 = value;

		if (m_isTargetWow64)
		{
			// 32-bit process on 64-bit Windows - use WOW64_CONTEXT
			WOW64_CONTEXT ctx {};
			ctx.ContextFlags = WOW64_CONTEXT_ALL;
			if (!Wow64GetThreadContext(it->second, &ctx))
				return false;

			DWORD val32 = static_cast<DWORD>(val64);
			if (reg == "eax") ctx.Eax = val32;
			else if (reg == "ebx") ctx.Ebx = val32;
			else if (reg == "ecx") ctx.Ecx = val32;
			else if (reg == "edx") ctx.Edx = val32;
			else if (reg == "esi") ctx.Esi = val32;
			else if (reg == "edi") ctx.Edi = val32;
			else if (reg == "ebp") ctx.Ebp = val32;
			else if (reg == "esp") ctx.Esp = val32;
			else if (reg == "eip") ctx.Eip = val32;
			else if (reg == "eflags") ctx.EFlags = val32;
			else return false;

			return Wow64SetThreadContext(it->second, &ctx) != 0;
		}
		else
		{
			// Native 64-bit process
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_ALL;
			if (!GetThreadContext(it->second, &ctx))
				return false;

			if (reg == "rax") ctx.Rax = val64;
			else if (reg == "rbx") ctx.Rbx = val64;
			else if (reg == "rcx") ctx.Rcx = val64;
			else if (reg == "rdx") ctx.Rdx = val64;
			else if (reg == "rsi") ctx.Rsi = val64;
			else if (reg == "rdi") ctx.Rdi = val64;
			else if (reg == "rbp") ctx.Rbp = val64;
			else if (reg == "rsp") ctx.Rsp = val64;
			else if (reg == "r8") ctx.R8 = val64;
			else if (reg == "r9") ctx.R9 = val64;
			else if (reg == "r10") ctx.R10 = val64;
			else if (reg == "r11") ctx.R11 = val64;
			else if (reg == "r12") ctx.R12 = val64;
			else if (reg == "r13") ctx.R13 = val64;
			else if (reg == "r14") ctx.R14 = val64;
			else if (reg == "r15") ctx.R15 = val64;
			else if (reg == "rip") ctx.Rip = val64;
			else if (reg == "rflags") ctx.EFlags = static_cast<DWORD>(val64);
			else return false;

			return SetThreadContext(it->second, &ctx) != 0;
		}
	}


	std::vector<uint8_t> WindowsDebugEngine::ReadMemory(std::uintptr_t address, std::size_t size)
	{
		std::vector<uint8_t> buffer(size);
		SIZE_T bytesRead = 0;

		if (!ReadProcessMemory(m_processHandle, (LPCVOID)address, buffer.data(), size, &bytesRead))
		{
			return {};
		}

		// Shadow breakpoint bytes - replace 0xCC with original bytes so reads/disassembly are correct
		{
			std::lock_guard<std::mutex> lock(m_breakpointsMutex);
			for (const auto& bp : m_breakpoints)
			{
				if (bp.isActive && bp.address >= address && bp.address < address + bytesRead)
				{
					size_t offset = bp.address - address;
					buffer[offset] = bp.originalByte;
				}
			}
		}

		// Also shadow temporary breakpoint
		if (m_hasTempBreakpoint && m_tempBreakpointAddress >= address && m_tempBreakpointAddress < address + bytesRead)
		{
			size_t offset = m_tempBreakpointAddress - address;
			buffer[offset] = m_tempBreakpointOriginalByte;
		}

		buffer.resize(bytesRead);
		return buffer;
	}


	bool WindowsDebugEngine::WriteMemory(std::uintptr_t address, const std::vector<uint8_t>& buffer)
	{
		SIZE_T bytesWritten;
		DWORD oldProtect;

		// Try to make memory writable
		VirtualProtectEx(m_processHandle, (LPVOID)address, buffer.size(), PAGE_EXECUTE_READWRITE, &oldProtect);

		bool success = WriteProcessMemory(m_processHandle, (LPVOID)address, buffer.data(),
			buffer.size(), &bytesWritten) && bytesWritten == buffer.size();

		// This RPC can be used to patch code, not just data -- same reasoning as ApplyBreakpoint()
		// applies. Flushing a range that turns out to be pure data is harmless (just a wasted syscall).
		if (success)
			FlushInstructionCache(m_processHandle, (LPCVOID)address, buffer.size());

		// Restore protection
		VirtualProtectEx(m_processHandle, (LPVOID)address, buffer.size(), oldProtect, &oldProtect);

		return success;
	}


	std::vector<DebugModule> WindowsDebugEngine::GetModuleList()
	{
		std::lock_guard<std::mutex> lock(m_modulesMutex);
		return m_modules;
	}


	std::vector<DebugMemoryRegion> WindowsDebugEngine::GetMemoryMap()
	{
		if (!m_processHandle)
			return {};

		std::vector<DebugMemoryRegion> result;

		// Walk the whole virtual address space with VirtualQueryEx, starting at 0 and advancing by each
		// region's size. The query fails once we walk past the end of the user address space, which
		// terminates the loop. Free/reserved regions are reported too (with a size that spans the gap), so
		// skipping them still advances efficiently.
		uintptr_t address = 0;
		MEMORY_BASIC_INFORMATION info = {};
		while (VirtualQueryEx(m_processHandle, (LPCVOID)address, &info, sizeof(info)) == sizeof(info))
		{
			if (info.RegionSize == 0)
				break;

			// Only committed pages are actually mapped. Guard pages and no-access pages are committed but
			// cannot be read, so we exclude them from the "readable" map.
			const DWORD protect = info.Protect & 0xff;  // strip PAGE_GUARD / PAGE_NOCACHE / PAGE_WRITECOMBINE
			if (info.State == MEM_COMMIT && !(info.Protect & PAGE_GUARD) && protect != PAGE_NOACCESS)
			{
				DebugMemoryRegion region;
				region.m_start = (uint64_t)info.BaseAddress;
				region.m_size = info.RegionSize;
				region.m_read = true;  // any committed, non-no-access, non-guard page is readable on x86/x64
				region.m_write = (protect == PAGE_READWRITE) || (protect == PAGE_WRITECOPY)
					|| (protect == PAGE_EXECUTE_READWRITE) || (protect == PAGE_EXECUTE_WRITECOPY);
				region.m_execute = (protect == PAGE_EXECUTE) || (protect == PAGE_EXECUTE_READ)
					|| (protect == PAGE_EXECUTE_READWRITE) || (protect == PAGE_EXECUTE_WRITECOPY);
				// MEM_MAPPED sections (file/pagefile-backed) can be shared between processes; MEM_IMAGE is
				// copy-on-write and MEM_PRIVATE is private.
				region.m_shared = (info.Type == MEM_MAPPED);

				// Image- and file-backed regions have a backing file we can name. Leave the name empty
				// (rather than the helper's "<unknown>" sentinel) for mappings with no resolvable file.
				if (info.Type == MEM_IMAGE || info.Type == MEM_MAPPED)
				{
					std::string name = GetModuleNameFromHandle(nullptr, info.BaseAddress);
					if (name != "<unknown>")
						region.m_name = name;
				}

				result.push_back(region);
			}

			// Advance past this region; stop if the address would wrap around at the top of the space.
			uintptr_t next = (uintptr_t)info.BaseAddress + info.RegionSize;
			if (next <= address)
				break;
			address = next;
		}

		return result;
	}


	std::string WindowsDebugEngine::GetTargetArchitecture()
	{
		// Use cached WOW64 detection result
		if (m_isTargetWow64)
			return "x86";
		return "x86_64";
	}


	DebugStopReason WindowsDebugEngine::StopReason()
	{
		return m_stopReason;
	}


	uint64_t WindowsDebugEngine::ExitCode()
	{
		return m_exitCode;
	}


	bool WindowsDebugEngine::BreakInto()
	{
		if (!m_processHandle)
			return false;

		return DebugBreakProcess(m_processHandle) != 0;
	}


	bool WindowsDebugEngine::Go()
	{
		if (!m_activelyDebugging)
			return false;

		// If we're at a hardware breakpoint, we need to step over it first
		if (m_stepOverHwBreakpointIndex >= 0)
		{
			auto it = m_threads.find(m_activeThreadId);
			if (it != m_threads.end() && it->second)
			{
				if (m_isTargetWow64)
				{
					WOW64_CONTEXT ctx {};
					ctx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_DEBUG_REGISTERS;
					if (Wow64GetThreadContext(it->second, &ctx))
					{
						ctx.Dr7 &= ~(1UL << (m_stepOverHwBreakpointIndex * 2));
						ctx.EFlags |= 0x100;
						Wow64SetThreadContext(it->second, &ctx);
					}
				}
				else
				{
					CONTEXT ctx {};
					ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
					if (GetThreadContext(it->second, &ctx))
					{
						ctx.Dr7 &= ~(1ULL << (m_stepOverHwBreakpointIndex * 2));
						ctx.EFlags |= 0x100;
						SetThreadContext(it->second, &ctx);
					}
				}
			}
			m_hasStepOverHwBreakpoint = true;
			m_stepOverHwBreakpointContinue = true;
		}

		// If we're at a software breakpoint, we need to step over it first
		{
			std::lock_guard<std::mutex> lock(m_breakpointsMutex);
			uint64_t ip = GetInstructionOffset();
			for (const auto& bp : m_breakpoints)
			{
				if (bp.address == ip && bp.isActive)
				{
					// Remove the INT3 so we can execute the actual instruction
					RemoveBreakpointInternal(ip);

					// Need to single step past the breakpoint first
					m_stepOverBreakpointAddress = ip;
					m_hasStepOverBreakpoint = true;
					m_stepOverBreakpointContinue = true;  // Continue after re-applying breakpoint

					// CRITICAL: Suspend all other threads while stepping over the breakpoint
					// This prevents race conditions where another thread could execute the
					// breakpoint location while we have the INT3 removed
					for (const auto& [tid, handle] : m_threads)
					{
						if (tid != m_activeThreadId && handle)
						{
							::SuspendThread(handle);
						}
					}

					// Set single step flag
					auto it = m_threads.find(m_activeThreadId);
					if (it != m_threads.end() && it->second)
					{
						if (m_isTargetWow64)
						{
							WOW64_CONTEXT ctx {};
							ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
							if (Wow64GetThreadContext(it->second, &ctx))
							{
								ctx.EFlags |= 0x100;
								Wow64SetThreadContext(it->second, &ctx);
							}
						}
						else
						{
							CONTEXT ctx {};
							ctx.ContextFlags = CONTEXT_CONTROL;
							if (GetThreadContext(it->second, &ctx))
							{
								ctx.EFlags |= 0x100;
								SetThreadContext(it->second, &ctx);
							}
						}
					}
					break;
				}
			}
		}

		// Note: We don't suspend other threads when we have a temp breakpoint (StepOver/StepReturn).
		// StepOver internally does a "continue" operation with a breakpoint at the return address.
		// During this continue, all threads should run normally. If another thread hits a breakpoint,
		// that's expected behavior (the debugger stops). Only StepInto() uses scheduler-locking.

		// Publish the resume under m_debugMutex so the parked DebugLoop predicate observes it and
		// the notify can't be lost (see Quit for the race detail).
		{
			std::lock_guard<std::mutex> lock(m_debugMutex);
			m_targetRunning = true;
		}
		m_debugCondition.notify_one();

		// Notify that the target has resumed
		EngineEvent event;
		event.type = EngineEventType::Resumed;
		PostEngineEvent(event);

		return true;
	}


	bool WindowsDebugEngine::StepInto()
	{
		if (!m_activelyDebugging)
			return false;

		auto it = m_threads.find(m_activeThreadId);
		if (it == m_threads.end() || !it->second)
			return false;

		// If we're at a hardware breakpoint, we need to temporarily disable it
		if (m_stepOverHwBreakpointIndex >= 0)
		{
			if (m_isTargetWow64)
			{
				WOW64_CONTEXT ctx {};
				ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
				if (Wow64GetThreadContext(it->second, &ctx))
				{
					ctx.Dr7 &= ~(1UL << (m_stepOverHwBreakpointIndex * 2));
					Wow64SetThreadContext(it->second, &ctx);
				}
			}
			else
			{
				CONTEXT ctx {};
				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				if (GetThreadContext(it->second, &ctx))
				{
					ctx.Dr7 &= ~(1ULL << (m_stepOverHwBreakpointIndex * 2));
					SetThreadContext(it->second, &ctx);
				}
			}
			m_hasStepOverHwBreakpoint = true;
			m_stepOverHwBreakpointContinue = false;  // Stop after re-applying
		}

		// Check if we're at a software breakpoint and need to re-apply it after stepping
		{
			std::lock_guard<std::mutex> lock(m_breakpointsMutex);
			uint64_t ip = GetInstructionOffset();
			for (const auto& bp : m_breakpoints)
			{
				if (bp.address == ip && bp.isActive)
				{
					// Remove the INT3 so we can execute the actual instruction
					RemoveBreakpointInternal(ip);

					// Need to re-apply breakpoint after stepping
					m_stepOverBreakpointAddress = ip;
					m_hasStepOverBreakpoint = true;
					m_stepOverBreakpointContinue = false;  // Stop after re-applying breakpoint
					break;
				}
			}
		}

		// Set the trap flag for single stepping
		if (m_isTargetWow64)
		{
			WOW64_CONTEXT ctx {};
			ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
			if (!Wow64GetThreadContext(it->second, &ctx))
				return false;

			ctx.EFlags |= 0x100;
			if (!Wow64SetThreadContext(it->second, &ctx))
				return false;
		}
		else
		{
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(it->second, &ctx))
				return false;

			ctx.EFlags |= 0x100;
			if (!SetThreadContext(it->second, &ctx))
				return false;
		}

		m_singleStepping = true;

		// Suspend all other threads when stepping to prevent them from hitting breakpoints
		// This implements GDB-style "scheduler-locking step" behavior
		for (const auto& [tid, handle] : m_threads)
		{
			if (tid != m_activeThreadId && handle)
			{
				::SuspendThread(handle);
			}
		}

		// Publish the resume under m_debugMutex so the parked DebugLoop predicate observes it and
		// the notify can't be lost (see Quit for the race detail).
		{
			std::lock_guard<std::mutex> lock(m_debugMutex);
			m_targetRunning = true;
		}
		m_debugCondition.notify_one();

		// Notify that the target has resumed
		EngineEvent event;
		event.type = EngineEventType::StepIntoComplete;
		PostEngineEvent(event);

		return true;
	}


	bool WindowsDebugEngine::StepOver()
	{
		if (!m_activelyDebugging)
			return false;

		uint64_t ip = GetInstructionOffset();
		size_t instrLength = 0;

		// Check if current instruction is a call
		if (IsCallInstruction(ip, instrLength))
		{
			// Set temporary breakpoint after the call instruction
			uint64_t nextAddr = ip + instrLength;
			if (!SetTempBreakpoint(nextAddr))
				return false;

			// Resume execution - will stop at the temp breakpoint
			return Go();
		}

		// Not a call, just do a single step
		return StepInto();
	}


	bool WindowsDebugEngine::StepReturn()
	{
		if (!m_activelyDebugging)
			return false;

		// Use stack unwinding to get the return address reliably
		// Frame 0 is the current frame, frame 1 is the caller
		auto frames = GetFramesOfThread(m_activeThreadId);
		if (frames.size() < 2)
		{
			// Fallback to simple stack read if unwinding fails
			uint64_t returnAddr = GetReturnAddress();
			if (returnAddr == 0)
				return false;

			if (!SetTempBreakpoint(returnAddr))
				return false;

			return Go();
		}

		// The return address is the PC of the caller's frame
		uint64_t returnAddr = frames[1].m_pc;
		if (returnAddr == 0)
			return false;

		// Set temporary breakpoint at return address
		if (!SetTempBreakpoint(returnAddr))
			return false;

		// Resume execution - will stop when function returns
		return Go();
	}


	uint64_t WindowsDebugEngine::GetInstructionOffset()
	{
		auto it = m_threads.find(m_activeThreadId);
		if (it == m_threads.end() || !it->second)
			return 0;

		if (m_isTargetWow64)
		{
			WOW64_CONTEXT ctx {};
			ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
			if (!Wow64GetThreadContext(it->second, &ctx))
				return 0;
			return ctx.Eip;
		}
		else
		{
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(it->second, &ctx))
				return 0;
			return ctx.Rip;
		}
	}


	uint64_t WindowsDebugEngine::GetStackPointer()
	{
		auto it = m_threads.find(m_activeThreadId);
		if (it == m_threads.end() || !it->second)
			return 0;

		if (m_isTargetWow64)
		{
			WOW64_CONTEXT ctx {};
			ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
			if (!Wow64GetThreadContext(it->second, &ctx))
				return 0;
			return ctx.Esp;
		}
		else
		{
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(it->second, &ctx))
				return 0;
			return ctx.Rsp;
		}
	}


	std::uint32_t WindowsDebugEngine::GetActivePID()
	{
		return m_processId;
	}


	bool WindowsDebugEngine::SupportFeature(DebugAdapterCapacity feature)
	{
		switch (feature)
		{
		case DebugAdapterSupportStepOver:
			return true;
		case DebugAdapterSupportStepReturn:
			return true;
		case DebugAdapterSupportModules:
			return true;
		case DebugAdapterSupportThreads:
			return true;
		case DebugAdapterSupportStepOverReverse:
		case DebugAdapterSupportTTD:
			return false;
		default:
			return false;
		}
	}


	std::vector<DebugFrame> WindowsDebugEngine::GetFramesOfThread(uint32_t tid)
	{
		std::vector<DebugFrame> frames;

		auto it = m_threads.find(tid);
		if (it == m_threads.end() || !it->second)
			return frames;

		HANDLE threadHandle = it->second;

		// Initialize symbol handler (needed for StackWalk64)
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
		SymInitialize(m_processHandle, nullptr, TRUE);

		STACKFRAME64 stackFrame {};
		DWORD machineType;

		// Storage for both context types - StackWalk64 takes PVOID
		CONTEXT ctx64 {};
		WOW64_CONTEXT ctx32 {};
		PVOID contextPtr;

		if (m_isTargetWow64)
		{
			// 32-bit process on 64-bit Windows
			ctx32.ContextFlags = WOW64_CONTEXT_FULL;
			if (!Wow64GetThreadContext(threadHandle, &ctx32))
				return frames;

			machineType = IMAGE_FILE_MACHINE_I386;
			stackFrame.AddrPC.Offset = ctx32.Eip;
			stackFrame.AddrPC.Mode = AddrModeFlat;
			stackFrame.AddrFrame.Offset = ctx32.Ebp;
			stackFrame.AddrFrame.Mode = AddrModeFlat;
			stackFrame.AddrStack.Offset = ctx32.Esp;
			stackFrame.AddrStack.Mode = AddrModeFlat;
			contextPtr = &ctx32;
		}
		else
		{
			// Native 64-bit process
			ctx64.ContextFlags = CONTEXT_FULL;
			if (!GetThreadContext(threadHandle, &ctx64))
				return frames;

			machineType = IMAGE_FILE_MACHINE_AMD64;
			stackFrame.AddrPC.Offset = ctx64.Rip;
			stackFrame.AddrPC.Mode = AddrModeFlat;
			stackFrame.AddrFrame.Offset = ctx64.Rbp;
			stackFrame.AddrFrame.Mode = AddrModeFlat;
			stackFrame.AddrStack.Offset = ctx64.Rsp;
			stackFrame.AddrStack.Mode = AddrModeFlat;
			contextPtr = &ctx64;
		}

		int frameIndex = 0;
		const int maxFrames = 256;

		while (frameIndex < maxFrames)
		{
			if (!StackWalk64(
				machineType,
				m_processHandle,
				threadHandle,
				&stackFrame,
				contextPtr,
				nullptr,
				SymFunctionTableAccess64,
				SymGetModuleBase64,
				nullptr))
			{
				break;
			}

			// Check for invalid frame
			if (stackFrame.AddrPC.Offset == 0)
				break;

			DebugFrame frame;
			frame.m_index = frameIndex;
			frame.m_pc = stackFrame.AddrPC.Offset;
			frame.m_sp = stackFrame.AddrStack.Offset;
			frame.m_fp = stackFrame.AddrFrame.Offset;

			// Find which module this address belongs to
			{
				std::lock_guard<std::mutex> lock(m_modulesMutex);
				for (const auto& mod : m_modules)
				{
					if (frame.m_pc >= mod.m_address && frame.m_pc < mod.m_address + mod.m_size)
					{
						frame.m_module = mod.m_short_name;
						break;
					}
				}
			}

			frames.push_back(frame);

			frameIndex++;
		}

		SymCleanup(m_processHandle);

		return frames;
	}

}  // namespace x2win
