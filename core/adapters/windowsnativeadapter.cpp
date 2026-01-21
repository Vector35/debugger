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

#include "windowsnativeadapter.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <delayimp.h>
#include <algorithm>
#include <memory>
#include <filesystem>

// dbghelp.dll is delay-loaded. We use a notification hook to try loading it from the
// configured DbgEng path first, falling back to the system version if that fails.
// This avoids conflicts with the DbgEng adapter which needs specific versions of these DLLs.

static std::string GetDbgHelpPathFromSettings()
{
	// Try to get the path from settings - same logic as DbgEngAdapter::GetDbgEngPath
	auto settings = BinaryNinja::Settings::Instance();
	std::string path = settings->Get<std::string>("debugger.x64dbgEngPath");

	if (!path.empty())
	{
		auto dbgHelpPath = std::filesystem::path(path) / "dbghelp.dll";
		if (std::filesystem::exists(dbgHelpPath))
			return dbgHelpPath.string();
	}

	// Check the bundled dbgeng folder
	std::string pluginRoot;
	if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
		pluginRoot = BinaryNinja::GetUserPluginDirectory();
	else
		pluginRoot = BinaryNinja::GetBundledPluginDirectory();

	auto bundledPath = std::filesystem::path(pluginRoot) / "dbgeng" / "amd64" / "dbghelp.dll";
	if (std::filesystem::exists(bundledPath))
		return bundledPath.string();

	return "";
}

static FARPROC WINAPI DelayLoadNotifyHook(unsigned dliNotify, PDelayLoadInfo pdli)
{
	if (dliNotify == dliNotePreLoadLibrary)
	{
		// Check if this is dbghelp.dll being loaded
		if (pdli->szDll && _stricmp(pdli->szDll, "dbghelp.dll") == 0)
		{
			// Try to load from our preferred path first
			std::string customPath = GetDbgHelpPathFromSettings();
			if (!customPath.empty())
			{
				HMODULE hModule = LoadLibraryA(customPath.c_str());
				if (hModule)
				{
					BinaryNinja::LogDebug("Delay-loaded dbghelp.dll from: %s", customPath.c_str());
					return reinterpret_cast<FARPROC>(hModule);
				}
				BinaryNinja::LogDebug("Failed to load dbghelp.dll from %s, falling back to system", customPath.c_str());
			}
			// Return NULL to let the system load it from the default search path
		}
	}
	return NULL;
}

// Register our delay load hook
const PfnDliHook __pfnDliNotifyHook2 = DelayLoadNotifyHook;

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

// INT3 instruction opcode
constexpr uint8_t INT3_OPCODE = 0xCC;

WindowsNativeAdapter::WindowsNativeAdapter(BinaryView* data) : DebugAdapter(data)
{
	// Determine if we're targeting a 64-bit binary
	auto arch = data->GetDefaultArchitecture();
	if (arch)
	{
		m_is64Bit = arch->GetAddressSize() == 8;
	}

	GenerateDefaultAdapterSettings(data);
}


WindowsNativeAdapter::~WindowsNativeAdapter()
{
	if (m_activelyDebugging)
		Quit();
}


bool WindowsNativeAdapter::Init()
{
	return true;
}


bool WindowsNativeAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return ExecuteWithArgs(path, "", "", configs);
}


bool WindowsNativeAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	// Reset any previous state
	Reset();

	// Read settings instead of using passed-in arguments
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto executablePath = adapterSettings->Get<std::string>("launch.executablePath", data, &scope);
	scope = SettingsResourceScope;
	auto workingDirectory = adapterSettings->Get<std::string>("launch.workingDirectory", data, &scope);
	scope = SettingsResourceScope;
	auto commandLineArgs = adapterSettings->Get<std::string>("launch.commandLineArguments", data, &scope);

	// Store parameters for the debug thread
	m_launchExecutable = executablePath;
	m_launchWorkingDir = workingDirectory;
	m_launchCommandLine = executablePath;
	if (!commandLineArgs.empty())
		m_launchCommandLine += " " + commandLineArgs;
	m_isAttaching = false;
	m_launchResult = false;
	m_launchError.clear();

	// Start the debug loop thread - it will create the process
	m_debugThread = std::thread(&WindowsNativeAdapter::DebugLoop, this);

	// Wait for the debug thread to signal success or failure
	{
		std::unique_lock<std::mutex> lock(m_launchMutex);
		m_launchCondition.wait(lock, [this] { return m_launchResult.load() || !m_launchError.empty(); });
	}

	if (!m_launchError.empty())
	{
		LogError("Failed to create process: %s", m_launchError.c_str());
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = m_launchError;
		event.data.errorData.shortError = "CreateProcess failed";
		PostDebuggerEvent(event);

		// Wait for debug thread to finish
		if (m_debugThread.joinable())
			m_debugThread.join();
		return false;
	}

	return true;
}


bool WindowsNativeAdapter::Attach(std::uint32_t pid)
{
	// Reset any previous state
	Reset();

	// Read PID from settings
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto attachPID = adapterSettings->Get<uint64_t>("attach.pid", data, &scope);

	// Store parameters for the debug thread
	m_attachPID = static_cast<DWORD>(attachPID);
	m_isAttaching = true;
	m_launchResult = false;
	m_launchError.clear();

	// Start the debug loop thread - it will attach to the process
	m_debugThread = std::thread(&WindowsNativeAdapter::DebugLoop, this);

	// Wait for the debug thread to signal success or failure
	{
		std::unique_lock<std::mutex> lock(m_launchMutex);
		m_launchCondition.wait(lock, [this] { return m_launchResult.load() || !m_launchError.empty(); });
	}

	if (!m_launchError.empty())
	{
		LogError("Failed to attach to process: %s", m_launchError.c_str());
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = m_launchError;
		event.data.errorData.shortError = "Attach failed";
		PostDebuggerEvent(event);

		// Wait for debug thread to finish
		if (m_debugThread.joinable())
			m_debugThread.join();
		return false;
	}

	return true;
}


bool WindowsNativeAdapter::Connect(const std::string& server, std::uint32_t port)
{
	// Windows native debugging doesn't support remote connections
	LogError("WindowsNativeAdapter does not support remote debugging");
	return false;
}


bool WindowsNativeAdapter::Detach()
{
	if (!m_activelyDebugging)
		return true;

	m_shouldStop = true;

	// Wake up the debug thread if it's waiting
	m_debugCondition.notify_one();

	// Remove all breakpoints before detaching
	{
		std::lock_guard<std::mutex> lock(m_breakpointsMutex);
		for (auto& bp : m_breakpoints)
		{
			if (bp.isActive)
				RemoveBreakpointInternal(bp.address);
		}
		m_breakpoints.clear();
	}

	if (!DebugActiveProcessStop(m_processId))
	{
		LogError("Failed to detach from process: %d", GetLastError());
		return false;
	}

	if (m_debugThread.joinable())
		m_debugThread.join();

	// Close all thread handles
	for (auto& [tid, handle] : m_threads)
	{
		if (handle && handle != m_threadHandle)
			CloseHandle(handle);
	}
	m_threads.clear();

	if (m_processHandle)
	{
		CloseHandle(m_processHandle);
		m_processHandle = nullptr;
	}

	m_activelyDebugging = false;
	m_targetRunning = false;

	DebuggerEvent event;
	event.type = TargetExitedEventType;
	event.data.exitData.exitCode = 0;
	PostDebuggerEvent(event);

	return true;
}


bool WindowsNativeAdapter::Quit()
{
	if (!m_activelyDebugging)
		return true;

	m_shouldStop = true;

	// Wake up the debug thread if it's waiting
	m_debugCondition.notify_one();

	// Terminate the process
	if (m_processHandle)
		TerminateProcess(m_processHandle, 0);

	if (m_debugThread.joinable())
		m_debugThread.join();

	// Close all thread handles
	for (auto& [tid, handle] : m_threads)
	{
		if (handle)
			CloseHandle(handle);
	}
	m_threads.clear();

	if (m_processHandle)
	{
		CloseHandle(m_processHandle);
		m_processHandle = nullptr;
	}

	m_activelyDebugging = false;
	m_targetRunning = false;

	DebuggerEvent event;
	event.type = TargetExitedEventType;
	event.data.exitData.exitCode = m_exitCode;
	PostDebuggerEvent(event);

	return true;
}


void WindowsNativeAdapter::Reset()
{
	// Wait for any existing debug thread to finish
	if (m_debugThread.joinable())
		m_debugThread.join();

	// Close all thread handles
	for (auto& [tid, handle] : m_threads)
	{
		if (handle)
			CloseHandle(handle);
	}
	m_threads.clear();

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

	// Clear breakpoints (but keep them for re-apply on restart)
	{
		std::lock_guard<std::mutex> lock(m_breakpointsMutex);
		for (auto& bp : m_breakpoints)
		{
			bp.isActive = false;
			bp.originalByte = 0;  // Clear stale original byte from previous session
		}
	}

	// Clear hardware breakpoints state
	{
		std::lock_guard<std::mutex> lock(m_hwBreakpointsMutex);
		for (auto& hwbp : m_hardwareBreakpoints)
		{
			hwbp.isActive = false;
			hwbp.drIndex = -1;
		}
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

	// Reset launch state
	m_launchResult = false;
	m_launchError.clear();
}


bool WindowsNativeAdapter::StartDebugging()
{
	LogWarn("WindowsNativeAdapter::StartDebugging - isAttaching=%d", m_isAttaching);

	if (m_isAttaching)
	{
		// Attach to existing process
		if (!DebugActiveProcess(m_attachPID))
		{
			m_launchError = fmt::format("Failed to attach to process {}: {}", m_attachPID, GetLastError());
			LogError("%s", m_launchError.c_str());
			return false;
		}

		m_processId = m_attachPID;
		m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_attachPID);
		if (!m_processHandle)
		{
			m_launchError = fmt::format("Failed to open process {}: {}", m_attachPID, GetLastError());
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

		LogWarn("CreateProcessA: %s, workingDir=%s",
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
			m_launchError = fmt::format("Failed to create process: {}", GetLastError());
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

		LogWarn("Process created: PID=%d, TID=%d", m_processId, m_threadId);
	}

	m_activelyDebugging = true;
	m_targetRunning = true;

	return true;
}


void WindowsNativeAdapter::DebugLoop()
{
	LogWarn("WindowsNativeAdapter::DebugLoop started");

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

		LogWarn("Received debug event: code=%d, pid=%d, tid=%d",
			debugEvent.dwDebugEventCode, debugEvent.dwProcessId, debugEvent.dwThreadId);

		m_lastDebugEvent = debugEvent;
		m_hasLastDebugEvent = true;

		DWORD continueStatus = DBG_CONTINUE;

		bool shouldBreak = HandleDebugEvent(debugEvent);
		LogWarn("HandleDebugEvent returned shouldBreak=%d", shouldBreak);

		if (shouldBreak)
		{
			m_targetRunning = false;

			// Notify the controller that we've stopped
			LogWarn("Posting AdapterStoppedEventType with reason=%d, thread=%d", m_stopReason, m_activeThreadId);
			DebuggerEvent event;
			event.type = AdapterStoppedEventType;
			event.data.targetStoppedData.reason = m_stopReason;
			event.data.targetStoppedData.lastActiveThread = m_activeThreadId;
			event.data.targetStoppedData.exitCode = 0;
			event.data.targetStoppedData.data = nullptr;
			PostDebuggerEvent(event);

			// Wait for Go() or other commands
			LogWarn("Waiting for Go() or stop signal...");
			std::unique_lock<std::mutex> lock(m_debugMutex);
			m_debugCondition.wait(lock, [this] { return m_targetRunning || m_shouldStop; });
			LogWarn("Wait completed: m_targetRunning=%d, m_shouldStop=%d", m_targetRunning.load(), m_shouldStop.load());

			if (m_shouldStop)
			{
				ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
				break;
			}
		}

		// Handle exception continue status
		if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT ||
				debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
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

	m_activelyDebugging = false;
}


bool WindowsNativeAdapter::HandleDebugEvent(const DEBUG_EVENT& event)
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


bool WindowsNativeAdapter::HandleException(const EXCEPTION_DEBUG_INFO& info)
{
	m_activeThreadId = m_lastDebugEvent.dwThreadId;

	LogWarn("HandleException: code=0x%08X, address=0x%llX, firstChance=%d",
		info.ExceptionRecord.ExceptionCode,
		(uint64_t)info.ExceptionRecord.ExceptionAddress,
		info.dwFirstChance);

	switch (info.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
	{
		uint64_t address = (uint64_t)info.ExceptionRecord.ExceptionAddress;
		LogWarn("EXCEPTION_BREAKPOINT at 0x%llX", address);

		// Check if this is a temporary breakpoint (from StepOver/StepReturn)
		if (m_hasTempBreakpoint && address == m_tempBreakpointAddress)
		{
			// Remove the temporary breakpoint
			RemoveTempBreakpoint();

			// Set IP back to the breakpoint address so the instruction executes
			HANDLE threadHandle = m_threads[m_activeThreadId];
			if (threadHandle)
			{
				CONTEXT ctx {};
				ctx.ContextFlags = CONTEXT_CONTROL;
				if (GetThreadContext(threadHandle, &ctx))
				{
#ifdef _WIN64
					ctx.Rip = address;
#else
					ctx.Eip = static_cast<DWORD>(address);
#endif
					SetThreadContext(threadHandle, &ctx);
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
					WriteMemory(address, DataBuffer(&bp.originalByte, 1));

					// Decrement IP to point back to the breakpoint address
					HANDLE threadHandle = m_threads[m_activeThreadId];
					if (threadHandle)
					{
						CONTEXT ctx {};
						ctx.ContextFlags = CONTEXT_CONTROL;
						if (GetThreadContext(threadHandle, &ctx))
						{
#ifdef _WIN64
							ctx.Rip = address;
#else
							ctx.Eip = static_cast<DWORD>(address);
#endif
							SetThreadContext(threadHandle, &ctx);
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

			auto settings = Settings::Instance();

			// If stopAtEntryPoint is enabled and we have an entry function, add a breakpoint there
			if (settings->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction)
			{
				// Get the main module name for the breakpoint
				std::string moduleName;
				{
					std::lock_guard<std::mutex> lock(m_modulesMutex);
					if (!m_modules.empty())
						moduleName = m_modules[0].m_name;  // First module is the main executable
				}

				if (!moduleName.empty())
				{
					AddBreakpoint(ModuleNameAndOffset(moduleName, m_entryPoint - m_start));
				}
			}

			// If stopAtSystemEntryPoint is false, continue execution
			if (!settings->Get<bool>("debugger.stopAtSystemEntryPoint"))
			{
				return false;  // Don't stop, continue running
			}
		}

		m_stopReason = Breakpoint;
		return true;
	}

	case EXCEPTION_SINGLE_STEP:
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
				CONTEXT ctx {};
				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				if (GetThreadContext(threadHandle, &ctx))
				{
					// Re-enable the hardware breakpoint in DR7
					ctx.Dr7 |= (1ULL << (m_stepOverHwBreakpointIndex * 2));  // Local enable
					SetThreadContext(threadHandle, &ctx);
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
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (GetThreadContext(threadHandle, &ctx))
			{
				if (ctx.Dr6 & 0xF)  // Hardware breakpoint hit
				{
					// Determine which DR register caused the hit
					int hitIndex = -1;
					for (int i = 0; i < 4; i++)
					{
						if (ctx.Dr6 & (1 << i))
						{
							hitIndex = i;
							break;
						}
					}

					// Clear Dr6
					ctx.Dr6 = 0;
					SetThreadContext(threadHandle, &ctx);

					// Store info for step-over when Go() is called
					m_stepOverHwBreakpointIndex = hitIndex;

					m_stopReason = Breakpoint;
					return true;
				}
			}
		}

		m_stopReason = SingleStep;
		m_singleStepping = false;
		return true;
	}

	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_DATATYPE_MISALIGNMENT:
	case EXCEPTION_FLT_DENORMAL_OPERAND:
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
	case EXCEPTION_FLT_INEXACT_RESULT:
	case EXCEPTION_FLT_INVALID_OPERATION:
	case EXCEPTION_FLT_OVERFLOW:
	case EXCEPTION_FLT_STACK_CHECK:
	case EXCEPTION_FLT_UNDERFLOW:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_INT_OVERFLOW:
	case EXCEPTION_INVALID_DISPOSITION:
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
	case EXCEPTION_PRIV_INSTRUCTION:
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


bool WindowsNativeAdapter::HandleCreateProcess(const CREATE_PROCESS_DEBUG_INFO& info)
{
	LogWarn("HandleCreateProcess: baseOfImage=0x%llX, startAddress=0x%llX",
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


bool WindowsNativeAdapter::HandleExitProcess(const EXIT_PROCESS_DEBUG_INFO& info)
{
	m_exitCode = info.dwExitCode;
	m_activelyDebugging = false;
	m_stopReason = ProcessExited;

	DebuggerEvent event;
	event.type = TargetExitedEventType;
	event.data.exitData.exitCode = info.dwExitCode;
	PostDebuggerEvent(event);

	return false;
}


bool WindowsNativeAdapter::HandleCreateThread(const CREATE_THREAD_DEBUG_INFO& info, DWORD threadId)
{
	m_threads[threadId] = info.hThread;

	// Apply hardware breakpoints to the new thread
	ApplyHardwareBreakpointsToThread(info.hThread);

	return false;
}


bool WindowsNativeAdapter::HandleExitThread(const EXIT_THREAD_DEBUG_INFO& info, DWORD threadId)
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


bool WindowsNativeAdapter::HandleLoadDll(const LOAD_DLL_DEBUG_INFO& info)
{
	std::string moduleName = GetModuleNameFromHandle(info.hFile, info.lpBaseOfDll);
	LogWarn("HandleLoadDll: %s at 0x%llX", moduleName.c_str(), (uint64_t)info.lpBaseOfDll);

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


bool WindowsNativeAdapter::HandleUnloadDll(const UNLOAD_DLL_DEBUG_INFO& info)
{
	std::lock_guard<std::mutex> lock(m_modulesMutex);
	auto it = std::remove_if(m_modules.begin(), m_modules.end(),
		[&info](const DebugModule& m) { return m.m_address == (uintptr_t)info.lpBaseOfDll; });
	m_modules.erase(it, m_modules.end());
	return false;
}


bool WindowsNativeAdapter::HandleOutputDebugString(const OUTPUT_DEBUG_STRING_INFO& info)
{
	std::vector<char> buffer(info.nDebugStringLength);
	SIZE_T bytesRead;
	if (ReadProcessMemory(m_processHandle, info.lpDebugStringData, buffer.data(),
		info.nDebugStringLength, &bytesRead))
	{
		std::string message(buffer.data(), bytesRead);
		LogDebug("Debug output: %s", message.c_str());
	}
	return false;
}


std::string WindowsNativeAdapter::GetModuleNameFromHandle(HANDLE fileHandle, LPVOID baseAddress)
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


std::vector<DebugProcess> WindowsNativeAdapter::GetProcessList()
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
			processes.push_back(proc);
		} while (Process32Next(snapshot, &pe32));
	}

	CloseHandle(snapshot);
	return processes;
}


std::vector<DebugThread> WindowsNativeAdapter::GetThreadList()
{
	std::vector<DebugThread> threads;

	for (const auto& [tid, handle] : m_threads)
	{
		DebugThread thread;
		thread.m_tid = tid;

		// Get thread instruction pointer
		if (handle)
		{
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL;
			if (GetThreadContext(handle, &ctx))
			{
#ifdef _WIN64
				thread.m_rip = ctx.Rip;
#else
				thread.m_rip = ctx.Eip;
#endif
			}
		}
		threads.push_back(thread);
	}

	return threads;
}


DebugThread WindowsNativeAdapter::GetActiveThread() const
{
	DebugThread thread;
	thread.m_tid = m_activeThreadId;

	auto it = m_threads.find(m_activeThreadId);
	if (it != m_threads.end() && it->second)
	{
		CONTEXT ctx {};
		ctx.ContextFlags = CONTEXT_CONTROL;
		if (GetThreadContext(it->second, &ctx))
		{
#ifdef _WIN64
			thread.m_rip = ctx.Rip;
#else
			thread.m_rip = ctx.Eip;
#endif
		}
	}

	return thread;
}


std::uint32_t WindowsNativeAdapter::GetActiveThreadId() const
{
	return m_activeThreadId;
}


bool WindowsNativeAdapter::SetActiveThread(const DebugThread& thread)
{
	return SetActiveThreadId(thread.m_tid);
}


bool WindowsNativeAdapter::SetActiveThreadId(std::uint32_t tid)
{
	if (m_threads.find(tid) == m_threads.end())
		return false;

	m_activeThreadId = tid;
	return true;
}


bool WindowsNativeAdapter::SuspendThread(std::uint32_t tid)
{
	auto it = m_threads.find(tid);
	if (it == m_threads.end())
		return false;

	return ::SuspendThread(it->second) != (DWORD)-1;
}


bool WindowsNativeAdapter::ResumeThread(std::uint32_t tid)
{
	auto it = m_threads.find(tid);
	if (it == m_threads.end())
		return false;

	return ::ResumeThread(it->second) != (DWORD)-1;
}


DebugBreakpoint WindowsNativeAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags)
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
		ApplyBreakpoint(address, id);
	}

	// Return the updated state
	for (const auto& b : m_breakpoints)
	{
		if (b.address == address)
			return DebugBreakpoint(address, b.id, b.isActive);
	}
	return DebugBreakpoint(address, id, false);
}


DebugBreakpoint WindowsNativeAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
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


bool WindowsNativeAdapter::ApplyBreakpoint(uint64_t address, unsigned long id)
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
		return false;

	// If the byte is already INT3, the breakpoint is already applied
	if (currentByte == INT3_OPCODE)
	{
		// If we already have a saved original byte, we're good - just ensure isActive is set
		if (targetBp->originalByte != 0)
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

	// Write INT3
	DWORD oldProtect;
	if (!VirtualProtectEx(m_processHandle, (LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
		return false;

	SIZE_T bytesWritten;
	uint8_t int3 = INT3_OPCODE;
	bool success = WriteProcessMemory(m_processHandle, (LPVOID)address, &int3, 1, &bytesWritten) && bytesWritten == 1;

	VirtualProtectEx(m_processHandle, (LPVOID)address, 1, oldProtect, &oldProtect);

	if (success)
	{
		targetBp->isActive = true;
	}

	return success;
}


bool WindowsNativeAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
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


bool WindowsNativeAdapter::RemoveBreakpoint(const ModuleNameAndOffset& breakpoint)
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


bool WindowsNativeAdapter::RemoveBreakpointInternal(uint64_t address)
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

	VirtualProtectEx(m_processHandle, (LPVOID)address, 1, oldProtect, &oldProtect);

	return success;
}


void WindowsNativeAdapter::ApplyPendingBreakpoints()
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


uint64_t WindowsNativeAdapter::ResolveModuleOffset(const ModuleNameAndOffset& location)
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


bool WindowsNativeAdapter::SetTempBreakpoint(uint64_t address)
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

	VirtualProtectEx(m_processHandle, (LPVOID)address, 1, oldProtect, &oldProtect);

	if (success)
	{
		m_tempBreakpointAddress = address;
		m_hasTempBreakpoint = true;
	}

	return success;
}


bool WindowsNativeAdapter::RemoveTempBreakpoint()
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

	VirtualProtectEx(m_processHandle, (LPVOID)m_tempBreakpointAddress, 1, oldProtect, &oldProtect);

	m_hasTempBreakpoint = false;
	m_tempBreakpointAddress = 0;

	return success;
}


bool WindowsNativeAdapter::IsCallInstruction(uint64_t address, size_t& instrLength)
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


uint64_t WindowsNativeAdapter::GetReturnAddress()
{
	auto it = m_threads.find(m_activeThreadId);
	if (it == m_threads.end() || !it->second)
		return 0;

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(it->second, &ctx))
		return 0;

	uint64_t sp;
#ifdef _WIN64
	sp = ctx.Rsp;
#else
	sp = ctx.Esp;
#endif

	// Read return address from stack
	uint64_t returnAddr = 0;
	SIZE_T bytesRead;

#ifdef _WIN64
	if (!ReadProcessMemory(m_processHandle, (LPCVOID)sp, &returnAddr, 8, &bytesRead) || bytesRead != 8)
		return 0;
#else
	uint32_t addr32;
	if (!ReadProcessMemory(m_processHandle, (LPCVOID)sp, &addr32, 4, &bytesRead) || bytesRead != 4)
		return 0;
	returnAddr = addr32;
#endif

	return returnAddr;
}


std::vector<DebugBreakpoint> WindowsNativeAdapter::GetBreakpointList() const
{
	std::vector<DebugBreakpoint> result;

	// Note: Can't lock mutex in const method, but this is called from controller
	// which should ensure proper synchronization
	for (const auto& bp : m_breakpoints)
	{
		result.emplace_back(bp.address, bp.id, bp.isActive);
	}

	return result;
}


bool WindowsNativeAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
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

	m_hardwareBreakpoints.push_back(hwBp);
	return true;
}


bool WindowsNativeAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
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

			m_hardwareBreakpoints.erase(it);
			return true;
		}
	}

	return false;
}


bool WindowsNativeAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
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


bool WindowsNativeAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
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


int WindowsNativeAdapter::FindFreeDebugRegister()
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


bool WindowsNativeAdapter::SetHardwareBreakpointInContext(CONTEXT& ctx, int drIndex, uint64_t address, DebugBreakpointType type, size_t size)
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


bool WindowsNativeAdapter::ClearHardwareBreakpointInContext(CONTEXT& ctx, int drIndex)
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


bool WindowsNativeAdapter::ApplyHardwareBreakpointsToThread(HANDLE threadHandle)
{
	if (m_hardwareBreakpoints.empty())
		return true;

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


std::unordered_map<std::string, DebugRegister> WindowsNativeAdapter::ReadAllRegisters()
{
	std::unordered_map<std::string, DebugRegister> registers;

	auto it = m_threads.find(m_activeThreadId);
	if (it == m_threads.end() || !it->second)
		return registers;

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(it->second, &ctx))
		return registers;

#ifdef _WIN64
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
#else
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
#endif

	return registers;
}


DebugRegister WindowsNativeAdapter::ReadRegister(const std::string& reg)
{
	auto registers = ReadAllRegisters();
	auto it = registers.find(reg);
	if (it != registers.end())
		return it->second;

	return DebugRegister();
}


bool WindowsNativeAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
	auto it = m_threads.find(m_activeThreadId);
	if (it == m_threads.end() || !it->second)
		return false;

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(it->second, &ctx))
		return false;

	uint64_t val64 = static_cast<uint64_t>(value);

#ifdef _WIN64
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
#else
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
#endif

	return SetThreadContext(it->second, &ctx) != 0;
}


DataBuffer WindowsNativeAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	auto source = std::make_unique<uint8_t[]>(size);
	SIZE_T bytesRead;

	if (!ReadProcessMemory(m_processHandle, (LPCVOID)address, source.get(), size, &bytesRead))
	{
		return DataBuffer();
	}

	// Shadow breakpoint bytes - replace 0xCC with original bytes so disassembly is correct
	{
		std::lock_guard<std::mutex> lock(m_breakpointsMutex);
		for (const auto& bp : m_breakpoints)
		{
			if (bp.isActive && bp.address >= address && bp.address < address + bytesRead)
			{
				size_t offset = bp.address - address;
				source[offset] = bp.originalByte;
			}
		}
	}

	// Also shadow temporary breakpoint
	if (m_hasTempBreakpoint && m_tempBreakpointAddress >= address && m_tempBreakpointAddress < address + bytesRead)
	{
		size_t offset = m_tempBreakpointAddress - address;
		source[offset] = m_tempBreakpointOriginalByte;
	}

	return DataBuffer(source.get(), bytesRead);
}


bool WindowsNativeAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	SIZE_T bytesWritten;
	DWORD oldProtect;

	// Try to make memory writable
	VirtualProtectEx(m_processHandle, (LPVOID)address, buffer.GetLength(), PAGE_EXECUTE_READWRITE, &oldProtect);

	bool success = WriteProcessMemory(m_processHandle, (LPVOID)address, buffer.GetData(),
		buffer.GetLength(), &bytesWritten) && bytesWritten == buffer.GetLength();

	// Restore protection
	VirtualProtectEx(m_processHandle, (LPVOID)address, buffer.GetLength(), oldProtect, &oldProtect);

	return success;
}


std::vector<DebugModule> WindowsNativeAdapter::GetModuleList()
{
	std::lock_guard<std::mutex> lock(m_modulesMutex);
	return m_modules;
}


std::string WindowsNativeAdapter::GetTargetArchitecture()
{
	// Check if this is a WoW64 process
	BOOL isWow64 = FALSE;
	if (IsWow64Process(m_processHandle, &isWow64) && isWow64)
		return "x86";

#ifdef _WIN64
	return "x86_64";
#else
	return "x86";
#endif
}


DebugStopReason WindowsNativeAdapter::StopReason()
{
	return m_stopReason;
}


uint64_t WindowsNativeAdapter::ExitCode()
{
	return m_exitCode;
}


bool WindowsNativeAdapter::BreakInto()
{
	if (!m_processHandle)
		return false;

	return DebugBreakProcess(m_processHandle) != 0;
}


bool WindowsNativeAdapter::Go()
{
	if (!m_activelyDebugging)
		return false;

	// If we're at a hardware breakpoint, we need to step over it first
	if (m_stepOverHwBreakpointIndex >= 0)
	{
		auto it = m_threads.find(m_activeThreadId);
		if (it != m_threads.end() && it->second)
		{
			CONTEXT ctx {};
			ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
			if (GetThreadContext(it->second, &ctx))
			{
				// Temporarily disable the hardware breakpoint in DR7
				ctx.Dr7 &= ~(1ULL << (m_stepOverHwBreakpointIndex * 2));  // Clear local enable
				ctx.EFlags |= 0x100;  // Set trap flag for single step
				SetThreadContext(it->second, &ctx);
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
				// Need to single step past the breakpoint first
				m_stepOverBreakpointAddress = ip;
				m_hasStepOverBreakpoint = true;
				m_stepOverBreakpointContinue = true;  // Continue after re-applying breakpoint

				// Set single step flag
				auto it = m_threads.find(m_activeThreadId);
				if (it != m_threads.end() && it->second)
				{
					CONTEXT ctx {};
					ctx.ContextFlags = CONTEXT_CONTROL;
					if (GetThreadContext(it->second, &ctx))
					{
						ctx.EFlags |= 0x100;  // Set trap flag
						SetThreadContext(it->second, &ctx);
					}
				}
				break;
			}
		}
	}

	m_targetRunning = true;
	m_debugCondition.notify_one();
	return true;
}


bool WindowsNativeAdapter::StepInto()
{
	if (!m_activelyDebugging)
		return false;

	auto it = m_threads.find(m_activeThreadId);
	if (it == m_threads.end() || !it->second)
		return false;

	// If we're at a hardware breakpoint, we need to temporarily disable it
	if (m_stepOverHwBreakpointIndex >= 0)
	{
		CONTEXT ctx {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (GetThreadContext(it->second, &ctx))
		{
			// Temporarily disable the hardware breakpoint in DR7
			ctx.Dr7 &= ~(1ULL << (m_stepOverHwBreakpointIndex * 2));  // Clear local enable
			SetThreadContext(it->second, &ctx);
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
				// Need to re-apply breakpoint after stepping
				m_stepOverBreakpointAddress = ip;
				m_hasStepOverBreakpoint = true;
				m_stepOverBreakpointContinue = false;  // Stop after re-applying breakpoint
				break;
			}
		}
	}

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(it->second, &ctx))
		return false;

	// Set the trap flag for single stepping
	ctx.EFlags |= 0x100;
	if (!SetThreadContext(it->second, &ctx))
		return false;

	m_singleStepping = true;
	m_targetRunning = true;
	m_debugCondition.notify_one();

	return true;
}


bool WindowsNativeAdapter::StepOver()
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


bool WindowsNativeAdapter::StepReturn()
{
	if (!m_activelyDebugging)
		return false;

	uint64_t returnAddr = GetReturnAddress();
	if (returnAddr == 0)
		return false;

	// Set temporary breakpoint at return address
	if (!SetTempBreakpoint(returnAddr))
		return false;

	// Resume execution - will stop when function returns
	return Go();
}


std::string WindowsNativeAdapter::InvokeBackendCommand(const std::string& command)
{
	return "Backend commands not supported in Windows Native adapter";
}


uint64_t WindowsNativeAdapter::GetInstructionOffset()
{
	auto it = m_threads.find(m_activeThreadId);
	if (it == m_threads.end() || !it->second)
		return 0;

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(it->second, &ctx))
		return 0;

#ifdef _WIN64
	return ctx.Rip;
#else
	return ctx.Eip;
#endif
}


uint64_t WindowsNativeAdapter::GetStackPointer()
{
	auto it = m_threads.find(m_activeThreadId);
	if (it == m_threads.end() || !it->second)
		return 0;

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(it->second, &ctx))
		return 0;

#ifdef _WIN64
	return ctx.Rsp;
#else
	return ctx.Esp;
#endif
}


std::uint32_t WindowsNativeAdapter::GetActivePID()
{
	return m_processId;
}


bool WindowsNativeAdapter::SupportFeature(DebugAdapterCapacity feature)
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


std::vector<DebugFrame> WindowsNativeAdapter::GetFramesOfThread(uint32_t tid)
{
	std::vector<DebugFrame> frames;

	auto it = m_threads.find(tid);
	if (it == m_threads.end() || !it->second)
		return frames;

	HANDLE threadHandle = it->second;

	CONTEXT ctx {};
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(threadHandle, &ctx))
		return frames;

	// Initialize symbol handler (needed for StackWalk64)
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
	SymInitialize(m_processHandle, nullptr, TRUE);

	STACKFRAME64 stackFrame {};
	DWORD machineType;

#ifdef _WIN64
	machineType = IMAGE_FILE_MACHINE_AMD64;
	stackFrame.AddrPC.Offset = ctx.Rip;
	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Offset = ctx.Rbp;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
	stackFrame.AddrStack.Offset = ctx.Rsp;
	stackFrame.AddrStack.Mode = AddrModeFlat;
#else
	machineType = IMAGE_FILE_MACHINE_I386;
	stackFrame.AddrPC.Offset = ctx.Eip;
	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Offset = ctx.Ebp;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
	stackFrame.AddrStack.Offset = ctx.Esp;
	stackFrame.AddrStack.Mode = AddrModeFlat;
#endif

	int frameIndex = 0;
	const int maxFrames = 256;

	while (frameIndex < maxFrames)
	{
		if (!StackWalk64(
			machineType,
			m_processHandle,
			threadHandle,
			&stackFrame,
			&ctx,
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


// Adapter Type implementation
WindowsNativeAdapterType::WindowsNativeAdapterType() : DebugAdapterType("WINDOWS_NATIVE")
{
}


DebugAdapter* WindowsNativeAdapterType::Create(BinaryNinja::BinaryView* data)
{
	return new WindowsNativeAdapter(data);
}


bool WindowsNativeAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool WindowsNativeAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
	return true;
#endif
	return false;
}


bool WindowsNativeAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	// Windows native adapter doesn't support remote connections
	return false;
}


Ref<Settings> WindowsNativeAdapter::GetAdapterSettings()
{
	return WindowsNativeAdapterType::GetAdapterSettings();
}


Ref<Settings> WindowsNativeAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = WindowsNativeAdapterType::RegisterAdapterSettings();
	return settings;
}


Ref<Settings> WindowsNativeAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("WindowsNativeAdapterSettings");
	settings->SetResourceId("windows_native_adapter_settings");

	settings->RegisterGroup("launch", "Launch");
	settings->RegisterGroup("attach", "Attach");
	settings->RegisterGroup("common", "Common");

	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Path of the input file for the debugger to find the base address",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");

	settings->RegisterSetting("launch.executablePath",
		R"({
			"title" : "Executable Path",
			"type" : "string",
			"default" : "",
			"description" : "Path of the executable to launch.",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");
	settings->RegisterSetting("launch.workingDirectory",
			R"({
			"title" : "Working Directory",
			"type" : "string",
			"default" : "",
			"description" : "Working directory to launch the target in.",
			"readOnly" : false,
			"uiSelectionAction" : "directory"
			})");
	settings->RegisterSetting("launch.commandLineArguments",
			R"({
			"title" : "Command Line Arguments",
			"type" : "string",
			"default" : "",
			"description" : "Command line arguments to pass to the target",
			"readOnly" : false
			})");

	settings->RegisterSetting("attach.pid",
		R"({
			"title" : "PID to attach to",
			"type" : "number",
			"default" : 0,
			"minValue" : 0,
			"maxValue" : 4294967295,
			"description" : "PID of the process to attach to",
			"readOnly" : false
			})");

	return settings;
}


void WindowsNativeAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto executablePath = adapterSettings->Get<std::string>("launch.executablePath", data, &scope);
	// If the value is not loaded from the database, we need to populate it with a default value
	if (scope != SettingsResourceScope)
	{
		executablePath = data->GetFile()->GetOriginalFilename();
		adapterSettings->Set("launch.executablePath", executablePath, data, SettingsResourceScope);
	}

	scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);

	scope = SettingsResourceScope;
	auto workingDirectory = adapterSettings->Get<std::string>("launch.workingDirectory", data, &scope);
	if (scope != SettingsResourceScope)
	{
		try
		{
			workingDirectory = std::filesystem::path(executablePath).parent_path().string();
		}
		catch (const std::exception&)
		{
			LogWarn("Cannot get the default working directory for the input file.");
		}
		adapterSettings->Set("launch.workingDirectory", workingDirectory, data, SettingsResourceScope);
	}
}


void BinaryNinjaDebugger::InitWindowsNativeAdapterType()
{
	static WindowsNativeAdapterType adapterType;
	DebugAdapterType::Register(&adapterType);
}
