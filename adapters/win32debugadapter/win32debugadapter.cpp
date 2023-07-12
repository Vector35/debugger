#include "win32debugadapter.h"
#include <processthreadsapi.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include "fmt/format.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;


static Win32DebugAdapterType * g_Win32DebugAdapterType = nullptr;


void InitWin32DebugAdapter()
{
	static Win32DebugAdapterType type;
	DebugAdapterType::Register(&type);
	g_Win32DebugAdapterType = &type;
}


Win32DebugAdapterType::Win32DebugAdapterType(): DebugAdapterType("WIN32_DBG")
{

}


bool Win32DebugAdapterType::IsValidForData(Ref<BinaryView> data)
{
	return data->GetTypeName() == "PE";
}


bool Win32DebugAdapterType::CanConnect(Ref<BinaryView> data)
{
	return true;
}


bool Win32DebugAdapterType::CanExecute(Ref<BinaryView> data)
{
#ifdef WIN32
	return true;
#endif
	return false;
}


DbgRef<DebugAdapter> Win32DebugAdapterType::Create(BinaryNinja::BinaryView* data)
{
	return new Win32DebugAdapter(data);
}


Win32DebugAdapter::Win32DebugAdapter(BinaryNinja::BinaryView* data): DebugAdapter(data)
{

}


bool Win32DebugAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
	const BinaryNinjaDebuggerAPI::LaunchConfigurations& configs)
{
	std::atomic_bool ret = false;
	std::atomic_bool finished = false;
	// Doing the operation on a different thread ensures the same thread starts the session and runs EngineLoop().
	// This is required by DngEng. Although things sometimes work even if it is violated, it can fail randomly.
	std::thread([=, &ret, &finished]() {
		ret = ExecuteWithArgsInternal(path, args, workingDir, configs);
		finished = true;
		if (ret)
			DebugLoop();
	}).detach();

	while (!finished)
	{}
	return ret;
}


bool Win32DebugAdapter::ExecuteWithArgsInternal(const std::string& path, const std::string& args, const std::string& workingDir,
	const BinaryNinjaDebuggerAPI::LaunchConfigurations& configs)
{
	STARTUPINFOA st{};
	st.cb = sizeof(st);
	PROCESS_INFORMATION info{};

	m_debugEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

	if (!CreateProcessA(path.c_str(),
		strdup(args.c_str()),
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
		NULL,
		workingDir.c_str(),
		&st,
		&info)
	)
	{
		auto lastError = GetLastError();
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.error = fmt::format("CreateProcessA failed: 0x{:x}", lastError);
		event.data.errorData.shortError = fmt::format("CreateProcessA failed: 0x{:x}", lastError);
		PostDebuggerEvent(event);
		return false;
	}

	m_processInfo = info;

//	auto settings = Settings::Instance();
//	if (settings->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction)
//	{
//		ModuleNameAndOffset addr;
//		addr.module = configs.inputFile;
//		addr.offset = m_entryPoint - m_start;
//		AddBreakpoint(addr);
//	}
//	else
//	{
//
//	}

	return true;
}


void Win32DebugAdapter::Reset()
{
	if (m_symInitialized)
		SymCleanup(m_process);

	m_threads.clear();
	for (const auto& module: m_modules)
	{
		CloseHandle(module.m_fileHandle);
	}
	m_modules.clear();
	CloseHandle(m_debugEvent);
	CloseHandle(m_processInfo.hThread);
	CloseHandle(m_processInfo.hProcess);
}


void Win32DebugAdapter::DebugLoop()
{
	DEBUG_EVENT dbgEvent;
	DWORD dwContinueStatus = DBG_CONTINUE;
	bool shouldExit = false;

	while (!shouldExit)
	{
		if (!WaitForDebugEvent(&dbgEvent, INFINITE))
		{
			auto lastError = GetLastError();
			DebuggerEvent event;
			event.type = ErrorEventType;
			event.data.errorData.error = fmt::format("WaitForDebugEvent failed: 0x{:x}", lastError);
			event.data.errorData.shortError = fmt::format("WaitForDebugEvent failed: 0x{:x}", lastError);
			PostDebuggerEvent(event);
			shouldExit = true;
			continue;
		}

		m_activeThreadID = dbgEvent.dwThreadId;
		LogWarn("active thread id: %d", m_activeThreadID);

		switch (dbgEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
		{
			if (!m_symInitialized)
			{
				SymSetHomeDirectory(m_process, "C:\\ProgramData\\Dbg");
				// TODO: we should load the symbols on demand
				if (!SymInitialize(m_process, NULL, true))
				{
					LogWarn("SymInitialize failed");
				}
				else
				{
					m_symInitialized = true;
					SymSetOptions(SYMOPT_UNDNAME);
				}
			}

			LogWarn("EXCEPTION_DEBUG_EVENT, code: 0x%lx", dbgEvent.u.Exception.ExceptionRecord.ExceptionCode);
			switch(dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
			{
				DebuggerEvent event;
				event.type = AdapterStoppedEventType;
				event.data.targetStoppedData.reason = Breakpoint;
				PostDebuggerEvent(event);
				WaitForSingleObject(m_debugEvent, INFINITE);
				break;
			}
			}
			break;
		}
		case CREATE_THREAD_DEBUG_EVENT:
		{
			LogWarn("CREATE_THREAD_DEBUG_EVENT");
			DWORD tid = GetThreadId(dbgEvent.u.CreateThread.hThread);
			m_threads[tid] = {dbgEvent.u.CreateThread.hThread, tid, (uint64_t)dbgEvent.u.CreateThread.lpStartAddress,
				(uint64_t)dbgEvent.u.CreateThread.lpThreadLocalBase};
			break;
		}
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			LogWarn("CREATE_PROCESS_DEBUG_EVENT");
			m_process = dbgEvent.u.CreateProcessInfo.hProcess;
			// There is no CREATE_THREAD_DEBUG_EVENT for the very first thread, we need to simulate it here
			DWORD tid = dbgEvent.dwThreadId;
			m_threads[tid] = {dbgEvent.u.CreateProcessInfo.hThread, tid,
				(uint64_t)dbgEvent.u.CreateProcessInfo.lpStartAddress,
				(uint64_t)dbgEvent.u.CreateProcessInfo.lpThreadLocalBase};
//			if (!SymInitialize(m_process, NULL, false))
//			{
//				LogWarn("SymInitialize failed");
//			}
//			else
//			{
//				m_symInitialized = true;
//				SymSetOptions(SYMOPT_UNDNAME);
//			}
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
		{
			LogWarn("EXIT_THREAD_DEBUG_EVENT");
			DWORD tid = GetThreadId(dbgEvent.u.CreateThread.hThread);
			m_threads.erase(tid);
			break;
		}
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			LogWarn("EXIT_PROCESS_DEBUG_EVENT");
			DebuggerEvent event;
			event.type = TargetExitedEventType;
			event.data.exitData.exitCode = dbgEvent.u.ExitProcess.dwExitCode;
			PostDebuggerEvent(event);
			shouldExit = true;
			break;
		}
		case LOAD_DLL_DEBUG_EVENT:
		{
			LogWarn("LOAD_DLL_DEBUG_EVENT");
//			ModuleInfo module;
//			module.m_fileHandle = dbgEvent.u.LoadDll.hFile;
//			module.m_base = (uint64_t)dbgEvent.u.LoadDll.lpBaseOfDll;
//
//			HMODULE handle{};
//			if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)module.m_base, &handle))
//			{
//				LogWarn("GetModuleHandleExA failed");
//			}
//			else
//			{
//				module.m_moduleHandle = handle;
//			}
//
//			// dbgEvent.u.LoadDll.lpImageName is unreliable -- we need to figure out the file path ourselves
//			char path[MAX_PATH] = {0};
//			DWORD bytes = GetModuleFileNameA(module.m_moduleHandle, path, MAX_PATH);
//			module.m_fileName = std::string(path, bytes);
//			// TODO: add m_shortFileName
//
//			// Calling GetModuleInformation will fail now, probably because the DLL has not fully initialized.
//			// We will populate the information when we get the initial breakpoint EXCEPTION_BREAKPOINT
//
//			m_modules.push_back(module);
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT:
		{
			LogWarn("UNLOAD_DLL_DEBUG_EVENT");
//			uint64_t base = (uint64_t)dbgEvent.u.UnloadDll.lpBaseOfDll;
//			for (auto it = m_modules.begin(); it != m_modules.end(); it++)
//			{
//				if (it->m_base == base)
//				{
//					m_modules.erase(it);
//					break;
//				}
//			}
			break;
		}
		case OUTPUT_DEBUG_STRING_EVENT:
		{
			LogWarn("OUTPUT_DEBUG_STRING_EVENT");
			break;
		}
		case RIP_EVENT:
		{
			LogWarn("RIP_EVENT");
			break;
		}
		}

		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwContinueStatus);
	}

	Reset();
}


HANDLE Win32DebugAdapter::GetActiveThreadHandle()
{
	return GetThreadHandleFromTid(m_activeThreadID);
}


HANDLE Win32DebugAdapter::GetThreadHandleFromTid(DWORD tid)
{
	auto it = m_threads.find(tid);
	if (it == m_threads.end())
		return INVALID_HANDLE_VALUE;
	return it->second.m_handle;
}


std::map<std::string, DebugRegister> Win32DebugAdapter::ReadAllRegisters()
{
	LogWarn("Win32DebugAdapter::ReadAllRegisters");
	CONTEXT context{};
	context.ContextFlags = CONTEXT_ALL;
	std::map<std::string, DebugRegister> result;

	HANDLE activeThreadHandle = GetActiveThreadHandle();
	if (activeThreadHandle == INVALID_HANDLE_VALUE)
		return result;

	GetThreadContext(activeThreadHandle, &context);
	size_t index = 0;

	result["rax"] = DebugRegister("rax", context.Rax, 64, index++);
	result["rcx"] = DebugRegister("rcx", context.Rcx, 64, index++);
	result["rdx"] = DebugRegister("rdx", context.Rdx, 64, index++);
	result["rbx"] = DebugRegister("rbx", context.Rbx, 64, index++);
	result["rsp"] = DebugRegister("rsp", context.Rsp, 64, index++);
	result["rbp"] = DebugRegister("rbp", context.Rbp, 64, index++);
	result["rsi"] = DebugRegister("rsi", context.Rsi, 64, index++);
	result["rdi"] = DebugRegister("rdi", context.Rdi, 64, index++);
	result["r8"] = DebugRegister("r8", context.R8, 64, index++);
	result["r9"] = DebugRegister("r9", context.R9, 64, index++);
	result["r10"] = DebugRegister("r10", context.R10, 64, index++);
	result["r11"] = DebugRegister("r11", context.R11, 64, index++);
	result["r12"] = DebugRegister("r12", context.R12, 64, index++);
	result["r13"] = DebugRegister("r13", context.R13, 64, index++);
	result["r14"] = DebugRegister("r14", context.R14, 64, index++);
	result["r15"] = DebugRegister("r15", context.R15, 64, index++);

	result["rip"] = DebugRegister("rip", context.Rip, 64, index++);
	result["eflags"] = DebugRegister("eflags", context.EFlags, 32, index++);

	result["dr0"] = DebugRegister("dr0", context.Dr0, 64, index++);
	result["dr1"] = DebugRegister("dr1", context.Dr1, 64, index++);
	result["dr2"] = DebugRegister("dr2", context.Dr2, 64, index++);
	result["dr3"] = DebugRegister("dr3", context.Dr3, 64, index++);
	result["dr6"] = DebugRegister("dr6", context.Dr6, 64, index++);
	result["dr7"] = DebugRegister("dr7", context.Dr7, 64, index++);

	result["cs"] = DebugRegister("cs", context.SegCs, 16, index++);
	result["ds"] = DebugRegister("ds", context.SegDs, 16, index++);
	result["es"] = DebugRegister("es", context.SegEs, 16, index++);
	result["fs"] = DebugRegister("fs", context.SegFs, 16, index++);
	result["gs"] = DebugRegister("gs", context.SegGs, 16, index++);
	result["ss"] = DebugRegister("ss", context.SegSs, 16, index++);

//	TODO: XMM registers: https://learn.microsoft.com/en-us/windows/win32/debug/working-with-xstate-context
	return result;
}


size_t Win32DebugAdapter::ReadMemory(void* dest, uint64_t address, size_t size)
{
	size_t bytesRead = 0;
	if (!ReadProcessMemory(m_process, (const char*)address, dest, size, &bytesRead))
		return 0;
	return bytesRead;
}


bool Win32DebugAdapter::WriteMemory(uint64_t address, const void* buffer, size_t size)
{
	size_t bytesWritten = 0;
	bool ok = WriteProcessMemory(m_process, (LPVOID)address, buffer, size, &bytesWritten);
	return ok && (size == bytesWritten);
}


uint32_t Win32DebugAdapter::GetActiveThreadId()
{
	return m_activeThreadID;
}


DebugThread Win32DebugAdapter::GetActiveThread()
{
	HANDLE activeThreadHandle = GetActiveThreadHandle();
	if (activeThreadHandle == INVALID_HANDLE_VALUE)
		return {};

	CONTEXT context{};
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(activeThreadHandle, &context);

	DebugThread thread;
	thread.m_tid = m_activeThreadID;
	thread.m_rip = context.Rip;
	// TODO: is this really used?
	thread.m_isFrozen = false;

	return thread;
}


std::vector<DebugThread> Win32DebugAdapter::GetThreadList()
{
	std::vector<DebugThread> result;

	for (const auto& it: m_threads)
	{
		CONTEXT context{};
		context.ContextFlags = CONTEXT_ALL;
		GetThreadContext(it.second.m_handle, &context);
		DebugThread thread;
		thread.m_tid = it.second.m_tid;
		thread.m_rip = context.Rip;
		thread.m_isFrozen = false;
		result.emplace_back(thread);
	}
	return result;
}


std::vector<DebugModule> Win32DebugAdapter::GetModuleList()
{
	std::vector<DebugModule> result;

	// TODO: cosider switching to EnumProcessModules
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_processInfo.dwProcessId);
	if (snapshot == INVALID_HANDLE_VALUE)
		return result;

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(snapshot, &me32))
	{
		CloseHandle(snapshot);
		return result;
	}

	do
	{
		DebugModule module;
		module.m_size = me32.modBaseSize;
		module.m_address = (uint64_t)me32.modBaseAddr;
		module.m_loaded = true;
		module.m_name = std::string(me32.szExePath);
		module.m_short_name = std::string(me32.szModule);
		result.push_back(module);
	}
	while (Module32Next(snapshot, &me32));

	CloseHandle(snapshot);
	return result;
}


std::vector<DebugFrame> Win32DebugAdapter::GetFramesOfThread(uint32_t tid)
{
	std::vector<DebugFrame> result;
	HANDLE handle = GetThreadHandleFromTid(tid);
	if (handle == INVALID_HANDLE_VALUE)
		return result;

	CONTEXT context{};
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(handle, &context))
		return result;

	// TODO: this needs to be repeated for each thread. We should cache the result
	const auto modules = GetModuleList();

	STACKFRAME_EX frame{};
	frame.AddrPC.Offset = context.Rip;
	frame.AddrPC.Mode = AddrModeFlat;
	frame.AddrStack.Offset = context.Rsp;
	frame.AddrStack.Mode = AddrModeFlat;
	frame.AddrFrame.Offset = context.Rbp;
	frame.AddrFrame.Mode = AddrModeFlat;
	frame.StackFrameSize = sizeof(STACKFRAME_EX);

	size_t i = 0;
	while (true)
	{
		if (!StackWalkEx(IMAGE_FILE_MACHINE_AMD64, m_process, handle, &frame, &context,
				NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL, SYM_STKWALK_FORCE_FRAMEPTR ))
			break;
		if (frame.AddrPC.Offset == 0)
			break;
		DebugFrame debugFrame;
		debugFrame.m_index = i++;
		debugFrame.m_fp = frame.AddrFrame.Offset;
		debugFrame.m_sp = frame.AddrStack.Offset;
		debugFrame.m_pc = frame.AddrPC.Offset;

		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;

		DWORD64 displacement{};
		if (SymFromAddr(m_process, frame.AddrPC.Offset, &displacement, pSymbol))
		{
			debugFrame.m_functionStart = pSymbol->Address;
			debugFrame.m_functionName = std::string((char*)pSymbol->Name);
			for (const auto& module: modules)
			{
				if (module.m_address == pSymbol->ModBase)
				{
					debugFrame.m_module = module.m_short_name;
					break;
				}
			}
		}

		result.push_back(debugFrame);
	}
	return result;
}


bool Win32DebugAdapter::Quit()
{
	if (!SetEvent(m_debugEvent))
		return false;

	return TerminateProcess(m_process, -1);
}


bool Win32DebugAdapter::Go()
{
	if (!SetEvent(m_debugEvent))
		return false;

	return true;
}


extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		SetCurrentPluginLoadOrder(LatePluginLoadOrder);
		AddRequiredPluginDependency("debuggercore");
	}
#endif

#ifdef DEMO_VERSION
	bool DebuggerPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		LogDebug("win32 debug adapter loaded!");
		InitWin32DebugAdapter();
		return true;
	}
}
