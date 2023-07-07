#include "win32debugadapter.h"
#include <processthreadsapi.h>
#include <windows.h>
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

		switch (dbgEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
		{
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
			break;
		}
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			LogWarn("CREATE_PROCESS_DEBUG_EVENT");
			break;
		}
		case EXIT_THREAD_DEBUG_EVENT:
		{
			LogWarn("EXIT_THREAD_DEBUG_EVENT");
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
			break;
		}
		case UNLOAD_DLL_DEBUG_EVENT:
		{
			LogWarn("UNLOAD_DLL_DEBUG_EVENT");
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
}


std::map<std::string, DebugRegister> Win32DebugAdapter::ReadAllRegisters()
{
	LogWarn("Win32DebugAdapter::ReadAllRegisters");
	CONTEXT context;
	GetThreadContext(m_processInfo.hThread, &context);
	size_t index = 0;
	std::map<std::string, DebugRegister> result;

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


DataBuffer Win32DebugAdapter::ReadMemory(uint64_t address, size_t size)
{
	uint8_t* buffer = new uint8_t[size];
	size_t bytesRead = 0;
	if (!ReadProcessMemory(m_processInfo.hProcess, (const char*)address, buffer, size, &bytesRead))
		return {};
	return DataBuffer(buffer, bytesRead);
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
