#include "win32debugadapter.h"
#include <processthreadsapi.h>
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
	STARTUPINFOA st;
	PROCESS_INFORMATION info;

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
