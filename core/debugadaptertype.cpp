#include "debugadaptertype.h"
#include "./adapters/gdbadapter.h"
#include "./adapters/lldbadapter.h"

#ifdef WIN32
#include "./adapters/dbgengadapter.h"
#include "./adapters/lldbadapter.h"
#endif

#include "debuggerexceptions.h"
#include "../api/ffi.h"

using namespace BinaryNinjaDebugger;


bool DebugAdapterType::CanUse(AdapterType type)
{
#ifdef WIN32
    return (type == DefaultAdapterType) || (type == LocalDBGENGAdapterType) ||
        (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
        (type == RemoteSenseAdapterType);
#elif defined(__clang__)
    return (type == DefaultAdapterType) || (type == LocalLLDBADapterType) ||
    (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
    (type == RemoteSenseAdapterType);
#elif defined(__GNUC__)
    return (type == DefaultAdapterType) || (type == LocalGDBAdapterType) ||
        (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
        (type == RemoteSenseAdapterType);
#else
    return false;
#endif
}


DebugAdapterType::DebugAdapterType(const std::string& name): m_name(name)
{
	INIT_DEBUGGER_API_OBJECT();
}


void DebugAdapterType::Register(DebugAdapterType *type)
{
    m_types.push_back(type);
}


DebugAdapterType* DebugAdapterType::GetByName(const std::string &name)
{
    for (DebugAdapterType* adapter: m_types)
    {
        if (adapter->GetName() == name)
            return adapter;
    }
    return nullptr;
}


std::vector<std::string> DebugAdapterType::GetAvailableAdapters(BinaryNinja::BinaryView* data)
{
	std::vector<std::string> result;
	for (DebugAdapterType* adapter: m_types)
	{
		// The adapter must be:
		// 1. valid for the data
		// 2. can connect/execute on the current host system
		if (adapter->IsValidForData(data) &&
			(adapter->CanConnect(data) || adapter->CanExecute(data)))
		{
			result.push_back(adapter->GetName());
		}
	}
	return result;
}


std::string DebugAdapterType::GetBestAdapterForCurrentSystem(BinaryNinja::BinaryView *data)
{
#ifdef WIN32
    return "Local DBGENG";
#elif defined(__clang__)
    return "Local LLDB";
#elif defined(__GNUC__)
    return "Local GDB";
#endif
}
