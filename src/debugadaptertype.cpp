#include "debugadaptertype.h"
#include "./adapters/dummyadapter.h"

bool DebugAdapterType::UseExec(AdapterType type)
{
    return (type == DefaultAdapterType) || (type == LocalDBGENGAdapterType) ||
        (type == LocalGDBAdapterType) || (type == LocalLLDBADapterType);
}


bool DebugAdapterType::UseConnect(AdapterType type)
{
    return (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
        (type == RemoteSenseAdapterType);
}


bool DebugAdapterType::CanUse(AdapterType type)
{
#ifdef WIN32
    return (type == DefaultAdapterType) || (type == LocalDBGENGAdapterType) ||
        (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
        (type == RemoteSenseAdapterType);
#elif defined(__GNUC__)
    return (type == DefaultAdapterType) || (type == LocalGDBAdapterType) ||
        (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
        (type == RemoteSenseAdapterType);
#elif defined(__clang__)
    return (type == DefaultAdapterType) || (type == LocalLLDBADapterType) ||
        (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
        (type == RemoteSenseAdapterType);
#else
    return false;
#endif
}


// TODO: porting is not done for this and GetNewAdapter()
DebugAdapter* DebugAdapterType::GetAdapterForCurrentSystem()
{
    return new DummyAdapter();
}


DebugAdapter* DebugAdapterType::GetNewAdapter()
{
    return GetAdapterForCurrentSystem();
}


std::string DebugAdapterType::GetName(AdapterType type)
{
    switch (type)
    {
    case DefaultAdapterType:
        return "DEFAULT";
    case LocalDBGENGAdapterType:
        return "LOCAL_DBGEND";
    case LocalGDBAdapterType:
        return "LOCAL_GDB";
    case LocalLLDBADapterType:
        return "LOCAL_LLDB";
    case RemoteGDBAdapterType:
        return "REMOTE_GDB";
    case RemoteLLDBAdapterType:
        return "REMOTE_LLDB";
    case RemoteSenseAdapterType:
        return "REMOTE_SENSE";
    default:
        return "UNKNOWN";
    }
}
