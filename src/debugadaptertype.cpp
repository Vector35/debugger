#include "debugadaptertype.h"
#include "./adapters/dummyadapter.h"
#include "./adapters/gdbadapter.h"

#ifdef WIN32
#include "./adapters/dbgengadapter.h"
#endif

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


DebugAdapter* DebugAdapterType::GetAdapterForCurrentSystem()
{
#ifdef WIN32
    return new DbgEngAdapter();
#endif

#ifdef APPLE
    // return LLDBAdapter();
#endif

#ifdef __GNUC__
    // Do not redirect the gdbserver stdin/out/err to /dev/null, when running in GUI
    return new GdbAdapter(false);
#endif
    // return new DummyAdapter();
}


DebugAdapter* DebugAdapterType::GetNewAdapter(AdapterType adapterType)
{
    switch (adapterType)
    {
#ifdef WIN32
    case LocalDBGENGAdapterType:
        return new DbgEngAdapter();
#endif

#ifdef APPLE
    // case LocalLLDBADapterType:
    // case RemoteLLDBAdapterType:
        // return LLDBAdapter();
#endif

#ifdef __GNUC__
    case LocalGDBAdapterType:
    case RemoteGDBAdapterType:
        return new GdbAdapter();
#endif
    case DefaultAdapterType:
        return GetAdapterForCurrentSystem();
    default:
        throw std::runtime_error("Unsupported adapter type " + GetName(adapterType));
    }
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
