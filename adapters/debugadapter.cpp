#include "debugadapter.h"
#include "dummyadapter.h"

bool DebugAdapterType::useExec(AdapterType type)
{
    return (type == DefaultAdapterType) || (type == LocalDBGENGAdapterType) ||
        (type == LocalGDBAdapterType) || (type == LocalLLDBADapterType);
}


bool DebugAdapterType::useConnect(AdapterType type)
{
    return (type == RemoteGDBAdapterType) || (type == RemoteLLDBAdapterType) ||
        (type == RemoteSenseAdapterType);
}


bool DebugAdapterType::canUse(AdapterType type)
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
