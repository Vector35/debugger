#include "debugadapter.h"

class DebugAdapter;
class DebugAdapterType
{
public:

    enum AdapterType
    {
        DefaultAdapterType,
        LocalDBGENGAdapterType,
        LocalGDBAdapterType,
        LocalLLDBADapterType,
        RemoteGDBAdapterType,
        RemoteLLDBAdapterType,
        RemoteSenseAdapterType
    };

    static bool UseExec(AdapterType type);
    static bool UseConnect(AdapterType type);
    static bool CanUse(AdapterType type);
    static DebugAdapter* GetAdapterForCurrentSystem();
    static DebugAdapter* GetNewAdapter();
    static std::string GetName(AdapterType type);
};
