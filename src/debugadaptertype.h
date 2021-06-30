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

    static bool useExec(AdapterType type);
    static bool useConnect(AdapterType type);
    static bool canUse(AdapterType type);
    static DebugAdapter* GetAdapterForCurrentSystem();
    static DebugAdapter* GetNewAdapter();
};
