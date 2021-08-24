#pragma once

#include "debugadapter.h"
#include "binaryninjaapi.h"

class DebugAdapter;

class DebugAdapterType
{
private:
    std::string m_name;
    inline static std::vector<DebugAdapterType*> m_types;

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
    static DebugAdapter* GetNewAdapter(AdapterType);
    static std::string GetName(AdapterType type);

    DebugAdapterType(const std::string& name);
    static void Register(DebugAdapterType* type);
    virtual DebugAdapter* Create(BinaryNinja::BinaryView* data) = 0;
    virtual bool IsValidForData(BinaryNinja::BinaryView* data) = 0;
    virtual bool CanExecute(BinaryNinja::BinaryView* data) = 0;
    virtual bool CanConnect(BinaryNinja::BinaryView* data) = 0;
};
