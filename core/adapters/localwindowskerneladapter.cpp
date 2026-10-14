#include "localwindowskerneladapter.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;


LocalWindowsKernelAdapter::LocalWindowsKernelAdapter(BinaryView* data) :
	DbgEngAdapter(data, std::make_unique<DbgEngLocalKernelEngine>())
{
	GenerateDefaultAdapterSettings(data);
}


bool LocalWindowsKernelAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	ConfigureEngine();
	return m_engine->ExecuteWithArgs("", "", "");
}


LocalWindowsKernelAdapterType::LocalWindowsKernelAdapterType() : DebugAdapterType("LOCAL_WINDOWS_KERNEL") {}


DebugAdapter* LocalWindowsKernelAdapterType::Create(BinaryNinja::BinaryView* data)
{
    // TODO: someone should free this.
    return new LocalWindowsKernelAdapter(data);
}


bool LocalWindowsKernelAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool LocalWindowsKernelAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
    return true;
}


bool LocalWindowsKernelAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
    return true;
#endif
    return false;
}


Ref<Settings> LocalWindowsKernelAdapter::GetAdapterSettings()
{
	return LocalWindowsKernelAdapterType::GetAdapterSettings();
}


Ref<Settings> LocalWindowsKernelAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}


Ref<Settings> LocalWindowsKernelAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("LocalWindowsKernelAdapterSettings");
	settings->SetResourceId("local_windows_kernel_adapter_settings");

	return settings;
}


void LocalWindowsKernelAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{

}


void BinaryNinjaDebugger::InitLocalWindowsKernelAdapterType()
{
    static LocalWindowsKernelAdapterType localType;
    DebugAdapterType::Register(&localType);
}
