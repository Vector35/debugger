#include "windowskerneladapter.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;


WindowsKernelAdapter::WindowsKernelAdapter(BinaryView* data) :
	DbgEngAdapter(data, std::make_unique<DbgEngKernelEngine>())
{
	GenerateDefaultAdapterSettings(data);
}


bool WindowsKernelAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	ConfigureEngine();
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto connectionString = adapterSettings->Get<std::string>("launch.connection_string", data, &scope);
	return m_engine->ExecuteWithArgs(connectionString, "", "");
}


WindowsKernelAdapterType::WindowsKernelAdapterType() : DebugAdapterType("WINDOWS_KERNEL") {}


DebugAdapter* WindowsKernelAdapterType::Create(BinaryNinja::BinaryView* data)
{
    // TODO: someone should free this.
    return new WindowsKernelAdapter(data);
}


bool WindowsKernelAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool WindowsKernelAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
    return true;
}


bool WindowsKernelAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
    return true;
#endif
    return false;
}


Ref<Settings> WindowsKernelAdapter::GetAdapterSettings()
{
	return WindowsKernelAdapterType::GetAdapterSettings();
}


Ref<Settings> WindowsKernelAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}


Ref<Settings> WindowsKernelAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("WindowsKernelAdapterSettings");
	settings->SetResourceId("windows_kernel_adapter_settings");
	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Input file to use to find the base address of the binary view",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");
	settings->RegisterSetting("launch.connection_string",
		R"({
			"title" : "Connection String",
			"type" : "string",
			"default" : "",
			"description" : "Kernel connection string to use.",
			"readOnly" : false
			})");

	return settings;
}


void WindowsKernelAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
}


void BinaryNinjaDebugger::InitWindowsKernelAdapterType()
{
    static WindowsKernelAdapterType localType;
    DebugAdapterType::Register(&localType);
}
