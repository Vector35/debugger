#include "windowsdumpfile.h"

using namespace BinaryNinjaDebugger;


WindowsDumpFileAdapter::WindowsDumpFileAdapter(BinaryView* data) :
	DbgEngAdapter(data, std::make_unique<DbgEngDumpEngine>())
{
	GenerateDefaultAdapterSettings(data);
}


bool WindowsDumpFileAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	ConfigureEngine();
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto dumpFile = adapterSettings->Get<std::string>("launch.dump_file", data, &scope);
	return m_engine->ExecuteWithArgs(dumpFile, "", "");
}


WindowsDumpFileAdapterType::WindowsDumpFileAdapterType() : DebugAdapterType("WINDOWS_DUMP_FILE") {}


DebugAdapter* WindowsDumpFileAdapterType::Create(BinaryNinja::BinaryView* data)
{
    // TODO: someone should free this.
    return new WindowsDumpFileAdapter(data);
}


bool WindowsDumpFileAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool WindowsDumpFileAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
    return true;
}


bool WindowsDumpFileAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
    return true;
#endif
    return false;
}




Ref<Settings> WindowsDumpFileAdapter::GetAdapterSettings()
{
	return WindowsDumpFileAdapterType::GetAdapterSettings();
}


Ref<Settings> WindowsDumpFileAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}


Ref<Settings> WindowsDumpFileAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("WindowsDumpFIleAdapterSettings");
	settings->SetResourceId("windows_dump_file_adapter_settings");
	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Input file to use to find the base address of the binary view",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");
	settings->RegisterSetting("launch.dump_file",
		R"({
			"title" : "Dump File Path",
			"type" : "string",
			"default" : "",
			"description" : "Path of the dump file to open",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");

	return settings;
}


void WindowsDumpFileAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
}


void BinaryNinjaDebugger::InitWindowsDumpFileAdapterType()
{
    static WindowsDumpFileAdapterType localType;
    DebugAdapterType::Register(&localType);
}
