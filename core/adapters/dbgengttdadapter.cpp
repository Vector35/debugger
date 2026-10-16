#include "dbgengttdadapter.h"

using namespace BinaryNinjaDebugger;


DbgEngTTDAdapter::DbgEngTTDAdapter(BinaryView* data) : DbgEngAdapter(data, std::make_unique<DbgEngTTDEngine>())
{
	GenerateDefaultAdapterSettings(data);
}


bool DbgEngTTDAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
	const std::string& workingDir, const LaunchConfigurations& configs)
{
	ConfigureEngine();
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto tracePath = adapterSettings->Get<std::string>("launch.trace_path", data, &scope);
	return m_engine->ExecuteWithArgs(tracePath, "", "");
}


bool DbgEngTTDAdapter::GoReverse()
{
	return TTD().GoReverse();
}


bool DbgEngTTDAdapter::StepIntoReverse()
{
	return TTD().StepIntoReverse();
}


bool DbgEngTTDAdapter::StepOverReverse()
{
	return TTD().StepOverReverse();
}


bool DbgEngTTDAdapter::StepReturnReverse()
{
	return TTD().StepReturnReverse();
}


DbgEngTTDAdapterType::DbgEngTTDAdapterType() : DebugAdapterType("DBGENG_TTD") {}


DebugAdapter* DbgEngTTDAdapterType::Create(BinaryNinja::BinaryView* data)
{
    // TODO: someone should free this.
    return new DbgEngTTDAdapter(data);
}


bool DbgEngTTDAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	return data->GetTypeName() == "PE" || data->GetTypeName() == "Raw" || data->GetTypeName() == "Mapped";
}


bool DbgEngTTDAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
    return true;
}


bool DbgEngTTDAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
#ifdef WIN32
    return true;
#endif
    return false;
}


Ref<Settings> DbgEngTTDAdapter::GetAdapterSettings()
{
	return DbgEngTTDAdapterType::GetAdapterSettings();
}


Ref<Settings> DbgEngTTDAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = RegisterAdapterSettings();
	return settings;
}


Ref<Settings> DbgEngTTDAdapterType::RegisterAdapterSettings()
{
	Ref<Settings> settings = Settings::Instance("DbgEngTTDAdapterSettings");
	settings->SetResourceId("dbgeng_ttd_adapter_settings");
	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Input file to use to find the base address of the binary view",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");
	settings->RegisterSetting("launch.trace_path",
		R"({
			"title" : "Trace Path",
			"type" : "string",
			"default" : "",
			"description" : "Path of the trace file to replay.",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");
	settings->RegisterSetting("ttd.maxMemoryQueryResults",
		R"({
			"title" : "Max Memory Query Results",
			"type" : "number",
			"default" : 100000,
			"minValue" : 0,
			"maxValue" : 18446744073709551615,
			"description" : "Maximum number of results to return from TTD Memory queries. Set to 0 for no limit.",
			"readOnly" : false
			})");
	settings->RegisterSetting("ttd.maxCallsQueryResults",
		R"({
			"title" : "Max Calls Query Results",
			"type" : "number",
			"default" : 100000,
			"minValue" : 0,
			"maxValue" : 18446744073709551615,
			"description" : "Maximum number of results to return from TTD Calls queries. Set to 0 for no limit.",
			"readOnly" : false
			})");
	settings->RegisterSetting("ttd.maxEventsQueryResults",
	R"({
			"title" : "Max Events Query Results",
			"type" : "number",
			"default" : 100000,
			"minValue" : 0,
			"maxValue" : 18446744073709551615,
			"description" : "Maximum number of results to return from TTD Events queries. Set to 0 for no limit.",
			"readOnly" : false
			})");

	return settings;
}


std::vector<TTDMemoryEvent> DbgEngTTDAdapter::GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxMemoryQueryResults", GetData(), &scope);

	return TTD().GetTTDMemoryAccessForAddress(startAddress, endAddress, accessType, maxResults);
}


std::vector<TTDPositionRangeIndexedMemoryEvent> DbgEngTTDAdapter::GetTTDMemoryAccessForPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, const TTDPosition startTime, const TTDPosition endTime)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxMemoryQueryResults", GetData(), &scope);

	return TTD().GetTTDMemoryAccessForPositionRange(
		startAddress, endAddress, accessType, startTime, endTime, maxResults);
}


TTDPosition DbgEngTTDAdapter::GetCurrentTTDPosition()
{
	return TTD().GetCurrentTTDPosition();
}


bool DbgEngTTDAdapter::SetTTDPosition(const TTDPosition& position)
{
	return TTD().SetTTDPosition(position);
}


std::pair<bool, TTDMemoryEvent> DbgEngTTDAdapter::GetTTDNextMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType)
{
	return TTD().GetTTDNextMemoryAccess(address, size, accessType);
}


std::pair<bool, TTDMemoryEvent> DbgEngTTDAdapter::GetTTDPrevMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType)
{
	return TTD().GetTTDPrevMemoryAccess(address, size, accessType);
}


std::optional<TTDRegisterWriteEvent> DbgEngTTDAdapter::GetTTDNextRegisterWrite(const std::string& reg)
{
	return TTD().GetTTDNextRegisterWrite(reg);
}


std::optional<TTDRegisterWriteEvent> DbgEngTTDAdapter::GetTTDPrevRegisterWrite(const std::string& reg)
{
	return TTD().GetTTDPrevRegisterWrite(reg);
}


void DbgEngTTDAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
}


std::vector<TTDCallEvent> DbgEngTTDAdapter::GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxCallsQueryResults", GetData(), &scope);

	return TTD().GetTTDCallsForSymbols(symbols, startReturnAddress, endReturnAddress, maxResults);
}


std::vector<TTDEvent> DbgEngTTDAdapter::GetTTDEvents(TTDEventType eventType)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxCallsQueryResults", GetData(), &scope);

	return TTD().GetTTDEvents(eventType, maxResults);
}


std::vector<TTDEvent> DbgEngTTDAdapter::GetAllTTDEvents()
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxCallsQueryResults", GetData(), &scope);

	return TTD().GetAllTTDEvents(maxResults);
}


void BinaryNinjaDebugger::InitDbgEngTTDAdapterType()
{
    static DbgEngTTDAdapterType localType;
    DebugAdapterType::Register(&localType);
}
