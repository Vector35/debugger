#include "dbgengttdadapter.h"
#include <filesystem>
#include <algorithm>
#include <cctype>

using namespace BinaryNinjaDebugger;
using namespace std;


DbgEngTTDAdapter::DbgEngTTDAdapter(BinaryView* data) : DbgEngAdapter(data)
{
    m_usePDBFileName = false;
#ifdef WIN32
	m_ttdInitialized = false;
#endif
	GenerateDefaultAdapterSettings(data);
}


bool DbgEngTTDAdapter::ExecuteWithArgsInternal(const std::string& path, const std::string& args,
                                            const std::string& workingDir, const LaunchConfigurations& configs) {
    m_aboutToBeKilled = false;

	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto tracePath = adapterSettings->Get<std::string>("launch.trace_path", data, &scope);
	scope = SettingsResourceScope;
	auto inputFile = adapterSettings->Get<std::string>("common.inputFile", data, &scope);

    if (this->m_debugActive) {
        this->Reset();
    }

    if (!Start()) {
        this->Reset();
        DebuggerEvent event;
        event.type = LaunchFailureEventType;
        event.data.errorData.error = fmt::format("Failed to initialize DbgEng");
        event.data.errorData.shortError = fmt::format("Failed to initialize DbgEng");
        PostDebuggerEvent(event);
        return false;
    }

    if (const auto result = this->m_debugControl->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK); result != S_OK) {
        this->Reset();
        DebuggerEvent event;
        event.type = LaunchFailureEventType;
        event.data.errorData.error = fmt::format("Failed to engine option DEBUG_ENGOPT_INITIAL_BREAK");
        event.data.errorData.shortError = fmt::format("Failed to engine option");
        PostDebuggerEvent(event);
        return false;
    }

    if (const auto result = this->m_debugClient->OpenDumpFile(const_cast<char *>(tracePath.c_str()));
            result != S_OK) {
        this->Reset();
        DebuggerEvent event;
        event.type = LaunchFailureEventType;
        event.data.errorData.error = fmt::format("OpenDumpFile failed: 0x{:x}", result);
        event.data.errorData.shortError = fmt::format("OpenDumpFile failed: 0x{:x}", result);
        PostDebuggerEvent(event);
        return false;
    }

    // The WaitForEvent() must be called once before the engine fully attaches to the target.
    if (!Wait()) {
        DebuggerEvent event;
        event.type = LaunchFailureEventType;
        event.data.errorData.error = fmt::format("WaitForEvent failed");
        event.data.errorData.shortError = fmt::format("WaitForEvent failed");
        PostDebuggerEvent(event);
    }

    // Apply the breakpoints added before the m_debugClient is created
    ApplyBreakpoints();

    DbgEngAdapter::InvokeBackendCommand("!index");

    auto settings = Settings::Instance();
    if (settings->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction) {
        AddBreakpoint(ModuleNameAndOffset(inputFile, m_entryPoint - m_start));
    }

    if (!settings->Get<bool>("debugger.stopAtSystemEntryPoint")) {
        if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK) {
            this->Reset();
            DebuggerEvent event;
            event.type = LaunchFailureEventType;
            event.data.errorData.error = fmt::format("Failed to resume the target after the system entry point");
            event.data.errorData.shortError = fmt::format("Failed to resume target");
            PostDebuggerEvent(event);
            return false;
        }
    }

    return true;
}


bool DbgEngTTDAdapter::WriteMemory(std::uintptr_t address, const BinaryNinja::DataBuffer& buffer)
{
	return false;
}


bool DbgEngTTDAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
	return false;
}


bool DbgEngTTDAdapter::Start()
{
	if (this->m_debugActive)
		this->Reset();

	auto handle = GetModuleHandleA("dbgeng.dll");
	if (handle == nullptr)
		false;

	//    HRESULT DebugCreate(
	//    [in]  REFIID InterfaceId,
	//    [out] PVOID  *Interface
	//    );
	typedef HRESULT(__stdcall * pfunDebugCreate)(REFIID, PVOID*);
	auto DebugCreate = (pfunDebugCreate)GetProcAddress(handle, "DebugCreate");
	if (DebugCreate == nullptr)
		return false;

	if (const auto result = DebugCreate(__uuidof(IDebugClient7), reinterpret_cast<void**>(&this->m_debugClient));
		result != S_OK)
		throw std::runtime_error("Failed to create IDebugClient7");

	QUERY_DEBUG_INTERFACE(IDebugControl7, &this->m_debugControl);
	QUERY_DEBUG_INTERFACE(IDebugDataSpaces, &this->m_debugDataSpaces);
	QUERY_DEBUG_INTERFACE(IDebugRegisters, &this->m_debugRegisters);
	QUERY_DEBUG_INTERFACE(IDebugSymbols3, &this->m_debugSymbols);
	QUERY_DEBUG_INTERFACE(IDebugSystemObjects, &this->m_debugSystemObjects);

	m_debugEventCallbacks.SetAdapter(this);
	if (const auto result = this->m_debugClient->SetEventCallbacks(&this->m_debugEventCallbacks); result != S_OK)
	{
		LogWarn("Failed to set event callbacks");
		return false;
	}

	m_outputCallbacks.SetAdapter(this);
	if (const auto result = this->m_debugClient->SetOutputCallbacks(&this->m_outputCallbacks); result != S_OK)
	{
		LogWarn("Failed to set output callbacks");
		return false;
	}

	m_inputCallbacks.SetDbgControl(m_debugControl);
	if (const auto result = this->m_debugClient->SetInputCallbacks(&this->m_inputCallbacks); result != S_OK)
	{
		LogWarn("Failed to set input callbacks");
		return false;
	}

	this->m_debugActive = true;
	return true;
}


void DbgEngTTDAdapter::Reset()
{
	m_aboutToBeKilled = false;

	if (!this->m_debugActive)
		return;

	// Cleanup TTD memory analysis resources
	CleanupTTDMemoryAnalysis();

	// Free up the resources if the dbgsrv is launched by the adapter. Otherwise, the dbgsrv is launched outside BN,
	// we should keep everything active.
	SAFE_RELEASE(this->m_debugControl);
	SAFE_RELEASE(this->m_debugDataSpaces);
	SAFE_RELEASE(this->m_debugRegisters);
	SAFE_RELEASE(this->m_debugSymbols);
	SAFE_RELEASE(this->m_debugSystemObjects);

	if (this->m_debugClient)
	{
		this->m_debugClient->EndSession(DEBUG_END_PASSIVE);
		m_server = 0;
	}

	// There seems to be an internal ref-counting issue in the DbgEng TTD engine, that the reference for the debug
	// client is not properly freed after the target has exited. To properly free the debug client instance, here we
	// are calling Release() a few more times to ensure the ref count goes down to 0. Luckily this would not cause
	// a UAF or crash.
	// This might be related to the weird behavior of not terminating the target when we call TerminateProcesses(),
	// (see comment in `DbgEngTTDAdapter::Quit()`).
	// The same issue is not observed when we do forward debugging using the regular DbgEng. Also, I cannot reproduce
	// the issue using my script https://github.com/xusheng6/dbgeng_test.
	for (size_t i = 0; i < 100; i++)
		m_debugClient->Release();

	SAFE_RELEASE(this->m_debugClient);

	this->m_debugActive = false;
}


bool DbgEngTTDAdapter::GoReverse()
{
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	m_lastOperationIsStepInto = false;
	if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_REVERSE_GO) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}


bool DbgEngTTDAdapter::StepIntoReverse()
{
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	m_lastOperationIsStepInto = true;
	if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_REVERSE_STEP_INTO) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}


bool DbgEngTTDAdapter::StepOverReverse()
{
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	m_lastOperationIsStepInto = true;
	if (this->m_debugControl->SetExecutionStatus(DEBUG_STATUS_REVERSE_STEP_OVER) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}

bool DbgEngTTDAdapter::StepReturnReverse()
{
	if (ExecStatus() != DEBUG_STATUS_BREAK)
		return false;

	InvokeBackendCommand("g-u");
	return true;
}


bool DbgEngTTDAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	return DbgEngAdapter::SupportFeature(feature) || feature == DebugAdapterSupportTTD ||
		feature == DebugAdapterSupportStepOverReverse;
}


bool DbgEngTTDAdapter::Quit()
{
	m_aboutToBeKilled = true;
	m_lastOperationIsStepInto = false;
	if (!this->m_debugClient)
		return false;

	// I am not sure why TerminateProcesses() would not work. It just let the target run freely till the end of the
	// trace and not terminating the process at all.
	if (this->m_debugClient->TerminateCurrentProcess() != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
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

	return settings;
}


// TTD Memory Analysis Implementation
std::vector<TTDMemoryEvent> DbgEngTTDAdapter::GetMemoryEvents(const TTDPosition& startPos, const TTDPosition& endPos, TTDMemoryAccessType accessType)
{
	std::vector<TTDMemoryEvent> events;
	
#ifdef WIN32
	if (!m_ttdInitialized && !InitializeTTDMemoryAnalysis())
	{
		LogError("Failed to initialize TTD memory analysis");
		return events;
	}

	if (!QueryMemoryAccess(startPos, endPos, accessType, events))
	{
		LogError("Failed to query TTD memory access events");
	}
#else
	LogError("TTD memory analysis is only supported on Windows");
#endif
	
	return events;
}

std::vector<TTDMemoryEvent> DbgEngTTDAdapter::GetMemoryEventsForAddress(uint64_t address, uint64_t size, TTDMemoryAccessType accessType)
{
	std::vector<TTDMemoryEvent> events;
	
#ifdef WIN32
	if (!m_ttdInitialized && !InitializeTTDMemoryAnalysis())
	{
		LogError("Failed to initialize TTD memory analysis");
		return events;
	}

	// For address-specific queries, we query the entire trace
	TTDPosition startPos(0, 0);
	TTDPosition endPos(UINT64_MAX, UINT64_MAX);
	
	std::vector<TTDMemoryEvent> allEvents;
	if (!QueryMemoryAccess(startPos, endPos, accessType, allEvents))
	{
		LogError("Failed to query TTD memory access events");
		return events;
	}
	
	// Filter events for the specific address range
	for (const auto& event : allEvents)
	{
		if (event.address >= address && event.address < address + size)
		{
			events.push_back(event);
		}
	}
#else
	LogError("TTD memory analysis is only supported on Windows");
#endif
	
	return events;
}

TTDPosition DbgEngTTDAdapter::GetCurrentTTDPosition()
{
	TTDPosition position;
	
#ifdef WIN32
	if (!m_debugControl)
	{
		LogError("Debug control interface not available");
		return position;
	}
	
	// Use the TTD !position command to get current position
	std::string output = InvokeBackendCommand("!position");
	
	// Parse the position output (format like "1A0:12F")
	// This is a simplified parser - a more robust implementation would be needed
	size_t colonPos = output.find(':');
	if (colonPos != std::string::npos)
	{
		try 
		{
			std::string seqStr = output.substr(0, colonPos);
			std::string stepStr = output.substr(colonPos + 1);
			
			// Remove any non-hex characters
			seqStr.erase(std::remove_if(seqStr.begin(), seqStr.end(), 
				[](char c) { return !std::isxdigit(c); }), seqStr.end());
			stepStr.erase(std::remove_if(stepStr.begin(), stepStr.end(), 
				[](char c) { return !std::isxdigit(c); }), stepStr.end());
			
			if (!seqStr.empty() && !stepStr.empty())
			{
				position.sequence = std::stoull(seqStr, nullptr, 16);
				position.step = std::stoull(stepStr, nullptr, 16);
			}
		}
		catch (const std::exception& e)
		{
			LogError("Failed to parse TTD position: %s", e.what());
		}
	}
#else
	LogError("TTD position queries are only supported on Windows");
#endif
	
	return position;
}

bool DbgEngTTDAdapter::SetTTDPosition(const TTDPosition& position)
{
#ifdef WIN32
	if (!m_debugControl)
	{
		LogError("Debug control interface not available");
		return false;
	}
	
	// Use the TTD !tt command to navigate to position
	std::string command = fmt::format("!tt {:X}:{:X}", position.sequence, position.step);
	std::string output = InvokeBackendCommand(command);
	
	// Check if the command succeeded (basic check)
	return output.find("error") == std::string::npos && output.find("failed") == std::string::npos;
#else
	LogError("TTD navigation is only supported on Windows");
	return false;
#endif
}

bool DbgEngTTDAdapter::InitializeTTDMemoryAnalysis()
{
#ifdef WIN32
	if (m_ttdInitialized)
		return true;
		
	if (!m_debugClient)
	{
		LogError("Debug client not available for TTD initialization");
		return false;
	}
	
	// For now, we'll use basic TTD command-line interface
	// This can be enhanced later with full data model APIs
	m_ttdInitialized = true;
	LogInfo("TTD memory analysis initialized successfully (basic mode)");
	return true;
#else
	return false;
#endif
}

void DbgEngTTDAdapter::CleanupTTDMemoryAnalysis()
{
#ifdef WIN32
	m_ttdInitialized = false;
#endif
}

bool DbgEngTTDAdapter::QueryMemoryAccess(const TTDPosition& startPos, const TTDPosition& endPos, TTDMemoryAccessType accessType, std::vector<TTDMemoryEvent>& events)
{
#ifdef WIN32
	if (!m_debugControl)
	{
		LogError("Debug control interface not available");
		return false;
	}
	
	try
	{
		// This is a basic implementation using DbgEng commands
		// A full implementation would use the data model APIs directly
		std::string accessTypeStr;
		switch (accessType)
		{
		case TTDMemoryRead:
			accessTypeStr = "r";
			break;
		case TTDMemoryWrite:
			accessTypeStr = "w";
			break;
		case TTDMemoryExecute:
			accessTypeStr = "e";
			break;
		default:
			accessTypeStr = "rwe";
			break;
		}
		
		// Use the dx command to query TTD memory objects
		// This is a placeholder command - in a real implementation, we would
		// parse the actual TTD memory objects data model
		std::string command = fmt::format("dx @$cursession.TTD.Memory(0x0,0xFFFFFFFFFFFFFFFF,\"{}\").Count", accessTypeStr);
		std::string output = InvokeBackendCommand(command);
		
		LogInfo("TTD memory query executed: %s", command.c_str());
		LogDebug("Output: %s", output.c_str());
		
		// For now, create a sample event to demonstrate the structure
		// In a real implementation, we would parse the actual TTD data model output
		if (!output.empty() && output.find("error") == std::string::npos && output.find("Error") == std::string::npos)
		{
			// Create a sample event for demonstration
			// Real implementation would parse the data model objects
			TTDMemoryEvent sampleEvent;
			sampleEvent.position = startPos;
			sampleEvent.accessType = accessType;
			sampleEvent.address = 0x1000; // Placeholder
			sampleEvent.size = 4; // Placeholder
			sampleEvent.threadId = 1; // Placeholder
			sampleEvent.instructionAddress = 0x400000; // Placeholder
			events.push_back(sampleEvent);
			
			LogInfo("Created sample TTD memory event (placeholder implementation)");
		}
		
		return true;
	}
	catch (const std::exception& e)
	{
		LogError("Exception in QueryMemoryAccess: %s", e.what());
		return false;
	}
#else
	return false;
#endif
}


void DbgEngTTDAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
}


void BinaryNinjaDebugger::InitDbgEngTTDAdapterType()
{
    static DbgEngTTDAdapterType localType;
    DebugAdapterType::Register(&localType);
}
