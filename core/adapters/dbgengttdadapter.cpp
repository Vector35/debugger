#include "dbgengttdadapter.h"
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <sstream>

using namespace BinaryNinjaDebugger;
using namespace std;


DbgEngTTDAdapter::DbgEngTTDAdapter(BinaryView* data) : DbgEngAdapter(data)
{
    m_usePDBFileName = false;
	m_eventsCached = false;
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

    if (this->m_dbgengInitialized) {
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
	if (this->m_dbgengInitialized)
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

	QUERY_DEBUG_INTERFACE(IHostDataModelAccess, &this->m_dataModelManager);
	m_dataModelManager->GetDataModel(&m_modelMgr, &m_debugHost);

	if (m_debugHost->QueryInterface(__uuidof(IDebugHostEvaluator), reinterpret_cast<void**>(&m_hostEvaluator)) != S_OK)
	{
		LogWarn("Failed to get IDebugHostEvaluator interface");
	}

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

	this->m_dbgengInitialized = true;
	return true;
}


void DbgEngTTDAdapter::Reset()
{
	m_aboutToBeKilled = false;
	
	// Clear TTD events cache when resetting
	ClearTTDEventsCache();

	if (!this->m_dbgengInitialized)
		return;

	// Free up the resources if the dbgsrv is launched by the adapter. Otherwise, the dbgsrv is launched outside BN,
	// we should keep everything active.
	SAFE_RELEASE(this->m_debugControl);
	SAFE_RELEASE(this->m_debugDataSpaces);
	SAFE_RELEASE(this->m_debugRegisters);
	SAFE_RELEASE(this->m_debugSymbols);
	SAFE_RELEASE(this->m_dataModelManager);
	SAFE_RELEASE(this->m_modelMgr);
	SAFE_RELEASE(this->m_debugHost);
	SAFE_RELEASE(this->m_hostEvaluator);

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

	this->m_dbgengInitialized = false;
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
	std::vector<TTDMemoryEvent> events;
	
	if (!QueryMemoryAccessByAddress(startAddress, endAddress, accessType, events))
	{
		LogError("Failed to query TTD memory access events for address range 0x%llx-0x%llx", startAddress, endAddress);
	}
	
	return events;
}

TTDPosition DbgEngTTDAdapter::GetCurrentTTDPosition()
{
	TTDPosition position;
	
	if (!m_debugControl)
	{
		LogError("Debug control interface not available");
		return position;
	}
	
	// Always use the !position command to retrieve the current timestamp
	std::string output = InvokeBackendCommand("!position");
	
	if (!output.empty())
	{
		// Parse the position output (format like "Time Travel Position: 602C:0")
		size_t prefixPos = output.find("Time Travel Position:");
		if (prefixPos != std::string::npos)
		{
			// Find the position data after the prefix
			size_t dataStart = prefixPos + strlen("Time Travel Position:");
			std::string positionData = output.substr(dataStart);
			
			// Find the colon in the position data
			size_t colonPos = positionData.find(':');
			if (colonPos != std::string::npos)
			{
				try 
				{
					std::string seqStr = positionData.substr(0, colonPos);
					std::string stepStr = positionData.substr(colonPos + 1);
					
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
		}
		else
		{
			// Fallback: try to find a simple "XXXX:Y" pattern in the output
			size_t colonPos = output.find(':');
			if (colonPos != std::string::npos)
			{
				try 
				{
					// Look backwards from colon to find start of hex sequence
					size_t seqStart = colonPos;
					while (seqStart > 0 && std::isxdigit(output[seqStart - 1]))
						seqStart--;
					
					// Look forwards from colon to find end of hex step
					size_t stepEnd = colonPos + 1;
					while (stepEnd < output.length() && std::isxdigit(output[stepEnd]))
						stepEnd++;
					
					if (seqStart < colonPos && stepEnd > colonPos + 1)
					{
						std::string seqStr = output.substr(seqStart, colonPos - seqStart);
						std::string stepStr = output.substr(colonPos + 1, stepEnd - colonPos - 1);
						
						if (!seqStr.empty() && !stepStr.empty())
						{
							position.sequence = std::stoull(seqStr, nullptr, 16);
							position.step = std::stoull(stepStr, nullptr, 16);
						}
					}
				}
				catch (const std::exception& e)
				{
					LogError("Failed to parse TTD position from fallback parsing: %s", e.what());
				}
			}
		}
	}
	
	return position;
}

bool DbgEngTTDAdapter::SetTTDPosition(const TTDPosition& position)
{
	if (!m_debugControl)
	{
		LogError("Debug control interface not available");
		return false;
	}
	
	// Use InvokeBackendCommand with !tt command to navigate to position
	std::string command = fmt::format("!tt {:X}:{:X}", position.sequence, position.step);
	std::string output = InvokeBackendCommand(command);
	
	// Check if the command succeeded (basic check)
	bool success = output.find("error") == std::string::npos && output.find("failed") == std::string::npos;
	if (success)
	{
		LogInfo("%s", fmt::format("Successfully navigated to TTD position {:X}:{:X}", position.sequence, position.step).c_str());
	}
	else
	{
		LogError("%s", fmt::format("Failed to navigate to TTD position {:X}:{:X}", position.sequence, position.step).c_str());
	}
	return success;
}

bool DbgEngTTDAdapter::QueryMemoryAccessByAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, std::vector<TTDMemoryEvent>& events)
{
	if (!m_debugControl)
	{
		LogError("Debug control interface not available");
		return false;
	}
	
	try
	{
		// Build the access type string for TTD memory queries - combine flags as needed
		std::string accessTypeStr;
		if (accessType & TTDMemoryRead) accessTypeStr += "r";
		if (accessType & TTDMemoryWrite) accessTypeStr += "w";
		if (accessType & TTDMemoryExecute) accessTypeStr += "e";
		
		if (accessTypeStr.empty())
		{
			LogError("Invalid access type specified");
			return false;
		}
		
		// Create the actual TTD memory query expression
		std::string expression = fmt::format("@$cursession.TTD.Memory(0x{:x},0x{:x},\"{}\")", startAddress, endAddress, accessTypeStr);
		
		LogInfo("Executing TTD memory query: %s", expression.c_str());
		
		// Execute the query and parse results
		if (!ParseTTDMemoryObjects(expression, accessType, events))
		{
			LogError("Failed to parse TTD memory objects from query");
			return false;
		}
		
		LogInfo("Successfully retrieved %zu TTD memory events", events.size());
		return true;
	}
	catch (const std::exception& e)
	{
		LogError("Exception in QueryMemoryAccessByAddress: %s", e.what());
		return false;
	}
}


void DbgEngTTDAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
}


// Data model helper method implementation
std::string DbgEngTTDAdapter::EvaluateDataModelExpression(const std::string& expression)
{
	if (!m_hostEvaluator)
	{
		LogError("Data model evaluator not available");
		return "";
	}

	try
	{
		// Convert expression to wide string
		std::wstring wExpression(expression.begin(), expression.end());
		
		// Create context for evaluation
		ComPtr<IDebugHostContext> hostContext;
		if (FAILED(m_debugHost->GetCurrentContext(hostContext.GetAddressOf())))
		{
			LogError("Failed to get current debug host context");
			return "";
		}

		// Evaluate the expression
		ComPtr<IModelObject> result;
		ComPtr<IKeyStore> metadata;
		HRESULT hr = m_hostEvaluator->EvaluateExtendedExpression(
			hostContext.Get(),
			wExpression.c_str(),
			nullptr, // No binding context
			result.GetAddressOf(),
			metadata.GetAddressOf()
		);

		if (FAILED(hr))
		{
			LogError("Failed to evaluate expression '%s': 0x%08x", expression.c_str(), hr);
			return "";
		}

		// Convert result to string
		if (result)
		{
			// Try to get intrinsic value directly
			VARIANT vtValue;
			VariantInit(&vtValue);
			
			if (SUCCEEDED(result->GetIntrinsicValueAs(VT_BSTR, &vtValue)))
			{
				if (vtValue.vt == VT_BSTR && vtValue.bstrVal)
				{
					// Convert BSTR to std::string
					int len = WideCharToMultiByte(CP_UTF8, 0, vtValue.bstrVal, -1, nullptr, 0, nullptr, nullptr);
					if (len > 0)
					{
						std::string result_str(len - 1, '\0');
						WideCharToMultiByte(CP_UTF8, 0, vtValue.bstrVal, -1, &result_str[0], len, nullptr, nullptr);
						VariantClear(&vtValue);
						return result_str;
					}
				}
			}
			
			VariantClear(&vtValue);
			
			// If we can't get intrinsic value, try to convert object to string representation
			// This is a simplified approach - real implementation might need more sophisticated handling
			LogInfo("Successfully evaluated expression '%s' (complex result)", expression.c_str());
			return "complex_result"; // Placeholder
		}

		return "";
	}
	catch (const std::exception& e)
	{
		LogError("Exception in EvaluateDataModelExpression: %s", e.what());
		return "";
	}
}

// Implementation of TTD memory objects parsing
bool DbgEngTTDAdapter::ParseTTDMemoryObjects(const std::string& expression, TTDMemoryAccessType accessType, std::vector<TTDMemoryEvent>& events)
{
	if (!m_hostEvaluator)
	{
		LogError("Data model evaluator not available");
		return false;
	}

	try
	{
		// Convert expression to wide string
		std::wstring wExpression(expression.begin(), expression.end());
		
		// Create context for evaluation
		ComPtr<IDebugHostContext> hostContext;
		if (FAILED(m_debugHost->GetCurrentContext(hostContext.GetAddressOf())))
		{
			LogError("Failed to get current debug host context");
			return false;
		}

		// Evaluate the TTD memory collection expression
		ComPtr<IModelObject> result;
		ComPtr<IKeyStore> metadata;
		HRESULT hr = m_hostEvaluator->EvaluateExtendedExpression(
			hostContext.Get(),
			wExpression.c_str(),
			nullptr, // No binding context
			result.GetAddressOf(),
			metadata.GetAddressOf()
		);

		if (FAILED(hr))
		{
			LogError("Failed to evaluate TTD memory expression '%s': 0x%08x", expression.c_str(), hr);
			return false;
		}

		// Check if result is iterable (collection)
		ComPtr<IIterableConcept> iterableConcept;
		if (FAILED(result->GetConcept(__uuidof(IIterableConcept), &iterableConcept, nullptr)))
		{
			LogError("TTD memory result is not iterable");
			return false;
		}

		// Get iterator
		ComPtr<IModelIterator> iterator;
		if (FAILED(iterableConcept->GetIterator(result.Get(), &iterator)))
		{
			LogError("Failed to get iterator for TTD memory objects");
			return false;
		}

		// Iterate through memory objects
		ComPtr<IModelObject> memoryObject;
		ComPtr<IKeyStore> metadataKeyStore;
		
		// Get the max results setting
		auto adapterSettings = GetAdapterSettings();
		BNSettingsScope scope = SettingsResourceScope;
		auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxMemoryQueryResults", GetData(), &scope);
		
		uint64_t resultCounter = 0;
		bool wasLimited = false;
		
		while (SUCCEEDED(iterator->GetNext(&memoryObject, 0, nullptr, &metadataKeyStore)))
		{
			if (!memoryObject)
				break;
			
			// Check if we've reached the limit (0 means no limit)
			if (maxResults > 0 && resultCounter >= maxResults)
			{
				wasLimited = true;
				break;
			}
				
			TTDMemoryEvent event;
			
			// Extract all fields from the memory object based on Microsoft documentation
			
			// Get EventType (should be "MemoryAccess")
			ComPtr<IModelObject> eventTypeObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"EventType", &eventTypeObj, nullptr)))
			{
				VARIANT vtEventType;
				VariantInit(&vtEventType);
				if (SUCCEEDED(eventTypeObj->GetIntrinsicValueAs(VT_BSTR, &vtEventType)) && vtEventType.bstrVal)
				{
					// Convert BSTR to std::string
					_bstr_t bstr(vtEventType.bstrVal);
					event.eventType = std::string(bstr);
				}
				VariantClear(&vtEventType);
			}
			
			// Get ThreadId
			ComPtr<IModelObject> threadIdObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"ThreadId", &threadIdObj, nullptr)))
			{
				VARIANT vtThreadId;
				VariantInit(&vtThreadId);
				if (SUCCEEDED(threadIdObj->GetIntrinsicValueAs(VT_UI4, &vtThreadId)))
				{
					event.threadId = vtThreadId.ulVal;
				}
				VariantClear(&vtThreadId);
			}
			
			// Get UniqueThreadId
			ComPtr<IModelObject> uniqueThreadIdObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"UniqueThreadId", &uniqueThreadIdObj, nullptr)))
			{
				VARIANT vtUniqueThreadId;
				VariantInit(&vtUniqueThreadId);
				if (SUCCEEDED(uniqueThreadIdObj->GetIntrinsicValueAs(VT_UI4, &vtUniqueThreadId)))
				{
					event.uniqueThreadId = vtUniqueThreadId.ulVal;
				}
				VariantClear(&vtUniqueThreadId);
			}
			
			// Get TimeStart for position
			ComPtr<IModelObject> timeStartObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"TimeStart", &timeStartObj, nullptr)))
			{
				// TimeStart is typically a TTD position object with Sequence and Steps
				ComPtr<IModelObject> sequenceObj, stepsObj;
				if (SUCCEEDED(timeStartObj->GetKeyValue(L"Sequence", &sequenceObj, nullptr)))
				{
					VARIANT vtSequence;
					VariantInit(&vtSequence);
					if (SUCCEEDED(sequenceObj->GetIntrinsicValueAs(VT_UI8, &vtSequence)))
					{
						event.timeStart.sequence = vtSequence.ullVal;
					}
					VariantClear(&vtSequence);
				}
				
				if (SUCCEEDED(timeStartObj->GetKeyValue(L"Steps", &stepsObj, nullptr)))
				{
					VARIANT vtSteps;
					VariantInit(&vtSteps);
					if (SUCCEEDED(stepsObj->GetIntrinsicValueAs(VT_UI8, &vtSteps)))
					{
						event.timeStart.step = vtSteps.ullVal;
					}
					VariantClear(&vtSteps);
				}
			}
			
			// Get TimeEnd for position
			ComPtr<IModelObject> timeEndObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"TimeEnd", &timeEndObj, nullptr)))
			{
				// TimeEnd is typically a TTD position object with Sequence and Steps
				ComPtr<IModelObject> sequenceObj, stepsObj;
				if (SUCCEEDED(timeEndObj->GetKeyValue(L"Sequence", &sequenceObj, nullptr)))
				{
					VARIANT vtSequence;
					VariantInit(&vtSequence);
					if (SUCCEEDED(sequenceObj->GetIntrinsicValueAs(VT_UI8, &vtSequence)))
					{
						event.timeEnd.sequence = vtSequence.ullVal;
					}
					VariantClear(&vtSequence);
				}
				
				if (SUCCEEDED(timeEndObj->GetKeyValue(L"Steps", &stepsObj, nullptr)))
				{
					VARIANT vtSteps;
					VariantInit(&vtSteps);
					if (SUCCEEDED(stepsObj->GetIntrinsicValueAs(VT_UI8, &vtSteps)))
					{
						event.timeEnd.step = vtSteps.ullVal;
					}
					VariantClear(&vtSteps);
				}
			}
			
			// Get Address
			ComPtr<IModelObject> addressObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"Address", &addressObj, nullptr)))
			{
				VARIANT vtAddress;
				VariantInit(&vtAddress);
				if (SUCCEEDED(addressObj->GetIntrinsicValueAs(VT_UI8, &vtAddress)))
				{
					event.address = vtAddress.ullVal;
				}
				VariantClear(&vtAddress);
			}
			
			// Get MemoryAddress (may be same as Address)
			ComPtr<IModelObject> memoryAddressObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"MemoryAddress", &memoryAddressObj, nullptr)))
			{
				VARIANT vtMemoryAddress;
				VariantInit(&vtMemoryAddress);
				if (SUCCEEDED(memoryAddressObj->GetIntrinsicValueAs(VT_UI8, &vtMemoryAddress)))
				{
					event.memoryAddress = vtMemoryAddress.ullVal;
				}
				VariantClear(&vtMemoryAddress);
			}
			else
			{
				// If MemoryAddress is not available, use Address as fallback
				event.memoryAddress = event.address;
			}
			
			// Get Size
			ComPtr<IModelObject> sizeObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"Size", &sizeObj, nullptr)))
			{
				VARIANT vtSize;
				VariantInit(&vtSize);
				if (SUCCEEDED(sizeObj->GetIntrinsicValueAs(VT_UI8, &vtSize)))
				{
					event.size = vtSize.ullVal;
				}
				VariantClear(&vtSize);
			}
			
			// Get IP (Instruction Pointer)
			ComPtr<IModelObject> ipObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"IP", &ipObj, nullptr)))
			{
				VARIANT vtIP;
				VariantInit(&vtIP);
				if (SUCCEEDED(ipObj->GetIntrinsicValueAs(VT_UI8, &vtIP)))
				{
					event.instructionAddress = vtIP.ullVal;
				}
				VariantClear(&vtIP);
			}
			
			// Get Value (the value that was read/written/executed)
			ComPtr<IModelObject> valueObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"Value", &valueObj, nullptr)))
			{
				VARIANT vtValue;
				VariantInit(&vtValue);
				if (SUCCEEDED(valueObj->GetIntrinsicValueAs(VT_UI8, &vtValue)))
				{
					event.value = vtValue.ullVal;
				}
				VariantClear(&vtValue);
			}
			
			// Get AccessType from the object itself
			ComPtr<IModelObject> accessTypeObj;
			if (SUCCEEDED(memoryObject->GetKeyValue(L"AccessType", &accessTypeObj, nullptr)))
			{
				VARIANT vtAccessType;
				VariantInit(&vtAccessType);
				if (SUCCEEDED(accessTypeObj->GetIntrinsicValueAs(VT_BSTR, &vtAccessType)))
				{
					_bstr_t bstr(vtAccessType.bstrVal);
					std::string accessTypeStr = std::string(bstr);
					
					// Parse access type string to bitfield
					TTDMemoryAccessType parsedAccessType = static_cast<TTDMemoryAccessType>(0);
					if (accessTypeStr.find("Read") != std::string::npos)
						parsedAccessType = static_cast<TTDMemoryAccessType>(parsedAccessType | TTDMemoryRead);
					if (accessTypeStr.find("Write") != std::string::npos)
						parsedAccessType = static_cast<TTDMemoryAccessType>(parsedAccessType | TTDMemoryWrite);
					if (accessTypeStr.find("Execute") != std::string::npos)
						parsedAccessType = static_cast<TTDMemoryAccessType>(parsedAccessType | TTDMemoryExecute);
					
					event.accessType = parsedAccessType;
				}
				else
				{
					// Fallback to query parameter if parsing fails
					event.accessType = accessType;
				}
				VariantClear(&vtAccessType);
			}
			else
			{
				// Fallback to query parameter if field is not available
				event.accessType = accessType;
			}
			
			events.push_back(event);
			resultCounter++;
			
			// Reset objects for next iteration
			memoryObject.Reset();
			metadataKeyStore.Reset();
		}
		
		if (wasLimited)
		{
			LogWarnF("Successfully parsed {} TTD memory events from data model (limited by max results setting of {})", events.size(), maxResults);
		}
		else
		{
			LogInfo("Successfully parsed %zu TTD memory events from data model", events.size());
		}
		return true;
	}
	catch (const std::exception& e)
	{
		LogError("Exception in ParseTTDMemoryObjects: %s", e.what());
		return false;
	}
}


std::vector<TTDCallEvent> DbgEngTTDAdapter::GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress)
{
	std::vector<TTDCallEvent> events;

	if (symbols.empty())
	{
		LogError("No symbols provided for TTD calls query");
		return events;
	}
	
	// Parse comma-separated symbols
	std::vector<std::string> symbolList;
	std::stringstream ss(symbols);
	std::string symbol;
	
	while (std::getline(ss, symbol, ','))
	{
		// Trim whitespace
		symbol.erase(0, symbol.find_first_not_of(" \t\n\r\f\v"));
		symbol.erase(symbol.find_last_not_of(" \t\n\r\f\v") + 1);
		
		if (!symbol.empty())
			symbolList.push_back(symbol);
	}
	
	if (symbolList.empty())
	{
		LogError("No valid symbols found after parsing input string");
		return events;
	}
	
	if (!QueryCallsForSymbols(symbolList, startReturnAddress, endReturnAddress, events))
	{
		LogError("Failed to query TTD calls for symbols");
		return events;
	}
	
	LogInfo("Successfully retrieved %zu TTD call events", events.size());
	return events;
}


bool DbgEngTTDAdapter::QueryCallsForSymbols(const std::vector<std::string>& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress, std::vector<TTDCallEvent>& events)
{
	if (!m_debugHost || !m_hostEvaluator)
	{
		LogError("Data model interfaces not initialized for TTD calls query");
		return false;
	}
	
	try
	{
		// Build symbol list for the query
		std::string symbolList;
		for (size_t i = 0; i < symbols.size(); ++i)
		{
			if (i > 0)
				symbolList += ", ";
			symbolList += "\"" + symbols[i] + "\"";
		}
		
		// Build the TTD.Calls query expression
		std::string expression = "@$cursession.TTD.Calls(" + symbolList + ")";
		
		// Add address range filtering if specified
		if (startReturnAddress != 0 && endReturnAddress != 0)
		{
			expression += ".Where(c => c.ReturnAddress >= 0x" + 
				fmt::format("{:x}", startReturnAddress) + 
				" && c.ReturnAddress < 0x" + 
				fmt::format("{:x}", endReturnAddress) + ")";
		}
		else if (startReturnAddress != 0)
		{
			expression += ".Where(c => c.ReturnAddress >= 0x" + 
				fmt::format("{:x}", startReturnAddress) + ")";
		}
		else if (endReturnAddress != 0)
		{
			expression += ".Where(c => c.ReturnAddress < 0x" + 
				fmt::format("{:x}", endReturnAddress) + ")";
		}
		
		LogInfo("Executing TTD calls query: %s", expression.c_str());
		
		return ParseTTDCallObjects(expression, events);
	}
	catch (const std::exception& e)
	{
		LogError("Exception in QueryCallsForSymbols: %s", e.what());
		return false;
	}
}


bool DbgEngTTDAdapter::ParseTTDCallObjects(const std::string& expression, std::vector<TTDCallEvent>& events)
{
	try
	{
		LogInfo("Parsing TTD call objects from expression: %s", expression.c_str());

		// Convert expression to wide string
		std::wstring wExpression(expression.begin(), expression.end());

		// Create context for evaluation
		ComPtr<IDebugHostContext> hostContext;
		if (FAILED(m_debugHost->GetCurrentContext(hostContext.GetAddressOf())))
		{
			LogError("Failed to get current debug host context");
			return "";
		}

		// Execute the expression to get call objects
		ComPtr<IModelObject> resultObject;
		ComPtr<IKeyStore> metadataKeyStore;
		
		HRESULT hr = m_hostEvaluator->EvaluateExtendedExpression(
			hostContext.Get(),
			wExpression.c_str(),
			nullptr,  // bindingContext
			&resultObject,
			&metadataKeyStore
		);
		
		if (FAILED(hr))
		{
			LogError("Failed to evaluate TTD calls expression: 0x%x", hr);
			return false;
		}
		
		if (!resultObject)
		{
			LogError("Null result object from TTD calls expression");
			return false;
		}
		
		// Check if the result is iterable
		ComPtr<IIterableConcept> iterableConcept;
		hr = resultObject->GetConcept(__uuidof(IIterableConcept), &iterableConcept, nullptr);
		if (FAILED(hr))
		{
			LogError("Result object is not iterable: 0x%x", hr);
			return false;
		}
		
		// Get the iterator
		ComPtr<IModelIterator> iterator;
		hr = iterableConcept->GetIterator(resultObject.Get(), &iterator);
		if (FAILED(hr))
		{
			LogError("Failed to get iterator: 0x%x", hr);
			return false;
		}
		
		// Iterate through call objects
		ComPtr<IModelObject> callObject;
		ComPtr<IKeyStore> callMetadataKeyStore;
		
		// Get the max results setting
		auto adapterSettings = GetAdapterSettings();
		BNSettingsScope scope = SettingsResourceScope;
		auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxCallsQueryResults", GetData(), &scope);
		
		uint64_t resultCounter = 0;
		bool wasLimited = false;
		
		while (SUCCEEDED(iterator->GetNext(&callObject, 0, nullptr, &callMetadataKeyStore)))
		{
			if (!callObject)
				break;
			
			// Check if we've reached the limit (0 means no limit)
			if (maxResults > 0 && resultCounter >= maxResults)
			{
				wasLimited = true;
				break;
			}
				
			TTDCallEvent event;
			
			// Parse EventType
			ComPtr<IModelObject> eventTypeObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"EventType", &eventTypeObj, nullptr)))
			{
				VARIANT vtEventType;
				VariantInit(&vtEventType);
				if (SUCCEEDED(eventTypeObj->GetIntrinsicValueAs(VT_BSTR, &vtEventType)))
				{
					_bstr_t bstr(vtEventType.bstrVal);
					event.eventType = std::string(bstr);
				}
				VariantClear(&vtEventType);
			}
			
			// Parse ThreadId
			ComPtr<IModelObject> threadIdObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"ThreadId", &threadIdObj, nullptr)))
			{
				VARIANT vtThreadId;
				VariantInit(&vtThreadId);
				if (SUCCEEDED(threadIdObj->GetIntrinsicValueAs(VT_UI4, &vtThreadId)))
				{
					event.threadId = vtThreadId.ulVal;
				}
				VariantClear(&vtThreadId);
			}
			
			// Parse UniqueThreadId
			ComPtr<IModelObject> uniqueThreadIdObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"UniqueThreadId", &uniqueThreadIdObj, nullptr)))
			{
				VARIANT vtUniqueThreadId;
				VariantInit(&vtUniqueThreadId);
				if (SUCCEEDED(uniqueThreadIdObj->GetIntrinsicValueAs(VT_UI4, &vtUniqueThreadId)))
				{
					event.uniqueThreadId = vtUniqueThreadId.ulVal;
				}
				VariantClear(&vtUniqueThreadId);
			}
			
			// Parse Function name
			ComPtr<IModelObject> functionObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"Function", &functionObj, nullptr)))
			{
				VARIANT vtFunction;
				VariantInit(&vtFunction);
				if (SUCCEEDED(functionObj->GetIntrinsicValueAs(VT_BSTR, &vtFunction)))
				{
					_bstr_t bstr(vtFunction.bstrVal);
					event.function = std::string(bstr);
				}
				VariantClear(&vtFunction);
			}
			
			// Parse FunctionAddress
			ComPtr<IModelObject> functionAddressObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"FunctionAddress", &functionAddressObj, nullptr)))
			{
				VARIANT vtFunctionAddress;
				VariantInit(&vtFunctionAddress);
				if (SUCCEEDED(functionAddressObj->GetIntrinsicValueAs(VT_UI8, &vtFunctionAddress)))
				{
					event.functionAddress = vtFunctionAddress.ullVal;
				}
				VariantClear(&vtFunctionAddress);
			}
			
			// Parse ReturnAddress
			ComPtr<IModelObject> returnAddressObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"ReturnAddress", &returnAddressObj, nullptr)))
			{
				VARIANT vtReturnAddress;
				VariantInit(&vtReturnAddress);
				if (SUCCEEDED(returnAddressObj->GetIntrinsicValueAs(VT_UI8, &vtReturnAddress)))
				{
					event.returnAddress = vtReturnAddress.ullVal;
				}
				VariantClear(&vtReturnAddress);
			}
			
			// Parse ReturnValue (may not be present for void functions)
			ComPtr<IModelObject> returnValueObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"ReturnValue", &returnValueObj, nullptr)))
			{
				VARIANT vtReturnValue;
				VariantInit(&vtReturnValue);
				if (SUCCEEDED(returnValueObj->GetIntrinsicValueAs(VT_UI8, &vtReturnValue)))
				{
					event.returnValue = vtReturnValue.ullVal;
					event.hasReturnValue = true;
				}
				VariantClear(&vtReturnValue);
			}
			
			// Parse Parameters array
			ComPtr<IModelObject> parametersObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"Parameters", &parametersObj, nullptr)))
			{
				// Check if Parameters is iterable
				ComPtr<IIterableConcept> paramsIterableConcept;
				if (SUCCEEDED(parametersObj->GetConcept(__uuidof(IIterableConcept), &paramsIterableConcept, nullptr)))
				{
					ComPtr<IModelIterator> paramsIterator;
					if (SUCCEEDED(paramsIterableConcept->GetIterator(parametersObj.Get(), &paramsIterator)))
					{
						ComPtr<IModelObject> paramObj;
						ComPtr<IKeyStore> paramMetadataKeyStore;
						
						while (SUCCEEDED(paramsIterator->GetNext(&paramObj, 0, nullptr, &paramMetadataKeyStore)))
						{
							if (!paramObj)
								break;
								
							VARIANT vtParam;
							VariantInit(&vtParam);
							if (SUCCEEDED(paramObj->GetIntrinsicValueAs(VT_BSTR, &vtParam)))
							{
								_bstr_t bstr(vtParam.bstrVal);
								event.parameters.push_back(std::string(bstr));
							}
							else
							{
								// If we can't get as string, convert the value to string representation
								event.parameters.push_back("<value>");
							}
							VariantClear(&vtParam);
							
							paramObj.Reset();
							paramMetadataKeyStore.Reset();
						}
					}
				}
			}
			
			// Parse TimeStart
			ComPtr<IModelObject> timeStartObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"TimeStart", &timeStartObj, nullptr)))
			{
				// TimeStart is typically a TTD position object with Sequence and Steps
				ComPtr<IModelObject> sequenceObj, stepsObj;
				if (SUCCEEDED(timeStartObj->GetKeyValue(L"Sequence", &sequenceObj, nullptr)))
				{
					VARIANT vtSequence;
					VariantInit(&vtSequence);
					if (SUCCEEDED(sequenceObj->GetIntrinsicValueAs(VT_UI8, &vtSequence)))
					{
						event.timeStart.sequence = vtSequence.ullVal;
					}
					VariantClear(&vtSequence);
				}
				
				if (SUCCEEDED(timeStartObj->GetKeyValue(L"Steps", &stepsObj, nullptr)))
				{
					VARIANT vtSteps;
					VariantInit(&vtSteps);
					if (SUCCEEDED(stepsObj->GetIntrinsicValueAs(VT_UI8, &vtSteps)))
					{
						event.timeStart.step = vtSteps.ullVal;
					}
					VariantClear(&vtSteps);
				}
			}
			
			// Parse TimeEnd
			ComPtr<IModelObject> timeEndObj;
			if (SUCCEEDED(callObject->GetKeyValue(L"TimeEnd", &timeEndObj, nullptr)))
			{
				// TimeEnd is typically a TTD position object with Sequence and Steps
				ComPtr<IModelObject> sequenceObj, stepsObj;
				if (SUCCEEDED(timeEndObj->GetKeyValue(L"Sequence", &sequenceObj, nullptr)))
				{
					VARIANT vtSequence;
					VariantInit(&vtSequence);
					if (SUCCEEDED(sequenceObj->GetIntrinsicValueAs(VT_UI8, &vtSequence)))
					{
						event.timeEnd.sequence = vtSequence.ullVal;
					}
					VariantClear(&vtSequence);
				}
				
				if (SUCCEEDED(timeEndObj->GetKeyValue(L"Steps", &stepsObj, nullptr)))
				{
					VARIANT vtSteps;
					VariantInit(&vtSteps);
					if (SUCCEEDED(stepsObj->GetIntrinsicValueAs(VT_UI8, &vtSteps)))
					{
						event.timeEnd.step = vtSteps.ullVal;
					}
					VariantClear(&vtSteps);
				}
			}
			
			events.push_back(event);
			resultCounter++;
			
			// Reset objects for next iteration
			callObject.Reset();
			callMetadataKeyStore.Reset();
		}
		
		if (wasLimited)
		{
			LogWarnF("Successfully parsed {} TTD call events from data model (limited by max results setting of {})", events.size(), maxResults);
		}
		else
		{
			LogInfo("Successfully parsed %zu TTD call events from data model", events.size());
		}
		return true;
	}
	catch (const std::exception& e)
	{
		LogError("Exception in ParseTTDCallObjects: %s", e.what());
		return false;
	}
}


std::vector<TTDEvent> DbgEngTTDAdapter::GetTTDEvents(TTDEventType eventType)
{
	std::vector<TTDEvent> events;
	
	// Cache all events if not already cached
	if (!m_eventsCached)
	{
		if (!QueryAllTTDEvents())
		{
			LogError("Failed to query all TTD events");
			return events;
		}
	}
	
	// Filter cached events by type using bitfield operations
	for (const auto& event : m_cachedEvents)
	{
		if (eventType & event.type)
		{
			events.push_back(event);
		}
	}
	
	LogInfo("Successfully retrieved %zu TTD events of type %d from cache", events.size(), eventType);
	return events;
}


std::vector<TTDEvent> DbgEngTTDAdapter::GetAllTTDEvents()
{
	// Cache all events if not already cached
	if (!m_eventsCached)
	{
		if (!QueryAllTTDEvents())
		{
			LogError("Failed to query all TTD events");
			return {};
		}
	}
	
	LogDebug("Successfully retrieved %zu total TTD events from cache", m_cachedEvents.size());
	return m_cachedEvents;
}


bool DbgEngTTDAdapter::QueryAllTTDEvents()
{
	if (!m_debugHost || !m_hostEvaluator)
	{
		LogError("Data model interfaces not initialized for TTD events query");
		return false;
	}
	
	try
	{
		// Build the TTD.Events query expression to get all events (using curprocess instead of cursession)
		std::string expression = "@$curprocess.TTD.Events";
		
		LogInfo("Executing TTD events query: %s", expression.c_str());
		
		m_cachedEvents.clear();
		if (ParseTTDEventObjects(expression, m_cachedEvents))
		{
			m_eventsCached = true;
			return true;
		}
		return false;
	}
	catch (const std::exception& e)
	{
		LogError("Exception in QueryAllTTDEvents: %s", e.what());
		return false;
	}
}


bool DbgEngTTDAdapter::ParseTTDEventObjects(const std::string& expression, std::vector<TTDEvent>& events)
{
	try
	{
		LogInfo("Parsing TTD event objects from expression: %s", expression.c_str());

		// Convert expression to wide string
		std::wstring wExpression(expression.begin(), expression.end());

		// Create context for evaluation
		ComPtr<IDebugHostContext> hostContext;
		if (FAILED(m_debugHost->GetCurrentContext(hostContext.GetAddressOf())))
		{
			LogError("Failed to get current debug host context");
			return false;
		}

		// Execute the expression to get event objects
		ComPtr<IModelObject> resultObject;
		ComPtr<IKeyStore> metadataKeyStore;
		
		HRESULT hr = m_hostEvaluator->EvaluateExtendedExpression(
			hostContext.Get(),
			wExpression.c_str(),
			nullptr,  // bindingContext
			&resultObject,
			&metadataKeyStore
		);
		
		if (FAILED(hr))
		{
			LogError("Failed to evaluate TTD events expression: 0x%x", hr);
			return false;
		}
		
		if (!resultObject)
		{
			LogError("Null result object from TTD events expression");
			return false;
		}
		
		// Check if the result is iterable
		ComPtr<IIterableConcept> iterableConcept;
		hr = resultObject->GetConcept(__uuidof(IIterableConcept), &iterableConcept, nullptr);
		if (FAILED(hr))
		{
			LogError("TTD events result is not iterable: 0x%x", hr);
			return false;
		}
		
		// Get iterator
		ComPtr<IModelIterator> iterator;
		hr = iterableConcept->GetIterator(resultObject.Get(), &iterator);
		if (FAILED(hr))
		{
			LogError("Failed to get iterator for TTD events: 0x%x", hr);
			return false;
		}
		
		// Get maximum results setting
		auto adapterSettings = GetAdapterSettings();
		BNSettingsScope scope = SettingsResourceScope;
		auto maxResults = adapterSettings->Get<uint64_t>("ttd.maxCallsQueryResults", GetData(), &scope);
		size_t resultCounter = 0;
		bool wasLimited = false;
		
		// Iterate through events
		ComPtr<IModelObject> eventObject;
		ComPtr<IKeyStore> eventMetadataKeyStore;
		
		while (SUCCEEDED(iterator->GetNext(&eventObject, 0, nullptr, &eventMetadataKeyStore)) && eventObject)
		{
			if (resultCounter >= maxResults)
			{
				wasLimited = true;
				break;
			}
			
			// Parse event type from the event object first
			TTDEventType eventType = TTDEventThreadCreated; // default
			
			ComPtr<IModelObject> typeObj;
			if (SUCCEEDED(eventObject->GetKeyValue(L"Type", &typeObj, nullptr)))
			{
				VARIANT vtType;
				VariantInit(&vtType);
				if (SUCCEEDED(typeObj->GetIntrinsicValueAs(VT_BSTR, &vtType)))
				{
					_bstr_t bstr(vtType.bstrVal);
					std::string typeStr = std::string(bstr);
					
					if (typeStr == "ThreadCreated")
						eventType = TTDEventThreadCreated;
					else if (typeStr == "ThreadTerminated")
						eventType = TTDEventThreadTerminated;
					else if (typeStr == "ModuleLoaded")
						eventType = TTDEventModuleLoaded;
					else if (typeStr == "ModuleUnloaded")
						eventType = TTDEventModuleUnloaded;
					else if (typeStr == "Exception")
						eventType = TTDEventException;
				}
				VariantClear(&vtType);
			}
			
			TTDEvent event(eventType);
			
			// Parse Position
			ComPtr<IModelObject> positionObj;
			if (SUCCEEDED(eventObject->GetKeyValue(L"Position", &positionObj, nullptr)))
			{
				// Parse Sequence
				ComPtr<IModelObject> sequenceObj;
				if (SUCCEEDED(positionObj->GetKeyValue(L"Sequence", &sequenceObj, nullptr)))
				{
					VARIANT vtSequence;
					VariantInit(&vtSequence);
					if (SUCCEEDED(sequenceObj->GetIntrinsicValueAs(VT_UI8, &vtSequence)))
					{
						event.position.sequence = vtSequence.ullVal;
					}
					VariantClear(&vtSequence);
				}
				
				// Parse Steps
				ComPtr<IModelObject> stepsObj;
				if (SUCCEEDED(positionObj->GetKeyValue(L"Steps", &stepsObj, nullptr)))
				{
					VARIANT vtSteps;
					VariantInit(&vtSteps);
					if (SUCCEEDED(stepsObj->GetIntrinsicValueAs(VT_UI8, &vtSteps)))
					{
						event.position.step = vtSteps.ullVal;
					}
					VariantClear(&vtSteps);
				}
			}
			
			// Parse event-specific details based on type
			switch (eventType)
			{
				case TTDEventThreadCreated:
				case TTDEventThreadTerminated:
					ParseThreadDetails(eventObject.Get(), event);
					break;
				case TTDEventModuleLoaded:
				case TTDEventModuleUnloaded:
					ParseModuleDetails(eventObject.Get(), event);
					break;
				case TTDEventException:
					ParseExceptionDetails(eventObject.Get(), event);
					break;
			}
			
			events.push_back(event);
			resultCounter++;
			
			// Reset objects for next iteration
			eventObject.Reset();
			eventMetadataKeyStore.Reset();
		}
		
		if (wasLimited)
		{
			LogWarnF("Successfully parsed {} TTD events from data model (limited by max results setting of {})", events.size(), maxResults);
		}
		else
		{
			LogInfo("Successfully parsed %zu TTD events from data model", events.size());
		}
		return true;
	}
	catch (const std::exception& e)
	{
		LogError("Exception in ParseTTDEventObjects: %s", e.what());
		return false;
	}
}


void DbgEngTTDAdapter::ParseThreadDetails(IModelObject* eventObject, TTDEvent& event)
{
	ComPtr<IModelObject> threadObj;
	if (SUCCEEDED(eventObject->GetKeyValue(L"Thread", &threadObj, nullptr)))
	{
		TTDThread thread;
		
		// Parse UniqueId
		ComPtr<IModelObject> uniqueIdObj;
		if (SUCCEEDED(threadObj->GetKeyValue(L"UniqueId", &uniqueIdObj, nullptr)))
		{
			VARIANT vtUniqueId;
			VariantInit(&vtUniqueId);
			if (SUCCEEDED(uniqueIdObj->GetIntrinsicValueAs(VT_UI4, &vtUniqueId)))
			{
				thread.uniqueId = vtUniqueId.ulVal;
			}
			VariantClear(&vtUniqueId);
		}
		
		// Parse Id (TID)
		ComPtr<IModelObject> idObj;
		if (SUCCEEDED(threadObj->GetKeyValue(L"Id", &idObj, nullptr)))
		{
			VARIANT vtId;
			VariantInit(&vtId);
			if (SUCCEEDED(idObj->GetIntrinsicValueAs(VT_UI4, &vtId)))
			{
				thread.id = vtId.ulVal;
			}
			VariantClear(&vtId);
		}
		
		// Parse LifeTime
		ComPtr<IModelObject> lifetimeObj;
		if (SUCCEEDED(threadObj->GetKeyValue(L"LifeTime", &lifetimeObj, nullptr)))
		{
			// Parse LifeTime.MinPosition
			ComPtr<IModelObject> minPosObj;
			if (SUCCEEDED(lifetimeObj->GetKeyValue(L"MinPosition", &minPosObj, nullptr)))
			{
				ParseTTDPosition(minPosObj.Get(), thread.lifetimeStart);
			}
			
			// Parse LifeTime.MaxPosition
			ComPtr<IModelObject> maxPosObj;
			if (SUCCEEDED(lifetimeObj->GetKeyValue(L"MaxPosition", &maxPosObj, nullptr)))
			{
				ParseTTDPosition(maxPosObj.Get(), thread.lifetimeEnd);
			}
		}
		
		// Parse ActiveTime 
		ComPtr<IModelObject> activeTimeObj;
		if (SUCCEEDED(threadObj->GetKeyValue(L"ActiveTime", &activeTimeObj, nullptr)))
		{
			// Parse ActiveTime.MinPosition
			ComPtr<IModelObject> minActiveObj;
			if (SUCCEEDED(activeTimeObj->GetKeyValue(L"MinPosition", &minActiveObj, nullptr)))
			{
				ParseTTDPosition(minActiveObj.Get(), thread.activeTimeStart);
			}
			
			// Parse ActiveTime.MaxPosition
			ComPtr<IModelObject> maxActiveObj;
			if (SUCCEEDED(activeTimeObj->GetKeyValue(L"MaxPosition", &maxActiveObj, nullptr)))
			{
				ParseTTDPosition(maxActiveObj.Get(), thread.activeTimeEnd);
			}
		}
		
		event.thread = thread;
	}
}


void DbgEngTTDAdapter::ParseModuleDetails(IModelObject* eventObject, TTDEvent& event)
{
	ComPtr<IModelObject> moduleObj;
	if (SUCCEEDED(eventObject->GetKeyValue(L"Module", &moduleObj, nullptr)))
	{
		TTDModule module;
		
		// Parse Name
		ComPtr<IModelObject> nameObj;
		if (SUCCEEDED(moduleObj->GetKeyValue(L"Name", &nameObj, nullptr)))
		{
			VARIANT vtName;
			VariantInit(&vtName);
			if (SUCCEEDED(nameObj->GetIntrinsicValueAs(VT_BSTR, &vtName)))
			{
				_bstr_t bstr(vtName.bstrVal);
				module.name = std::string(bstr);
			}
			VariantClear(&vtName);
		}
		
		// Parse Address
		ComPtr<IModelObject> addressObj;
		if (SUCCEEDED(moduleObj->GetKeyValue(L"Address", &addressObj, nullptr)))
		{
			VARIANT vtAddress;
			VariantInit(&vtAddress);
			if (SUCCEEDED(addressObj->GetIntrinsicValueAs(VT_UI8, &vtAddress)))
			{
				module.address = vtAddress.ullVal;
			}
			VariantClear(&vtAddress);
		}
		
		// Parse Size
		ComPtr<IModelObject> sizeObj;
		if (SUCCEEDED(moduleObj->GetKeyValue(L"Size", &sizeObj, nullptr)))
		{
			VARIANT vtSize;
			VariantInit(&vtSize);
			if (SUCCEEDED(sizeObj->GetIntrinsicValueAs(VT_UI8, &vtSize)))
			{
				module.size = vtSize.ullVal;
			}
			VariantClear(&vtSize);
		}
		
		// Parse Checksum
		ComPtr<IModelObject> checksumObj;
		if (SUCCEEDED(moduleObj->GetKeyValue(L"Checksum", &checksumObj, nullptr)))
		{
			VARIANT vtChecksum;
			VariantInit(&vtChecksum);
			if (SUCCEEDED(checksumObj->GetIntrinsicValueAs(VT_UI4, &vtChecksum)))
			{
				module.checksum = vtChecksum.ulVal;
			}
			VariantClear(&vtChecksum);
		}
		
		// Parse Timestamp
		ComPtr<IModelObject> timestampObj;
		if (SUCCEEDED(moduleObj->GetKeyValue(L"Timestamp", &timestampObj, nullptr)))
		{
			VARIANT vtTimestamp;
			VariantInit(&vtTimestamp);
			if (SUCCEEDED(timestampObj->GetIntrinsicValueAs(VT_UI4, &vtTimestamp)))
			{
				module.timestamp = vtTimestamp.ulVal;
			}
			VariantClear(&vtTimestamp);
		}
		
		event.module = module;
	}
}


void DbgEngTTDAdapter::ParseExceptionDetails(IModelObject* eventObject, TTDEvent& event)
{
	ComPtr<IModelObject> exceptionObj;
	if (SUCCEEDED(eventObject->GetKeyValue(L"Exception", &exceptionObj, nullptr)))
	{
		TTDException exception;
		
		// Parse Type
		ComPtr<IModelObject> typeObj;
		if (SUCCEEDED(exceptionObj->GetKeyValue(L"Type", &typeObj, nullptr)))
		{
			VARIANT vtType;
			VariantInit(&vtType);
			if (SUCCEEDED(typeObj->GetIntrinsicValueAs(VT_BSTR, &vtType)))
			{
				_bstr_t bstr(vtType.bstrVal);
				std::string typeStr = std::string(bstr);
				exception.type = (typeStr == "Hardware") ? TTDExceptionHardware : TTDExceptionSoftware;
			}
			VariantClear(&vtType);
		}
		
		// Parse ProgramCounter
		ComPtr<IModelObject> pcObj;
		if (SUCCEEDED(exceptionObj->GetKeyValue(L"ProgramCounter", &pcObj, nullptr)))
		{
			VARIANT vtPC;
			VariantInit(&vtPC);
			if (SUCCEEDED(pcObj->GetIntrinsicValueAs(VT_UI8, &vtPC)))
			{
				exception.programCounter = vtPC.ullVal;
			}
			VariantClear(&vtPC);
		}
		
		// Parse Code
		ComPtr<IModelObject> codeObj;
		if (SUCCEEDED(exceptionObj->GetKeyValue(L"Code", &codeObj, nullptr)))
		{
			VARIANT vtCode;
			VariantInit(&vtCode);
			if (SUCCEEDED(codeObj->GetIntrinsicValueAs(VT_UI4, &vtCode)))
			{
				exception.code = vtCode.ulVal;
			}
			VariantClear(&vtCode);
		}
		
		// Parse Flags
		ComPtr<IModelObject> flagsObj;
		if (SUCCEEDED(exceptionObj->GetKeyValue(L"Flags", &flagsObj, nullptr)))
		{
			VARIANT vtFlags;
			VariantInit(&vtFlags);
			if (SUCCEEDED(flagsObj->GetIntrinsicValueAs(VT_UI4, &vtFlags)))
			{
				exception.flags = vtFlags.ulVal;
			}
			VariantClear(&vtFlags);
		}
		
		// Parse RecordAddress
		ComPtr<IModelObject> recordAddrObj;
		if (SUCCEEDED(exceptionObj->GetKeyValue(L"RecordAddress", &recordAddrObj, nullptr)))
		{
			VARIANT vtRecordAddr;
			VariantInit(&vtRecordAddr);
			if (SUCCEEDED(recordAddrObj->GetIntrinsicValueAs(VT_UI8, &vtRecordAddr)))
			{
				exception.recordAddress = vtRecordAddr.ullVal;
			}
			VariantClear(&vtRecordAddr);
		}
		
		// Parse Position
		ComPtr<IModelObject> positionObj;
		if (SUCCEEDED(exceptionObj->GetKeyValue(L"Position", &positionObj, nullptr)))
		{
			ParseTTDPosition(positionObj.Get(), exception.position);
		}
		
		event.exception = exception;
	}
}


void DbgEngTTDAdapter::ParseTTDPosition(IModelObject* positionObj, TTDPosition& position)
{
	if (!positionObj)
		return;
		
	// Parse Sequence
	ComPtr<IModelObject> sequenceObj;
	if (SUCCEEDED(positionObj->GetKeyValue(L"Sequence", &sequenceObj, nullptr)))
	{
		VARIANT vtSequence;
		VariantInit(&vtSequence);
		if (SUCCEEDED(sequenceObj->GetIntrinsicValueAs(VT_UI8, &vtSequence)))
		{
			position.sequence = vtSequence.ullVal;
		}
		VariantClear(&vtSequence);
	}
	
	// Parse Steps
	ComPtr<IModelObject> stepsObj;
	if (SUCCEEDED(positionObj->GetKeyValue(L"Steps", &stepsObj, nullptr)))
	{
		VARIANT vtSteps;
		VariantInit(&vtSteps);
		if (SUCCEEDED(stepsObj->GetIntrinsicValueAs(VT_UI8, &vtSteps)))
		{
			position.step = vtSteps.ullVal;
		}
		VariantClear(&vtSteps);
	}
}


void DbgEngTTDAdapter::ClearTTDEventsCache()
{
	m_cachedEvents.clear();
	m_eventsCached = false;
}


void BinaryNinjaDebugger::InitDbgEngTTDAdapterType()
{
    static DbgEngTTDAdapterType localType;
    DebugAdapterType::Register(&localType);
}
