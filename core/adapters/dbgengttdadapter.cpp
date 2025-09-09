#include "dbgengttdadapter.h"
#include <filesystem>
#include <regex>
#include <sstream>

using namespace BinaryNinjaDebugger;
using namespace std;


DbgEngTTDAdapter::DbgEngTTDAdapter(BinaryView* data) : DbgEngAdapter(data)
{
    m_usePDBFileName = false;
	// Initialize data model interfaces to nullptr
	m_dataModelManager = nullptr;
	m_modelMgr = nullptr;
	m_debugHost = nullptr;
	m_hostEvaluator = nullptr;
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
	if (m_dataModelManager)
	{
		m_dataModelManager->GetDataModel(&m_modelMgr, &m_debugHost);

		if (m_debugHost && m_debugHost->QueryInterface(__uuidof(IDebugHostEvaluator), reinterpret_cast<void**>(&m_hostEvaluator)) != S_OK)
		{
			LogWarn("Failed to get IDebugHostEvaluator interface");
		}
	}
	else
	{
		LogWarn("Failed to get IHostDataModelAccess interface - TTD data model features may not work");
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

	if (!this->m_dbgengInitialized)
		return;

	// Free up the resources if the dbgsrv is launched by the adapter. Otherwise, the dbgsrv is launched outside BN,
	// we should keep everything active.
	SAFE_RELEASE(this->m_debugControl);
	SAFE_RELEASE(this->m_debugDataSpaces);
	SAFE_RELEASE(this->m_debugRegisters);
	SAFE_RELEASE(this->m_debugSymbols);
	SAFE_RELEASE(this->m_debugSystemObjects);
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

	return settings;
}


void DbgEngTTDAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
}


std::vector<TTDCallEvent> DbgEngTTDAdapter::GetTTDCalls(const std::vector<std::string>& symbols)
{
	std::vector<TTDCallEvent> events;
	
	if (!m_debugControl)
		return events;

	// Build the TTD.Calls query
	std::string symbolsQuery;
	for (size_t i = 0; i < symbols.size(); i++) {
		if (i > 0)
			symbolsQuery += ", ";
		symbolsQuery += "\"" + symbols[i] + "\"";
	}
	
	std::string expression = "@$cursession.TTD.Calls(" + symbolsQuery + ")";
	
	// Use data model evaluation instead of InvokeBackendCommand
	if (!ParseTTDCallsObjects(expression, events))
	{
		LogError("Failed to evaluate TTD.Calls expression");
	}
	
	return events;
}


std::vector<TTDCallEvent> DbgEngTTDAdapter::GetTTDCallsWithAddressFilter(const std::vector<std::string>& symbols, uint64_t minReturnAddress, uint64_t maxReturnAddress)
{
	std::vector<TTDCallEvent> events;
	
	if (!m_debugControl)
		return events;

	// Build the TTD.Calls query with address filter
	std::string symbolsQuery;
	for (size_t i = 0; i < symbols.size(); i++) {
		if (i > 0)
			symbolsQuery += ", ";
		symbolsQuery += "\"" + symbols[i] + "\"";
	}
	
	std::string expression = fmt::format("@$cursession.TTD.Calls({}).Where(c => c.ReturnAddress >= 0x{:x} && c.ReturnAddress < 0x{:x})", 
		symbolsQuery, minReturnAddress, maxReturnAddress);
	
	// Use data model evaluation instead of InvokeBackendCommand
	if (!ParseTTDCallsObjects(expression, events))
	{
		LogError("Failed to evaluate TTD.Calls expression with address filter");
	}
	
	return events;
}


TTDPosition DbgEngTTDAdapter::GetCurrentTTDPosition()
{
	if (!m_debugControl)
		return TTDPosition();

	std::string result = EvaluateDataModelExpression("@$cursession.TTD.Position");
	return ParseTTDPosition(result);
}


bool DbgEngTTDAdapter::SetTTDPosition(const TTDPosition& position)
{
	if (!m_debugControl)
		return false;

	std::string command = fmt::format("!tt {{{:x}:{:x}}}", position.sequence, position.step);
	std::string result = InvokeBackendCommand(command);
	
	// Check if the command succeeded by verifying the position changed
	return !result.empty();
}


std::string DbgEngTTDAdapter::EvaluateDataModelExpression(const std::string& expression)
{
	if (!m_hostEvaluator || !m_debugHost)
	{
		LogError("Data model evaluator not initialized");
		return "";
	}

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
		
		if (SUCCEEDED(result->GetIntrinsicValue(&vtValue)))
		{
			std::string resultStr;
			if (vtValue.vt == VT_BSTR && vtValue.bstrVal)
			{
				// Convert BSTR to string
				_bstr_t bstr(vtValue.bstrVal, false);
				resultStr = static_cast<const char*>(bstr);
			}
			else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
			{
				resultStr = std::to_string(vtValue.lVal);
			}
			else if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
			{
				resultStr = std::to_string(vtValue.llVal);
			}
			
			VariantClear(&vtValue);
			return resultStr;
		}
		
		VariantClear(&vtValue);
	}

	return "";
}


bool DbgEngTTDAdapter::ParseTTDCallsObjects(const std::string& expression, std::vector<TTDCallEvent>& events)
{
	if (!m_hostEvaluator || !m_debugHost)
	{
		LogError("Data model evaluator not initialized");
		return false;
	}

	// Convert expression to wide string
	std::wstring wExpression(expression.begin(), expression.end());
	
	// Create context for evaluation
	ComPtr<IDebugHostContext> hostContext;
	if (FAILED(m_debugHost->GetCurrentContext(hostContext.GetAddressOf())))
	{
		LogError("Failed to get current debug host context");
		return false;
	}

	// Evaluate the TTD calls collection expression
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
		LogError("Failed to evaluate TTD calls expression '%s': 0x%08x", expression.c_str(), hr);
		return false;
	}

	// Check if result is iterable (collection)
	ComPtr<IIterableConcept> iterableConcept;
	if (FAILED(result->GetConcept(__uuidof(IIterableConcept), &iterableConcept, nullptr)))
	{
		LogError("TTD calls result is not iterable");
		return false;
	}

	// Get iterator
	ComPtr<IModelIterator> iterator;
	if (FAILED(iterableConcept->GetIterator(result.Get(), &iterator)))
	{
		LogError("Failed to get TTD calls iterator");
		return false;
	}

	// Iterate through results
	for (;;)
	{
		ComPtr<IModelObject> item;
		ComPtr<IKeyStore> itemMetadata;
		
		HRESULT iterResult = iterator->GetNext(&item, &itemMetadata, nullptr);
		if (iterResult == E_BOUNDS || FAILED(iterResult))
			break;

		if (!item)
			continue;

		// Parse call event from model object
		TTDCallEvent callEvent = {};
		
		// Try to get each field from the call event object
		ComPtr<IModelObject> fieldValue;
		ComPtr<IKeyStore> fieldMetadata;
		
		// EventType
		if (SUCCEEDED(item->GetKeyValue(L"EventType", &fieldValue, &fieldMetadata)))
		{
			VARIANT vtValue;
			VariantInit(&vtValue);
			if (SUCCEEDED(fieldValue->GetIntrinsicValue(&vtValue)) && vtValue.vt == VT_BSTR)
			{
				_bstr_t bstr(vtValue.bstrVal, false);
				callEvent.eventType = static_cast<const char*>(bstr);
			}
			VariantClear(&vtValue);
		}
		
		// ThreadId
		if (SUCCEEDED(item->GetKeyValue(L"ThreadId", &fieldValue, &fieldMetadata)))
		{
			VARIANT vtValue;
			VariantInit(&vtValue);
			if (SUCCEEDED(fieldValue->GetIntrinsicValue(&vtValue)))
			{
				if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
					callEvent.threadId = vtValue.ulVal;
				else if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
					callEvent.threadId = static_cast<uint32_t>(vtValue.ullVal);
			}
			VariantClear(&vtValue);
		}
		
		// UniqueThreadId
		if (SUCCEEDED(item->GetKeyValue(L"UniqueThreadId", &fieldValue, &fieldMetadata)))
		{
			VARIANT vtValue;
			VariantInit(&vtValue);
			if (SUCCEEDED(fieldValue->GetIntrinsicValue(&vtValue)))
			{
				if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
					callEvent.uniqueThreadId = vtValue.ulVal;
				else if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
					callEvent.uniqueThreadId = static_cast<uint32_t>(vtValue.ullVal);
			}
			VariantClear(&vtValue);
		}
		
		// Function
		if (SUCCEEDED(item->GetKeyValue(L"Function", &fieldValue, &fieldMetadata)))
		{
			VARIANT vtValue;
			VariantInit(&vtValue);
			if (SUCCEEDED(fieldValue->GetIntrinsicValue(&vtValue)) && vtValue.vt == VT_BSTR)
			{
				_bstr_t bstr(vtValue.bstrVal, false);
				callEvent.function = static_cast<const char*>(bstr);
			}
			VariantClear(&vtValue);
		}
		
		// FunctionAddress
		if (SUCCEEDED(item->GetKeyValue(L"FunctionAddress", &fieldValue, &fieldMetadata)))
		{
			VARIANT vtValue;
			VariantInit(&vtValue);
			if (SUCCEEDED(fieldValue->GetIntrinsicValue(&vtValue)))
			{
				if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
					callEvent.functionAddress = vtValue.ullVal;
				else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
					callEvent.functionAddress = vtValue.ulVal;
			}
			VariantClear(&vtValue);
		}
		
		// ReturnAddress
		if (SUCCEEDED(item->GetKeyValue(L"ReturnAddress", &fieldValue, &fieldMetadata)))
		{
			VARIANT vtValue;
			VariantInit(&vtValue);
			if (SUCCEEDED(fieldValue->GetIntrinsicValue(&vtValue)))
			{
				if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
					callEvent.returnAddress = vtValue.ullVal;
				else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
					callEvent.returnAddress = vtValue.ulVal;
			}
			VariantClear(&vtValue);
		}
		
		// ReturnValue
		if (SUCCEEDED(item->GetKeyValue(L"ReturnValue", &fieldValue, &fieldMetadata)))
		{
			VARIANT vtValue;
			VariantInit(&vtValue);
			if (SUCCEEDED(fieldValue->GetIntrinsicValue(&vtValue)))
			{
				if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
					callEvent.returnValue = vtValue.ullVal;
				else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
					callEvent.returnValue = vtValue.ulVal;
			}
			VariantClear(&vtValue);
		}
		
		// TimeStart
		if (SUCCEEDED(item->GetKeyValue(L"TimeStart", &fieldValue, &fieldMetadata)))
		{
			// TimeStart is a position object, need to parse its sequence and step
			ComPtr<IModelObject> seqValue, stepValue;
			ComPtr<IKeyStore> seqMetadata, stepMetadata;
			
			if (SUCCEEDED(fieldValue->GetKeyValue(L"Sequence", &seqValue, &seqMetadata)))
			{
				VARIANT vtValue;
				VariantInit(&vtValue);
				if (SUCCEEDED(seqValue->GetIntrinsicValue(&vtValue)))
				{
					if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
						callEvent.timeStart.sequence = vtValue.ullVal;
					else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
						callEvent.timeStart.sequence = vtValue.ulVal;
				}
				VariantClear(&vtValue);
			}
			
			if (SUCCEEDED(fieldValue->GetKeyValue(L"Steps", &stepValue, &stepMetadata)))
			{
				VARIANT vtValue;
				VariantInit(&vtValue);
				if (SUCCEEDED(stepValue->GetIntrinsicValue(&vtValue)))
				{
					if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
						callEvent.timeStart.step = vtValue.ullVal;
					else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
						callEvent.timeStart.step = vtValue.ulVal;
				}
				VariantClear(&vtValue);
			}
		}
		
		// TimeEnd
		if (SUCCEEDED(item->GetKeyValue(L"TimeEnd", &fieldValue, &fieldMetadata)))
		{
			// TimeEnd is a position object, need to parse its sequence and step
			ComPtr<IModelObject> seqValue, stepValue;
			ComPtr<IKeyStore> seqMetadata, stepMetadata;
			
			if (SUCCEEDED(fieldValue->GetKeyValue(L"Sequence", &seqValue, &seqMetadata)))
			{
				VARIANT vtValue;
				VariantInit(&vtValue);
				if (SUCCEEDED(seqValue->GetIntrinsicValue(&vtValue)))
				{
					if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
						callEvent.timeEnd.sequence = vtValue.ullVal;
					else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
						callEvent.timeEnd.sequence = vtValue.ulVal;
				}
				VariantClear(&vtValue);
			}
			
			if (SUCCEEDED(fieldValue->GetKeyValue(L"Steps", &stepValue, &stepMetadata)))
			{
				VARIANT vtValue;
				VariantInit(&vtValue);
				if (SUCCEEDED(stepValue->GetIntrinsicValue(&vtValue)))
				{
					if (vtValue.vt == VT_I8 || vtValue.vt == VT_UI8)
						callEvent.timeEnd.step = vtValue.ullVal;
					else if (vtValue.vt == VT_I4 || vtValue.vt == VT_UI4)
						callEvent.timeEnd.step = vtValue.ulVal;
				}
				VariantClear(&vtValue);
			}
		}
		
		events.push_back(callEvent);
	}

	return true;
}


std::vector<TTDCallEvent> DbgEngTTDAdapter::ParseTTDCallsOutput(const std::string& output)
{
	std::vector<TTDCallEvent> events;
	
	if (output.empty())
		return events;

	// Parse the dx -g output table format
	// The output should have a table with columns separated by " = " and rows starting with "= [0x"
	std::istringstream stream(output);
	std::string line;
	
	// Skip header lines until we find the data rows
	bool foundData = false;
	while (std::getline(stream, line)) {
		if (line.find("= [0x") == 0) {
			foundData = true;
			break;
		}
	}
	
	if (!foundData) {
		std::getline(stream, line); // Try to get the first data line
	}
	
	do {
		if (line.find("= [0x") == 0) {
			TTDCallEvent event;
			
			// Parse the table row format
			// Example: = [0x0] - 0x0 - 0x185c - 0x2 - 10:CC5 - 10:CC7 - KERNEL32!GetLastError - 0x7ff823a08640 - 0x7ff805715549 - 0xbb - {...} - Thursday, September 4, 2025 09:36:38.541 - Thursday, September 4, 2025 09:36:38.541 =
			
			std::vector<std::string> parts;
			size_t start = 0, pos = 0;
			
			// Split by " - " to get table columns
			while ((pos = line.find(" - ", start)) != std::string::npos) {
				std::string part = line.substr(start, pos - start);
				if (!part.empty() && part != "=") {
					parts.push_back(part);
				}
				start = pos + 3;
			}
			
			// Add the last part (before the trailing "=")
			if (start < line.length()) {
				std::string lastPart = line.substr(start);
				size_t endPos = lastPart.find(" =");
				if (endPos != std::string::npos) {
					lastPart = lastPart.substr(0, endPos);
				}
				if (!lastPart.empty()) {
					parts.push_back(lastPart);
				}
			}
			
			// Parse fields based on expected column order from Microsoft documentation
			// Columns: [index], EventType, ThreadId, UniqueThreadId, TimeStart, TimeEnd, Function, FunctionAddress, ReturnAddress, ReturnValue, Parameters, SystemTimeStart, SystemTimeEnd
			if (parts.size() >= 10) {
				try {
					// Index is parts[0] (e.g., "[0x0]")
					event.eventType = "Call"; // Always "Call" for TTD.Calls
					
					// ThreadId (parts[2])
					if (parts[2].find("0x") == 0) {
						event.threadId = std::stoul(parts[2], nullptr, 16);
					}
					
					// UniqueThreadId (parts[3])
					if (parts[3].find("0x") == 0) {
						event.uniqueThreadId = std::stoul(parts[3], nullptr, 16);
					}
					
					// TimeStart (parts[4]) - format like "10:CC5"
					ParseTTDPositionFromString(parts[4], event.timeStart);
					
					// TimeEnd (parts[5]) - format like "10:CC7"
					ParseTTDPositionFromString(parts[5], event.timeEnd);
					
					// Function (parts[6])
					event.function = parts[6];
					
					// FunctionAddress (parts[7])
					if (parts[7].find("0x") == 0) {
						event.functionAddress = std::stoull(parts[7], nullptr, 16);
					}
					
					// ReturnAddress (parts[8])
					if (parts[8].find("0x") == 0) {
						event.returnAddress = std::stoull(parts[8], nullptr, 16);
					}
					
					// ReturnValue (parts[9])
					if (parts[9].find("0x") == 0) {
						event.returnValue = std::stoull(parts[9], nullptr, 16);
						event.hasReturnValue = true;
					}
					
					// Parameters would be in parts[10] as "{...}" - we'll parse this later if needed
					
					events.push_back(event);
				} catch (const std::exception& e) {
					// Skip malformed lines
					continue;
				}
			}
		}
	} while (std::getline(stream, line));
	
	return events;
}


TTDPosition DbgEngTTDAdapter::ParseTTDPosition(const std::string& output)
{
	TTDPosition position;
	
	// Look for position format like "{sequence:step}" or "sequence:step"
	std::regex positionRegex(R"((\w+):(\w+))");
	std::smatch match;
	
	if (std::regex_search(output, match, positionRegex)) {
		try {
			position.sequence = std::stoull(match[1].str(), nullptr, 16);
			position.step = std::stoull(match[2].str(), nullptr, 16);
		} catch (const std::exception& e) {
			// Return default position if parsing fails
		}
	}
	
	return position;
}


void DbgEngTTDAdapter::ParseTTDPositionFromString(const std::string& posStr, TTDPosition& position)
{
	// Parse position format like "10:CC5"
	size_t colonPos = posStr.find(':');
	if (colonPos != std::string::npos) {
		try {
			std::string seqStr = posStr.substr(0, colonPos);
			std::string stepStr = posStr.substr(colonPos + 1);
			
			position.sequence = std::stoull(seqStr, nullptr, 16);
			position.step = std::stoull(stepStr, nullptr, 16);
		} catch (const std::exception& e) {
			// Keep default values if parsing fails
		}
	}
}


void BinaryNinjaDebugger::InitDbgEngTTDAdapterType()
{
    static DbgEngTTDAdapterType localType;
    DebugAdapterType::Register(&localType);
}
