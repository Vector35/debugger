#include "windowskerneladapter.h"
#include <filesystem>

using namespace BinaryNinjaDebugger;
using namespace std;


WindowsKernelAdapter::WindowsKernelAdapter(BinaryView* data) : DbgEngAdapter(data)
{
    m_usePDBFileName = false;
	GenerateDefaultAdapterSettings(data);
}


bool WindowsKernelAdapter::ExecuteWithArgsInternal(const std::string& path, const std::string& args,
                                            const std::string& workingDir, const LaunchConfigurations& configs) {
    m_aboutToBeKilled = false;

	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto adapterSettings = GetAdapterSettings();
	auto connectionString = adapterSettings->Get<std::string>("launch.connection_string", data, &scope);
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

    if (const auto result = this->m_debugClient->AttachKernel(DEBUG_ATTACH_KERNEL_CONNECTION,
			const_cast<char *>(connectionString.c_str()));
            result != S_OK) {
        this->Reset();
        DebuggerEvent event;
        event.type = LaunchFailureEventType;
        event.data.errorData.error = fmt::format("AttachKernel failed: 0x{:x}", result);
        event.data.errorData.shortError = fmt::format("AttachKernel failed: 0x{:x}", result);
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


bool WindowsKernelAdapter::Start()
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


void WindowsKernelAdapter::Reset()
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


bool WindowsKernelAdapter::Detach()
{
	m_aboutToBeKilled = true;
	m_lastOperationIsStepInto = false;
	if (!this->m_debugClient)
		return false;

	if (this->m_debugClient->EndSession(DEBUG_END_PASSIVE) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
}


bool WindowsKernelAdapter::Quit()
{
	m_aboutToBeKilled = true;
	m_lastOperationIsStepInto = false;
	if (!this->m_debugClient)
		return false;

	if (this->m_debugClient->EndSession(DEBUG_END_PASSIVE) != S_OK)
		return false;

	m_debugClient->ExitDispatch(reinterpret_cast<PDEBUG_CLIENT>(m_debugClient));
	return true;
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
