#include "debuggerstate.h"
#include "debugadapter.h"
#include "ui/ui.h"
#include <chrono>
#include <thread>
#include <utility>
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "../debuggerexceptions.h"
#include "semaphore.h"
#include "./adapters/queuedadapter.h"

using namespace BinaryNinja;
using namespace std;

DebuggerRegisters::DebuggerRegisters(DebuggerState* state): m_state(state)
{
    MarkDirty();
}


void DebuggerRegisters::MarkDirty()
{
    m_dirty = true;
    m_registerCache.clear();
}


void DebuggerRegisters::Update()
{
    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw ConnectionRefusedError("Cannot update registers when disconnected");

    m_registerCache = adapter->ReadAllRegisters();
    m_dirty = false;
}


uint64_t DebuggerRegisters::GetRegisterValue(const std::string& name)
{
    // Unlike the Python implementation, we requrie the DebuggerState to explicitly check for dirty caches
    // and update the values when necessary. This is mainly because the update can be expensive.
    if (IsDirty())
        throw runtime_error("Reading register value from a dirty cache");

    auto iter = m_registerCache.find(name);
    if (iter == m_registerCache.end())
        return 0x0;

    return iter->second.m_value;
}


bool DebuggerRegisters::UpdateRegisterValue(const std::string& name, uint64_t value)
{
    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        return false;

    return adapter->WriteRegister(name, value);
}


std::vector<DebugRegister> DebuggerRegisters::GetAllRegisters() const
{
    std::vector<DebugRegister> result{};
    for (auto& [reg_name, reg]: m_registerCache)
        result.push_back(reg);

    std::sort(result.begin(), result.end(),
              [](const DebugRegister& lhs, const DebugRegister& rhs) {
        return lhs.m_registerIndex < rhs.m_registerIndex;
    });

	// TODO: maybe we should not hold a m_state at all; instead we just hold a m_controller
	DebuggerController* controller = m_state->GetController();
    if (!controller->GetState()->IsConnected())
        throw ConnectionRefusedError("Cannot update hints when disconnected");

    for (auto& reg : result) {
        const DataBuffer memory = controller->ReadMemory(reg.m_value, 128);
        std::string reg_string;
        if (memory.GetLength() > 0)
            reg_string = std::string((const char*)memory.GetData(), memory.GetLength());
        else
            reg_string = "x";

        const auto can_print = std::all_of(reg_string.begin(), reg_string.end(), [](unsigned char c){
            return c == '\n' || std::isprint(c);
        });

        if (!reg_string.empty() && reg_string.size() > 3 && can_print)
        {
            reg.m_hint = fmt::format("\"{}\"", reg_string);
        }
        else
        {
            DataBuffer buffer = controller->ReadMemory(reg.m_value, reg.m_width);
            if (buffer.GetLength() > 0)
                reg.m_hint = fmt::format("{:x}", *reinterpret_cast<std::uintptr_t*>(buffer.GetData()));
            else
                reg.m_hint = "";
        }
    }

    return result;
}


DebuggerThreads::DebuggerThreads(DebuggerState* state): m_state(state)
{
    MarkDirty();
}


void DebuggerThreads::MarkDirty()
{
    m_dirty = true;
    m_threads.clear();
	// TODO: consider also caching the last active thread
}


void DebuggerThreads::Update()
{
    if (!m_state)
        throw runtime_error("Cannot update threads when disconnected");

    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw NotInstalledError("invalid adapter");

    m_threads.clear();

	m_threads = adapter->GetThreadList();
    m_dirty = false;
}


DebugThread DebuggerThreads::GetActiveThread() const
{
    if (!m_state)
        throw runtime_error("Cannot update threads when disconnected");

    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw NotInstalledError("invalid adapter");

    return adapter->GetActiveThread();
}


bool DebuggerThreads::SetActiveThread(const DebugThread& thread)
{
    if (!m_state)
        throw runtime_error("Cannot update threads when disconnected");

    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw NotInstalledError("invalid adapter");

    return adapter->SetActiveThread(thread);
}


DebuggerModules::DebuggerModules(DebuggerState* state):
    m_state(state)
{
    MarkDirty();
}


void DebuggerModules::MarkDirty()
{
    m_dirty = true;
    m_modules.clear();
}


void DebuggerModules::Update()
{
    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        return;

    m_modules = adapter->GetModuleList();
    m_dirty = false;
}


uint64_t DebuggerModules::GetModuleBase(const std::string& name) const
{
    for (const DebugModule& module: m_modules)
    {
        if ((name == module.m_name) || (name == module.m_short_name))
        {
            return module.m_address;
        }
    }
    return 0;
}


DebugModule DebuggerModules::GetModuleByName(const std::string& name) const
{
    for (const DebugModule& module: m_modules)
    {
        if (module.m_name == name)
        {
            return module;
        }
        if (module.m_short_name == name)
        {
            return module;
        }
    }
    return DebugModule();
}


DebugModule DebuggerModules::GetModuleForAddress(uint64_t remoteAddress) const
{
    for (const DebugModule& module: m_modules)
    {
        // This is slighlty different from the Python implementation, which finds the largest module start that is
        // smaller than the remoteAddress. 
        // TODO: check if the m_size of DebugModule is present for all platforms
        if ((module.m_address <= remoteAddress) && (remoteAddress < module.m_address + module.m_size))
            return module;
    }

    return {};
}


ModuleNameAndOffset DebuggerModules::AbsoluteAddressToRelative(uint64_t absoluteAddress) const
{
    DebugModule module = GetModuleForAddress(absoluteAddress);
    uint64_t relativeAddress;

    if (module.m_name != "")
    {
        relativeAddress = absoluteAddress - module.m_address;
    }
    else
    {
        relativeAddress = absoluteAddress;
    }

    return ModuleNameAndOffset(module.m_name, relativeAddress);
}


uint64_t DebuggerModules::RelativeAddressToAbsolute(const ModuleNameAndOffset& relativeAddress) const
{
    if (!relativeAddress.module.empty()) {
        for (const DebugModule& module: m_modules) {
            if (module.m_name == relativeAddress.module || module.m_short_name == relativeAddress.module) {
                return module.m_address + relativeAddress.offset;
            }
        }
    }

    return relativeAddress.offset;
}


DebuggerBreakpoints::DebuggerBreakpoints(DebuggerState* state, std::vector<ModuleNameAndOffset> initial):
    m_state(state), m_breakpoints(std::move(initial))
{
}


bool DebuggerBreakpoints::AddAbsolute(uint64_t remoteAddress)
{
    if (!m_state->GetAdapter())
        throw ConnectionRefusedError("Cannot add breakpoint at absolute address when disconnected");

    ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(remoteAddress);
    if (!ContainsOffset(info))
    {
        m_breakpoints.push_back(info);
        SerializeMetadata();
        // TODO: right now AddBreakpoint returns DebugBreakpoint rather than a bool.
        m_state->GetAdapter()->AddBreakpoint(remoteAddress);
        return true;
    }
    // TODO: I do not think its a good idea to return false here. We would better have a way to inform the caller that
    // the breakpoint already exists.
    return false;
}


bool DebuggerBreakpoints::AddOffset(const ModuleNameAndOffset& address)
{
    if (!ContainsOffset(address))
    {
        m_breakpoints.push_back(address);
        SerializeMetadata();

        // Only add the breakpoint via the adapter when it is connected
        if (m_state->GetAdapter() && m_state->IsConnected())
        {
            uint64_t remoteAddress = m_state->GetModules()->RelativeAddressToAbsolute(address);
            m_state->GetAdapter()->AddBreakpoint(remoteAddress);
            return true;
        }
        return true;
    }
    return false;
}


bool DebuggerBreakpoints::RemoveAbsolute(uint64_t remoteAddress)
{
    if (!m_state->GetAdapter())
        throw ConnectionRefusedError("Cannot remove breakpoint at absolute address when disconnected");

    ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(remoteAddress);
    if (ContainsOffset(info))
    {
        auto iter = std::find(m_breakpoints.begin(), m_breakpoints.end(), info);
        if (iter != m_breakpoints.end())
        {
            m_breakpoints.erase(iter);
        }
        SerializeMetadata();
        m_state->GetAdapter()->RemoveBreakpoint(remoteAddress);
        return true;
    }
    return false;
}


bool DebuggerBreakpoints::RemoveOffset(const ModuleNameAndOffset& address)
{
    if (ContainsOffset(address))
    {
        if (auto iter = std::find(m_breakpoints.begin(), m_breakpoints.end(), address);
                iter != m_breakpoints.end())
            m_breakpoints.erase(iter);

        SerializeMetadata();

        if (m_state->GetAdapter() && m_state->IsConnected())
        {
            uint64_t remoteAddress = m_state->GetModules()->RelativeAddressToAbsolute(address);
            m_state->GetAdapter()->RemoveBreakpoint(remoteAddress);
            return true;
        }
        return true;
    }
    return false;
}


bool DebuggerBreakpoints::ContainsOffset(const ModuleNameAndOffset& address)
{
    // If there is no backend, then only check if the breakpoint is in the list
    // This is useful when we deal with the breakpoint before the target is launched
    if (!m_state->GetAdapter())
        return std::find(m_breakpoints.begin(), m_breakpoints.end(), address) != m_breakpoints.end();

    // When the backend is live, convert the relative address to absolute address and check its existence
    uint64_t absolute = m_state->GetModules()->RelativeAddressToAbsolute(address);
    return ContainsAbsolute(absolute);
}


bool DebuggerBreakpoints::ContainsAbsolute(uint64_t address)
{
    if (!m_state->GetAdapter())
        throw ConnectionRefusedError("Cannot check the existence of breakpoint with absolute address when disconnected");

    // We need to convert every ModuleAndOffset to absolute address and compare with the input address
    // Because every ModuleAndOffset can be converted to an absolute address, but there is no guarantee that it works
    // backward
    // Well, that is because lldb does not report the size of the loaded libraries, so it is currently screwed up
    for (const ModuleNameAndOffset& breakpoint: m_breakpoints)
    {
        uint64_t absolute = m_state->GetModules()->RelativeAddressToAbsolute(breakpoint);
        if (absolute == address)
            return true;
    }
    return false;
}


void DebuggerBreakpoints::SerializeMetadata()
{
    // TODO: who should free these Metadata objects?
    std::vector<Ref<Metadata>> breakpoints;
    for (const ModuleNameAndOffset& bp: m_breakpoints)
    {
        std::map<std::string, Ref<Metadata>> info;
        info["module"] = new Metadata(bp.module);
        info["offset"] = new Metadata(bp.offset);
        breakpoints.push_back(new Metadata(info));
    }
    m_state->GetController()->GetData()->StoreMetadata("native_debugger.breakpoints", new Metadata(breakpoints));
}


void DebuggerBreakpoints::UnserializedMetadata()
{
    Ref<Metadata> metadata = m_state->GetController()->GetData()->QueryMetadata("native_debugger.breakpoints");
    if (!metadata || (!metadata->IsArray()))
        return;

    vector<Ref<Metadata>> array = metadata->GetArray();
    std::vector<ModuleNameAndOffset> newBreakpoints;

    for (auto& element: array)
    {
        if (!element || (!element->IsKeyValueStore()))
            continue;

        std::map<std::string, Ref<Metadata>> info = element->GetKeyValueStore();
        ModuleNameAndOffset address;

        if (!(info["module"] && info["module"]->IsString()))
            continue;

        address.module = info["module"]->GetString();

        if (!(info["offset"] && info["offset"]->IsUnsignedInteger()))
            continue;

        address.offset = info["offset"]->GetUnsignedInteger();
        newBreakpoints.push_back(address);        
    }

    m_breakpoints = newBreakpoints;
}


void DebuggerBreakpoints::Apply()
{
    if (!m_state->GetAdapter())
        throw ConnectionRefusedError("cannot apply breakpoints when disconnected");

    std::vector<DebugBreakpoint> remoteBreakpoints = m_state->GetAdapter()->GetBreakpointList();
    for (const ModuleNameAndOffset& address: m_breakpoints)
    {
        uint64_t remoteAddress = m_state->GetModules()->RelativeAddressToAbsolute(address);
        if (std::find(remoteBreakpoints.begin(), remoteBreakpoints.end(), remoteAddress) == remoteBreakpoints.end())
        {
            LogWarn(fmt::format("adding breakpoint at remote address {:x}", remoteAddress).c_str());
            m_state->GetAdapter()->AddBreakpoint(remoteAddress);
        }
    }
}


DebuggerState::DebuggerState(BinaryViewRef data, DebuggerController* controller): m_controller(controller)
{
    m_modules = new DebuggerModules(this);
    m_registers = new DebuggerRegisters(this);
    m_threads = new DebuggerThreads(this);
    m_breakpoints = new DebuggerBreakpoints(this);
    m_breakpoints->UnserializedMetadata();

	// TODO: A better way to deal with this is to have the adapters return a fitness score, and then we pick the highest
	// one from the list. Similar to what we do for the views.
	m_availableAdapters = DebugAdapterType::GetAvailableAdapters(data);
	m_adapterType = DebugAdapterType::GetBestAdapterForCurrentSystem(data);
	// Check whether there is no available adapters at all
	if (m_availableAdapters.size() == 0)
	{
		m_adapterType = "";
	}
	else if (std::find(m_availableAdapters.begin(), m_availableAdapters.end(), m_adapterType) ==
		m_availableAdapters.end())
	{
		// The system's default adapter does not work with the current data, e.g., an .exe is opened on macOS,
		// then pick one from the available ones.
		m_adapterType = m_availableAdapters[0];
	}

    Ref<Metadata> metadata;
    // metadata = m_data->QueryMetadata("native_debugger.command_line_args");
    // if (metadata && metadata->IsStringList())
    //     m_commandLineArgs = metadata->GetStringList();

	metadata = m_controller->GetData()->QueryMetadata("native_debugger.executable_path");
	if (metadata && metadata->IsString())
		m_executablePath = metadata->GetString();

	if (m_executablePath == "")
		m_executablePath = m_controller->GetData()->GetFile()->GetOriginalFilename();

    metadata = m_controller->GetData()->QueryMetadata("native_debugger.remote_host");
    if (metadata && metadata->IsString())
        m_remoteHost = metadata->GetString();
	if (m_remoteHost.empty())
		m_remoteHost = "127.0.0.1";

    metadata = m_controller->GetData()->QueryMetadata("native_debugger.remote_port");
    if (metadata && metadata->IsUnsignedInteger())
        m_remotePort = metadata->GetUnsignedInteger();
	if (m_remotePort == 0)
        m_remotePort = 31337;

    metadata = m_controller->GetData()->QueryMetadata("native_debugger.adapter_type");
    if (metadata && metadata->IsString())
        m_adapterType = metadata->GetString();

    metadata = m_controller->GetData()->QueryMetadata("native_debugger.terminal_emulator");
    if (metadata && metadata->IsUnsignedInteger())
        m_requestTerminalEmulator = metadata->GetBoolean();
    else
        m_requestTerminalEmulator = true;

    m_connectionStatus = DebugAdapterNotConnectedStatus;
}


bool DebuggerState::CreateDebugAdapter()
{
//    std::string adapterTypeName = "Local GDB";
//    std::string adapterTypeName = "Local LLDB";
    DebugAdapterType* type = DebugAdapterType::GetByName(m_adapterType);
    if (!type)
    {
        LogWarn("fail to get an debug adapter of type %s", m_adapterType.c_str());
		return false;
    }
    DebugAdapter* adapter = type->Create(m_controller->GetData());
	if (!adapter)
	{
		LogWarn("fail to create an adapter of type %s", m_adapterType.c_str());
		return false;
	}
	// TODO: this causes memory leak. Consider making the adapter ref counted
	m_adapter = adapter;

	// Forward the DebuggerEvent from the adapters to the controller
	adapter->SetEventCallback([this](const DebuggerEvent& event){
		m_controller->PostDebuggerEvent(event);
	});
	return true;
}


bool DebuggerState::Launch()
{
    if (!CreateDebugAdapter())
		return false;
	return Exec();
}


void DebuggerState::Restart()
{
    Quit();
    // TODO: why is this necessary?
    std::this_thread::sleep_for(1000ms);
    Launch();
}


void DebuggerState::Quit()
{
    if (IsConnected())
    {
        m_adapter->Quit();
        m_adapter = nullptr;
        m_remoteArch = nullptr;
        m_connectionStatus = DebugAdapterNotConnectedStatus;
    }
    MarkDirty();

    // TODO: delete temp file
}


bool DebuggerState::Exec()
{
    if (IsConnected() || IsConnecting())
        throw ConnectionRefusedError("Tried to execute, but already debugging");

    m_connectionStatus = DebugAdapterConnectingStatus;
    string filePath = m_controller->GetState()->GetExecutablePath();
    // We should switch to use std::filesystem::exists() later
    FILE* file = fopen(filePath.c_str(), "r");
    if (!file)
	{
		LogWarn("file \"%s\" does not exist, fail to execute it", filePath.c_str());
		// TODO: Post error event
		return false;
	}
    else
	{
        fclose(file);
	}

	bool requestTerminal = GetRequestTerminalEmulator();
	LaunchConfigurations configs = {requestTerminal};

    return m_adapter->Execute(filePath, configs);
}


bool DebuggerState::Attach()
{
	if (IsConnected() || IsConnecting())
        throw ConnectionRefusedError("Tried to exec but already debugging");

	if (!CreateDebugAdapter())
    	return false;

    m_connectionStatus = DebugAdapterConnectingStatus;
	bool ok = m_adapter->Connect(m_remoteHost, m_remotePort);
	// TODO: some of these updates might be redundant
	if (!ok)
	{
	    m_connectionStatus = DebugAdapterNotConnectedStatus;
		return ok;
	}
	m_connectionStatus = DebugAdapterConnectedStatus;
    m_targetStatus = DebugAdapterRunningStatus;
	return ok;
}


void DebuggerState::Detach()
{
    if (IsConnected())
    {
        m_adapter->Detach();
        m_adapter = nullptr;
        m_remoteArch = nullptr;
    }
    m_connectionStatus = DebugAdapterNotConnectedStatus;
    MarkDirty();
}


void DebuggerState::Pause()
{
    if (!IsConnected())
        throw ConnectionRefusedError("Cannot pause when disconncted");

    m_adapter->BreakInto();
    MarkDirty();
}


void DebuggerState::Go()
{
    m_targetStatus = DebugAdapterRunningStatus;
	DebugStopReason reason;

    uint64_t remoteIP = IP();
    // TODO: for dbgeng, it handles this sequence of operations for us, so we can simply can Go()
    if (this->m_adapterType != "LOCAL DBGENG" && m_breakpoints->ContainsAbsolute(remoteIP))
    {
        m_adapter->RemoveBreakpoint(remoteIP);
        m_adapter->StepInto();
		reason = m_adapter->StopReason();
        // Always restore the breakpoint despite any errors
		m_adapter->AddBreakpoint(remoteIP);
		if (reason != DebugStopReason::SingleStep)
		{
			// We single stepped, but the target stops for a different reason, e.g., an exception.
			// We should not resume the target; instead, we should report the stop to the user immediately
			SetLastStopReason(reason);

			m_targetStatus = DebugAdapterPausedStatus;
			MarkDirty();
			return;
		}
        m_adapter->Go();
    }
    else
    {
        m_adapter->Go();
    }

	// This code might read odd, which I agree with. In the future, we should have DebugAdapter::Go() didreclty
	// returning the stop reason.
	reason = m_adapter->StopReason();
	SetLastStopReason(reason);
    m_targetStatus = DebugAdapterPausedStatus;
    MarkDirty();
}


void DebuggerState::StepInto(BNFunctionGraphType il)
{
    if (!IsConnected())
        throw ConnectionRefusedError("cannot step into when disconnected");

    switch (il)
    {
    case NormalFunctionGraph:
    {
        uint64_t remoteIP = IP();
        fmt::print("IP : {:#x}\n", remoteIP);
        if (m_breakpoints->ContainsAbsolute(remoteIP))
        {
            m_adapter->RemoveBreakpoint(remoteIP);
            m_adapter->StepInto();
            m_adapter->AddBreakpoint(remoteIP);
        }
        else
        {
            m_adapter->StepInto();
        }

        MarkDirty();
        break;
    }
    case LowLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
            StepInto(NormalFunctionGraph);
            // We must do the udpate here, otherwise the ip will not change
            m_registers->Update();
            uint64_t newRemoteRip = IP();
            std::vector<FunctionRef> functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                LowLevelILFunctionRef llil = func->GetLowLevelIL();
                size_t start = llil->GetInstructionStart(m_controller->GetLiveView()->GetDefaultArchitecture(), newRemoteRip);
                if (start < llil->GetInstructionCount())
                {
                    if (llil->GetInstruction(start).address == newRemoteRip)
                        return;
                }
            }
        }
        break;
    }
    case MediumLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
            StepInto(NormalFunctionGraph);
            m_registers->Update();
            uint64_t newRemoteRip = IP();
            std::vector<FunctionRef> functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                MediumLevelILFunctionRef mlil = func->GetMediumLevelIL();
                size_t start = mlil->GetInstructionStart(m_controller->GetLiveView()->GetDefaultArchitecture(), newRemoteRip);
                if (start < mlil->GetInstructionCount())
                {
                    if (mlil->GetInstruction(start).address == newRemoteRip)
                        return;
                }
            }
        }
        break;
    }
    case HighLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
            StepInto(NormalFunctionGraph);
            m_registers->Update();
            uint64_t newRemoteRip = IP();
            std::vector<FunctionRef> functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                HighLevelILFunctionRef hlil = func->GetHighLevelIL();
                for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
                {
                    if (hlil->GetInstruction(i).address == newRemoteRip)
                        return;
                }
            }
        }
        break;
    }
    default:
        LogWarn("step into unimplemented in the current il type");
        break;
    }
}


void DebuggerState::StepOverInternal()
{
    if (!IsConnected())
        throw ConnectionRefusedError("cannot step over asm when disconnected");

    if (m_adapter->SupportFeature(DebugAdapterSupportStepOver))
    {
        // TODO: if the current rip has a breakpoint on it, do we need any extra treatment for it?
        m_adapter->StepOver();
        MarkDirty();
        return;
    }

    uint64_t remoteIP = IP();

    // TODO: support the case where we cannot determined the remote arch
    size_t size = m_remoteArch->GetMaxInstructionLength();
    DataBuffer buffer = m_adapter->ReadMemory(remoteIP, size);
    size_t bytesRead = buffer.GetLength();

    Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(m_remoteArch, nullptr);
    ilFunc->SetCurrentAddress(m_remoteArch, remoteIP);
    m_remoteArch->GetInstructionLowLevelIL((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, *ilFunc);

    const auto& instr = (*ilFunc)[0];
    if (instr.operation != LLIL_CALL)
    {
        StepInto(NormalFunctionGraph);
    }
    else
    {
        InstructionInfo info;
        if (!m_remoteArch->GetInstructionInfo((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, info))
        {
            // Whenever there is a failure, we fail back to step into
            // TODO: decide if there is another better options
            StepInto(NormalFunctionGraph);
            return;
        }

        if (info.length == 0)
        {
            StepInto(NormalFunctionGraph);
            return;
        }

        uint64_t remoteIPNext = remoteIP + info.length;
        StepTo({remoteIPNext});
    }

    MarkDirty();
}


void DebuggerState::StepOver(BNFunctionGraphType il)
{
    if (!IsConnected())
        throw ConnectionRefusedError("cannot step over il when disconnected");

    switch (il)
    {
    case NormalFunctionGraph:
    {
        StepOverInternal();
        break;
    }
    case LowLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
            StepOverInternal();
            // We must do the udpate here, otherwise the ip will not change
            m_registers->Update();
            uint64_t newRemoteRip = IP();
            std::vector<FunctionRef> functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                LowLevelILFunctionRef llil = func->GetLowLevelIL();
                size_t start = llil->GetInstructionStart(m_controller->GetLiveView()->GetDefaultArchitecture(), newRemoteRip);
                if (start < llil->GetInstructionCount())
                {
                    if (llil->GetInstruction(start).address == newRemoteRip)
                        return;
                }
            }
        }
        break;
    }
    case MediumLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
            StepOverInternal();
            m_registers->Update();
            uint64_t newRemoteRip = IP();
            std::vector<FunctionRef> functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                MediumLevelILFunctionRef mlil = func->GetMediumLevelIL();
                size_t start = mlil->GetInstructionStart(m_controller->GetLiveView()->GetDefaultArchitecture(), newRemoteRip);
                if (start < mlil->GetInstructionCount())
                {
                    if (mlil->GetInstruction(start).address == newRemoteRip)
                        return;
                }
            }
        }
        break;
    }
    case HighLevelILFunctionGraph:
    {
        // TODO: This might cause infinite loop
        while (true)
        {
            StepOverInternal();
            m_registers->Update();
            uint64_t newRemoteRip = IP();
            std::vector<FunctionRef> functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
            if (functions.size() == 0)
                return;

            for (FunctionRef& func: functions)
            {
                HighLevelILFunctionRef hlil = func->GetHighLevelIL();
                for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
                {
                    if (hlil->GetInstruction(i).address == newRemoteRip)
                        return;
                }
            }
        }
        break;
    }
    default:
        LogWarn("step into unimplemented in the current il type");
        break;
    }
}


void DebuggerState::StepReturn()
{
	if (!IsConnected())
		throw ConnectionRefusedError("cannot step return when disconnected");

	// TODO: dbgeng supports step out natively, consider using that as well once we implement a similar functionality
	// for gdb and lldb
	uint64_t address = IP();
	std::vector<FunctionRef> functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(address);
	if (functions.size() == 0)
	{
		// TODO: shall we create a function here?
		LogWarn("There is no analysis function at 0x%llx, cannot step return", address);
		return;
	}

	std::vector<uint64_t> returnAddresses;
	FunctionRef function = functions[0];
	MediumLevelILFunctionRef mlilFunc = function->GetMediumLevelIL();
	for (size_t i = 0; i < mlilFunc->GetInstructionCount(); i++)
	{
		MediumLevelILInstruction instruction = mlilFunc->GetInstruction(i);
		if ((instruction.operation == MLIL_RET) || (instruction.operation == MLIL_TAILCALL))
			returnAddresses.push_back(instruction.address);
	}

	StepTo(returnAddresses);
}


void DebuggerState::StepTo(std::vector<uint64_t> remoteAddresses)
{
    if (!IsConnected())
        throw ConnectionRefusedError("cannot step to when disconnected");

    for (uint64_t remoteAddress: remoteAddresses)
    {
        if (!m_breakpoints->ContainsAbsolute(remoteAddress))
        {
            m_adapter->AddBreakpoint(remoteAddress);
        }
    }

    uint64_t remoteIP = IP();
    if (m_breakpoints->ContainsAbsolute(remoteIP))
    {
        m_adapter->RemoveBreakpoint(remoteIP);
        m_adapter->StepInto();
        m_adapter->AddBreakpoint(remoteIP);
        m_adapter->Go();
    }
    else
    {
        m_adapter->Go();
    }

    for (uint64_t remoteAddress: remoteAddresses)
    {
        if (!m_breakpoints->ContainsAbsolute(remoteAddress))
        {
            m_adapter->RemoveBreakpoint(remoteAddress);
        }
    }

    MarkDirty();
}


bool DebuggerState::CanExec()
{
    // TODO: query the underlying DebugAdapter for the info
    return true;
}


bool DebuggerState::CanConnect()
{
    // TODO: query the underlying DebugAdapter for the info
    return true;
}


void DebuggerState::AddBreakpoint(uint64_t address)
{
    m_breakpoints->AddAbsolute(address);
}


void DebuggerState::AddBreakpoint(const ModuleNameAndOffset& address)
{
    m_breakpoints->AddOffset(address);
}


void DebuggerState::DeleteBreakpoint(uint64_t address)
{
    m_breakpoints->RemoveAbsolute(address);
}


void DebuggerState::DeleteBreakpoint(const ModuleNameAndOffset& address)
{
    m_breakpoints->RemoveOffset(address);
}


uint64_t DebuggerState::IP()
{
    if (!IsConnected())
        throw ConnectionRefusedError("Cannot read ip when disconnected");

//    This leads to redundant updates to the register values. They should already be updated --
//    since the first thing to do when the target stops is to update caches.
//    m_registers->Update();
    string archName = m_remoteArch->GetName();
    if (archName == "x86_64")
        return m_registers->GetRegisterValue("rip");
    else if (archName == "x86")
        return m_registers->GetRegisterValue("eip");
    else if ((archName == "aarch64") || (archName == "arm") || (archName == "armv7") || (archName == "Z80"))
        return m_registers->GetRegisterValue("pc");

    throw NotInstalledError("unimplemented architecture " + archName);
}


uint64_t DebuggerState::StackPointer()
{
    // TODO: we would better have the DebugAdapter either tell us which register holds the stack pointer
    if (!IsConnected())
        throw ConnectionRefusedError("Cannot read stack pointer when disconnected");
    string archName = m_remoteArch->GetName();
    if (archName == "x86_64")
        return m_registers->GetRegisterValue("rsp");
    else if (archName == "x86")
        return m_registers->GetRegisterValue("esp");
    else if ((archName == "aarch64") || (archName == "arm") || (archName == "armv7") || (archName == "Z80"))
        return m_registers->GetRegisterValue("sp");

    throw NotInstalledError("unimplemented architecture " + archName);
}


bool DebuggerState::SetActiveThread(const DebugThread& thread)
{
    if (!m_threads)
        return false;

    return m_threads->SetActiveThread(thread);
}


void DebuggerState::MarkDirty()
{
    m_registers->MarkDirty();
    DebugProcessView* view = dynamic_cast<DebugProcessView*>(m_controller->GetLiveView().GetPtr());
    if (view)
        view->MarkDirty();

    m_threads->MarkDirty();
    m_modules->MarkDirty();
    if (m_connectionStatus == DebugAdapterConnectedStatus)
        m_remoteArch = DetectRemoteArch();
}


void DebuggerState::UpdateCaches()
{
    if (m_registers->IsDirty())
        m_registers->Update();

    if (m_threads->IsDirty())
        m_threads->Update();

    if (m_modules->IsDirty())
        m_modules->Update();
}


ArchitectureRef DebuggerState::DetectRemoteArch()
{
    // TODO: The backend should report any architecture change and notify us.
    // Here we read it (in order to allow the adapter to cache it), but we do not really use the return value
    m_adapter->GetTargetArchitecture();
    return m_controller->GetData()->GetDefaultArchitecture();
}


uint64_t DebuggerState::GetRemoteBase(BinaryViewRef relativeView)
{
    return m_modules->GetModuleBase(m_controller->GetData()->GetFile()->GetOriginalFilename());
}


std::string DebuggerState::ResolveTargetBase()
{
    // TODO: not implemented
    // if (m_adapter->GetTargetPath() == "")
    // {

    // }
    // else
    // {
    //     return GetModules()->GetModuleForAddress(m_adapter->)
    // }
    return 0;
}


void DebuggerState::ApplyBreakpoints()
{
    m_breakpoints->Apply();
}


void DebuggerState::UpdateRemoteArch()
{
    m_remoteArch = DetectRemoteArch();
}
