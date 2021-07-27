#include "debuggerstate.h"
#include "debugadapter.h"
#include "ui/ui.h"
#include <chrono>
#include <thread>
#include "lowlevelilinstruction.h"

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
    BinaryNinja::LogWarn("Updating register cache");
    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw runtime_error("Cannot update registers when disconnected");

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
    std::vector<DebugRegister> result;
    for (auto& iter: m_registerCache)
    {
        result.push_back(iter.second);
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
}


void DebuggerThreads::Update()
{
    if (!m_state)
        throw runtime_error("Cannot update threads when disconnected");

    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw runtime_error("invalid adapter");

    m_threads.clear();

    DebugThread selectedThread = adapter->GetActiveThread();
    DebugThread lastThread = selectedThread;
    for (const DebugThread& thread: adapter->GetThreadList())
    {
        if (lastThread != thread)
        {
            // TODO: This forces a thread swtich for every thread, which is too expensive
            adapter->SetActiveThread(thread);
            lastThread = thread;
        }
        DebuggerThreadCache cache;
        cache.thread = thread;
        cache.ip = m_state->IP();
        cache.selected = (thread == selectedThread);
        m_threads.push_back(cache);
    }
    // Restore the original active thread after the above operations
    if (lastThread != selectedThread)
        adapter->SetActiveThread(selectedThread);

    m_dirty = false;
}


DebugThread DebuggerThreads::GetActiveThread() const
{
    if (!m_state)
        throw runtime_error("Cannot update threads when disconnected");

    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw runtime_error("invalid adapter");

    return adapter->GetActiveThread();
}


bool DebuggerThreads::SetActiveThread(const DebugThread& thread)
{
    if (!m_state)
        throw runtime_error("Cannot update threads when disconnected");

    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw runtime_error("invalid adapter");

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
        {
            return module;
        }
    }
    return DebugModule();
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


uint64_t DebuggerModules::RelativeAddressToAbsolute(ModuleNameAndOffset relativeAddress) const
{
    if (relativeAddress.module != "")
    {
        for (const DebugModule& module: m_modules)
        {
            if (module.m_name == relativeAddress.module)
                return module.m_address + relativeAddress.offset;
            else if (module.m_short_name == relativeAddress.module)
                return module.m_address + relativeAddress.offset;
        }
    }
    return relativeAddress.offset;
}


DebuggerBreakpoints::DebuggerBreakpoints(DebuggerState* state, std::vector<ModuleNameAndOffset> initial):
    m_state(state), m_breakpoints(initial)
{
}


bool DebuggerBreakpoints::AddAbsolute(uint64_t remoteAddress)
{
    if (!m_state->GetAdapter())
        throw ("Cannot add breakpoint at absolute address when disconnected");

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
        throw ("Cannot remove breakpoint at absolute address when disconnected");

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
        auto iter = std::find(m_breakpoints.begin(), m_breakpoints.end(), address);
        if (iter != m_breakpoints.end())
        {
            m_breakpoints.erase(iter);
        }
        SerializeMetadata();

        if (m_state->GetAdapter())
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
    return std::find(m_breakpoints.begin(), m_breakpoints.end(), address) != m_breakpoints.end();
}


bool DebuggerBreakpoints::ContainsAbsolute(uint64_t address)
{
    if (!m_state->GetAdapter())
        throw runtime_error("Cannot check the existence of breakpoint with absolute address when disconnected");

    ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(address);
    return ContainsOffset(info);
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
    m_state->GetData()->StoreMetadata("native_debugger.breakpoints", new Metadata(breakpoints));
}


void DebuggerBreakpoints::UnserializedMetadata()
{
    Ref<Metadata> metadata = m_state->GetData()->QueryMetadata("native_debugger.breakpoints");
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
        throw runtime_error("cannot apply breakpoints when disconnected");

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


DebuggerState::DebuggerState(BinaryViewRef data): m_data(data)
{
    m_memoryView = new DebugProcessView(data);
    m_modules = new DebuggerModules(this);
    m_registers = new DebuggerRegisters(this);
    m_threads = new DebuggerThreads(this);
    m_breakpoints = new DebuggerBreakpoints(this);
    m_breakpoints->UnserializedMetadata();
    m_ui = new DebuggerUI(this);

    Ref<Metadata> metadata;
    // metadata = m_data->QueryMetadata("native_debugger.command_line_args");
    // if (metadata && metadata->IsStringList())
    //     m_commandLineArgs = metadata->GetStringList();

    metadata = m_data->QueryMetadata("native_debugger.remote_host");
    if (metadata && metadata->IsString())
        m_remoteHost = metadata->GetString();

    metadata = m_data->QueryMetadata("native_debugger.remote_port");
    if (metadata && metadata->IsUnsignedInteger())
        m_remotePort = metadata->GetUnsignedInteger();
    else
        m_remotePort = 31337;

    metadata = m_data->QueryMetadata("native_debugger.adapter_type");
    if (metadata && metadata->IsUnsignedInteger())
        m_adapterType = (DebugAdapterType::AdapterType)metadata->GetUnsignedInteger();
    else
        m_adapterType = DebugAdapterType::DefaultAdapterType;

    metadata = m_data->QueryMetadata("native_debugger.request_terminal_emulator");
    if (metadata && metadata->IsUnsignedInteger())
        m_requestTerminalEmulator = metadata->GetBoolean();
    else
        m_requestTerminalEmulator = false;

    m_connectionStatus = DebugAdapterNotConnectedStatus;
}


void DebuggerState::Run()
{
    if (DebugAdapterType::UseExec(m_adapterType))
        Exec();
    else if (DebugAdapterType::UseConnect(m_adapterType))
        Attach();
    else
        throw runtime_error("don't know how to connect to adapter of type " + DebugAdapterType::GetName(m_adapterType));
}


void DebuggerState::Restart()
{
    Quit();
    // TODO: why is this necessary?
    std::this_thread::sleep_for(1000ms);
    Run();
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


void DebuggerState::Exec()
{
    if (IsConnected() || IsConnecting())
        throw runtime_error("Tried to exec but already debugging");

    m_connectionStatus = DebugAdapterConnectingStatus;
    bool runFromTemp = false;
    string filePath = m_data->GetFile()->GetOriginalFilename();
    // We should switch to use std::filesystem::exists() later
    FILE* file = fopen(filePath.c_str(), "r");
    if (!file)
    {
        runFromTemp = true;
    }
    else
    {
        fclose(file);
    }

    if (runFromTemp)
    {

    }

    m_adapter = DebugAdapterType::GetNewAdapter(m_adapterType);
    if (DebugAdapterType::UseExec(m_adapterType))
    {
        // TODO: what should I do for QueuedAdapter?
        bool ok = m_adapter->Execute(filePath);
        // m_adapter->ExecuteWithArgs(filePath, getCommandLineArguments());
        // The Execute() function is blocking, and it only returns when there is a status change
        if (!ok)
        {
            LogWarn("fail to execute %s", filePath.c_str());
            m_connectionStatus = DebugAdapterNotConnectedStatus;
            return;
        }
        m_connectionStatus = DebugAdapterConnectedStatus;
    }

    // std::string currentModule = ResolveTargetBase();
    // We must first update the modules, then the breakpoints can be applied correctly
    m_modules->Update();
    m_breakpoints->Apply();
    m_remoteArch = DetectRemoteArch();
}


void DebuggerState::Attach()
{
    BinaryNinja::LogWarn("attach() requested");
}


void DebuggerState::Detach()
{
    if (IsConnected())
    {
        m_adapter->Detach();
        m_adapter = nullptr;
        m_remoteArch = nullptr;
    }
    MarkDirty();
}


void DebuggerState::Pause()
{
    if (!IsConnected())
        throw runtime_error("Cannot pause when disconncted");

    m_adapter->BreakInto();
    MarkDirty();
}


void DebuggerState::Go()
{
    if (!IsConnected())
        throw runtime_error("missing adapter");

    m_targetStatus = DebugAdapterRunningStatus;

    uint64_t remoteIP = IP();
    // TODO: for gdbeng, it handles this sequence of operations for us, so we can simply can Go()
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

    m_targetStatus = DebugAdapterPausedStatus;
    MarkDirty();
}


void DebuggerState::StepIntoAsm()
{
    if (!IsConnected())
        throw runtime_error("cannot step into asm when disconnected");

    uint64_t remoteIP = IP();
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
}


void DebuggerState::StepIntoIL()
{
    BinaryNinja::LogWarn("stepIntoIL() requested");
}


void DebuggerState::StepOverAsm()
{
    if (!IsConnected())
        throw runtime_error("cannot step over asm when disconnected");

    if (m_adapter->SupportFeature(DebugAdapterSupportStepOver))
    {
        // TODO: if the current rip has a breakpoint on it, do we need any extra treatment for it?
        m_adapter->StepOver();
        MarkDirty();
        return;
    }

    uint64_t remoteIP = IP();
    uint64_t localIP = m_memoryView->RemoteAddressToLocal(remoteIP);

    // TODO: support the case where we cannot determined the remote arch
    size_t size = m_remoteArch->GetMaxInstructionLength();
    uint8_t* buffer = new uint8_t[size];
    m_adapter->ReadMemory(remoteIP, buffer, size);

    Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(m_remoteArch, nullptr);
    ilFunc->SetCurrentAddress(m_remoteArch, remoteIP);
    m_remoteArch->GetInstructionLowLevelIL(buffer, remoteIP, size, *ilFunc);

    const auto& instr = (*ilFunc)[0];
    if (instr.operation != LLIL_CALL)
    {
        StepIntoAsm();
    }
    else
    {
        InstructionInfo info;
        if (!m_remoteArch->GetInstructionInfo(buffer, remoteIP, size, info))
        {
            // Whenever there is a failure, we fail back to step into
            // TODO: decide if there is another better options
            delete buffer;
            StepIntoAsm();
            return;
        }

        if (info.length == 0)
        {
            delete buffer;
            StepIntoAsm();
            return;
        }

        uint64_t remoteIPNext = remoteIP + info.length;
        StepTo({remoteIPNext});
    }

    delete buffer;
    MarkDirty();
}


void DebuggerState::StepOverIL()
{
    BinaryNinja::LogWarn("stepOverIL() requested");
}


void DebuggerState::StepReturn()
{
    BinaryNinja::LogWarn("stepReturn() requested");
}


void DebuggerState::StepTo(std::vector<uint64_t> remoteAddresses)
{
    if (!IsConnected())
        throw runtime_error("cannot step to when disconnected");

    uint64_t remoteIP = IP();

    for (uint64_t remoteAddress: remoteAddresses)
    {
        if (!m_breakpoints->ContainsAbsolute(remoteAddress))
        {
            m_adapter->AddBreakpoint(remoteAddress);
        }
    }

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


DebuggerState* DebuggerState::GetState(BinaryViewRef data)
{
    for (auto& state: g_debuggerStates)
    {
        if (state->GetData() == data)
            return state;
    }

    DebuggerState* state = new DebuggerState(data);
    g_debuggerStates.push_back(state);
    return state;    
}


void DebuggerState::DeleteState(BinaryViewRef data)
{
    for (auto it = g_debuggerStates.begin(); it != g_debuggerStates.end(); )
    {
        if ((*it)->GetData() == data)
        {
            it = g_debuggerStates.erase(it);
        }
        else
        {
            ++it;
        }
    }
}


uint64_t DebuggerState::IP()
{
    if (!IsConnected())
        throw runtime_error("Cannot read ip when disconnected");
    string archName = m_remoteArch->GetName();
    if (archName == "x86_64")
        return m_registers->GetRegisterValue("rip");
    else if (archName == "x86")
        return m_registers->GetRegisterValue("eip");
    else if ((archName == "aarch64") || (archName == "arm") || (archName == "armv7") || (archName == "Z80"))
        return m_registers->GetRegisterValue("pc");

    throw runtime_error("unimplemented architecture " + archName);
}


uint64_t DebuggerState::LocalIP()
{
    uint64_t remoteIP = IP();
    return m_memoryView->RemoteAddressToLocal(remoteIP);
}


uint64_t DebuggerState::StackPointer()
{
    // TODO: we would better have the DebugAdapter either tell us which register holds the stack pointer
    if (!IsConnected())
        throw runtime_error("Cannot read ip when disconnected");
    string archName = m_remoteArch->GetName();
    if (archName == "x86_64")
        return m_registers->GetRegisterValue("rsp");
    else if (archName == "x86")
        return m_registers->GetRegisterValue("esp");
    else if ((archName == "aarch64") || (archName == "arm") || (archName == "armv7") || (archName == "Z80"))
        return m_registers->GetRegisterValue("sp");

    throw runtime_error("unimplemented architecture " + archName);
}


bool DebuggerState::SetActiveThread(const DebugThread& thread)
{
    if (!m_threads)
        return false;

    return m_threads->SetActiveThread(thread);
}


void DebuggerState::OnStep()
{
    if (!m_ui)
        return;

    // Cached registers, threads, and modules must be updated explicitly
    if (IsConnected())
        UpdateCaches();

    m_ui->OnStep();
}


void DebuggerState::MarkDirty()
{
    m_registers->MarkDirty();
    m_memoryView->MarkDirty();
    m_threads->MarkDirty();
    m_modules->MarkDirty();
    if (m_connectionStatus == DebugAdapterConnectedStatus)
        m_remoteArch = DetectRemoteArch();
}


void DebuggerState::UpdateCaches()
{
    // try
    // {
    if (m_registers->IsDirty())
        m_registers->Update();

    if (m_threads->IsDirty())
        m_threads->Update();

    if (m_modules->IsDirty())
        m_modules->Update();
    // }
    // catch (const std::exception& except)
    // {
    //     printf("Exception -> %s\n", except.what());
    // }
    // TODO: what about m_memoryView?
}


ArchitectureRef DebuggerState::DetectRemoteArch()
{
    // TODO: The backend should report any architecture change and notify us.
    return m_data->GetDefaultArchitecture();
}


uint64_t DebuggerState::GetRemoteBase(BinaryViewRef relativeView)
{
    if (!m_memoryView)
        throw runtime_error("Invalid DebugProcessView");

    return m_memoryView->GetRemoteBase(relativeView);
}


bool DebuggerState::IsCodeASLR(BinaryViewRef relativeView)
{
    if (!m_memoryView)
        throw runtime_error("Invalid DebugProcessView");

    return m_memoryView->IsCodeASLR(relativeView);
}


uint64_t DebuggerState::LocalAddressToRemote(uint64_t localAddr, BinaryViewRef relativeView)
{
    if (!m_memoryView)
        throw runtime_error("Invalid DebugProcessView");

    return m_memoryView->LocalAddressToRemote(localAddr, relativeView);
}


uint64_t DebuggerState::RemoteAddressToLocal(uint64_t remoteAddr, BinaryViewRef relativeView)
{
    if (!m_memoryView)
        throw runtime_error("Invalid DebugProcessView");

    return m_memoryView->RemoteAddressToLocal(remoteAddr, relativeView);
}


bool DebuggerState::IsLocalAddress(uint64_t remoteAddr, BinaryViewRef relativeView)
{
    if (!m_memoryView)
        throw runtime_error("Invalid DebugProcessView");

    return m_memoryView->IsLocalAddress(remoteAddr, relativeView);
}


std::string DebuggerState::ResolveTargetBase()
{
    // if (m_adapter->GetTargetPath() == "")
    // {

    // }
    // else
    // {
    //     return GetModules()->GetModuleForAddress(m_adapter->)
    // }
}
