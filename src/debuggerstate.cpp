#include "debuggerstate.h"
#include "debugadapter.h"
#include "ui/ui.h"

using namespace BinaryNinja;
using namespace std;


DebuggerRegisters::DebuggerRegisters(DebuggerState* state): m_state(state)
{
    MarkDirty();
}


void DebuggerRegisters::MarkDirty()
{
    m_cachedRgisterList.clear();
    m_registerCache.clear();
}


void DebuggerRegisters::Update()
{
    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        throw runtime_error("Cannot update registers when disconnected");

    // TODO: This is ineffective, especially during remote debugging.
    // We need to get all register and its values in one request
    m_cachedRgisterList = adapter->GetRegisterList();
    for (const std::string reg: m_cachedRgisterList)
    {
        m_registerCache[reg] = adapter->ReadRegister(reg);
    }
}


uint64_t DebuggerRegisters::GetRegisterValue(const std::string& name)
{
    auto iter = m_registerCache.find(name);
    if (iter == m_registerCache.end())
        // TODO: we should return a boolean to indicate the call succeeds, and return the value by reference
        return 0;

    return iter->second.m_value;
}


void DebuggerRegisters::UpdateRegisterValue(const std::string& name, uint64_t value)
{
    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        return;

    adapter->WriteRegister(name, value);
    // TODO: Do we really need to mark it dirty? How about we just update our cache
    MarkDirty();
}


DebuggerModules::DebuggerModules(DebuggerState* state):
    m_state(state)
{

}


void DebuggerModules::MarkDirty()
{
    m_modules.clear();
}


void DebuggerModules::Update()
{
    DebugAdapter* adapter = m_state->GetAdapter();
    if (!adapter)
        return;

    m_modules = adapter->GetModuleList();
}


bool DebuggerModules::GetModuleBase(const std::string& name, uint64_t& address)
{
    for (const DebugModule& module: m_modules)
    {
        if ((name == module.m_name) || (name == module.m_short_name))
        {
            address = module.m_address;
            return true;
        }
    }
    return false;
}


DebuggerThreads::DebuggerThreads(DebuggerState* state): m_state(state)
{
    MarkDirty();
}


void DebuggerThreads::MarkDirty()
{
    m_cacheValid = false;
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
    m_cacheValid = false;

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

    m_cacheValid = true;    
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


DebuggerState::DebuggerState(BinaryViewRef data): m_data(data)
{
    m_memoryView = new DebugProcessView(data);
    m_modules = new DebuggerModules(this);
    m_registers = new DebuggerRegisters(this);
    m_threads = new DebuggerThreads(this);
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
    BinaryNinja::LogWarn("restart() requested");
}


void DebuggerState::Quit()
{
    BinaryNinja::LogWarn("quit() requested");
}


void DebuggerState::Exec()
{
    if ((m_connectionStatus == DebugAdapterConnectedStatus) ||
        (m_connectionStatus == DebugAdapterConnectingStatus))
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
}


void DebuggerState::Attach()
{
    BinaryNinja::LogWarn("attach() requested");
}


void DebuggerState::Detach()
{
    BinaryNinja::LogWarn("detach() requested");
}


void DebuggerState::Pause()
{
    BinaryNinja::LogWarn("pause() requested");
}


void DebuggerState::Go()
{
    if (m_connectionStatus != DebugAdapterConnectedStatus)
        throw runtime_error("missing adapter");

    m_running = true;
    // TODO: we should handle the case when the current IP is in the breakpoint list. Simply resuming the
    // target will cause it to break again, on the same address.
    bool ok = m_adapter->Go();

    MarkDirty();
}


void DebuggerState::StepIntoAsm()
{
    BinaryNinja::LogWarn("stepIntoAsm() requested");
}


void DebuggerState::StepIntoIL()
{
    BinaryNinja::LogWarn("stepIntoIL() requested");
}


void DebuggerState::StepOverAsm()
{
    BinaryNinja::LogWarn("stepOverAsm() requested");
}


void DebuggerState::StepOverIL()
{
    BinaryNinja::LogWarn("stepOverIL() requested");
}


void DebuggerState::StepReturn()
{
    BinaryNinja::LogWarn("stepReturn() requested");
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
    if (!m_connected)
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

    m_ui->OnStep();
}


void DebuggerState::MarkDirty()
{
    m_registers->MarkDirty();
    m_memoryView->MarkDirty();
    m_threads->MarkDirty();
    m_modules->MarkDirty();
    // if (m_connected)
        // m_remoteArch = DetecteRemoteArchitecture();
}
