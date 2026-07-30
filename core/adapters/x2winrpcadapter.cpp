#include "./x2winrpcadapter.h"

using namespace BinaryNinjaDebugger;

// Just forwards to the DebugAdapter base constructor; socket/thread state is set up later in
// Attach()/Connect(), not here.
X2WinRpcAdapter::X2WinRpcAdapter(BinaryView* data): DebugAdapter(data){
}

X2WinRpcAdapter::~X2WinRpcAdapter(){
    // Force the blocking Recv() inside ReaderLoop() to fail and return, so the loop can exit
    // and join() below won't hang forever waiting for a thread that never stops on its own.
    TeardownConnection();
}

Ref<Settings> X2WinRpcAdapter::GetAdapterSettings(){
    return X2WinRpcAdapterType::GetAdapterSettings();
}

bool X2WinRpcAdapter::ConnectSocket(const std::string& ip, uint16_t port){
    if(m_connected){
        return true;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    m_socket = Socket(AF_INET, SOCK_STREAM, 0);
    if(!m_socket.Connect(addr)) return false;

    m_readerThread = std::thread([this]() {ReaderLoop();});
    m_connected = true;

    return true;
}

bool X2WinRpcAdapter::ConnectFromSettings(){
    auto adapterSettings = GetAdapterSettings();
    auto data = GetData();

    BNSettingsScope scope = SettingsResourceScope;
    auto ipAddress = adapterSettings->Get<std::string>("connect.ipAddress", data, &scope);
    scope = SettingsResourceScope;
    auto port = adapterSettings->Get<uint64_t>("connect.port", data, &scope);

    return ConnectSocket(ipAddress, (uint16_t)port);
}

// Connects to the stub and asks it to attach to an already-running Windows process by pid.
bool X2WinRpcAdapter::Attach(std::uint32_t pid){
    if(!ConnectFromSettings())
        return false;

    x2win::Envelope request;
    request.mutable_attach_request()->set_pid(pid);
    x2win::Envelope response = CallSync(std::move(request));
    return response.attach_response().success();
}

bool X2WinRpcAdapter::Connect(const std::string& server, std::uint32_t port){
    return ConnectSocket(server, (uint16_t) port);
}

bool X2WinRpcAdapter::Execute(const std::string& path, const LaunchConfigurations& configs){
    return ExecuteWithArgs(path, "", "", configs);
}

bool X2WinRpcAdapter::ConnectToDebugServer(const std::string &server, std::uint32_t port){
    if(!ConnectSocket(server, (uint16_t)port)) return false;

    x2win::Envelope request;
    request.mutable_connect_server_request();
    x2win::Envelope response = CallSync(std::move(request));
    return response.connect_server_response().success();
}

bool X2WinRpcAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
  const std::string& workingDir, const LaunchConfigurations& configs){
    if(!ConnectFromSettings())
        return false;

    x2win::Envelope request;
    auto* launch = request.mutable_launch_request();
    launch->set_path(path);
    launch->set_args(args);
    launch->set_working_dir(workingDir);
    x2win::Envelope response = CallSync(request);
    return response.launch_response().success();
}

// TCP is a byte stream, not a message stream: a single Recv() call may return fewer bytes than
// requested. Loop until exactly `size` bytes have been collected (or the connection dies).
bool X2WinRpcAdapter::RecvExact(void* buffer, size_t size){
    uint8_t* p = (uint8_t*) buffer;
    size_t received = 0;
    while(received < size){
        intptr_t n = m_socket.Recv((char*)p+received, (int32_t)(size-received));
        if(n <= 0){
            return false; // 0 connection cloased, <0 error
        }
        received += (size_t) n;
    }
    return true;
}

// Sends one Request frame and blocks the calling thread until ReaderLoop() receives the
// matching Response (matched by requestId) and fulfills the promise registered below.
// Multiple concurrent callers each get their own request_id/promise, so a slow response to one
// call never blocks another call's response from being delivered.
x2win::Envelope X2WinRpcAdapter::CallSync(x2win::Envelope request){
    uint64_t requestId = m_nextRequestId++;
    request.set_request_id(requestId);

    std::promise<x2win::Envelope> promise;
    std::future<x2win::Envelope> future = promise.get_future();

    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingRequests[requestId] = std::move(promise);
    }

    std::string body = request.SerializeAsString();

    std::vector<uint8_t> frame;
    uint32_t bodyLen = (uint32_t)body.size();
    for(int i = 0; i < 4; i++){
        frame.push_back((bodyLen >> (i*8)) & 0xff);
    }
    frame.insert(frame.end(), body.begin(), body.end());

    m_socket.Send((char*)frame.data(), (int32_t)frame.size());

    return future.get();
}

// Dedicated socket-reader loop, run on m_readerThread. Never used for a "write then read"
// call -- it just pulls frames forever and dispatches them, so unsolicited Event frames can
// arrive at any time, even while some other call is waiting inside CallSync() above.
void X2WinRpcAdapter::ReaderLoop(){
    while (true) {
        uint8_t lenBuf[4];
        if(!RecvExact(lenBuf, 4)) break;
        uint32_t bodyLen = (uint32_t)lenBuf[0] | ((uint32_t)lenBuf[1] << 8) | ((uint32_t)lenBuf[2] << 16) | ((uint32_t)lenBuf[3] << 24);

        std::vector<uint8_t> body(bodyLen);
        if(!RecvExact(body.data(), bodyLen)) break;

        x2win::Envelope envelope;
        if(!envelope.ParseFromArray(body.data(), (int)body.size())) continue;

        if(envelope.body_case() == x2win::Envelope::kTargetStoppedEvent){
            const auto& evt = envelope.target_stopped_event();
            BNDebugStopReason reason = (evt.reason() == x2win::STOP_REASON_BREAKPOINT) ? DebugStopReason::Breakpoint
                                        : (evt.reason() == x2win::STOP_REASON_SINGLE_STEP) ? DebugStopReason::SingleStep
                                        : (evt.reason() == x2win::STOP_REASON_INITIAL_BREAKPOINT) ? DebugStopReason::InitialBreakpoint
                                        : DebugStopReason::UnknownReason;
            
            m_lastStopReason = reason;
            m_lastStopAddress = evt.address();

            DebuggerEvent event;
            event.type = AdapterStoppedEventType;
            event.data.targetStoppedData.reason = reason;
            PostDebuggerEvent(event);
            continue;
        }

        // Otherwise this is a reply to something CallSync() is blocked waiting on.
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        auto it = m_pendingRequests.find(envelope.request_id());
        if(it != m_pendingRequests.end()){
            it->second.set_value(std::move(envelope));
            m_pendingRequests.erase(it);
        }
    }
}

// Simplest example of the repeating "send request, decode response" shape most methods follow:
// the reply payload is just the architecture string's raw bytes.
std::string X2WinRpcAdapter::GetTargetArchitecture(){
    x2win::Envelope request;
    request.mutable_get_target_arch_request();
    x2win::Envelope response = CallSync(std::move(request));
    return response.get_target_arch_response().architecture();
}

// --- Lifecycle ---
bool X2WinRpcAdapter::Detach(){
    x2win::Envelope request;
    request.mutable_detach_request();
    x2win::Envelope response = CallSync(std::move(request));

    TeardownConnection();

    DebuggerEvent event;
    event.type = DetachedEventType;
    PostDebuggerEvent(event);

    return response.detach_response().success();
}

bool X2WinRpcAdapter::Quit(){
    x2win::Envelope request;
    request.mutable_quit_request();
    x2win::Envelope response = CallSync(std::move(request));
    
    TeardownConnection();

    DebuggerEvent event;
    event.type = TargetExitedEventType;
    event.data.exitData.exitCode = 0;
    PostDebuggerEvent(event);
    
    return response.quit_response().success();
}

std::vector<DebugProcess> X2WinRpcAdapter::GetProcessList(){
    if(!ConnectFromSettings()){
        return {};
    }

    x2win::Envelope request;
    request.mutable_get_process_list_request();
    x2win::Envelope response = CallSync(std::move(request));
    
    std::vector<DebugProcess> result;
    for(const auto& p : response.get_process_list_response().processes()){
        result.emplace_back(p.pid(), p.name());
    }

    return result;
}

std::uint32_t X2WinRpcAdapter::GetActivePID(){ return 0; }
std::vector<DebugThread> X2WinRpcAdapter::GetThreadList(){ return {}; }
DebugThread X2WinRpcAdapter::GetActiveThread() const { return DebugThread(); }
std::uint32_t X2WinRpcAdapter::GetActiveThreadId() const { return 0; }
bool X2WinRpcAdapter::SetActiveThread(const DebugThread& thread){ return false; }
bool X2WinRpcAdapter::SetActiveThreadId(std::uint32_t tid){ return false; }
bool X2WinRpcAdapter::SuspendThread(std::uint32_t tid){ return false; }
bool X2WinRpcAdapter::ResumeThread(std::uint32_t tid){ return false; }

DebugBreakpoint X2WinRpcAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type){
    x2win::Envelope request;
    auto* req = request.mutable_set_breakpoint_request();
    req->set_address(address);
    req->set_type(x2win::BREAKPOINT_TYPE_SOFTWARE);
    x2win::Envelope response = CallSync(std::move(request));

    const auto& resp = response.set_breakpoint_response();
    if(!resp.success()) return DebugBreakpoint();

    return DebugBreakpoint(address, (unsigned long)resp.breakpoint_id(), true, SoftwareBreakpoint);

}
DebugBreakpoint X2WinRpcAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type){
    uint64_t resolved = 0;
    if(!ResolveModuleAddress(address, resolved)) return DebugBreakpoint();

    return AddBreakpoint(resolved, breakpoint_type);
}
bool X2WinRpcAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint){ return false; }
std::vector<DebugBreakpoint> X2WinRpcAdapter::GetBreakpointList() const { return {}; }

bool X2WinRpcAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size){ return false; }
bool X2WinRpcAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size){ return false; }
bool X2WinRpcAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size){ return false; }
bool X2WinRpcAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size){ return false; }


std::unordered_map<std::string, DebugRegister> X2WinRpcAdapter::ReadAllRegisters(){ return {}; }
DebugRegister X2WinRpcAdapter::ReadRegister(const std::string& reg){ return DebugRegister(); }
bool X2WinRpcAdapter::WriteRegister(const std::string& reg, intx::uint512 value){ return false; }
DataBuffer X2WinRpcAdapter::ReadMemory(std::uintptr_t address, std::size_t size){ return DataBuffer(); }
bool X2WinRpcAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer){ return false; }


// --- Modules ---
std::vector<DebugModule> X2WinRpcAdapter::GetModuleList(){ return {}; }

// --- Execution control ---
DebugStopReason X2WinRpcAdapter::StopReason(){ return m_lastStopReason.load(); }
uint64_t X2WinRpcAdapter::ExitCode(){ return 0; }
bool X2WinRpcAdapter::BreakInto(){ return false; }
bool X2WinRpcAdapter::Go(){
    x2win::Envelope request;
    request.mutable_go_request();
    x2win::Envelope response = CallSync(std::move(request));
    return response.go_response().success();
}
bool X2WinRpcAdapter::StepInto(){ return false; }
bool X2WinRpcAdapter::StepOver(){ return false; }

std::string X2WinRpcAdapter::InvokeBackendCommand(const std::string& command){ return ""; }
uint64_t X2WinRpcAdapter::GetInstructionOffset(){ return m_lastStopAddress.load(); }
bool X2WinRpcAdapter::SupportFeature(DebugAdapterCapacity feature){ return false; }

Ref<Settings> X2WinRpcAdapterType::RegisterAdapterSettings(){
    Ref<Settings> settings = Settings::Instance("X2WinRpcAdapterSettings");
    settings->SetResourceId("x2win_rpc_adapter_settings");

    settings->RegisterSetting("connect.ipAddress", 
    R"({
    "title" : "IP Address",
    "type" : "string",
    "default" : "127.0.0.1",
    "description" : "IP address of the x2win stub to connect to",
    "readOnly" : false
    })");

    settings->RegisterSetting("connect.port", 
    R"({
    "title" : "Port",
    "type" : "number",
    "default" : 31338,
    "minValue" : 0,
    "maxValue" : 65535,
    "description" : "Port of the x2win stub to connect to",
    "readOnly" : false
    })");

    settings->RegisterSetting("attach.pid", 
    R"({
    "title" : "PID to attach to",
    "type" : "number",
    "default" : 0,
    "minValue" : 0,
    "maxValue" : 4294967295,
    "description" : "PID of the process to attach to",
    "readOnly" : false
    })");

    return settings;
}

X2WinRpcAdapterType::X2WinRpcAdapterType() : DebugAdapterType("X2WIN_RPC"){
}

Ref<Settings> X2WinRpcAdapterType::GetAdapterSettings(){
    static Ref<Settings> settings = X2WinRpcAdapterType::RegisterAdapterSettings();
    return settings;
}

DebugAdapter* X2WinRpcAdapterType::Create(BinaryNinja::BinaryView* data){
    return new X2WinRpcAdapter(data);
}

bool X2WinRpcAdapterType::IsValidForData(BinaryNinja::BinaryView* data){
    return true;
}

bool X2WinRpcAdapterType::CanExecute(BinaryNinja::BinaryView* data){
    return data->GetTypeName() == "PE";
}

bool X2WinRpcAdapterType::CanConnect(BinaryNinja::BinaryView* data){
    return data->GetTypeName() == "PE";
}

void BinaryNinjaDebugger::InitX2WinRpcAdapterType(){
    static X2WinRpcAdapterType x2winType;
    DebugAdapterType::Register(&x2winType);
}


// --- Helper Functions ---
void X2WinRpcAdapter::TeardownConnection(){
    m_socket.Kill();
    if(m_readerThread.joinable()){
        m_readerThread.join();
    }
    m_connected = false;
}

bool X2WinRpcAdapter::ResolveModuleAddress(const ModuleNameAndOffset &location, uint64_t &address){
    for(const auto& module : GetModuleList()){
        if(module.IsSameBaseModule(location.module)){
            address = module.m_address + location.offset;
            return true;
        }
    }
    return false;
}