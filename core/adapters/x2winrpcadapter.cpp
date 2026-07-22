#include "./x2winrpcadapter.h"

using namespace BinaryNinjaDebugger;

namespace {
    // Category of a wire frame: is this a call, a reply to a call, or an unsolicited notification.
    enum class FrameType: uint8_t {Request = 0, Response = 1, Event = 2};

    // Which RPC operation a Request/Response frame is about. Must match the stub's numbering exactly.
    enum class MethodId:uint16_t {
        Launch = 1,
        Attach = 2,
        GetTargetArch = 3,
        Detach = 4,
        Quit = 5,
        GetProcessList = 6,
    };

    enum class EventId: uint16_t{
        TargetStopped = 1,
    };

    void AppendString(std::vector<uint8_t>& buf, const std::string& s){
        uint32_t len = (uint32_t)s.size();
        buf.push_back(len & 0xff);
        buf.push_back((len >> 8) & 0xff);
        buf.push_back((len >> 16) & 0xff);
        buf.push_back((len >> 24) & 0xff);
        buf.insert(buf.end(), s.begin(), s.end());
    }

    uint32_t ParseU32(const std::vector<uint8_t>& buf, size_t& offset){
        uint32_t v = (uint32_t)buf[offset] | ((uint32_t)buf[offset+1] << 8 )
                    | ((uint32_t)buf[offset+2] << 16) | ((uint32_t)buf[offset+3] << 24);
        offset += 4;
        return v;
    }

    std::string ParseString(const std::vector<uint8_t>& buf, size_t& offset){
        uint32_t len = ParseU32(buf, offset);
        std::string s(buf.begin() + offset, buf.begin() + offset + len);
        offset += len;
        return s;
    }
}

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

    // pid packed little-endian, 4 bytes.
    std::vector<uint8_t> payload = {
        (uint8_t)(pid & 0xff), (uint8_t)((pid >> 8) & 0xff),
        (uint8_t)((pid >> 16) & 0xff), (uint8_t)((pid >> 24) & 0xff)
    };

    Frame reply = CallSync((uint16_t)MethodId::Attach, payload);
    return GetReplyStatus(reply);
}

bool X2WinRpcAdapter::Connect(const std::string& server, std::uint32_t port){
    return ConnectSocket(server, (uint16_t) port);
}

bool X2WinRpcAdapter::Execute(const std::string& path, const LaunchConfigurations& configs){
    return ExecuteWithArgs(path, "", "", configs);
}

bool X2WinRpcAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
  const std::string& workingDir, const LaunchConfigurations& configs){
    if(!ConnectFromSettings())
        return false;

    std::vector<uint8_t> payload;
    AppendString(payload, path);
    AppendString(payload, args);
    AppendString(payload, workingDir);

    Frame reply = CallSync((uint16_t)MethodId::Launch, payload);
    return GetReplyStatus(reply);
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
Frame X2WinRpcAdapter::CallSync(uint16_t methodId, const std::vector<uint8_t>& payload){
    uint64_t requestId = m_nextRequestId++;
    std::promise<Frame> promise;
    std::future<Frame> future = promise.get_future();
    {
        // Scoped narrowly: only the map insert needs the lock, not the send that follows.
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingRequests[requestId] = std::move(promise);
    }

    std::vector<uint8_t> frame;
    uint32_t bodyLen = 1 + 8 + 2 + (uint32_t)payload.size();

    // Little-endian byte packers for the frame header fields.
    auto appendU32 = [&](uint32_t v){
        for(int i = 0; i< 4; i++){
            frame.push_back((v >> (i*8)) & 0xff);
        }
    };
    auto appendU64 = [&](uint64_t v){
        for(int i = 0; i< 8; i++){
            frame.push_back((v >> (i*8)) & 0xff);
        }
    };
    auto appendU16 = [&](uint16_t v){
        for(int i = 0; i< 2; i++){
            frame.push_back((v>> (i*8)) & 0xff);
        }
    };

    // Wire layout: [4B bodyLen][1B FrameType][8B requestId][2B methodId][payload...]
    appendU32(bodyLen);
    frame.push_back((uint8_t)FrameType::Request);
    appendU64(requestId);
    appendU16(methodId);
    frame.insert(frame.end(), payload.begin(), payload.end());

    m_socket.Send((char*)frame.data(), (int32_t)frame.size());

    // Blocks here until ReaderLoop() (a different thread) calls promise.set_value(...).
    return future.get();
}

// Dedicated socket-reader loop, run on m_readerThread. Never used for a "write then read"
// call -- it just pulls frames forever and dispatches them, so unsolicited Event frames can
// arrive at any time, even while some other call is waiting inside CallSync() above.
void X2WinRpcAdapter::ReaderLoop(){
    while(true){
        uint8_t lenBuf[4];
        if(!RecvExact(lenBuf, 4)) break;
        uint32_t bodyLen = (uint32_t)lenBuf[0] | ((uint32_t)lenBuf[1] << 8) | ((uint32_t)lenBuf[2] << 16) | ((uint32_t)lenBuf[3] <<24);

        std::vector<uint8_t> body(bodyLen);
        if(!RecvExact(body.data(), bodyLen)) break;
        FrameType type = (FrameType)body[0];
        uint64_t requestId = 0;
        for(int i = 0; i < 8; i++){
            requestId |= ((uint64_t)body[i+1]) << (i*8);
        }
        uint16_t methodOrEvent = body[9] | body[10] << 8;

        Frame f;
        f.data.assign(body.begin() + 11, body.end());

        if(type == FrameType::Response){
            // Look up the promise this response belongs to and hand it the payload; this is
            // what unblocks the corresponding future.get() call in CallSync().
            std::lock_guard<std::mutex> lock(m_pendingMutex);
            auto it = m_pendingRequests.find(requestId);
            if(it != m_pendingRequests.end()){
                it->second.set_value(f);
                m_pendingRequests.erase(it);
            }
        }else if (type == FrameType::Event) {
            if((EventId)methodOrEvent == EventId::TargetStopped){
                uint8_t reasonCode = f.data.empty() ? 0 : f.data[0];
                DebuggerEvent event;
                event.type = AdapterStoppedEventType;
                event.data.targetStoppedData.reason = (reasonCode == 1) ? DebugStopReason::Breakpoint
                                                    : (reasonCode == 2) ? DebugStopReason::SingleStep
                                                    : DebugStopReason::UnknownReason;
                PostDebuggerEvent(event);
            }
        }
    }
}

// Simplest example of the repeating "send request, decode response" shape most methods follow:
// the reply payload is just the architecture string's raw bytes.
std::string X2WinRpcAdapter::GetTargetArchitecture(){
    Frame reply = CallSync((uint16_t)MethodId::GetTargetArch, {});
    return std::string(reply.data.begin(), reply.data.end());
}

// --- Lifecycle ---
bool X2WinRpcAdapter::Detach(){
    Frame reply = CallSync((uint16_t)MethodId::Detach, {});

    TeardownConnection();

    DebuggerEvent event;
    event.type = DetachedEventType;
    PostDebuggerEvent(event);

    return GetReplyStatus(reply);
}

bool X2WinRpcAdapter::Quit(){
    Frame reply = CallSync((uint16_t)MethodId::Quit, {});
    
    TeardownConnection();

    DebuggerEvent event;
    event.type = TargetExitedEventType;
    event.data.exitData.exitCode = 0;
    PostDebuggerEvent(event);

    return GetReplyStatus(reply);
}

std::vector<DebugProcess> X2WinRpcAdapter::GetProcessList(){
    if(!ConnectFromSettings()){
        return {};
    }

    Frame reply = CallSync((uint16_t)MethodId::GetProcessList, {});
    
    std::vector<DebugProcess> result;
    if(reply.data.size() < 4) return result;

    size_t offset = 0;
    uint32_t count = ParseU32(reply.data, offset);
    for(uint32_t i = 0; i < count; i++){
        uint32_t pid = ParseU32(reply.data, offset);
        std::string name = ParseString(reply.data, offset);
        result.emplace_back(pid, name);
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

DebugBreakpoint X2WinRpcAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type){ return DebugBreakpoint(); }
DebugBreakpoint X2WinRpcAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type){ return DebugBreakpoint(); }
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
DebugStopReason X2WinRpcAdapter::StopReason(){ return DebugStopReason::UnknownReason; }
uint64_t X2WinRpcAdapter::ExitCode(){ return 0; }
bool X2WinRpcAdapter::BreakInto(){ return false; }
bool X2WinRpcAdapter::Go(){ return false; }
bool X2WinRpcAdapter::StepInto(){ return false; }
bool X2WinRpcAdapter::StepOver(){ return false; }

std::string X2WinRpcAdapter::InvokeBackendCommand(const std::string& command){ return ""; }
uint64_t X2WinRpcAdapter::GetInstructionOffset(){ return 0; }
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

bool X2WinRpcAdapter::GetReplyStatus(const Frame& reply){
    return !reply.data.empty() && reply.data[0] == 1;
}
