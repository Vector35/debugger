#include "./x2winrpcadapter.h"
#include <algorithm>

using namespace BinaryNinjaDebugger;

// Just forwards to the DebugAdapter base constructor; socket/thread state is set up later in
// Attach()/Connect(), not here.
X2WinRpcAdapter::X2WinRpcAdapter(BinaryView* data): DebugAdapter(data){
    GenerateDefaultAdapterSettings(data);
}

// Same pattern as WindowsNativeAdapter::GenerateDefaultAdapterSettings (core/adapters/windowsnativeadapter.cpp):
// only fill in a default when the setting was never explicitly set for this resource, so a value the user
// already typed/picked (e.g. via common.inputFile's uiSelectionAction:"file") is never clobbered.
void X2WinRpcAdapter::GenerateDefaultAdapterSettings(BinaryView* data){
    auto adapterSettings = GetAdapterSettings();
    BNSettingsScope scope = SettingsResourceScope;
    adapterSettings->Get<std::string>("common.inputFile", data, &scope);
    if(scope != SettingsResourceScope)
        adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);
}

X2WinRpcAdapter::~X2WinRpcAdapter(){
    LogInfo("X2WinRpcAdapter::~X2WinRpcAdapter: adapter object being destroyed (connected=%d)", (int)m_connected);
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
    if(!m_socket.Connect(addr)){
        LogWarn("X2WinRpcAdapter: failed to connect to %s:%u", ip.c_str(), (unsigned)port);
        return false;
    }

    m_readerThread = std::thread([this]() {ReaderLoop();});
    m_connected = true;

    LogInfo("X2WinRpcAdapter: connected to %s:%u", ip.c_str(), (unsigned)port);
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
    if(!ConnectFromSettings()){
        LogWarn("X2WinRpcAdapter::Attach: failed to connect to stub");
        return false;
    }

    X2WinEnvelopeBuffer response = CallSync(x2win::Body_AttachRequest, [pid](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateAttachRequest(b, pid).Union();
    });
    const auto* resp = response.BodyAs<x2win::AttachResponse>();
    bool success = resp && resp->success();
    if(!success)
        LogWarn("X2WinRpcAdapter::Attach: stub rejected attach to pid %u", (unsigned)pid);
    else
        m_lastConnectionWasTargetMode = false;

    ApplyBreakPoints();
    return success;
}

bool X2WinRpcAdapter::Connect(const std::string& server, std::uint32_t port){
    if(!ConnectSocket(server, (uint16_t) port)){
        return false;
    }
    m_lastConnectionWasTargetMode = true;
    ApplyBreakPoints();
    return true;
}

bool X2WinRpcAdapter::Execute(const std::string& path, const LaunchConfigurations& configs){
    return ExecuteWithArgs(path, "", "", configs);
}

bool X2WinRpcAdapter::ConnectToDebugServer(const std::string &server, std::uint32_t port){
    if(!ConnectSocket(server, (uint16_t)port)) return false;

    X2WinEnvelopeBuffer response = CallSync(x2win::Body_ConnectServerRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateConnectServerRequest(b).Union();
    });
    const auto* resp = response.BodyAs<x2win::ConnectServerResponse>();
    bool success = resp && resp->success();
    if(!success)
        LogWarn("X2WinRpcAdapter::ConnectToDebugServer: stub rejected connect_server_request (stub not in server mode?)");
    else
        m_lastConnectionWasTargetMode = false;
    
    return success;
}

bool X2WinRpcAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
  const std::string& workingDir, const LaunchConfigurations& configs){
    if(m_lastConnectionWasTargetMode){
        LogWarn("X2WinRpcAdapter::ExecuteWithArgs: refusing to launch -- last connection was "
            "target mode, which only ever supports its original debuggee.\n");
        return false;
    }
    if(!ConnectFromSettings()){
        LogWarn("X2WinRpcAdapter::ExecuteWithArgs: failed to connect to stub");
        return false;
    }

    X2WinEnvelopeBuffer response = CallSync(x2win::Body_LaunchRequest,
        [&path, &args, &workingDir](flatbuffers::FlatBufferBuilder& b){
            auto pathOff = b.CreateString(path);
            auto argsOff = b.CreateString(args);
            auto workingDirOff = b.CreateString(workingDir);
            return x2win::CreateLaunchRequest(b, pathOff, argsOff, workingDirOff).Union();
        });
    const auto* resp = response.BodyAs<x2win::LaunchResponse>();
    bool success = resp && resp->success();
    if(!success)
        LogWarn("X2WinRpcAdapter::ExecuteWithArgs: stub failed to launch \"%s\"", path.c_str());
    
    ApplyBreakPoints();
    return success;
}

// TCP is a byte stream, not a message stream: a single Recv() call may return fewer bytes than
// requested. Loop until exactly `size` bytes have been collected (or the connection dies).
bool X2WinRpcAdapter::RecvExact(void* buffer, size_t size){
    uint8_t* p = (uint8_t*) buffer;
    size_t received = 0;
    while(received < size){
        intptr_t n = m_socket.Recv((char*)p+received, (int32_t)(size-received));
        if(n <= 0){
            LogWarn("X2WinRpcAdapter: RecvExact failed after %zu/%zu bytes (n=%lld, %s)",
                received, size, (long long)n, n == 0 ? "connection closed" : "socket error");
            return false; // 0 connection cloased, <0 error
        }
        received += (size_t) n;
    }
    return true;
}

bool X2WinRpcAdapter::SendExact(const void *buffer, size_t size){
    const uint8_t* p = (const uint8_t*) buffer;
    size_t sent = 0;
    while (sent < size) {
        intptr_t n = m_socket.Send((char*)p + sent, (int32_t)(size - sent));
        if(n <= 0){
            LogWarn("X2WinRpcAdapter: SendExact failed after %zu/%zu bytes (n=%lld)",
                sent, size, (long long)n);
            return false;
        }
        sent += (size_t) n;
    }
    return true;
}

// Sends one Request frame and blocks the calling thread until ReaderLoop() receives the
// matching Response (matched by requestId) and fulfills the promise registered below.
// Multiple concurrent callers each get their own request_id/promise, so a slow response to one
// call never blocks another call's response from being delivered.
X2WinEnvelopeBuffer X2WinRpcAdapter::CallSync(x2win::Body bodyType,
    const std::function<flatbuffers::Offset<void>(flatbuffers::FlatBufferBuilder&)>& buildBody){
    uint64_t requestId = m_nextRequestId++;

    // Bottom-up construction: the body table (built by the caller's callback) has to be
    // finished before the Envelope that wraps it, so both have to share this one builder.
    flatbuffers::FlatBufferBuilder builder;
    flatbuffers::Offset<void> bodyOffset = buildBody(builder);
    auto envelope = x2win::CreateEnvelope(builder, requestId, bodyType, bodyOffset);
    builder.Finish(envelope);

    std::promise<X2WinEnvelopeBuffer> promise;
    std::future<X2WinEnvelopeBuffer> future = promise.get_future();

    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingRequests[requestId] = std::move(promise);
    }

    std::vector<uint8_t> frame;
    uint32_t bodyLen = (uint32_t)builder.GetSize();
    for(int i = 0; i < 4; i++){
        frame.push_back((bodyLen >> (i*8)) & 0xff);
    }
    const uint8_t* bufPtr = builder.GetBufferPointer();
    frame.insert(frame.end(), bufPtr, bufPtr + builder.GetSize());

    // Unconditional, not just on failure: this is the only way to tell "we're stuck waiting for
    // a response that's never coming" (send succeeded, future.get() below just never returns)
    // apart from a plain teardown/failure -- without this, a hang below is indistinguishable
    // from "nothing happened yet" in the log. LogInfo, not LogDebug -- the Log panel filters
    // Debug-level messages out by default, which would make this call invisible right when we
    // need it most.
    LogInfo("X2WinRpcAdapter::CallSync: sending request_id=%llu body_type=%d",
        (unsigned long long)requestId, (int)bodyType);

    {
        std::lock_guard<std::mutex> lock(m_sendMutex);
        if(!SendExact(frame.data(), frame.size())){
            LogWarn("X2WinRpcAdapter::CallSync: failed to send request_id=%llu body_type=%d, treating as failed call",
                (unsigned long long)requestId, (int)bodyType);
            std::lock_guard<std::mutex> pendingLock(m_pendingMutex);
            m_pendingRequests.erase(requestId);
            return X2WinEnvelopeBuffer();
        }
    }

    X2WinEnvelopeBuffer response = future.get();
    LogInfo("X2WinRpcAdapter::CallSync: received response for request_id=%llu",
        (unsigned long long)requestId);
    return response;
}

// Dedicated socket-reader loop, run on m_readerThread. Never used for a "write then read"
// call -- it just pulls frames forever and dispatches them, so unsolicited Event frames can
// arrive at any time, even while some other call is waiting inside CallSync() above.
void X2WinRpcAdapter::ReaderLoop(){
    while (true) {
        uint8_t lenBuf[4];
        if(!RecvExact(lenBuf, 4)){
            LogInfo("X2WinRpcAdapter::ReaderLoop: failed to read frame length prefix, exiting reader loop");
            break;
        }
        uint32_t bodyLen = (uint32_t)lenBuf[0] | ((uint32_t)lenBuf[1] << 8) | ((uint32_t)lenBuf[2] << 16) | ((uint32_t)lenBuf[3] << 24);

        X2WinEnvelopeBuffer envelopeBuf;
        envelopeBuf.bytes.resize(bodyLen);
        if(!RecvExact(envelopeBuf.bytes.data(), bodyLen)){
            LogWarn("X2WinRpcAdapter::ReaderLoop: failed to read %u-byte frame body, exiting reader loop", bodyLen);
            break;
        }

        // Unlike Protobuf's ParseFromArray, FlatBuffers does no validation on access by default --
        // GetEnvelope() below just reinterprets these bytes as a table, and reading fields out of
        // a truncated/corrupted buffer is an out-of-bounds read, not a clean failure. Verifier is
        // what actually plays ParseFromArray's role here: walking the buffer to confirm every
        // offset/vector/string is in-bounds before anything touches it.
        flatbuffers::Verifier verifier(envelopeBuf.bytes.data(), envelopeBuf.bytes.size());
        if(!x2win::VerifyEnvelopeBuffer(verifier)){
            // A verify failure here almost always means the length-prefixed framing has desynced
            // (e.g. an unsynchronized/partial Send() on the other end split a frame) -- everything
            // received after this point on this connection is suspect until reconnecting.
            LogWarn("X2WinRpcAdapter::ReaderLoop: failed to verify %u-byte envelope -- protocol framing "
                "may be desynced, treating connection as unreliable", bodyLen);
            continue;
        }

        const x2win::Envelope* envelope = envelopeBuf.Get();

        if(envelope->body_type() == x2win::Body_TargetStoppedEvent){
            const auto* evt = envelope->body_as<x2win::TargetStoppedEvent>();
            BNDebugStopReason reason = (evt->reason() == x2win::StopReason_BREAKPOINT) ? DebugStopReason::Breakpoint
                                        : (evt->reason() == x2win::StopReason_SINGLE_STEP) ? DebugStopReason::SingleStep
                                        : (evt->reason() == x2win::StopReason_INITIAL_BREAKPOINT) ? DebugStopReason::InitialBreakpoint
                                        : DebugStopReason::UnknownReason;

            LogInfo("X2WinRpcAdapter::ReaderLoop: received TargetStoppedEvent reason=%d address=0x%llx",
                (int)evt->reason(), (unsigned long long)evt->address());

            m_lastStopReason = reason;
            m_lastStopAddress = evt->address();

            // Second chance for any breakpoint that couldn't resolve right after Attach/Launch/Connect
            // (module list not populated yet at that point) -- by the time any stop event arrives, the
            // module list is guaranteed complete.
            ApplyBreakPoints();

            DebuggerEvent event;
            event.type = AdapterStoppedEventType;
            event.data.targetStoppedData.reason = reason;
            PostDebuggerEvent(event);
            continue;
        }

        // Otherwise this is a reply to something CallSync() is blocked waiting on.
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        auto it = m_pendingRequests.find(envelope->request_id());
        if(it != m_pendingRequests.end()){
            it->second.set_value(std::move(envelopeBuf));
            m_pendingRequests.erase(it);
        }else{
            // No CallSync() is waiting on this request_id -- either a duplicate/late response, or
            // (more likely if this shows up unexpectedly) evidence of the framing desync described
            // above: bytes from a corrupted frame happened to parse into a plausible-looking envelope.
            LogWarn("X2WinRpcAdapter::ReaderLoop: received response for unknown request_id=%llu body_type=%d, dropping",
                (unsigned long long)envelope->request_id(), (int)envelope->body_type());
        }
    }
}

// Simplest example of the repeating "send request, decode response" shape most methods follow:
// the reply payload is just the architecture string's raw bytes.
std::string X2WinRpcAdapter::GetTargetArchitecture(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_GetTargetArchRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetTargetArchRequest(b).Union();
    });
    const auto* resp = response.BodyAs<x2win::GetTargetArchResponse>();
    return (resp && resp->architecture()) ? resp->architecture()->str() : std::string();
}

// --- Lifecycle ---
bool X2WinRpcAdapter::Detach(){
    LogInfo("X2WinRpcAdapter::Detach: called");
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_DetachRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateDetachRequest(b).Union();
    });
    const auto* resp = response.BodyAs<x2win::DetachResponse>();
    bool success = resp && resp->success();
    if(!success)
        LogWarn("X2WinRpcAdapter::Detach: stub reported failure");

    TeardownConnection();

    DebuggerEvent event;
    event.type = DetachedEventType;
    PostDebuggerEvent(event);

    return success;
}

bool X2WinRpcAdapter::Quit(){
    LogInfo("X2WinRpcAdapter::Quit: called");
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_QuitRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateQuitRequest(b).Union();
    });
    const auto* resp = response.BodyAs<x2win::QuitResponse>();
    bool success = resp && resp->success();
    if(!success)
        LogWarn("X2WinRpcAdapter::Quit: stub reported failure");

    TeardownConnection();

    DebuggerEvent event;
    event.type = TargetExitedEventType;
    event.data.exitData.exitCode = 0;
    PostDebuggerEvent(event);

    return success;
}

std::vector<DebugProcess> X2WinRpcAdapter::GetProcessList(){
    if(!m_connected){
        LogWarn("X2WinRpcAdapter::GetProcessList: not connected -- connect to the debug server first");
        return {};
    }

    X2WinEnvelopeBuffer response = CallSync(x2win::Body_GetProcessListRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetProcessListRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::GetProcessListResponse>();

    std::vector<DebugProcess> result;
    if(resp && resp->processes()){
        for(const auto* p : *resp->processes()){
            result.emplace_back(p->pid(), p->name() ? p->name()->str() : std::string());
        }
    }

    LogDebug("X2WinRpcAdapter::GetProcessList: got %zu process(es)", result.size());
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
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_SetBreakpointRequest, [address](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateSetBreakpointRequest(b, address, x2win::BreakpointType_SOFTWARE).Union();
    });

    const auto* resp = response.BodyAs<x2win::SetBreakpointResponse>();
    if(!resp || !resp->success()){
        LogWarn("X2WinRpcAdapter::AddBreakpoint: stub rejected breakpoint at 0x%llx", (unsigned long long)address);
        return DebugBreakpoint();
    }

    DebugBreakpoint bp(address, (unsigned long)resp->breakpoint_id(), true, SoftwareBreakpoint);
    m_breakpoints.push_back(bp);

    return bp;
}
DebugBreakpoint X2WinRpcAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type){
    // DebuggerBreakpoints::Apply() replays every breakpoint BN core already knows about as soon as
    // CreateDebugAdapter() creates/reuses this adapter -- which happens BEFORE Attach()/
    // ExecuteWithArgs()/Connect() has actually opened the socket. Trying to resolve+send at that
    // point just fails silently (not connected yet), and the breakpoint never makes it to a freshly
    // (re)connected stub -- this is exactly what was happening after a host-initiated disconnect +
    // stub restart. Stage it instead; ApplyBreakpoints() flushes the staged list for real once
    // connected. This has to happen here, at the ModuleNameAndOffset level, not in the uintptr_t
    // overload above -- module+offset is the only form that can still be resolved after a later
    // reconnect, once ResolveModuleAddress()/GetModuleList() actually works again.
    if(!m_connected){
        if(std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end()){
            m_pendingBreakpoints.push_back(address);
        }
        return DebugBreakpoint();
    }
    
    uint64_t resolved = 0;
    if(!ResolveModuleAddress(address, resolved)){
        // Connected, but the module isn't loaded/resolvable yet (e.g. ApplyBreakpoints() ran right
        // after Launch succeeded, before the stub's module list reflects the new process). Re-stage
        // rather than dropping it -- the next ApplyBreakpoints() call (see ReaderLoop()'s handling of
        // the initial-breakpoint stop event) gets another chance once modules are guaranteed populated.
        if(std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end()){
            m_pendingBreakpoints.push_back(address);
        }
        LogWarn("X2WinRpcAdapter::AddBreakpoint: failed to resolve module \"%s\"+0x%llx",
            address.module.c_str(), (unsigned long long)address.offset);
        return DebugBreakpoint();
    }

    return AddBreakpoint(resolved, breakpoint_type);
}

void X2WinRpcAdapter::ApplyBreakPoints(){
    std::vector<ModuleNameAndOffset> pending;
    pending.swap(m_pendingBreakpoints);

    for(const auto& bp : pending){
        AddBreakpoint(bp);
    }
}

bool X2WinRpcAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint){
    for(auto it = m_pendingBreakpoints.begin(); it != m_pendingBreakpoints.end(); ++it){
        uint64_t resolved = 0;
        if(ResolveModuleAddress(*it, resolved) && resolved == breakpoint.m_address){
            m_pendingBreakpoints.erase(it);
            return true;
        }
    }
    
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_RemoveBreakpointRequest, [&breakpoint](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateRemoveBreakpointRequest(b, breakpoint.m_address).Union();
    });

    const auto* resp = response.BodyAs<x2win::RemoveBreakpointResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::RemoveBreakpoint: stub rejected removal at 0x%llx",
            (unsigned long long)breakpoint.m_address);
        return false;
    }

    auto it = std::find(m_breakpoints.begin(), m_breakpoints.end(), breakpoint);
    if(it != m_breakpoints.end()){
        m_breakpoints.erase(it);
    }

    return true;
}
std::vector<DebugBreakpoint> X2WinRpcAdapter::GetBreakpointList() const { return m_breakpoints;}

bool X2WinRpcAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size){ return false; }
bool X2WinRpcAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size){ return false; }
bool X2WinRpcAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size){ return false; }
bool X2WinRpcAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size){ return false; }


std::unordered_map<std::string, DebugRegister> X2WinRpcAdapter::ReadAllRegisters(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_ReadAllRegistersRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateReadAllRegistersRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::ReadAllRegistersResponse>();

    std::unordered_map<std::string, DebugRegister> result;
    if(resp && resp->registers()){
        for(const auto* r: * resp->registers()){
            std::string name = r->name() ? r->name()->str() : std::string();
            result.emplace(name, DebugRegister(name, r->value(), r->width(), r->register_index()));
        }
    }
    LogDebug("X2WinRpcAdapter::ReadAllRegisters: got %zu register(s)", result.size());
    return result;
}

DebugRegister X2WinRpcAdapter::ReadRegister(const std::string& reg){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_ReadRegisterRequest, [&reg](flatbuffers::FlatBufferBuilder& b){
        auto nameOff = b.CreateString(reg);
        return x2win::CreateReadRegisterRequest(b, nameOff).Union();
    });
    const auto* resp = response.BodyAs<x2win::ReadRegisterResponse>();
    if(!resp || !resp->success()){
        LogDebug("X2WinRpcAdapter::ReadRegister: stub doesn't reognize regiser \"%s\"", reg.c_str());
        return DebugRegister();
    }

    return DebugRegister(reg, resp->value(), resp->width(), resp->register_index());
}

bool X2WinRpcAdapter::WriteRegister(const std::string& reg, intx::uint512 value){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_WriteRegisterRequest, [&reg, value](flatbuffers::FlatBufferBuilder& b){
        auto nameOff = b.CreateString(reg);
        // Narrow the 512-bit value down to the 64 bits the wire format ( and every real X2win
        // register) actually needs
        uint64_t narrowed = (uint64_t)value;
        return x2win::CreateWriteRegisterRequest(b, nameOff, narrowed).Union();
    });

    const auto* resp = response.BodyAs<x2win::WriteRegisterResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::WriteRegister: sutb rejected write to \"%s\"", reg.c_str());
    }
    return success;
}
DataBuffer X2WinRpcAdapter::ReadMemory(std::uintptr_t address, std::size_t size){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_ReadMemoryRequest, [address, size](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateReadMemoryRequest(b, address, size).Union();
    });

    const auto* resp = response.BodyAs<x2win::ReadMemoryResponse>();
    if(!resp || !resp->success() || !resp->data()){
        // LogDebug, not LogWarn -- the analysis engine routinely probes unmapped addresses
        // (e.g. speculative reads past the end of a section), so this is expected to fire often
        // and would flood the Log pane at a higher severity.
        LogDebug("X2WinRpcAdapter::ReadMemory: failed to read 0x%zx bytes at 0x%llx",
            size, (unsigned long long)address);
        return DataBuffer();
    }

    return DataBuffer(resp->data()->data(), resp->data()->size());
}
bool X2WinRpcAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer){ return false; }

// Extracts the filename portion of a path, recognizing both '/' and '\' as separators.
// Needed because module names come over the wire in Windows path format (backslashes), but
// DebugModule::GetPathBaseName() (core/debugadapter.cpp) only recognizes '\' when *this* process
// is itself compiled for Windows -- X2WinRpcAdapter is the first adapter where BN core can run on
// a different OS (macOS) than the debug target (always Windows), so that assumption breaks here.
// Extracting the basename ourselves, up front, sidesteps the problem entirely.
static std::string ExtractFileName(const std::string& path){
    size_t pos = path.find_last_of("/\\");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

// --- Modules ---

std::vector<DebugModule> X2WinRpcAdapter::GetModuleList(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_GetModuleListRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetModuleListRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::GetModuleListResponse>();
    std::vector<DebugModule> result;
    if(resp && resp->modules()){
        for(const auto* m : *resp->modules()){
            std::string name = m->name() ? m->name()->str() : std::string();
            std::string shortName = ExtractFileName(name);
            result.emplace_back(name, shortName, (std::uintptr_t)m->base(), (std::size_t)m->size(), true);
            LogDebug("X2WinRpcAdapter::GetModuleList: module \"%s\" base=0x%llx size=0x%llx",
                name.c_str(), (unsigned long long)m->base(), (unsigned long long)m->size());
        }
    }
    if(result.empty())
        LogWarn("X2WinRpcAdapter::GetModuleList: stub returned no modules -- rebase to the remote base will not happen");
    return result;
}

// --- Execution control ---
DebugStopReason X2WinRpcAdapter::StopReason(){ return m_lastStopReason.load(); }
uint64_t X2WinRpcAdapter::ExitCode(){ return 0; }
bool X2WinRpcAdapter::BreakInto(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_BreakIntoRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateBreakIntoRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::BreakIntoResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::BreakInto: stub reported failure");
    }else{
        DebuggerEvent event;
        event.type = ResumeEventType;
        PostDebuggerEvent(event);
    }
    return success;
}
bool X2WinRpcAdapter::Go(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_GoRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGoRequest(b).Union();
    });
    const auto* resp = response.BodyAs<x2win::GoResponse>();
    bool success = resp && resp->success();
    if(!success)
        LogWarn("X2WinRpcAdapter::Go: stub reported failure");
    return success;
}
bool X2WinRpcAdapter::StepInto(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_StepIntoRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateStepIntoRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::StepIntoResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::StepInto: stub reported failure");
    }else{
        DebuggerEvent event;
        event.type = StepIntoEventType;
        PostDebuggerEvent(event);
    }
    return success;
}
bool X2WinRpcAdapter::StepOver(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_StepOverRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateStepOverRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::StepOverResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::StepOver: stub reported failure");
    }else{
        DebuggerEvent event;
        event.type = StepOverEventType;
        PostDebuggerEvent(event);
    }
    return success;
}

std::string X2WinRpcAdapter::InvokeBackendCommand(const std::string& command){ return ""; }
uint64_t X2WinRpcAdapter::GetInstructionOffset(){ return m_lastStopAddress.load(); }
bool X2WinRpcAdapter::SupportFeature(DebugAdapterCapacity feature){
    switch(feature){
        // StepOver/Go/BreakInto/GetModuleList are all wired over RPC to the stub -- report the
        // capabilities that actually correspond to real, implemented functionality so
        // DebuggerController uses them instead of silently falling back to its software
        // emulation paths (see StepOverAndWaitInternal() in debuggercontroller.cpp).
        case DebugAdapterSupportStepOver:
            return true;
        case DebugAdapterSupportModules:
            return true;
        // Not yet implemented on the stub side.
        case DebugAdapterSupportStepReturn:
        case DebugAdapterSupportStepOverReverse:
        case DebugAdapterSupportThreads:
        case DebugAdapterSupportTTD:
        default:
            return false;
    }
}

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

    settings->RegisterSetting("common.inputFile", R"({
    "title" : "Input File",
    "type" : "string",
    "default" : "",
    "description" : "Input file to use to find the base address of the binary view",
    "readOnly" : false,
    "uiSelectionAction" : "file"
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

    settings->RegisterSetting("launch.executablePath",
    R"({
    "title" : "Executable Path",
    "type" : "string",
    "default" : "",
    "description" : "Windows-side path of the executable for the stub to launch (e.g. C:\\\\path\\\\to\\\\target.exe) -- NOT the local path of the analyzed binary.",
    "readOnly" : false
    })");

    settings->RegisterSetting("launch.workingDirectory",
    R"({
    "title" : "Working Directory",
    "type" : "string",
    "default" : "",
    "description" : "Windows-side working directory to launch the target in.",
    "readOnly" : false
    })");

    settings->RegisterSetting("launch.commandLineArguments",
    R"({
    "title" : "Command Line Arguments",
    "type" : "string",
    "default" : "",
    "description" : "Command line arguments to pass to the target",
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
    LogInfo("X2WinRpcAdapter::TeardownConnection: closing connection to stub");
    m_socket.Kill();
    if(m_readerThread.joinable()){
        m_readerThread.join();
    }
    m_connected = false;
    // Every entry in m_breakpoints was set on the stub session this connection belonged to --
    // once that connection is gone, none of them are trustworthy anymore: a reconnect might land
    // on a brand-new stub session (server mode, or a restarted target-mode stub) that's never
    // heard of them, or might land back on the SAME persisted session (target mode's reconnect
    // support) where they're still genuinely set. Either way this cache can't tell which case it
    // is, and the *authoritative* list lives in DebuggerBreakpoints (core/debuggerstate.cpp)
    // anyway -- it re-sends every known breakpoint via ApplyBreakpoints() on the next successful
    // connect regardless. Clearing this cache here avoids the alternative: a stale m_breakpoints
    // entry surviving a reconnect, sitting alongside a *second*, newly (re-)applied entry for the
    // same address once the resend happens -- RemoveBreakpoint() would then find one but not the
    // other, or (if a pending-staged duplicate wins the race) skip the real stub-side removal
    // entirely.
    m_breakpoints.clear();
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