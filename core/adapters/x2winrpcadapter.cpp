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
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

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
        PostLaunchFailure("Connection failed", "X2WinRpcAdapter::Attach: failed to connect to stub");
        return false;
    }

    X2WinEnvelopeBuffer response = CallSync(x2win::Body_AttachRequest, [pid](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateAttachRequest(b, pid).Union();
    });
    const auto* resp = response.BodyAs<x2win::AttachResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::Attach: stub rejected attach to pid %u", (unsigned)pid);
        // DebuggerController::AttachAndWaitInternal() already posted an optimistic
        // LaunchEventType (-> DebugAdapterRunningStatus) before calling us -- if we just return
        // false here without correcting that, the controller is left believing a nonexistent
        // target is running forever (dbg.running stays true, nothing ever calls NotifyStopped()
        // since AttachAndWaitOnWorker() skips it for InternalError). Match the convention other
        // adapters use (e.g. GdbAdapter::Connect()) and post LaunchFailureEventType so
        // ApplyOwnStateForEvent() resets connection/execution status back to Invalid.
        PostLaunchFailure("Attach failed", fmt::format("stub rejected attach to pid {}", (unsigned)pid));
    }else
        m_lastConnectionWasTargetMode = false;

    ApplyBreakPoints();
    return success;
}

bool X2WinRpcAdapter::Connect(const std::string& server, std::uint32_t port){
    if(!ConnectSocket(server, (uint16_t) port)){
        PostLaunchFailure("Connection failed", fmt::format("X2WinRpcAdapter::Connect: failed to connect to {}:{}", server, port));
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

bool X2WinRpcAdapter::DisconnectDebugServer(){
    if(!m_connected){
        return true;
    }

    CallSync(x2win::Body_QuitRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateQuitRequest(b).Union();
    });

    LogInfo("X2WinRpcAdapter::DisconnectDebugServer: closing connection to stub");
    TeardownConnection();
    return true;
}

bool X2WinRpcAdapter::ExecuteWithArgs(const std::string& path, const std::string& args,
  const std::string& workingDir, const LaunchConfigurations& configs){
    if(m_lastConnectionWasTargetMode){
        LogWarn("X2WinRpcAdapter::ExecuteWithArgs: refusing to launch -- last connection was "
            "target mode, which only ever supports its original debuggee.");
        PostLaunchFailure("Launch failed",
            "X2WinRpcAdapter::ExecuteWithArgs: last connection was target mode, which only ever "
            "supports its original debuggee");
        return false;
    }
    if(!ConnectFromSettings()){
        LogWarn("X2WinRpcAdapter::ExecuteWithArgs: failed to connect to stub");
        PostLaunchFailure("Connection failed", "X2WinRpcAdapter::ExecuteWithArgs: failed to connect to stub");
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
    if(!success){
        LogWarn("X2WinRpcAdapter::ExecuteWithArgs: stub failed to launch \"%s\"", path.c_str());
        PostLaunchFailure("Launch failed", fmt::format("stub failed to launch \"{}\"", path));
    }

    ApplyBreakPoints();
    return success;
}

// See the declaration in x2winrpcadapter.h for why every Attach()/ExecuteWithArgs()/Connect()
// failure path needs to call this.
void X2WinRpcAdapter::PostLaunchFailure(const std::string& shortError, const std::string& error){
    DebuggerEvent event;
    event.type = LaunchFailureEventType;
    event.data.errorData.shortError = shortError;
    event.data.errorData.error = error;
    PostDebuggerEvent(event);
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
            if(evt->reason() == x2win::StopReason_EXITED){
                LogInfo("X2WinRpcAdapter::ReaderLoop: received TargetStoppedEvent reason=EXITED exit_code=%llu",
                    (unsigned long long)evt->exit_code());
                m_lastStopReason = DebugStopReason::ProcessExited;
                m_exitCode = evt->exit_code();

                DebuggerEvent event;
                event.type = TargetExitedEventType;
                event.data.exitData.exitCode = evt->exit_code();
                PostDebuggerEvent(event);
                continue;
            }
            BNDebugStopReason reason = (evt->reason() == x2win::StopReason_BREAKPOINT) ? DebugStopReason::Breakpoint
                                        : (evt->reason() == x2win::StopReason_SINGLE_STEP) ? DebugStopReason::SingleStep
                                        : (evt->reason() == x2win::StopReason_INITIAL_BREAKPOINT) ? DebugStopReason::InitialBreakpoint
                                        : (evt->reason() == x2win::StopReason_ACCESS_VIOLATION) ? DebugStopReason::AccessViolation
                                        : (evt->reason() == x2win::StopReason_CALCULATION) ? DebugStopReason::Calculation
                                        : (evt->reason() == x2win::StopReason_ILLEGAL_INSTRUCTION) ? DebugStopReason::IllegalInstruction
                                        : DebugStopReason::UnknownReason;

            LogInfo("X2WinRpcAdapter::ReaderLoop: received TargetStoppedEvent reason=%d address=0x%llx",
                (int)evt->reason(), (unsigned long long)evt->address());

            m_lastStopReason = reason;
            m_lastStopAddress = evt->address();

            // Second chance for any breakpoint that couldn't resolve right after Attach/Launch/Connect
            // (module list not populated yet at that point) -- by the time any stop event arrives, the
            // module list is guaranteed complete.
            //
            // This MUST NOT call ApplyBreakPoints() directly on this thread: flushing a pending
            // breakpoint can call CallSync() (AddBreakpoint()/AddHardwareBreakpoint() -> CallSync()),
            // which blocks until *this* ReaderLoop() reads the matching response frame. Called inline
            // from here, that response can never be read -- this thread is the only one that reads
            // frames, and it would be sitting inside CallSync() instead of back at the top of this
            // loop. That's a real, reproducible self-deadlock whenever a stop event arrives with a
            // non-empty pending list (e.g. a breakpoint re-staged because the module list wasn't
            // populated yet the first time around -- see AddBreakpoint(ModuleNameAndOffset) above).
            // Run the flush on its own thread instead, so this loop can get straight back to
            // RecvExact() and actually deliver the response that flush is waiting on. Guarded by
            // m_applyingBreakpoints so two stop events arriving close together don't spawn two
            // flushes racing on the same pending lists at once.
            bool expected = false;
            if(m_applyingBreakpoints.compare_exchange_strong(expected, true)){
                std::thread([this](){
                    ApplyBreakPoints();
                    m_applyingBreakpoints = false;
                }).detach();
            }

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

    // This thread is the only reader -- once it's exited (socket died/was killed), any request
    // still in m_pendingRequests can never get its response, and whatever thread is blocked in
    // CallSync()'s future.get() for it would hang forever without this. Most callers run on
    // whatever thread called into the adapter and naturally unwind once TeardownConnection() joins
    // this thread, but the breakpoint-flush thread ApplyBreakPoints() gets dispatched to (see the
    // TargetStoppedEvent handling above) is detached and isn't joined by anything -- it depends on
    // this to ever come back from CallSync() at all when the connection drops out from under it.
    // Same empty-envelope shape CallSync() already returns for a same-thread send failure, so every
    // existing caller's `if(!resp)`/`!resp->success()` check already treats this as a normal
    // rejected/failed call.
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    for(auto& [requestId, promise] : m_pendingRequests){
        promise.set_value(X2WinEnvelopeBuffer());
    }
    m_pendingRequests.clear();
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

    if(m_lastConnectionWasTargetMode){
        TeardownConnection();
    }else{
        ResetSessionState();
    }

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

    if(m_lastConnectionWasTargetMode){
        TeardownConnection();
    }else{
        ResetSessionState();
    }

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
std::vector<DebugThread> X2WinRpcAdapter::GetThreadList(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_GetThreadListRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetThreadListRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::GetThreadListResponse>();
    std::vector<DebugThread> result;
    if(resp && resp->threads()){
        for(const auto* t : *resp->threads()){
            // DebugThread has no ctor that takes is_frozen -- build with (tid, rip), then set
            // the field directly (m_isFrozen is a plain public bool, same as every other member).
            DebugThread thread((std::uint32_t)t->tid(), (std::uintptr_t)t->rip());
            thread.m_isFrozen = t->is_frozen();
            result.push_back(thread);
        }
    }
    LogDebug("X2WinRpcAdapter::GetThreadList: got %zu thread(s)", result.size());
    return result;
}

DebugThread X2WinRpcAdapter::GetActiveThread() const {
    // CallSync() isn't const (it does real socket I/O) but this override has to be -- same
    // const_cast workaround GdbMiAdapter::GetActiveThread() uses (core/adapters/gdbmiadapter.cpp).
    auto* self = const_cast<X2WinRpcAdapter*>(this);
    X2WinEnvelopeBuffer response = self->CallSync(x2win::Body_GetActiveThreadIdRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetActiveThreadIdRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::GetActiveThreadIdResponse>();
    std::uint32_t tid = resp ? resp->tid() : 0;

    // See the comment on GetActiveThreadIdResponse in x2win.fbs -- rip comes from the last
    // reported stop, not a separate RPC round trip.
    return DebugThread(tid, (std::uintptr_t)self->GetInstructionOffset());
}

std::uint32_t X2WinRpcAdapter::GetActiveThreadId() const {
    auto* self = const_cast<X2WinRpcAdapter*>(this);
    X2WinEnvelopeBuffer response = self->CallSync(x2win::Body_GetActiveThreadIdRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetActiveThreadIdRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::GetActiveThreadIdResponse>();
    return resp ? resp->tid() : 0;
}

bool X2WinRpcAdapter::SetActiveThread(const DebugThread& thread){
    return SetActiveThreadId(thread.m_tid);
}

bool X2WinRpcAdapter::SetActiveThreadId(std::uint32_t tid){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_SetActiveThreadIdRequest, [tid](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateSetActiveThreadIdRequest(b, tid).Union();
    });

    const auto* resp = response.BodyAs<x2win::SetActiveThreadIdResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::SetActiveThreadId: stub rejected switch to tid %u", (unsigned)tid);
    }
    return success;
}

bool X2WinRpcAdapter::SuspendThread(std::uint32_t tid){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_SuspendThreadRequest, [tid](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateSuspendThreadRequest(b, tid).Union();
    });

    const auto* resp = response.BodyAs<x2win::SuspendThreadResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::SuspendThread: stub rejected suspending tid %u", (unsigned)tid);
    }
    return success;
}

bool X2WinRpcAdapter::ResumeThread(std::uint32_t tid){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_ResumeThreadRequest, [tid](flatbuffers::FlatBufferBuilder&b){
        return x2win::CreateResumeThreadRequest(b, tid).Union();
    });

    const auto* resp = response.BodyAs<x2win::ResumeThreadResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::ResumeThread: stub rejected resuming tid %u", (unsigned)tid);
    }
    return success;
}


std::vector<DebugFrame> X2WinRpcAdapter::GetFramesOfThread(std::uint32_t tid){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_GetFramesOfThreadRequest, [tid](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetFramesOfThreadRequest(b, tid).Union();
    });

    const auto* resp = response.BodyAs<x2win::GetFramesOfThreadResponse>();
    std::vector<DebugFrame> result;
    if(resp && resp->frames()){
        for(const auto* f: *resp->frames()){
            std::string functionName = f->function_name() ? f->function_name()->str() : std::string();
            std::string module = f->module_() ? f->module_()->str() : std::string("<unknown>");
            result.emplace_back((size_t)f->index(), f->pc(), f->sp(), f->fp(), functionName, f->function_start(), module);
        }
    }
    LogDebug("X2WinRpcAdapter::GetFramesOfThread: got %zu frame(s) for tid %u", result.size(), (unsigned)tid);
    return result;
}

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
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
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
        {
            std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
            if(std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end()){
                m_pendingBreakpoints.push_back(address);
            }
        }
        LogWarn("X2WinRpcAdapter::AddBreakpoint: failed to resolve module \"%s\"+0x%llx",
            address.module.c_str(), (unsigned long long)address.offset);
        return DebugBreakpoint();
    }

    DebugBreakpoint bp = AddBreakpoint(resolved, breakpoint_type);
    if(!bp.m_is_active){
        // ResolveModuleAddress() succeeded (GetModuleList() answered with a real module entry) but
        // the stub still rejected the actual SetBreakpointRequest -- reproduced via Restart(): the
        // reused adapter's CreateDebugAdapter() replays every known breakpoint (DebuggerBreakpoints::
        // Apply()) before the restart's own Launch() RPC has even run, while the stub is between
        // debuggees (old one just Quit(), new one not launched yet). GetModuleList() on the stub
        // still answers with the just-terminated process's module info at that moment, so resolution
        // "succeeds" against a stale/dead target and the write is rejected -- with no re-staging,
        // this breakpoint would then be silently dropped for good, with no second chance once the
        // new process is actually up (unlike the ResolveModuleAddress()-failed case just above,
        // which already re-stages). Re-stage here too so the same second-chance flush (ReaderLoop()'s
        // TargetStoppedEvent handling) picks it up once the restarted target's own initial stop
        // event arrives and GetModuleList() reflects the real, current process.
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        if(std::find(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), address) == m_pendingBreakpoints.end()){
            m_pendingBreakpoints.push_back(address);
        }
    }
    return bp;
}

void X2WinRpcAdapter::ApplyBreakPoints(){
    // NOTE: if a caller reaches this from ReaderLoop()'s own thread (see its TargetStoppedEvent
    // handling), it must NOT still be running inline there -- AddBreakpoint()/AddHardwareBreakpoint()
    // below can call CallSync(), which blocks until ReaderLoop() reads the matching response. Called
    // from ReaderLoop() itself, that response can never arrive (this thread is the one that would
    // have to read it), so it deadlocks forever. ReaderLoop() defers to a separate thread instead of
    // calling this directly -- see there.
    std::vector<ModuleNameAndOffset> pending;
    std::vector<PendingHardwareBreakpoint> pendingHw;
    {
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        pending.swap(m_pendingBreakpoints);
        pendingHw.swap(m_pendingHardwareBreakpoints);
    }

    for(const auto& bp : pending){
        AddBreakpoint(bp);
    }

    for(const auto& hwbp : pendingHw){
        if(hwbp.isRelative){
            AddHardwareBreakpoint(hwbp.location, hwbp.type, hwbp.size);
        } else {
            AddHardwareBreakpoint(hwbp.address, hwbp.type, hwbp.size);
        }
    }
}

bool X2WinRpcAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint){
    {
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        for(auto it = m_pendingBreakpoints.begin(); it != m_pendingBreakpoints.end(); ++it){
            uint64_t resolved = 0;
            if(ResolveModuleAddress(*it, resolved) && resolved == breakpoint.m_address){
                m_pendingBreakpoints.erase(it);
                return true;
            }
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

bool X2WinRpcAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size){
    if(!m_connected){
        // Not connected yet (Apply() firing before Attach()/ExecuteWithArgs()/Connect()) -- stage
        // it, same reason AddBreakpoint(ModuleNameAndOffset) stages below.
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        PendingHardwareBreakpoint pending(address, type, size);
        if(std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
            == m_pendingHardwareBreakpoints.end()){
            m_pendingHardwareBreakpoints.push_back(pending);
        }
        return true;
    }

    X2WinEnvelopeBuffer response = CallSync(x2win::Body_SetHardwareBreakpointRequest,[address, type, size](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateSetHardwareBreakpointRequest(b, address, (x2win::BreakpointType)type, (uint8_t)size).Union();
    });

    const auto* resp = response.BodyAs<x2win::SetHardwareBreakpointResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::AddHardwareBreakpoint: stub rejected hw breakpoint at 0x%llx",
            (unsigned long long)address);
    }
    return success;
}
bool X2WinRpcAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size){
    // Still-staged (never actually sent) -- just drop it locally, same shape as the pending-list
    // check RemoveBreakpoint() does for software breakpoints.
    {
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        PendingHardwareBreakpoint pending(address, type, size);
        auto it = std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending);
        if(it != m_pendingHardwareBreakpoints.end()){
            m_pendingHardwareBreakpoints.erase(it);
            return true;
        }
    }

    if(!m_connected){
        return false;
    }

    X2WinEnvelopeBuffer response = CallSync(x2win::Body_RemoveHardwareBreakpointRequest,
        [address, type, size](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateRemoveHardwareBreakpointRequest(b, address, (x2win::BreakpointType)type, (uint8_t)size).Union();
    });

    const auto* resp = response.BodyAs<x2win::RemoveHardwareBreakpointResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::RemoveHardwareBreakpoint: stub rejected removal at 0x%llx",
            (unsigned long long)address);
    }
    return success;
}
bool X2WinRpcAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size){
    if(!m_connected){
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        PendingHardwareBreakpoint pending(location, type, size);
        if(std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
            == m_pendingHardwareBreakpoints.end()){
            m_pendingHardwareBreakpoints.push_back(pending);
        }
        return true;
    }

    uint64_t resolved = 0;
    if(!ResolveModuleAddress(location, resolved)){
        // Connected, but not resolvable yet (module not loaded) -- re-stage, same as
        // AddBreakpoint(ModuleNameAndOffset)'s equivalent branch.
        {
            std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
            PendingHardwareBreakpoint pending(location, type, size);
            if(std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
                == m_pendingHardwareBreakpoints.end()){
                m_pendingHardwareBreakpoints.push_back(pending);
            }
        }
        LogWarn("X2WinRpcAdapter::AddHardwareBreakpoint: failed to resolve module \"%s\"+0x%llx",
            location.module.c_str(), (unsigned long long)location.offset);
        return false;
    }

    return AddHardwareBreakpoint(resolved, type, size);
}
bool X2WinRpcAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size){
    {
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        PendingHardwareBreakpoint pending(location, type, size);
        auto it = std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending);
        if(it != m_pendingHardwareBreakpoints.end()){
            m_pendingHardwareBreakpoints.erase(it);
            return true;
        }
    }

    uint64_t resolved = 0;
    if(!ResolveModuleAddress(location, resolved)){
        return false;
    }

    return RemoveHardwareBreakpoint(resolved, type, size);
}


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
bool X2WinRpcAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_WriteMemoryRequest, [address, &buffer](flatbuffers::FlatBufferBuilder& b){
        auto dataOff = b.CreateVector(reinterpret_cast<const uint8_t*>(buffer.GetData()), buffer.GetLength());
        return x2win::CreateWriteMemoryRequest(b, address, dataOff).Union();
    });
    
    const auto* resp = response.BodyAs<x2win::WriteMemoryResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::WriteMemory: stub rejected write of %zu byte(s) at 0x%llx",
            buffer.GetLength(), (unsigned long long)address);
    }
    return success;
}

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

std::vector<DebugMemoryRegion>X2WinRpcAdapter::GetMemoryMap(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_GetMemoryMapRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateGetMemoryMapRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::GetMemoryMapResponse>();
    std::vector<DebugMemoryRegion> result;
    if(resp && resp->regions()){
        for(const auto* r : *resp->regions()){
            std::string name = r->name() ? r->name()->str() : std::string();
            result.emplace_back((std::uintptr_t)r->start(), (std::size_t)r->size(), name,
            r->read(), r->write(), r->execute(), r->shared());
        }
    }
    
    LogDebug("X2WinRpcAdapter::GetMemoryMap: got %zu region(s)", result.size());
    return result;
}

// --- Execution control ---
DebugStopReason X2WinRpcAdapter::StopReason(){ return m_lastStopReason.load(); }
uint64_t X2WinRpcAdapter::ExitCode(){
    return m_exitCode.load();
}
bool X2WinRpcAdapter::BreakInto(){
    if(m_lastStopReason.load() == DebugStopReason::ProcessExited){
        // Nothing to break into -- the process is already gone (ReaderLoop()'s StopReason_EXITED
        // handling sets this). RequestInterrupt() (core/debuggercontroller.cpp) fires BreakInto()
        // unconditionally before every Detach()/Quit(), regardless of whether the target is still
        // running -- skip the round trip instead of logging a "stub reported failure" that isn't
        // actually telling us anything new at that point.
        return false;
    }
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
    else{
        DebuggerEvent event;
        event.type = ResumeEventType;
        PostDebuggerEvent(event);
    }
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

bool X2WinRpcAdapter::StepReturn(){
    X2WinEnvelopeBuffer response = CallSync(x2win::Body_StepReturnRequest, [](flatbuffers::FlatBufferBuilder& b){
        return x2win::CreateStepReturnRequest(b).Union();
    });

    const auto* resp = response.BodyAs<x2win::StepReturnResponse>();
    bool success = resp && resp->success();
    if(!success){
        LogWarn("X2WinRpcAdapter::StepReturn: stub reported failure");
    }else{
        DebuggerEvent event;
        event.type = StepReturnEventType;
        PostDebuggerEvent(event);
    }
    return success;
}

std::string X2WinRpcAdapter::InvokeBackendCommand(const std::string& command){ return ""; }
uint64_t X2WinRpcAdapter::GetInstructionOffset(){ return m_lastStopAddress.load(); }
uint64_t X2WinRpcAdapter::GetStackPointer(){
    std::string spRegistername = (GetTargetArchitecture() == "x86") ? "esp" : "rsp";
    return (uint64_t)ReadRegister(spRegistername).m_value;
}
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
        case DebugAdapterSupportThreads:
            return true;
        case DebugAdapterSupportStepReturn:
            return true;
        // Not yet implemented on the stub side.
        case DebugAdapterSupportStepOverReverse:
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
    ResetSessionState();
}

void X2WinRpcAdapter::ResetSessionState(){
    // Every entry here was set on (or is a leftover of) the debuggee this connection was just
    // talking to -- once that debuggee is gone (Detach/Quit) or the connection itself dies, none
    // of it is trustworthy for whatever comes next: a reconnect might land on a brand-new stub
    // session that's never heard of these breakpoints, or a same-connection Attach()/Launch() might
    // target a completely different process where these addresses/stop info mean nothing. The
    // *authoritative* breakpoint list lives in DebuggerBreakpoints (core/debuggerstate.cpp) anyway --
    // it re-sends every known breakpoint via ApplyBreakpoints() on the next successful connect
    // regardless, so clearing these caches here just avoids stale/duplicate entries, never loses
    // anything BN core still cares about.
    m_breakpoints.clear();
    {
        std::lock_guard<std::mutex> lock(m_pendingBreakpointsMutex);
        m_pendingBreakpoints.clear();
        m_pendingHardwareBreakpoints.clear();
    }

    m_lastStopReason = DebugStopReason::UnknownReason;
    m_lastStopAddress = 0;
    m_exitCode = 0;
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