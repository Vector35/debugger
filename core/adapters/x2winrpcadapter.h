/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "../debugadapter.h"
#include "../debugadaptertype.h"
#include "./socket.h"
#include <x2win_generated.h>
#include <thread>
#include <mutex>
#include <future>
#include <functional>
#include <atomic>
#include <unordered_map>

namespace BinaryNinjaDebugger {

	// A parsed x2win::Envelope is just a read-only view into a byte buffer (unlike a Protobuf
	// message, it owns no state of its own) -- something has to keep that buffer alive for as
	// long as the view is used. This pairs the two: Get()/BodyAs() are only valid while this
	// object (or a copy of its `bytes`) is alive. An empty `bytes` (default-constructed, or a
	// send failure in CallSync()) is a valid "no response" state -- Get()/BodyAs() return
	// nullptr rather than dereferencing a nonexistent buffer.
	struct X2WinEnvelopeBuffer
	{
		std::vector<uint8_t> bytes;

		const x2win::Envelope* Get() const
		{
			return bytes.empty() ? nullptr : x2win::GetEnvelope(bytes.data());
		}

		template <typename T>
		const T* BodyAs() const
		{
			const x2win::Envelope* envelope = Get();
			return envelope ? envelope->body_as<T>() : nullptr;
		}
	};

	class X2WinRpcAdapter : public DebugAdapter
	{
	private:
		Socket m_socket;
		bool m_connected = false;
		std::thread m_readerThread;
		std::atomic<DebugStopReason> m_lastStopReason {DebugStopReason::UnknownReason};
		std::atomic<uint64_t> m_lastStopAddress {0};
		std::atomic<uint64_t> m_exitCode{0};

		// True once Connect() (the one-shot "target mode" style entry point, UI: "Connect to Remote
		// Process") has succeeded -- deliberately NOT reset in TeardownConnection(), because the
		// whole point is to remember this *across* a disconnect. A target-mode stub only ever owns
		// the one debuggee it was started with; ExecuteWithArgs() checks this to refuse a Launch
		// (e.g. Restart's Quit-then-Launch sequence) before ever touching the network, instead of
		// trying to reconnect to a stub that has, by design, already exited.
		bool m_lastConnectionWasTargetMode = false;

		// request_id -> promise, fulfilled by ReaderLoop() when the matching RESPONSE arrives.
		// EVENT frames (id == 0) never go through this table; they go straight to PostDebuggerEvent().
		std::mutex m_pendingMutex;
		std::mutex m_sendMutex;
		std::unordered_map<uint64_t, std::promise<X2WinEnvelopeBuffer>> m_pendingRequests;
		std::vector<DebugBreakpoint> m_breakpoints;
		// Guards m_pendingBreakpoints/m_pendingHardwareBreakpoints: read/written both from whatever
		// thread calls AddBreakpoint()/RemoveBreakpoint() normally *and* from ReaderLoop()'s deferred
		// ApplyBreakPoints() flush below -- see ApplyBreakPoints()'s comment for why that flush can't
		// run on ReaderLoop()'s own thread.
		std::mutex m_pendingBreakpointsMutex;
		std::vector<ModuleNameAndOffset> m_pendingBreakpoints;
		std::vector<PendingHardwareBreakpoint> m_pendingHardwareBreakpoints;
		// Sequences ApplyBreakPoints() flushes so two TargetStoppedEvents arriving close together
		// don't spawn two flushes racing on the same pending lists at once.
		std::atomic<bool> m_applyingBreakpoints {false};
		std::atomic<uint64_t> m_nextRequestId {1};

		Ref<Settings> GetAdapterSettings() override;

		// Helper to resolve module+offset to an absolute address using GetModuleList().
		// Same purpose as LldbAdapter::ResolveModuleAddress; every adapter needs its own copy
		// since there is no shared base-class implementation for this.
		bool ResolveModuleAddress(const ModuleNameAndOffset& location, uint64_t& address);

		// Flushes every breakpoint staged by AddBreakpoint(ModuleNameAndOffset&) while not yet connected 
		// Called once Attach()/ExecuteWithArgs()/Connect() acutally connects (never from ConnectToDebugServer()
		// Because server mode has no debuggee yet, nothing to resolve against).
		void ApplyBreakPoints();

		bool ConnectSocket(const std::string& ip, uint16_t port);
		bool ConnectFromSettings();
		void TeardownConnection();
		void ResetSessionState();

		// Populates common.inputFile (used by DetectLoadedModule()/GetRemoteBase() to match this
		// adapter's GetModuleList() entries against the currently-open BinaryView, which is what
		// drives auto-rebase on connect) from the BinaryView's own file path, same convention as
		// every other adapter (see e.g. WindowsNativeAdapter::GenerateDefaultAdapterSettings) --
		// only when the setting has never been explicitly set for this resource.
		void GenerateDefaultAdapterSettings(BinaryView* data);

	public:
		X2WinRpcAdapter(BinaryView* data);
		virtual ~X2WinRpcAdapter();

		// --- Lifecycle ---
		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
		bool Attach(std::uint32_t pid) override;
		bool Connect(const std::string& server, std::uint32_t port) override;
		bool ConnectToDebugServer(const std::string& server, std::uint32_t port) override;
		bool DisconnectDebugServer() override;
		bool Detach() override;
		bool Quit() override;

		// --- Process / thread enumeration ---
		std::vector<DebugProcess> GetProcessList() override;
		std::uint32_t GetActivePID() override;
		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;
		bool SuspendThread(std::uint32_t tid) override;
		bool ResumeThread(std::uint32_t tid) override;

		std::vector<DebugFrame> GetFramesOfThread(std::uint32_t tid) override;

		// --- Breakpoints ---
		// Software breakpoints: the stub owns the VirtualProtectEx/write/restore dance, not us.
		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type = 0) override;
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;
		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;
		std::vector<DebugBreakpoint> GetBreakpointList() const override;

		// Hardware breakpoints / watchpoints
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;

		// --- Registers / memory ---
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& reg) override;
		bool WriteRegister(const std::string& reg, intx::uint512 value) override;
		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;

		// --- Modules / target info ---
		std::vector<DebugModule> GetModuleList() override;
		std::vector<DebugMemoryRegion> GetMemoryMap() override;
		std::string GetTargetArchitecture() override;

		// --- Execution control ---
		// Go/StepInto/StepOver only confirm the stub accepted the request. The resulting stop is
		// never inline in that response; it always arrives later as its own out-of-band Event.
		DebugStopReason StopReason() override;
		uint64_t ExitCode() override;
		bool BreakInto() override;
		bool Go() override;
		bool StepInto() override;
		bool StepOver() override;
		bool StepReturn() override;

		// --- Misc ---
		std::string InvokeBackendCommand(const std::string& command) override;
		uint64_t GetInstructionOffset() override;
		uint64_t GetStackPointer() override;
		bool SupportFeature(DebugAdapterCapacity feature) override;

		// Dedicated socket-reader loop (runs on m_readerThread): pulls frames forever, routes
		// RESPONSE by id to m_pendingRequests, routes EVENT (id == 0) to PostDebuggerEvent().
		void ReaderLoop();

		// --- Helper function ---
		bool RecvExact(void* buffer, size_t size);
		bool SendExact(const void* buffer, size_t size);

		// Unlike Protobuf, a FlatBuffers table can't be built standalone and handed over --
		// nested objects (strings, the request's own body table) must be constructed bottom-up
		// with the *same* FlatBufferBuilder that will go on to wrap them in the Envelope, which
		// only CallSync() itself owns. So callers hand CallSync() a builder function for just
		// their request body instead of a pre-built Envelope; CallSync() supplies the builder,
		// wraps the result in an Envelope with the request_id it assigns, and does the
		// send/wait/response bookkeeping exactly as before.
		X2WinEnvelopeBuffer CallSync(x2win::Body bodyType,
			const std::function<flatbuffers::Offset<void>(flatbuffers::FlatBufferBuilder&)>& buildBody);

	};


	class X2WinRpcAdapterType : public DebugAdapterType
	{
		static Ref<Settings> RegisterAdapterSettings();
	public:
		X2WinRpcAdapterType();
		static Ref<Settings> GetAdapterSettings();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	void InitX2WinRpcAdapterType();
}  // namespace BinaryNinjaDebugger
