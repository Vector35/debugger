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
#include <thread>
#include <mutex>
#include <future>
#include <atomic>
#include <unordered_map>

namespace BinaryNinjaDebugger {

	// Placeholder for a parsed RESPONSE payload. Replace with the generated protobuf
	// Response type once protocol/x2win.proto is wired into the build.
	struct Frame
	{
		std::vector<uint8_t> data;
	};


	class X2WinRpcAdapter : public DebugAdapter
	{
	private:
		Socket m_socket;
		bool m_connected = false;
		std::thread m_readerThread;

		// request_id -> promise, fulfilled by ReaderLoop() when the matching RESPONSE arrives.
		// EVENT frames (id == 0) never go through this table; they go straight to PostDebuggerEvent().
		std::mutex m_pendingMutex;
		std::unordered_map<uint64_t, std::promise<Frame>> m_pendingRequests;
		std::atomic<uint64_t> m_nextRequestId {1};

		Ref<Settings> GetAdapterSettings() override;

		// Helper to resolve module+offset to an absolute address using GetModuleList().
		// Same purpose as LldbAdapter::ResolveModuleAddress; every adapter needs its own copy
		// since there is no shared base-class implementation for this.
		bool ResolveModuleAddress(const ModuleNameAndOffset& location, uint64_t& address);

		bool ConnectSocket(const std::string& ip, uint16_t port);
		bool ConnectFromSettings();
		void TeardownConnection();
		bool GetReplyStatus(const Frame& reply);

	public:
		X2WinRpcAdapter(BinaryView* data);
		virtual ~X2WinRpcAdapter();

		// --- Lifecycle ---
		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
		bool Attach(std::uint32_t pid) override;
		bool Connect(const std::string& server, std::uint32_t port) override;
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

		// --- Misc ---
		std::string InvokeBackendCommand(const std::string& command) override;
		uint64_t GetInstructionOffset() override;
		bool SupportFeature(DebugAdapterCapacity feature) override;

		// Dedicated socket-reader loop (runs on m_readerThread): pulls frames forever, routes
		// RESPONSE by id to m_pendingRequests, routes EVENT (id == 0) to PostDebuggerEvent().
		void ReaderLoop();

		// --- Helper function ---
		bool RecvExact(void* buffer, size_t size);
		Frame CallSync(uint16_t methodId, const std::vector<uint8_t>& payload);

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
