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

#pragma once
#include "../debugadapter.h"
#include "../debugadaptertype.h"
#include "rspconnector.h"
#include <map>
#include <queue>
#include "../semaphore.h"

namespace BinaryNinjaDebugger
{
	class EsrevenAdapter : public DebugAdapter
	{
	protected:
		struct RegisterInfo
		{
			std::uint32_t m_bitSize{};
			std::uint32_t m_regNum{};
			std::uint32_t m_offset{};
		};

		struct PendingBreakpoint
		{
			ModuleNameAndOffset address;
			unsigned long type;

			PendingBreakpoint(ModuleNameAndOffset address, unsigned long type) : address(address), type(type) {}
		};

		DebugStopReason m_lastStopReason{};

		using register_pair = std::pair<std::string, RegisterInfo>;

		Socket* m_socket;
		RspConnector* m_rspConnector{};

		std::map<std::string, RegisterInfo> m_registerInfo{};
		std::optional<std::unordered_map<std::string, DebugRegister>> m_regCache;

		std::uint32_t m_internalBreakpointId{};
		// THis is the breakpoint that is active on the gdbserver side
		std::vector<DebugBreakpoint> m_debugBreakpoints{};

		std::vector<PendingBreakpoint> m_pendingBreakpoints {};
		std::vector<PendingHardwareBreakpoint> m_pendingHardwareBreakpoints {};

		std::optional<std::vector<DebugModule>> m_moduleCache{};

		// Cache for thread list with frames (from rvn:list-threads)
		struct ThreadFrameCache
		{
			std::uint32_t tid;
			std::uintptr_t rip;
			std::vector<DebugFrame> frames;
		};
		std::optional<std::vector<ThreadFrameCache>> m_threadCache{};

		std::uint32_t m_lastActiveThreadId{};
		std::uint32_t m_processPid{};
		uint8_t m_exitCode{};

		std::string GetGDBServerPath();

		std::string ExecuteShellCommand(const std::string& command);
		virtual bool LoadRegisterInfo();

		// This name is confusing. It actually means whether the target is running, so certain operations, e.g.,
		// reading memory, adding breakpoint, cannot be carried out at the moment.
		bool m_isTargetRunning;

		// Cache the name of the remote architecture, so there is no need to read it repeatedly.
		// However, this does not handle the case when the remote arch changes. Though other changes are also needed to
		// support the case -- so we do not really lose a lot anyways.
		std::string m_remoteArch;

		// Whether the target uses big-endian byte order. Determined from target XML <endian> element
		// or inferred from architecture name.
		bool m_isBigEndian = false;

		bool m_canReverseContinue = false;
		bool m_canReverseStep = false;

		void InvalidateCache();

		virtual DebugStopReason SignalToStopReason(std::unordered_map<std::string, std::uint64_t>& map);

		bool GetModuleBase(const std::string& moduleName, uint64_t& base);
		void CheckApplyPendingBreakpoints();
		void ClearCachedBreakpoints() { m_debugBreakpoints.clear(); }

	public:
		EsrevenAdapter(BinaryView* data, bool redirectGDBServer = true);
		~EsrevenAdapter();

		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string &path, const std::string &args, const std::string &workingDir,
							 const LaunchConfigurations &configs) override;
		bool Attach(std::uint32_t pid) override;
		bool Connect(const std::string& server, std::uint32_t port) override;
		bool ConnectToDebugServer(const std::string& server, std::uint32_t port) override;

		bool Detach() override;
		bool Quit() override;

		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;
		std::vector<DebugFrame> GetFramesOfThread(std::uint32_t tid) override;

		DebugBreakpoint AddBreakpoint(std::uintptr_t address, unsigned long breakpoint_type = 0) override;

		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;
		bool BreakpointExists(uint64_t address) const;

		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& reg) override;
		bool WriteRegister(const std::string& reg, intx::uint512 value) override;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;
		std::string GetRemoteFile(const std::string& path);
		std::vector<DebugModule> GetModuleList() override;

		// TTD Memory Access support
		std::vector<TTDMemoryEvent> GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType = TTDMemoryRead) override;
		std::vector<TTDPositionRangeIndexedMemoryEvent> GetTTDMemoryAccessForPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, const TTDPosition startTime, const TTDPosition endTime) override;

		std::string GetTargetArchitecture() override;

		DebugStopReason StopReason() override;
		uint64_t ExitCode() override { return m_exitCode; }

		bool BreakInto() override;
		DebugStopReason GenericGo(const std::string& goCommand, bool notifyStopped = true);
		bool Go() override;
		bool StepInto() override;
		bool StepOver() override;
		bool StepReturn() override;

		bool GoReverse() override;
		bool StepIntoReverse() override;
		bool StepOverReverse() override;
		bool StepReturnReverse() override;

		std::string InvokeBackendCommand(const std::string& command) override;
		std::string RunMonitorCommand(const std::string& command);
		uint64_t GetInstructionOffset() override;
		uint64_t GetStackPointer() override;
		std::uint32_t GetActivePID() override;

		DebugStopReason ResponseHandler(bool notifyStopped = true);

		bool SupportFeature(DebugAdapterCapacity feature) override;
		void HandleAsyncPacket(const RspData& data);

		std::vector<DebugProcess> GetProcessList() override;
		bool SuspendThread(std::uint32_t tid) override;
		bool ResumeThread(std::uint32_t tid) override;
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;

		// Hardware breakpoint and watchpoint support
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) override;

		// Legacy methods - kept for backward compatibility
		bool AddHardwareWriteBreakpoint(uint64_t address);
		bool RemoveHardwareWriteBreakpoint(uint64_t address);

		// TTD (Time Travel Debugging) support
		TTDPosition GetCurrentTTDPosition() override;
		bool SetTTDPosition(const TTDPosition& position) override;
		std::vector<TTDCallEvent> GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress = 0, uint64_t endReturnAddress = 0) override;

		void GenerateDefaultAdapterSettings(BinaryView* data);
		Ref<Settings> GetAdapterSettings() override;
	};


	class EsrevenAdapterType: public DebugAdapterType
	{
		static Ref<Settings> RegisterAdapterSettings();

	public:
		EsrevenAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
		static Ref<Settings> GetAdapterSettings();
	};


	void InitEsrevenAdapterType();
};
