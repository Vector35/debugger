/*
Copyright 2020-2022 Vector 35 Inc.

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
	class GdbAdapter : public DebugAdapter
	{
	protected:
		struct RegisterInfo
		{
			std::uint32_t m_bitSize{};
			std::uint32_t m_regNum{};
			std::uint32_t m_offset{};
		};

		DebugStopReason m_lastStopReason{};

		using register_pair = std::pair<std::string, RegisterInfo>;

		Socket* m_socket;
		RspConnector m_rspConnector{};

		std::map<std::string, RegisterInfo> m_registerInfo{};

		std::uint32_t m_internalBreakpointId{};
		std::vector<DebugBreakpoint> m_debugBreakpoints{};

		std::uint32_t m_lastActiveThreadId{};
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

		virtual DebugStopReason SignalToStopReason(std::unordered_map<std::string, std::uint64_t>& map);

	public:
		GdbAdapter(BinaryView* data, bool redirectGDBServer = true);
		~GdbAdapter();

		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string &path, const std::string &args, const std::string &workingDir,
							 const LaunchConfigurations &configs) override;
		bool Attach(std::uint32_t pid) override;
		bool Connect(const std::string& server, std::uint32_t port) override;

		void Detach() override;
		void Quit() override;

		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;

		DebugBreakpoint AddBreakpoint(std::uintptr_t address, unsigned long breakpoint_type = 0) override;

		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;
		bool BreakpointExists(uint64_t address) const;

		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& reg) override;
		bool WriteRegister(const std::string& reg, std::uintptr_t value) override;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;
		std::string GetRemoteFile(const std::string& path);
		std::vector<DebugModule> GetModuleList() override;

		std::string GetTargetArchitecture() override;

		DebugStopReason StopReason() override;
		uint64_t ExitCode() override { return m_exitCode; }

		bool BreakInto() override;
		DebugStopReason GenericGo(const std::string& goCommand);
		DebugStopReason Go() override;
		DebugStopReason StepInto() override;
		DebugStopReason StepOver() override;

		std::string InvokeBackendCommand(const std::string& command) override;
		std::uintptr_t GetInstructionOffset() override;

		DebugStopReason ResponseHandler();

		bool SupportFeature(DebugAdapterCapacity feature) override;
		void HandleAsyncPacket(const RspData& data);
	};


	class LocalGdbAdapterType: public DebugAdapterType
	{
	public:
		LocalGdbAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	class RemoteGdbAdapterType: public DebugAdapterType
	{
	public:
		RemoteGdbAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	void InitGdbAdapterType();
};
