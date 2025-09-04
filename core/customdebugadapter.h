/*
Copyright 2020-2025 Vector 35 Inc.

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

#include "debugadapter.h"
#include "debugadaptertype.h"
#include "../api/ffi.h"
#include "ffi_global.h"

DECLARE_DEBUGGER_API_OBJECT(BNCustomDebugAdapter, CustomDebugAdapter);
DECLARE_DEBUGGER_API_OBJECT(BNCustomDebugAdapterType, CustomDebugAdapterType);

namespace BinaryNinjaDebugger {

	// Bridge adapter that forwards calls to user-provided callbacks
	class CustomDebugAdapter : public DebugAdapter
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNCustomDebugAdapter);

	private:
		BNCustomDebugAdapterCallbacks m_callbacks;

	public:
		CustomDebugAdapter(BinaryView* data, const BNCustomDebugAdapterCallbacks& callbacks);
		virtual ~CustomDebugAdapter();

		virtual bool Init() override;
		virtual bool Execute(const std::string& path, const LaunchConfigurations& configs = {}) override;
		virtual bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs = {}) override;
		virtual bool Attach(std::uint32_t pid) override;
		virtual bool Connect(const std::string& server, std::uint32_t port) override;
		virtual bool ConnectToDebugServer(const std::string& server, std::uint32_t port) override;
		virtual bool Detach() override;
		virtual bool Quit() override;

		virtual std::vector<DebugProcess> GetProcessList() override;
		virtual std::vector<DebugThread> GetThreadList() override;
		virtual DebugThread GetActiveThread() const override;
		virtual std::uint32_t GetActiveThreadId() const override;
		virtual bool SetActiveThread(const DebugThread& thread) override;
		virtual bool SetActiveThreadId(std::uint32_t tid) override;
		virtual bool SuspendThread(std::uint32_t tid) override;
		virtual bool ResumeThread(std::uint32_t tid) override;

		virtual DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type = 0) override;
		virtual DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;
		virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;
		virtual bool RemoveBreakpoint(const ModuleNameAndOffset& address) override;
		virtual std::vector<DebugBreakpoint> GetBreakpointList() const override;

		virtual std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		virtual DebugRegister ReadRegister(const std::string& reg) override;
		virtual bool WriteRegister(const std::string& reg, intx::uint512 value) override;

		virtual DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		virtual bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;

		virtual std::vector<DebugModule> GetModuleList() override;
		virtual std::string GetTargetArchitecture() override;
		virtual DebugStopReason StopReason() override;
		virtual uint64_t ExitCode() override;

		virtual bool BreakInto() override;
		virtual bool Go() override;
		virtual bool GoReverse() override;
		virtual bool StepInto() override;
		virtual bool StepIntoReverse() override;
		virtual bool StepOver() override;
		virtual bool StepOverReverse() override;
		virtual bool StepReturn() override;
		virtual bool StepReturnReverse() override;

		virtual std::string InvokeBackendCommand(const std::string& command) override;
		virtual uint64_t GetInstructionOffset() override;
		virtual uint64_t GetStackPointer() override;
		virtual bool SupportFeature(DebugAdapterCapacity feature) override;

		virtual void WriteStdin(const std::string& msg) override;
		virtual BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name) override;
		virtual bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value) override;
		virtual Ref<Settings> GetAdapterSettings() override;

	private:
		// Helper functions to convert between C++ and C types
		BNDebugThread ConvertDebugThread(const DebugThread& thread) const;
		DebugThread ConvertDebugThread(const BNDebugThread& thread) const;
		BNDebugBreakpoint ConvertDebugBreakpoint(const DebugBreakpoint& bp) const;
		DebugBreakpoint ConvertDebugBreakpoint(const BNDebugBreakpoint& bp) const;
	};

	// Bridge adapter type that forwards calls to user-provided callbacks
	class CustomDebugAdapterType : public DebugAdapterType
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNCustomDebugAdapterType);

	private:
		BNCustomDebugAdapterTypeCallbacks m_callbacks;

	public:
		CustomDebugAdapterType(const std::string& name, const BNCustomDebugAdapterTypeCallbacks& callbacks);
		virtual ~CustomDebugAdapterType();

		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data) override;
		virtual bool IsValidForData(BinaryNinja::BinaryView* data) override;
		virtual bool CanExecute(BinaryNinja::BinaryView* data) override;
		virtual bool CanConnect(BinaryNinja::BinaryView* data) override;
	};

}  // namespace BinaryNinjaDebugger