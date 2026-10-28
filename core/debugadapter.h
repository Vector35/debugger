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
#include <cstdint>
#include <utility>
#include <vector>
#include <optional>
#include <string>
#include <stdexcept>
#include <functional>
#include <unordered_map>
#include <array>
#include "binaryninjaapi.h"
#include <fmt/format.h>
#include "../api/ffi.h"
#include "ffi_global.h"
#include "debuggercommon.h"
#include "debuggerevent.h"
#include "debugadaptertypes.h"
#include "../vendor/intx/intx.hpp"

DECLARE_DEBUGGER_API_OBJECT(BNDebugAdapter, DebugAdapter);

using namespace BinaryNinja;

namespace BinaryNinjaDebugger {
	enum StopReason
	{
		UnknownStopReason,
		StdoutMessageReason,
		ProcessExitedReason,
		BackendDisconnectedReason,
		SingleStepStopReason,
		BreakpointStopReason,
		ExceptionStopReason
	};


	class DebuggerController;
	class DebugAdapter
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNDebugAdapter);

	private:
		// Function to call when the DebugAdapter wants to notify the front-end of certain events
		// TODO: we should not use a vector here; only the DebuggerController should register one here;
		// Other components should register their callbacks to the controller, who is responsible for notify them.
		std::function<void(const DebuggerEvent& event)> m_eventCallback;
		DebuggerController* m_controller;

	protected:
		uint64_t m_entryPoint;
		bool m_hasEntryFunction;
		uint64_t m_start;
		uint64_t m_originalImageBase;
		std::string m_defaultArchitecture;

	public:
		DebugAdapter(BinaryView* data);
		virtual ~DebugAdapter() {}

		virtual bool Init() { return true; }

		virtual void SetEventCallback(std::function<void(const DebuggerEvent& event)> function)
		{
			m_eventCallback = function;
		}

		[[nodiscard]] virtual bool Execute(const std::string& path, const LaunchConfigurations& configs = {}) = 0;

		[[nodiscard]] virtual bool ExecuteWithArgs(const std::string& path, const std::string& args,
			const std::string& workingDir, const LaunchConfigurations& configs = {}) = 0;

		[[nodiscard]] virtual bool Attach(std::uint32_t pid) = 0;

		[[nodiscard]] virtual bool Connect(const std::string& server, std::uint32_t port) = 0;

		virtual bool ConnectToDebugServer(const std::string& server, std::uint32_t port);

		virtual bool DisconnectDebugServer();

		virtual bool Detach() = 0;

		virtual bool Quit() = 0;

		virtual std::vector<DebugProcess> GetProcessList() = 0;

		virtual std::uint32_t GetActivePID() = 0;

		virtual std::vector<DebugThread> GetThreadList() = 0;

		virtual DebugThread GetActiveThread() const = 0;

		virtual std::uint32_t GetActiveThreadId() const = 0;

		virtual bool SetActiveThread(const DebugThread& thread) = 0;

		virtual bool SetActiveThreadId(std::uint32_t tid) = 0;

		virtual bool SuspendThread(std::uint32_t tid) = 0;

		virtual bool ResumeThread(std::uint32_t tid) = 0;

		virtual std::vector<DebugFrame> GetFramesOfThread(std::uint32_t tid);

		virtual DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type = 0) = 0;

		virtual DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) = 0;

		virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) = 0;

		virtual bool RemoveBreakpoint(const ModuleNameAndOffset& address) { return false; }

		virtual bool EnableBreakpoint(const std::uintptr_t address) { return false; }

		virtual bool EnableBreakpoint(const ModuleNameAndOffset& address) { return false; }

		virtual bool DisableBreakpoint(const std::uintptr_t address) { return false; }

		virtual bool DisableBreakpoint(const ModuleNameAndOffset& address) { return false; }

		virtual std::vector<DebugBreakpoint> GetBreakpointList() const = 0;

		// Hardware breakpoint and watchpoint support
		// Note: Adapters that don't support hardware breakpoints should return false from both methods

		// Hardware breakpoints - absolute address
		virtual bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) = 0;
		virtual bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) = 0;

		// Hardware breakpoints - module+offset (ASLR-safe)
		// Each adapter must implement this to handle module resolution in its own way
		virtual bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) = 0;
		virtual bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1) = 0;

		virtual std::unordered_map<std::string, DebugRegister> ReadAllRegisters() = 0;

		virtual DebugRegister ReadRegister(const std::string& reg) = 0;

		virtual bool WriteRegister(const std::string& reg, intx::uint512 value) = 0;

		virtual DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) = 0;

		virtual bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) = 0;

		virtual std::vector<DebugModule> GetModuleList() = 0;

		// Return the target's memory map: every mapped region of the virtual address space with its
		// permissions. Adapters opt in by overriding this; the default is an empty map for backends
		// that do not (yet) support it. See issue #96.
		virtual std::vector<DebugMemoryRegion> GetMemoryMap() { return {}; }

		// Read the symbols that the debugger backend knows about for the given module. These are the
		// symbols (e.g. exports like CreateFileA) that the static BinaryView analysis is not aware of.
		// The default implementation returns an empty list; adapters that support reading symbols from
		// the backend should override this and report DebugAdapterSupportSymbols in SupportFeature.
		virtual std::vector<DebugSymbol> GetSymbolsForModule(const DebugModule& module) { return {}; }

		virtual std::string GetTargetArchitecture() = 0;

		virtual DebugStopReason StopReason() = 0;

		virtual uint64_t ExitCode() = 0;

		virtual bool BreakInto() = 0;

		virtual bool Go() = 0;

		virtual bool GoReverse();

		virtual bool StepInto() = 0;

		virtual bool StepIntoReverse();

		virtual bool StepOver() = 0;

		virtual bool StepOverReverse();
		//    virtual bool RunTo(std::uintptr_t address) = 0;

		virtual bool StepReturn();

		virtual bool StepReturnReverse();

		virtual std::string InvokeBackendCommand(const std::string& command) = 0;

		virtual uint64_t GetInstructionOffset() = 0;

		virtual uint64_t GetStackPointer();

		virtual bool SupportFeature(DebugAdapterCapacity feature) = 0;

		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
		void PostDebuggerEvent(const DebuggerEvent& event);

		virtual void WriteStdin(const std::string& msg);

		virtual BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name);

		virtual bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);

		// The debug adapter some times need to have access to the controller and the binary view. However, it is
		// better NOT to directly keep a reference to the binary view, since the rebasing can make the view
		void SetController(DebuggerController* controller) { m_controller = controller; }
		DebuggerController* GetController() { return m_controller; }
		Ref<BinaryView> GetData();

		virtual Ref<Settings> GetAdapterSettings();

		// TTD (Time Travel Debugging) methods - default implementations return empty results
		virtual std::vector<TTDMemoryEvent> GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType = TTDMemoryRead);
		virtual std::vector<TTDPositionRangeIndexedMemoryEvent> GetTTDMemoryAccessForPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, const TTDPosition startTime, const TTDPosition endTime);
		virtual std::vector<TTDCallEvent> GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress = 0, uint64_t endReturnAddress = 0);
		virtual std::vector<TTDEvent> GetTTDEvents(TTDEventType eventType);
		virtual std::vector<TTDEvent> GetAllTTDEvents();
		virtual TTDPosition GetCurrentTTDPosition();
		virtual bool SetTTDPosition(const TTDPosition& position);
		virtual std::pair<bool, TTDMemoryEvent> GetTTDNextMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType);
		virtual std::pair<bool, TTDMemoryEvent> GetTTDPrevMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType);
		virtual std::optional<TTDRegisterWriteEvent> GetTTDNextRegisterWrite(const std::string& reg);
		virtual std::optional<TTDRegisterWriteEvent> GetTTDPrevRegisterWrite(const std::string& reg);

	};
};  // namespace BinaryNinjaDebugger
