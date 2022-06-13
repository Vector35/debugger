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

DECLARE_DEBUGGER_API_OBJECT(BNDebugAdapter, DebugAdapter);

using namespace BinaryNinja;

namespace BinaryNinjaDebugger
{
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


	// Used by the DebuggerState to query the capacities of the DebugAdapter, and take different actions accordingly.
	enum DebugAdapterCapacity
	{
		DebugAdapterSupportStepOver,
		DebugAdapterSupportModules,
		DebugAdapterSupportThreads,
	};


	struct LaunchConfigurations
	{
		bool requestTerminalEmulator;

		LaunchConfigurations() : requestTerminalEmulator(true) {}

		LaunchConfigurations(bool terminal) : requestTerminalEmulator(terminal) {}
	};


	struct DebugThread
	{
		std::uint32_t m_tid{};
		std::uintptr_t m_rip{};

		DebugThread() {}

		DebugThread(std::uint32_t tid) : m_tid(tid) {}

		DebugThread(std::uint32_t tid, std::uintptr_t rip) : m_tid(tid), m_rip(rip) {}

		bool operator==(const DebugThread &rhs) const {
			return (m_tid == rhs.m_tid) && (m_rip == rhs.m_rip);
		}

		bool operator!=(const DebugThread &rhs) const {
			return !(*this == rhs);
		}
	};

	struct DebugBreakpoint
	{
		std::uintptr_t m_address{};
		unsigned long m_id{};
		bool m_is_active{};

		DebugBreakpoint(std::uintptr_t address, unsigned long id, bool active) : m_address(address), m_id(id),
																				 m_is_active(active) {}

		DebugBreakpoint(std::uintptr_t address) : m_address(address) {}

		DebugBreakpoint() {}

		bool operator==(const DebugBreakpoint &rhs) const {
			return this->m_address == rhs.m_address;
		}

		bool operator!() const {
			return !this->m_address && !this->m_id && !this->m_is_active;
		}
	};

	struct DebugRegister
	{
		std::string m_name{};
		std::uintptr_t m_value{};
		std::size_t m_width{}, m_registerIndex{};
		std::string m_hint{};

		DebugRegister() = default;

		DebugRegister(std::string name, std::uintptr_t value, std::size_t width, std::size_t register_index) :
				m_name(std::move(name)), m_value(value), m_width(width), m_registerIndex(register_index) {}
	};

	struct DebugModule
	{
		std::string m_name{}, m_short_name{};
		std::uintptr_t m_address{};
		std::size_t m_size{};
		bool m_loaded{};

		DebugModule() : m_name(""), m_short_name(""), m_address(0), m_size(0) {}

		DebugModule(std::string name, std::string short_name, std::uintptr_t address, std::size_t size, bool loaded) :
				m_name(std::move(name)), m_short_name(std::move(short_name)), m_address(address), m_size(size),
				m_loaded(loaded) {}

		// These are useful for remote debugging. Paths can be different on the host and guest systems, e.g., /usr/bin/ls,
		// and C:\Users\user\Desktop\ls. So we must compare the base file name, rather than the full path.
		bool IsSameBaseModule(const DebugModule &other) const;

		bool IsSameBaseModule(const std::string &name) const;

		static bool IsSameBaseModule(const std::string &module, const std::string &module2);

		static std::string GetPathBaseName(const std::string &path);
	};

	struct DebugFrame
	{
		size_t m_index;
		uint64_t m_pc;
		uint64_t m_sp;
		uint64_t m_fp;
		std::string m_functionName;
		uint64_t m_functionStart;
		std::string m_module;

		DebugFrame() = default;
		DebugFrame(size_t index, uint64_t pc, uint64_t sp, uint64_t fp, const std::string& functionName,
				   uint64_t functionStart, const std::string& module):
				   m_index(index), m_pc(pc), m_sp(sp), m_fp(fp), m_functionName(functionName),
				   m_functionStart(functionStart), m_module(module)
		{}
	};

	class DebugAdapter
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNDebugAdapter);

	private:
		// Function to call when the DebugAdapter wants to notify the front-end of certain events
		// TODO: we should not use a vector here; only the DebuggerController should register one here;
		// Other components should register their callbacks to the controller, who is responsible for notify them.
		std::function<void(const DebuggerEvent &event)> m_eventCallback;

	public:
		Ref<BinaryView> m_data;

		DebugAdapter(BinaryView* data);

		virtual void SetEventCallback(std::function<void(const DebuggerEvent &event)> function) {
			m_eventCallback = function;
		}

		[[nodiscard]] virtual bool Execute(const std::string &path, const LaunchConfigurations &configs = {}) = 0;

		[[nodiscard]] virtual bool
		ExecuteWithArgs(const std::string &path, const std::string &args, const std::string &workingDir,
						const LaunchConfigurations &configs = {}) = 0;

		[[nodiscard]] virtual bool Attach(std::uint32_t pid) = 0;

		[[nodiscard]] virtual bool Connect(const std::string &server, std::uint32_t port) = 0;

        virtual bool ConnectToDebugServer(const std::string &server, std::uint32_t port);

        virtual bool DisconnectDebugServer();

        virtual void Detach() = 0;

		virtual void Quit() = 0;

		virtual std::vector<DebugThread> GetThreadList() = 0;

		virtual DebugThread GetActiveThread() const = 0;

		virtual std::uint32_t GetActiveThreadId() const = 0;

		virtual bool SetActiveThread(const DebugThread &thread) = 0;

		virtual bool SetActiveThreadId(std::uint32_t tid) = 0;

		virtual std::vector<DebugFrame> GetFramesOfThread(std::uint32_t tid);

		virtual DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type = 0) = 0;

		virtual DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0)
        {
            return DebugBreakpoint{};
        }

		virtual bool RemoveBreakpoint(const DebugBreakpoint &breakpoint) = 0;

		virtual bool RemoveBreakpoint(const ModuleNameAndOffset& address)
        {
            return false;
        }

		virtual std::vector<DebugBreakpoint> GetBreakpointList() const = 0;

		virtual std::unordered_map<std::string, DebugRegister> ReadAllRegisters() = 0;

		virtual DebugRegister ReadRegister(const std::string &reg) = 0;

		virtual bool WriteRegister(const std::string &reg, std::uintptr_t value) = 0;

		virtual DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) = 0;

		virtual bool WriteMemory(std::uintptr_t address, const DataBuffer &buffer) = 0;

		virtual std::vector<DebugModule> GetModuleList() = 0;

		virtual std::string GetTargetArchitecture() = 0;

		virtual DebugStopReason StopReason() = 0;

		virtual uint64_t ExitCode() = 0;

		virtual bool BreakInto() = 0;

		virtual DebugStopReason Go() = 0;

		virtual DebugStopReason StepInto() = 0;

		virtual DebugStopReason StepOver() = 0;
		//    virtual bool RunTo(std::uintptr_t address) = 0;

		virtual DebugStopReason StepReturn();

		virtual std::string InvokeBackendCommand(const std::string &command) = 0;

		virtual std::uintptr_t GetInstructionOffset() = 0;

		virtual uint64_t GetStackPointer();

		virtual bool SupportFeature(DebugAdapterCapacity feature) = 0;

		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
		void PostDebuggerEvent(const DebuggerEvent &event);

		virtual void WriteStdin(const std::string& msg);
	};
};
