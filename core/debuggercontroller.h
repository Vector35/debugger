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
#include "binaryninjaapi.h"
#include "debuggerstate.h"
#include "debuggerevent.h"
#include <queue>
#include "ffi_global.h"

DECLARE_DEBUGGER_API_OBJECT(BNDebuggerController, DebuggerController);

namespace BinaryNinjaDebugger
{
	struct DebuggerEventCallback
	{
		std::function<void(const DebuggerEvent &event)> function;
		size_t index;
	};

	// This is used by the debugger to track stack variables it defined. It is simpler than
	// BinaryNinja::VariableNameAndType that it does not track the Variable and autoDefined.
	struct StackVariableNameAndType
	{
		Confidence<Ref<Type>> type;
		std::string name;

		StackVariableNameAndType() = default;
		StackVariableNameAndType(Confidence<Ref<Type>> t, const std::string& n)
		{
			type = t;
			name = n;
		}

		bool operator==(const StackVariableNameAndType& other)
		{
			return (type == other.type) && (name == other.name);
		}

		bool operator!=(const StackVariableNameAndType& other)
		{
			return !(*this == other);
		}
	};

	// This is the controller class of the debugger. It receives the input from the UI/API, and then route them to
	// the state and UI, etc. Most actions should reach here.
	class DebuggerController
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNDebuggerController);

	private:
		DebugAdapter *m_adapter;
		DebuggerState *m_state;
		BinaryViewRef m_data;
		BinaryViewRef m_liveView;

		inline static std::vector<DebuggerController *> g_debuggerControllers;

		std::atomic<size_t> m_callbackIndex = 0;
		std::vector<DebuggerEventCallback> m_eventCallbacks;
		std::recursive_mutex m_callbackMutex;

		uint64_t m_lastIP = 0;
		uint64_t m_currentIP = 0;

		// This is only meaningful after the target exits. In the future, we should enforce a check for the target
		// status before returning the value
		uint32_t m_exitCode = 0;

		// Whether to treat a debug adapter stop as the target has stopped. Default to true.
		// Functions that wish to have more control over this, e.g., StopIntoIL(), should set this to false,
		// and call a NotifyStopped when the sequence of operation is done.
		bool m_treatAdapterStopAsTargetStop = true;

		void EventHandler(const DebuggerEvent &event);
		void UpdateStackVariables();
		bool CreateDebugAdapter();
		void HandleInitialBreakpoint();

		void SetLiveView(BinaryViewRef view) { m_liveView = view; }

		void SetData(BinaryViewRef view) { m_data = view; }

		// Internal control APIs
		void PauseInternal();
		void GoInternal();
		void StepIntoInternal();
		void StepOverInternal();
		void StepReturnInternal();
		void RunToInternal(const std::vector<uint64_t> &remoteAddresses);
		void StepIntoIL(BNFunctionGraphType il);
		void StepOverIL(BNFunctionGraphType il);

		// Whether we can resume the execution of the target, including stepping.
		bool CanResumeTarget();

		bool ExpectSingleStep(DebugStopReason reason);

		std::map<uint64_t, StackVariableNameAndType> m_debuggerVariables;
		std::set<uint64_t> m_addressesWithVariable;
		std::set<uint64_t> m_oldAddresses;
		std::set<uint64_t> m_addressesWithComment;
		void ProcessOneVariable(uint64_t address, Confidence<Ref<Type>> type, const std::string& name);
		void DefineVariablesRecursive(uint64_t address, Confidence<Ref<Type>> type);

		void ApplyBreakpoints();

        std::string m_lastAdapterName;

	public:
		DebuggerController(BinaryViewRef data);
		static DebuggerController *GetController(BinaryViewRef data);
		static void DeleteController(BinaryViewRef data);
		// Explicitly destroy the current controller, so a new controller on the same binaryview will be brand new.
		// I am not super sure that this is the correct way of doing things, but it addresses the controller reuse
		// problem.
		void Destroy();

		// breakpoints
		void AddBreakpoint(uint64_t address);
		void AddBreakpoint(const ModuleNameAndOffset &address);
		void DeleteBreakpoint(uint64_t address);
		void DeleteBreakpoint(const ModuleNameAndOffset &address);
		DebugBreakpoint GetAllBreakpoints();

		// registers
		uint64_t GetRegisterValue(const std::string &name);
		bool SetRegisterValue(const std::string &name, uint64_t value);
		std::vector<DebugRegister> GetAllRegisters();

		// threads
		DebugThread GetActiveThread() const;
		void SetActiveThread(const DebugThread &thread);
		std::vector<DebugThread> GetAllThreads();
		std::vector<DebugFrame> GetFramesOfThread(uint64_t tid);

		// modules
		std::vector<DebugModule> GetAllModules();
		DebugModule GetModuleByName(const std::string &module);
		uint64_t GetModuleBase(const std::string &name);
		DebugModule GetModuleForAddress(uint64_t remoteAddress);
		ModuleNameAndOffset AbsoluteAddressToRelative(uint64_t absoluteAddress);
		uint64_t RelativeAddressToAbsolute(const ModuleNameAndOffset &relativeAddress);

		// arch
		ArchitectureRef GetRemoteArchitecture();

		// status
		DebugAdapterConnectionStatus GetConnectionStatus();

		DebugAdapterTargetStatus GetExecutionStatus();

		// memory
		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size);
		bool WriteMemory(std::uintptr_t address, const DataBuffer &buffer);

		// debugger events
		size_t RegisterEventCallback(std::function<void(const DebuggerEvent &event)> callback);
		bool RemoveEventCallback(size_t index);
		void NotifyStopped(DebugStopReason reason, void *data = nullptr);
		void NotifyError(const std::string &error, void *data = nullptr);
		void NotifyEvent(DebuggerEventType event);
		void PostDebuggerEvent(const DebuggerEvent &event);

		// shortcut for instruction pointer
		uint64_t GetLastIP() const { return m_lastIP; }
		uint64_t GetCurrentIP() const { return m_currentIP; }

		// target control
		bool Launch();
		bool Execute();
		void Restart();
		void Quit();
		void Connect();
        bool ConnectToDebugServer();
        bool DisconnectDebugServer();
		void Detach();
		// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
		void LaunchOrConnect();
		bool Attach(int32_t pid);

		// Asynchronous APIs.
		bool Go();
		bool StepInto(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepOver(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepReturn();
		bool RunTo(const std::vector<uint64_t> &remoteAddresses);
		bool Pause();

		// Synchronous APIs
		DebugStopReason GoAndWait();
		DebugStopReason StepIntoAndWait(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepOverAndWait(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepReturnAndWait();
		DebugStopReason RunToAndWait(const std::vector<uint64_t> &remoteAddresses);
		DebugStopReason PauseAndWait();

		// getters
		DebugAdapter *GetAdapter() { return m_adapter; }
		DebuggerState *GetState() { return m_state; }
		BinaryViewRef GetData() const { return m_data; }
		BinaryViewRef GetLiveView() const { return m_liveView; }

		uint32_t GetExitCode();

		void WriteStdIn(const std::string message);

		std::string InvokeBackendCommand(const std::string& cmd);

		static std::string GetStopReasonString(DebugStopReason);
		DebugStopReason StopReason() const;

		DebugStopReason WaitForTargetStop();
		DebugStopReason WaitForAdapterStop();
	};
};
