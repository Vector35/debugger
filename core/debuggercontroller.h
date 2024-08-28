/*
Copyright 2020-2024 Vector 35 Inc.

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
#include <list>
#include "ffi_global.h"
#include "refcountobject.h"
#include "debuggerfileaccessor.h"

DECLARE_DEBUGGER_API_OBJECT(BNDebuggerController, DebuggerController);

namespace BinaryNinjaDebugger {
	struct DebuggerEventCallback
	{
		std::function<void(const DebuggerEvent& event)> function;
		size_t index;
		std::string name;
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

		bool operator==(const StackVariableNameAndType& other) { return (type == other.type) && (name == other.name); }

		bool operator!=(const StackVariableNameAndType& other) { return !(*this == other); }
	};

	// This is the controller class of the debugger. It receives the input from the UI/API, and then route them to
	// the state and UI, etc. Most actions should reach here.
	class DebuggerController : public DbgRefCountObject, BinaryNinja::BinaryDataNotification
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNDebuggerController);

	private:
		DebugAdapter* m_adapter;
		DebuggerState* m_state;
		FileMetadataRef m_file;
		BinaryViewRef m_data;
		DebuggerFileAccessor* m_accessor;
		// This is the start address of the first file segments in the m_data. Unlike the return value of GetStart(),
		// this does not change even if we add the debugger memory region. In the future, this should be provided by
		// the binary view -- we will no longer need to track it ourselves
		uint64_t m_viewStart;

		//	inline static std::vector<DbgRef<DebuggerController>> g_debuggerControllers;
		static DbgRef<DebuggerController>* g_debuggerControllers;
		static size_t g_controllerCount;

		std::atomic<size_t> m_callbackIndex = 0;
		std::list<DebuggerEventCallback> m_eventCallbacks;
		std::recursive_mutex m_callbackMutex;
		std::set<size_t> m_disabledCallbacks;

		// m_adapterMutex is a low-level mutex that protects the adapter access. It cannot be locked recursively.
		// m_targetControlMutex is a high-level mutex that prevents two threads from controlling the debugger at the
		// same time
		std::mutex m_adapterMutex;
		std::recursive_mutex m_targetControlMutex;

		uint64_t m_lastIP = 0;
		uint64_t m_currentIP = 0;

		// This is only meaningful after the target exits. In the future, we should enforce a check for the target
		// status before returning the value
		uint32_t m_exitCode = 0;

		bool m_userRequestedBreak = false;

		bool m_lastAdapterStopEventConsumed = true;

		bool m_inputFileLoaded = false;
		bool m_initialBreakpointSeen = false;

		bool m_firstLaunch = true;
		bool m_shouldAnnotateStackVariable = false;

		void EventHandler(const DebuggerEvent& event);
		void UpdateStackVariables();
		void AddRegisterValuesToExpressionParser();
		bool CreateDebugAdapter();
		bool CreateDebuggerBinaryView();

		DebugStopReason StepIntoIL(BNFunctionGraphType il);
		DebugStopReason StepIntoReverseIL(BNFunctionGraphType il);
		DebugStopReason StepOverIL(BNFunctionGraphType il);
		DebugStopReason StepOverReverseIL(BNFunctionGraphType il);

		// Low-level internal synchronous APIs. They resume the target and wait for the adapter to stop.
		// They do NOT dispatch the debugger event callbacks. Higher-level APIs must take care of notifying
		// the callbacks.
		DebugStopReason LaunchAndWaitInternal();
		DebugStopReason AttachAndWaitInternal();
		DebugStopReason ConnectAndWaitInternal();
		DebugStopReason PauseAndWaitInternal();
		DebugStopReason GoAndWaitInternal();
		DebugStopReason GoReverseAndWaitInternal();
		DebugStopReason StepIntoAndWaitInternal();
		DebugStopReason StepIntoReverseAndWaitInternal();
		DebugStopReason EmulateStepOverAndWait();
		DebugStopReason StepOverAndWaitInternal();
		DebugStopReason StepOverReverseAndWaitInternal();
		DebugStopReason EmulateStepReturnAndWait();
		DebugStopReason StepReturnAndWaitInternal();
		DebugStopReason StepReturnReverseAndWaitInternal();
		DebugStopReason RunToAndWaitInternal(const std::vector<uint64_t> &remoteAddresses);

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
		std::string m_lastCommand;

		bool m_zeroSegmentAddedByDebugger = false;

		void DetectLoadedModule();

	public:
		DebuggerController(BinaryViewRef data);
		static DbgRef<DebuggerController> GetController(BinaryViewRef data);
		static void DeleteController(BinaryViewRef data);
		static bool ControllerExists(BinaryViewRef data);

		static DbgRef<DebuggerController> GetController(FileMetadataRef file);
		static void DeleteController(FileMetadataRef file);
		static bool ControllerExists(FileMetadataRef file);

		// Explicitly destroy the current controller, so a new controller on the same binaryview will be brand new.
		// I am not super sure that this is the correct way of doing things, but it addresses the controller reuse
		// problem.
		void Destroy();
		~DebuggerController();

		// breakpoints
		void AddBreakpoint(uint64_t address);
		void AddBreakpoint(const ModuleNameAndOffset& address);
		void DeleteBreakpoint(uint64_t address);
		void DeleteBreakpoint(const ModuleNameAndOffset& address);
		DebugBreakpoint GetAllBreakpoints();

		// registers
		uint64_t GetRegisterValue(const std::string& name);
		bool SetRegisterValue(const std::string& name, uint64_t value);
		std::vector<DebugRegister> GetAllRegisters();

		// processes
		std::vector<DebugProcess> GetProcessList();

		// threads
		DebugThread GetActiveThread() const;
		void SetActiveThread(const DebugThread& thread);
		std::vector<DebugThread> GetAllThreads();
		std::vector<DebugFrame> GetFramesOfThread(uint64_t tid);
		bool SuspendThread(std::uint32_t tid);
		bool ResumeThread(std::uint32_t tid);

		// modules
		std::vector<DebugModule> GetAllModules();
		DebugModule GetModuleByName(const std::string& module);
		bool GetModuleBase(const std::string& name, uint64_t& address);
		DebugModule GetModuleForAddress(uint64_t remoteAddress);
		ModuleNameAndOffset AbsoluteAddressToRelative(uint64_t absoluteAddress);
		uint64_t RelativeAddressToAbsolute(const ModuleNameAndOffset& relativeAddress);

		// arch
		ArchitectureRef GetRemoteArchitecture();

		// status
		DebugAdapterConnectionStatus GetConnectionStatus();

		DebugAdapterTargetStatus GetExecutionStatus();

		// memory
		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size);
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer);

		// debugger events
		size_t RegisterEventCallback(
			std::function<void(const DebuggerEvent& event)> callback, const std::string& name = "");
		bool RemoveEventCallback(size_t index);
		bool RemoveEventCallbackInternal(size_t index);
		void NotifyStopped(DebugStopReason reason, void* data = nullptr);
		void NotifyError(const std::string& error, const std::string& shortError, void* data = nullptr);
		void NotifyEvent(DebuggerEventType event);
		void PostDebuggerEvent(const DebuggerEvent& event);
		void CleanUpDisabledEvent();

		// shortcut for instruction pointer
		uint64_t GetLastIP() const { return m_lastIP; }
		uint64_t GetCurrentIP() const { return m_currentIP; }
		bool SetIP(uint64_t address);

		// target control
		bool Execute();
		bool Restart();
		bool ConnectToDebugServer();
		bool DisconnectDebugServer();
		// Convenience function, either launch the target process or connect to a remote, depending on the selected
		// adapter
		void LaunchOrConnect();

		// Asynchronous APIs.
		bool Launch();
		bool Connect();
		bool Attach();
		void Detach();
		bool Go();
		bool GoReverse();
		void Quit();
		bool StepInto(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepIntoReverse(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepOver(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepOverReverse(BNFunctionGraphType il);
		bool StepReturn();
		bool StepReturnReverse();
		bool RunTo(const std::vector<uint64_t>& remoteAddresses);
		bool Pause();

		DebugStopReason ExecuteAdapterAndWait(const DebugAdapterOperation operation);

		// Synchronous APIs
		DebugStopReason LaunchAndWait();
		DebugStopReason GoAndWait();
		DebugStopReason GoReverseAndWait();
		DebugStopReason AttachAndWait();
		DebugStopReason RestartAndWait();
		DebugStopReason ConnectAndWait();
		DebugStopReason StepIntoAndWait(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepIntoReverseAndWait(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepOverAndWait(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepOverReverseAndWait(BNFunctionGraphType il);
		DebugStopReason StepReturnAndWait();
		DebugStopReason StepReturnReverseAndWait();
		DebugStopReason RunToAndWait(const std::vector<uint64_t>& remoteAddresses);
		DebugStopReason PauseAndWait();
		void DetachAndWait();
		void QuitAndWait();

		// getters
		DebugAdapter* GetAdapter() { return m_adapter; }
		DebuggerState* GetState() { return m_state; }
		BinaryViewRef GetData() { return m_data; }
		FileMetadataRef GetFile() { return m_file; }
		void SetData(BinaryViewRef view) {}
		DebuggerFileAccessor* GetMemoryAccessor() const { return m_accessor; }

		uint32_t GetExitCode();

		void WriteStdIn(const std::string message);

		std::string InvokeBackendCommand(const std::string& cmd);

		static std::string GetStopReasonString(DebugStopReason);
		DebugStopReason StopReason() const;

		BinaryNinja::Ref<BinaryNinja::Metadata> GetAdapterProperty(const std::string& name);
		bool SetAdapterProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);

		bool ActivateDebugAdapter();

		// Dereference an address and check for printable strings, functions, symbols, etc
		std::string GetAddressInformation(uint64_t address);

		bool IsFirstLaunch();
		bool IsTTD();

		void OnRebased(BinaryView* oldView, BinaryView* newView) override {
			m_data = newView;
			m_viewStart = newView->GetStart();
			// UnregisterNotification() is not designed to be called from one of the callbacks, so we cannot call it
			// here. Also, there is no need to do so -- the oldView is about to be deleted
			// oldView->UnregisterNotification(this);
			newView->RegisterNotification(this);
		}

		bool RemoveDebuggerMemoryRegion();
		bool ReAddDebuggerMemoryRegion();

		uint64_t GetViewFileSegmentsStart() { return m_viewStart; }

		bool ComputeExprValueAPI(const LowLevelILInstruction& instr, uint64_t& value);
		bool ComputeExprValue(const LowLevelILInstruction& instr, uint64_t& value);
		uint64_t GetValueFromComparison(const BNLowLevelILOperation op, uint64_t left, uint64_t right, size_t size);

		bool ComputeExprValueAPI(const MediumLevelILInstruction& instr, uint64_t& value);
		bool ComputeExprValue(const MediumLevelILInstruction& instr, uint64_t& value);
		uint64_t GetValueFromComparison(const BNMediumLevelILOperation op, uint64_t left, uint64_t right, size_t size);

		bool ComputeExprValueAPI(const HighLevelILInstruction& instr, uint64_t& value);
		bool ComputeExprValue(const HighLevelILInstruction& instr, uint64_t& value);
		uint64_t GetValueFromComparison(const BNHighLevelILOperation op, uint64_t left, uint64_t right, size_t size);

		bool GetVariableValueAPI(const Variable& var, uint64_t address, size_t size, uint64_t& value);
		bool GetVariableValue(const Variable& var, uint64_t address, size_t size, uint64_t& value);
	};
};  // namespace BinaryNinjaDebugger
