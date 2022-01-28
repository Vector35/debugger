#pragma once
#include "binaryninjaapi.h"
#include "debuggerstate.h"
#include "debuggerevent.h"
#include <queue>
#include "ffi.h"

namespace BinaryNinjaDebugger
{

	struct DebuggerEventCallback
	{
		std::function<void(const DebuggerEvent &event)> function;
		size_t index;
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

		void DeleteController(BinaryViewRef data);

		std::atomic<size_t> m_callbackIndex = 0;
		std::vector<DebuggerEventCallback> m_eventCallbacks;
		std::recursive_mutex m_callbackMutex;

		uint64_t m_lastIP = 0;
		uint64_t m_currentIP = 0;

		bool m_userRequestedBreak = false;

		void EventHandler(const DebuggerEvent &event);
		DebugAdapter *CreateDebugAdapter();
		void HandleTargetStop(BNDebugStopReason reason);
		void HandleInitialBreakpoint();
		void AddEntryBreakpoint();

		void SetLiveView(BinaryViewRef view) { m_liveView = view; }

		void SetData(BinaryViewRef view) { m_data = view; }

		void PauseInternal();
		BNDebugStopReason GoInternal();
		BNDebugStopReason StepIntoInternal();
		BNDebugStopReason StepOverInternal();
		BNDebugStopReason StepReturnInternal();
		BNDebugStopReason StepToInternal(const std::vector<uint64_t> &remoteAddresses);
		BNDebugStopReason StepIntoIL(BNFunctionGraphType il);
		BNDebugStopReason StepOverIL(BNFunctionGraphType il);

		// Whether we can resume the execution of the target, including stepping.
		bool CanResumeTarget();

	public:
		DebuggerController(BinaryViewRef data);
		static DebuggerController *GetController(BinaryViewRef data);

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
		void NotifyStopped(BNDebugStopReason reason, void *data = nullptr);
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
		void Detach();
		void Pause();
		// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
		void LaunchOrConnect();

		BNDebugStopReason Go();
		BNDebugStopReason StepInto(BNFunctionGraphType il = NormalFunctionGraph);
		BNDebugStopReason StepOver(BNFunctionGraphType il = NormalFunctionGraph);
		BNDebugStopReason StepReturn();
		BNDebugStopReason StepTo(const std::vector<uint64_t> &remoteAddresses);

		// getters
		DebugAdapter *GetAdapter() { return m_adapter; }
		DebuggerState *GetState() { return m_state; }
		BinaryViewRef GetData() const { return m_data; }
		BinaryViewRef GetLiveView() const { return m_liveView; }
	};
};
