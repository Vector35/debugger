#pragma once

#include "binaryninjaapi.h"
#include "ui/uitypes.h"
#include "processview.h"
#include "debugadaptertype.h"
#include "debuggercommon.h"
#include "semaphore.h"
#include "ffi_global.h"

DECLARE_DEBUGGER_API_OBJECT(BNDebuggerState, DebuggerState);

namespace BinaryNinjaDebugger
{
	class DebuggerState;

	typedef BNDebugAdapterConnectionStatus DebugAdapterConnectionStatus;
	typedef BNDebugAdapterTargetStatus DebugAdapterTargetStatus;

	class DebuggerRegisters
	{
	private:
		DebuggerState* m_state;
		std::unordered_map<std::string, DebugRegister> m_registerCache;
		bool m_dirty;

	public:
		DebuggerRegisters(DebuggerState* state);
		// DebugRegister operator[](std::string name);
		uint64_t GetRegisterValue(const std::string& name);
		bool SetRegisterValue(const std::string& name, uint64_t value);
		void MarkDirty();
		bool IsDirty() const { return m_dirty; }
		void Update();
		std::vector<DebugRegister> GetAllRegisters();
	};


	class DebuggerModules
	{
	private:
		DebuggerState* m_state;
		std::vector<DebugModule> m_modules;
		bool m_dirty;

	public:
		DebuggerModules(DebuggerState* state);
		void MarkDirty();
		void Update();
		bool IsDirty() const { return m_dirty; }

		std::vector<DebugModule> GetAllModules();
		// TODO: These conversion functions are not very robust for lookup failures. They need to be improved for it.
		DebugModule GetModuleByName(const std::string& module);
		uint64_t GetModuleBase(const std::string& name);
		DebugModule GetModuleForAddress(uint64_t remoteAddress);
		ModuleNameAndOffset AbsoluteAddressToRelative(uint64_t absoluteAddress);
		uint64_t RelativeAddressToAbsolute(const ModuleNameAndOffset& relativeAddress);
	};


	class DebuggerBreakpoints
	{
	private:
		DebuggerState* m_state;
		std::vector<ModuleNameAndOffset> m_breakpoints;

	public:
		DebuggerBreakpoints(DebuggerState* state, std::vector<ModuleNameAndOffset> initial = {});
		bool AddAbsolute(uint64_t remoteAddress);
		bool AddOffset(const ModuleNameAndOffset& address);
		bool RemoveAbsolute(uint64_t remoteAddress);
		bool RemoveOffset(const ModuleNameAndOffset& address);
		bool ContainsAbsolute(uint64_t address);
		bool ContainsOffset(const ModuleNameAndOffset& address);
		void Apply();
		void SerializeMetadata();
		void UnserializedMetadata();
		std::vector<ModuleNameAndOffset> GetBreakpointList() const { return m_breakpoints; }
	};


	class DebuggerThreads
	{
	private:
		DebuggerState* m_state;
		std::vector<DebugThread> m_threads;
		bool m_dirty;

	public:
		DebuggerThreads(DebuggerState* state);
		void MarkDirty();
		void Update();
		DebugThread GetActiveThread() const;
		bool SetActiveThread(const DebugThread& thread);
		bool IsDirty() const { return m_dirty; }
		std::vector<DebugThread> GetAllThreads();
	};


	class DebuggerController;

	// DebuggerState is the core of the debugger. Every operation is sent to this class, which then sends it the backend.
	// After the backend responds, it first updates its internal state, and then update the UI (if the UI is enabled).
	class DebuggerState
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNDebuggerState);

	private:
		DebuggerController* m_controller;
		DebugAdapterConnectionStatus m_connectionStatus;
		DebugAdapterTargetStatus m_targetStatus;

		DebugAdapter* m_adapter;
		DebuggerModules* m_modules;
		DebuggerRegisters* m_registers;
		DebuggerThreads* m_threads;
		DebuggerBreakpoints* m_breakpoints;
		bool m_remoteArchDirty;

		std::string m_executablePath;
		std::string m_commandLineArgs;
		std::string m_remoteHost;
		uint32_t m_remotePort = 0;
		bool m_requestTerminalEmulator;
		std::string m_adapterType;
		std::vector<std::string> m_availableAdapters;

		Ref<Architecture> m_remoteArch;

	public:
		DebuggerState(Ref<BinaryView> data, DebuggerController* controller);

		DebugAdapter* GetAdapter() const { return m_adapter; }
		DebuggerController* GetController() const { return m_controller; }

		DebuggerModules* GetModules() const { return m_modules; }
		DebuggerBreakpoints* GetBreakpoints() const { return m_breakpoints; }
		DebuggerRegisters* GetRegisters() const { return m_registers; }
		DebuggerThreads* GetThreads() const { return m_threads; }
		Ref<Architecture> GetRemoteArchitecture() const { return m_remoteArch; }

		std::string GetAdapterType() const { return m_adapterType; }
		std::string GetExecutablePath() const { return m_executablePath; }
		std::string GetCommandLineArguments() const { return m_commandLineArgs; }
		std::string GetRemoteHost() const { return m_remoteHost; }
		uint32_t GetRemotePort() const { return m_remotePort; }
		bool GetRequestTerminalEmulator() const { return m_requestTerminalEmulator; }

		void SetAdapterType(std::string adapter) { m_adapterType = adapter; }
		void SetExecutablePath(const std::string& path) { m_executablePath = path; }
		void SetCommandLineArguments(const std::string& arguments) { m_commandLineArgs = arguments; }
		void SetRemoteHost(const std::string& host) { m_remoteHost = host; }
		void SetRemotePort(uint32_t port) { m_remotePort = port; }
		void SetRequestTerminalEmulator(bool requested) { m_requestTerminalEmulator = requested; }

		// This is the center hub for adding and deleting breakpoints. It is called from DebugView, the CLI, the
		// DebugBreakpointsWidget, and the planned C++/Python API.
		// It will communicate with the adapter and add/delete the breakpoint. It will also update the UI if needed.
		void AddBreakpoint(uint64_t address);
		void AddBreakpoint(const ModuleNameAndOffset& address);
		void DeleteBreakpoint(uint64_t address);
		void DeleteBreakpoint(const ModuleNameAndOffset& address);

		uint64_t IP();
		uint64_t StackPointer();

		bool IsConnected() const { return m_connectionStatus == DebugAdapterConnectedStatus; }
		bool IsConnecting() const { return m_connectionStatus == DebugAdapterConnectingStatus; }
		bool IsRunning() const { return m_targetStatus == DebugAdapterRunningStatus; }
		DebugAdapterConnectionStatus GetConnectionStatus() const { return m_connectionStatus; }
		DebugAdapterTargetStatus GetTargetStatus() const { return m_targetStatus; }

		// This is slightly different from the Python implementation. The caller does not need to first
		// retrieve the DebuggerThreads object and then call SetActiveThread() on it. They call this function.
		bool SetActiveThread(const DebugThread& thread);

		void MarkDirty();
		void UpdateCaches();

		Ref<Architecture> DetectRemoteArch();

		uint64_t GetRemoteBase(Ref<BinaryView> relativeView = nullptr);

		void ApplyBreakpoints();

		void SetConnectionStatus(DebugAdapterConnectionStatus status) { m_connectionStatus = status; }
		void SetExecutionStatus(DebugAdapterTargetStatus status)
		{
			m_targetStatus = status;
		}

		std::vector<std::string> GetAvailableAdapters() { return m_availableAdapters; }

		void SetAdapter(DebugAdapter* adapter) { m_adapter = adapter; }
	};
};
