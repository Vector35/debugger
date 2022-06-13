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

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __GNUC__
	#ifdef DEBUGGER_LIBRARY
		#define DEBUGGER_FFI_API __attribute__((visibility("default")))
	#else // DEBUGGER_LIBRARY
		#define DEBUGGER_FFI_API
	#endif // DEBUGGER_LIBRARY
#else // __GNUC__
#ifdef _MSC_VER
	#ifndef DEMO_VERSION
		#ifdef DEBUGGER_LIBRARY
			#define DEBUGGER_FFI_API __declspec(dllexport)
		#else // DEBUGGER_LIBRARY
			#define DEBUGGER_FFI_API __declspec(dllimport)
		#endif // DEBUGGER_LIBRARY
	#else
		#define DEBUGGER_FFI_API
	#endif
#else // _MSC_VER
#define DEBUGGER_FFI_API
#endif // _MSC_VER
#endif // __GNUC__C

	struct BNDebuggerController;
	struct BNDebugAdapterType;
	struct BNDebugAdapter;
	struct BNDebuggerState;

	struct BNBinaryView;
	struct BNArchitecture;
	struct BNDataBuffer;
	enum BNFunctionGraphType;

	struct BNDebugThread
	{
		uint32_t m_tid;
		uint64_t m_rip;
	};

	struct BNDebugFrame
	{
		size_t m_index;
		uint64_t m_pc;
		uint64_t m_sp;
		uint64_t m_fp;
		char* m_functionName;
		uint64_t m_functionStart;
		char* m_module;
	};


	struct BNDebugModule
	{
		char* m_name;
		char* m_short_name;
		uint64_t m_address;
		size_t m_size;
		bool m_loaded;
	};


	struct BNDebugRegister
	{
		char* m_name;
		uint64_t m_value;
		size_t m_width;
		size_t m_registerIndex;
		char* m_hint;
	};


	struct BNDebugBreakpoint
	{
		// TODO: we should add an absolute address to this, along with a boolean telling whether it is valid
		char* module;
		uint64_t offset;
		uint64_t address;
		bool enabled;
	};


	struct BNModuleNameAndOffset
	{
		char* module;
		uint64_t offset;
	};


	enum BNDebugStopReason
	{
		UnknownReason = 0,
		InitialBreakpoint,
		ProcessExited,
		AccessViolation,
		SingleStep,
		Calculation,
		Breakpoint,
		IllegalInstruction,
		SignalHup,
		SignalInt,
		SignalQuit,
		SignalIll,
		SignalAbrt,
		SignalEmt,
		SignalFpe,
		SignalKill,
		SignalBus,
		SignalSegv,
		SignalSys,
		SignalPipe,
		SignalAlrm,
		SignalTerm,
		SignalUrg,
		SignalStop,
		SignalTstp,
		SignalCont,
		SignalChld,
		SignalTtin,
		SignalTtou,
		SignalIo,
		SignalXcpu,
		SignalXfsz,
		SignalVtalrm,
		SignalProf,
		SignalWinch,
		SignalInfo,
		SignalUsr1,
		SignalUsr2,
		SignalStkflt,
		SignalBux,
		SignalPoll,
		ExcEmulation,
		ExcSoftware,
		ExcSyscall,
		ExcMachSyscall,
		ExcRpcAlert,
		ExcCrash,

		InternalError,
		InvalidStatusOrOperation,

		UserRequestedBreak,

		OperationNotSupported
	};


	enum BNDebugAdapterConnectionStatus
	{
		DebugAdapterNotConnectedStatus,
		DebugAdapterConnectingStatus,
		DebugAdapterConnectedStatus,
	};


	enum BNDebugAdapterTargetStatus
	{
		// Target is not created yet, or not connected to yet
		DebugAdapterInvalidStatus,
		DebugAdapterRunningStatus,
		DebugAdapterPausedStatus,
	};


	enum BNDebuggerEventType
	{
		LaunchEventType,
		ResumeEventType,
		StepIntoEventType,
		StepOverEventType,
		StepReturnEventType,
		StepToEventType,
		RestartEventType,
		AttachEventType,
		DetachEventType,
		ConnectEventType,

		AdapterStoppedEventType,
		AdapterTargetExitedEventType,

		InvalidOperationEventType,
		InternalErrorEventType,

		TargetStoppedEventType,
		ErrorEventType,
		GeneralEventType,

		StdoutMessageEventType,
		BackendMessageEventType,

		TargetExitedEventType,
		DetachedEventType,
		QuitDebuggingEventType,
		BackEndDisconnectedEventType,

		AbsoluteBreakpointAddedEvent,
		RelativeBreakpointAddedEvent,
		AbsoluteBreakpointRemovedEvent,
		RelativeBreakpointRemovedEvent,

		ActiveThreadChangedEvent,

		DebuggerSettingsChangedEvent,
	};


	struct BNTargetStoppedEventData
	{
		BNDebugStopReason reason;
		uint32_t lastActiveThread;
		size_t exitCode;
		void* data;
	};


	struct BNErrorEventData
	{
		char* error;
		void* data;
	};


	struct BNTargetExitedEventData
	{
		uint64_t exitCode;
	};


	struct BNStdoutMessageEventData
	{
		char* message;
	};


	// This should really be a union, but gcc complains...
	struct BNDebuggerEventData
	{
		BNTargetStoppedEventData targetStoppedData;
		BNErrorEventData errorData;
		uint64_t absoluteAddress;
		BNModuleNameAndOffset relativeAddress;
		BNTargetExitedEventData exitData;
		BNStdoutMessageEventData messageData;
	};


	struct BNDebuggerEvent
	{
		BNDebuggerEventType type;
		BNDebuggerEventData data;
	};


	DEBUGGER_FFI_API char* BNDebuggerAllocString(const char* string);
	DEBUGGER_FFI_API char** BNDebuggerAllocStringList(const char** stringList, size_t count);
	DEBUGGER_FFI_API void BNDebuggerFreeString(char* string);
	DEBUGGER_FFI_API void BNDebuggerFreeStringList(char** stringList, size_t count);

	DEBUGGER_FFI_API BNDebuggerController* BNGetDebuggerController(BNBinaryView* data);
	DEBUGGER_FFI_API void BNDebuggerDestroyController(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNBinaryView* BNDebuggerGetLiveView(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNBinaryView* BNDebuggerGetData(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNArchitecture* BNDebuggerGetRemoteArchitecture(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsConnected(BNDebuggerController* controller);
    DEBUGGER_FFI_API bool BNDebuggerIsConnectedToDebugServer(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsRunning(BNDebuggerController* controller);

	DEBUGGER_FFI_API uint64_t BNDebuggerGetStackPointer(BNDebuggerController* controller);

	DEBUGGER_FFI_API BNDataBuffer* BNDebuggerReadMemory(BNDebuggerController* controller, uint64_t address, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerWriteMemory(BNDebuggerController* controller, uint64_t address, BNDataBuffer* buffer);

	DEBUGGER_FFI_API BNDebugThread* BNDebuggerGetThreads(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeThreads(BNDebugThread* threads, size_t count);

	DEBUGGER_FFI_API BNDebugThread BNDebuggerGetActiveThread(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerSetActiveThread(BNDebuggerController* controller, BNDebugThread thread);

	DEBUGGER_FFI_API BNDebugFrame* BNDebuggerGetFramesOfThread(BNDebuggerController* controller, uint32_t tid,
															   size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeFrames(BNDebugFrame* frames, size_t count);

	DEBUGGER_FFI_API BNDebugModule* BNDebuggerGetModules(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeModules(BNDebugModule* modules, size_t count);

	DEBUGGER_FFI_API BNDebugRegister* BNDebuggerGetRegisters(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeRegisters(BNDebugRegister* modules, size_t count);
	DEBUGGER_FFI_API bool BNDebuggerSetRegisterValue(BNDebuggerController* controller, const char* name, uint64_t value);
	DEBUGGER_FFI_API uint64_t BNDebuggerGetRegisterValue(BNDebuggerController* controller, const char* name);

	// target control
	DEBUGGER_FFI_API bool BNDebuggerLaunch(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerExecute(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerRestart(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerQuit(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerConnect(BNDebuggerController* controller);
    DEBUGGER_FFI_API bool BNDebuggerConnectToDebugServer(BNDebuggerController* controller);
    DEBUGGER_FFI_API bool BNDebuggerDisconnectDebugServer(BNDebuggerController* controller);
    DEBUGGER_FFI_API void BNDebuggerDetach(BNDebuggerController* controller);
	// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
	DEBUGGER_FFI_API void BNDebuggerLaunchOrConnect(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerAttach(BNDebuggerController* controller, uint32_t pid);

	DEBUGGER_FFI_API bool BNDebuggerGo(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerStepInto(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API bool BNDebuggerStepOver(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API bool BNDebuggerStepReturn(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerRunTo(BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);
	DEBUGGER_FFI_API void BNDebuggerPause(BNDebuggerController* controller);

	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGoAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepIntoAndWait(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepOverAndWait(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepReturnAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRunToAndWait(BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerPauseAndWait(BNDebuggerController* controller);

	DEBUGGER_FFI_API char* BNDebuggerGetAdapterType(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerSetAdapterType(BNDebuggerController* controller, const char* adapter);

	DEBUGGER_FFI_API BNDebugAdapterConnectionStatus BNDebuggerGetConnectionStatus(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugAdapterTargetStatus BNDebuggerGetTargetStatus(BNDebuggerController* controller);

	DEBUGGER_FFI_API char* BNDebuggerGetRemoteHost(BNDebuggerController* controller);
	DEBUGGER_FFI_API uint32_t BNDebuggerGetRemotePort(BNDebuggerController* controller);
	DEBUGGER_FFI_API char* BNDebuggerGetExecutablePath(BNDebuggerController* controller);
	DEBUGGER_FFI_API char* BNDebuggerGetWorkingDirectory(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerGetRequestTerminalEmulator(BNDebuggerController* controller);
	DEBUGGER_FFI_API char* BNDebuggerGetCommandLineArguments(BNDebuggerController* controller);

	DEBUGGER_FFI_API void BNDebuggerSetRemoteHost(BNDebuggerController* controller, const char* host);
	DEBUGGER_FFI_API void BNDebuggerSetRemotePort(BNDebuggerController* controller, uint32_t port);
	DEBUGGER_FFI_API void BNDebuggerSetExecutablePath(BNDebuggerController* controller, const char* path);
	DEBUGGER_FFI_API void BNDebuggerSetWorkingDirectory(BNDebuggerController* controller, const char* path);
	DEBUGGER_FFI_API void BNDebuggerSetRequestTerminalEmulator(BNDebuggerController* controller, bool requestEmulator);
	DEBUGGER_FFI_API void BNDebuggerSetCommandLineArguments(BNDebuggerController* controller, const char* args);

	DEBUGGER_FFI_API BNDebugBreakpoint* BNDebuggerGetBreakpoints(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeBreakpoints(BNDebugBreakpoint* breakpoints, size_t count);

	DEBUGGER_FFI_API void BNDebuggerDeleteAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API void BNDebuggerDeleteRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API void BNDebuggerAddAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API void BNDebuggerAddRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API bool BNDebuggerContainsAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API bool BNDebuggerContainsRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset);

	DEBUGGER_FFI_API uint64_t BNDebuggerGetIP(BNDebuggerController* controller);
	DEBUGGER_FFI_API uint64_t BNDebuggerGetLastIP(BNDebuggerController* controller);

	DEBUGGER_FFI_API uint64_t BNDebuggerRelativeAddressToAbsolute(BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API BNModuleNameAndOffset BNDebuggerAbsoluteAddressToRelative(BNDebuggerController* controller, uint64_t address);

	DEBUGGER_FFI_API uint32_t BNDebuggerGetExitCode(BNDebuggerController* controller);

	DEBUGGER_FFI_API void BNDebuggerWriteStdin(BNDebuggerController* controller, const char* data, size_t len);

	DEBUGGER_FFI_API char* BNDebuggerInvokeBackendCommand(BNDebuggerController* controller, const char* cmd);

	DEBUGGER_FFI_API char* BNDebuggerGetStopReasonString(BNDebugStopReason reason);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGetStopReason(BNDebuggerController* controller);

	// DebugAdapterType
	DEBUGGER_FFI_API BNDebugAdapterType* BNGetDebugAdapterTypeByName(const char* name);
	DEBUGGER_FFI_API bool BNDebugAdapterTypeCanExecute(BNDebugAdapterType* adapter, BNBinaryView* data);
	DEBUGGER_FFI_API bool BNDebugAdapterTypeCanConnect(BNDebugAdapterType* adapter, BNBinaryView* data);
	DEBUGGER_FFI_API char** BNGetAvailableDebugAdapterTypes(BNBinaryView* data, size_t* count);


	// DebugModule
	DEBUGGER_FFI_API bool BNDebuggerIsSameBaseModule(const char* module1, const char* module2);


	// Debugger events
	DEBUGGER_FFI_API size_t BNDebuggerRegisterEventCallback(BNDebuggerController* controller,
															void (*callback)(void* ctx, BNDebuggerEvent* event),
															void* ctx);
	DEBUGGER_FFI_API void BNDebuggerRemoveEventCallback(BNDebuggerController* controller, size_t index);

#ifdef __cplusplus
}
#endif
