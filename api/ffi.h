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

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __GNUC__
	#ifdef DEBUGGER_LIBRARY
		#define DEBUGGER_FFI_API __attribute__((visibility("default")))
	#else  // DEBUGGER_LIBRARY
		#define DEBUGGER_FFI_API
	#endif  // DEBUGGER_LIBRARY
#else       // __GNUC__
	#ifdef _MSC_VER
		#ifndef DEMO_EDITION
			#ifdef DEBUGGER_LIBRARY
				#define DEBUGGER_FFI_API __declspec(dllexport)
			#else  // DEBUGGER_LIBRARY
				#define DEBUGGER_FFI_API __declspec(dllimport)
			#endif  // DEBUGGER_LIBRARY
		#else
			#define DEBUGGER_FFI_API
		#endif
	#else  // _MSC_VER
		#define DEBUGGER_FFI_API
	#endif  // _MSC_VER
#endif      // __GNUC__C

	typedef struct BNDebuggerController BNDebuggerController;
	typedef struct BNDebugAdapterType BNDebugAdapterType;
	typedef struct BNDebugAdapter BNDebugAdapter;
	typedef struct BNDebuggerState BNDebuggerState;

	typedef struct BNBinaryView BNBinaryView;
	typedef struct BNFileMetadata BNFileMetadata;
	typedef struct BNArchitecture BNArchitecture;
	typedef struct BNDataBuffer BNDataBuffer;
	typedef struct BNMetadata BNMetadata;
	typedef struct BNLowLevelILFunction BNLowLevelILFunction;
	typedef struct BNMediumLevelILFunction BNMediumLevelILFunction;
	typedef struct BNHighLevelILFunction BNHighLevelILFunction;
	typedef struct BNVariable BNVariable;
	typedef struct BNSettings BNSettings;

//	When `ffi.h` gets parsed by clang type parser, the binaryninjacore.h is NOT included so this enum will become not
//	defined. As a workaround, I duplicate its definition here. When the code gets compiled, the `BN_TYPE_PARSER` is
//	not defined so the enum will not be redefined.
#ifdef BN_TYPE_PARSER
	typedef enum BNFunctionGraphType
	{
		InvalidILViewType = -1,
		NormalFunctionGraph = 0,
		LowLevelILFunctionGraph = 1,
		LiftedILFunctionGraph = 2,
		LowLevelILSSAFormFunctionGraph = 3,
		MediumLevelILFunctionGraph = 4,
		MediumLevelILSSAFormFunctionGraph = 5,
		MappedMediumLevelILFunctionGraph = 6,
		MappedMediumLevelILSSAFormFunctionGraph = 7,
		HighLevelILFunctionGraph = 8,
		HighLevelILSSAFormFunctionGraph = 9,
		HighLevelLanguageRepresentationFunctionGraph = 10,
	} BNFunctionGraphType;
#endif

	typedef struct BNDebugProcess
	{
		uint32_t m_pid;
		char* m_processName;
	} BNDebugProcess;

	typedef struct BNDebugThread
	{
		uint32_t m_tid;
		uint64_t m_rip;
		bool m_isFrozen;
	} BNDebugThread;

	typedef struct BNDebugFrame
	{
		size_t m_index;
		uint64_t m_pc;
		uint64_t m_sp;
		uint64_t m_fp;
		char* m_functionName;
		uint64_t m_functionStart;
		char* m_module;
	} BNDebugFrame;


	typedef struct BNDebugModule
	{
		char* m_name;
		char* m_short_name;
		uint64_t m_address;
		size_t m_size;
		bool m_loaded;
	} BNDebugModule;


	typedef struct BNDebugRegister
	{
		char* m_name;
		uint8_t m_value[64] = {0};
		size_t m_width;
		size_t m_registerIndex;
		char* m_hint;
	} BNDebugRegister;


	typedef struct BNDebugBreakpoint
	{
		// TODO: we should add an absolute address to this, along with a boolean telling whether it is valid
		char* module;
		uint64_t offset;
		uint64_t address;
		bool enabled;
	} BNDebugBreakpoint;


	typedef struct BNModuleNameAndOffset
	{
		char* module;
		uint64_t offset;
	} BNModuleNameAndOffset;


	typedef enum BNDebugStopReason
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
	} BNDebugStopReason;


	typedef enum BNDebugAdapterConnectionStatus
	{
		DebugAdapterNotConnectedStatus,
		DebugAdapterConnectingStatus,
		DebugAdapterConnectedStatus,
	} BNDebugAdapterConnectionStatus;


	typedef enum BNDebugAdapterTargetStatus
	{
		// Target is not created yet, or not connected to yet
		DebugAdapterInvalidStatus,
		DebugAdapterRunningStatus,
		DebugAdapterPausedStatus,
	} BNDebugAdapterTargetStatus;


	typedef enum BNDebuggerEventType
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
		LaunchFailureEventType,

		StdoutMessageEventType,
		BackendMessageEventType,

		TargetExitedEventType,
		DetachedEventType,

		AbsoluteBreakpointAddedEvent,
		RelativeBreakpointAddedEvent,
		AbsoluteBreakpointRemovedEvent,
		RelativeBreakpointRemovedEvent,

		ActiveThreadChangedEvent,

		DebuggerAdapterChangedEvent,
		// This event is only emitted when the value of a register is modified explicitly (e.g., using Python API,
		// in the register widget, etc.). It is not emitted when the target executes and then stops.
		RegisterChangedEvent,
		ThreadStateChangedEvent,

		ForceMemoryCacheUpdateEvent,
	} BNDebuggerEventType;


	typedef struct BNTargetStoppedEventData
	{
		BNDebugStopReason reason;
		uint32_t lastActiveThread;
		size_t exitCode;
		void* data;
	} BNTargetStoppedEventData;


	typedef struct BNErrorEventData
	{
		char* error;
		char* shortError;
		void* data;
	} BNErrorEventData;


	typedef struct BNTargetExitedEventData
	{
		uint64_t exitCode;
	} BNTargetExitedEventData;


	typedef struct BNStdoutMessageEventData
	{
		char* message;
	} BNStdoutMessageEventData;


	// This should really be a union, but gcc complains...
	typedef struct BNDebuggerEventData
	{
		BNTargetStoppedEventData targetStoppedData;
		BNErrorEventData errorData;
		uint64_t absoluteAddress;
		BNModuleNameAndOffset relativeAddress;
		BNTargetExitedEventData exitData;
		BNStdoutMessageEventData messageData;
	} BNDebuggerEventData;


	typedef struct BNDebuggerEvent
	{
		BNDebuggerEventType type;
		BNDebuggerEventData data;
	} BNDebuggerEvent;

    typedef enum BNDebuggerAdapterOperation
    {
		DebugAdapterLaunch,
		DebugAdapterAttach,
		DebugAdapterConnect,
        DebugAdapterGo,
        DebugAdapterStepInto,
        DebugAdapterStepOver,
        DebugAdapterStepReturn,
        DebugAdapterPause,
        DebugAdapterQuit,
        DebugAdapterDetach,
		DebugAdapterStepIntoReverse,
    	DebugAdapterStepOverReverse,
    	DebugAdapterGoReverse,
    	DebugAdapterStepReturnReverse,
    } BNDebuggerAdapterOperation;

	typedef struct BNDebuggerUICallbacks
	{
		void (*rebaseBinaryView)(void* ctxt, uint64_t newBase);
	}BNDebuggerUICallbacks;

	DEBUGGER_FFI_API char* BNDebuggerAllocString(const char* string);
	DEBUGGER_FFI_API char** BNDebuggerAllocStringList(const char** stringList, size_t count);
	DEBUGGER_FFI_API void BNDebuggerFreeString(char* string);
	DEBUGGER_FFI_API void BNDebuggerFreeStringList(char** stringList, size_t count);

	DEBUGGER_FFI_API BNDebuggerController* BNGetDebuggerController(BNBinaryView* data);
	DEBUGGER_FFI_API void BNDebuggerDestroyController(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerControllerExists(BNBinaryView* data);
	DEBUGGER_FFI_API BNDebuggerController* BNGetDebuggerControllerFromFile(BNFileMetadata* file);
	DEBUGGER_FFI_API bool BNDebuggerControllerExistsFromFile(BNFileMetadata* file);
	DEBUGGER_FFI_API BNBinaryView* BNDebuggerGetData(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerSetData(BNDebuggerController* controller, BNBinaryView* data);
	DEBUGGER_FFI_API BNArchitecture* BNDebuggerGetRemoteArchitecture(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsConnected(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsConnectedToDebugServer(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsRunning(BNDebuggerController* controller);

	DEBUGGER_FFI_API BNDebuggerController* BNDebuggerNewControllerReference(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerFreeController(BNDebuggerController* view);

	DEBUGGER_FFI_API uint64_t BNDebuggerGetStackPointer(BNDebuggerController* controller);

	DEBUGGER_FFI_API BNDataBuffer* BNDebuggerReadMemory(
		BNDebuggerController* controller, uint64_t address, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerWriteMemory(
		BNDebuggerController* controller, uint64_t address, BNDataBuffer* buffer);

	DEBUGGER_FFI_API BNDebugProcess* BNDebuggerGetProcessList(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeProcessList(BNDebugProcess* processes, size_t count);

	DEBUGGER_FFI_API BNDebugThread* BNDebuggerGetThreads(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeThreads(BNDebugThread* threads, size_t count);

	DEBUGGER_FFI_API BNDebugThread BNDebuggerGetActiveThread(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerSetActiveThread(BNDebuggerController* controller, BNDebugThread thread);
	DEBUGGER_FFI_API bool BNDebuggerSuspendThread(BNDebuggerController* controller, uint32_t tid);
	DEBUGGER_FFI_API bool BNDebuggerResumeThread(BNDebuggerController* controller, uint32_t tid);

	DEBUGGER_FFI_API BNDebugFrame* BNDebuggerGetFramesOfThread(
		BNDebuggerController* controller, uint32_t tid, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeFrames(BNDebugFrame* frames, size_t count);

	DEBUGGER_FFI_API BNDebugModule* BNDebuggerGetModules(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeModules(BNDebugModule* modules, size_t count);

	DEBUGGER_FFI_API BNDebugRegister* BNDebuggerGetRegisters(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeRegisters(BNDebugRegister* modules, size_t count);
	DEBUGGER_FFI_API bool BNDebuggerSetRegisterValue(
		BNDebuggerController* controller, const char* name, const uint8_t* value);
	DEBUGGER_FFI_API void BNDebuggerGetRegisterValue(BNDebuggerController* controller, const char* name,
		uint8_t* buffer);

	// target control
	DEBUGGER_FFI_API bool BNDebuggerLaunch(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerLaunchAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerExecute(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerRestart(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerQuit(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerQuitAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerConnect(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerConnectAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerConnectToDebugServer(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerDisconnectDebugServer(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerDetach(BNDebuggerController* controller);
	// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
	DEBUGGER_FFI_API void BNDebuggerLaunchOrConnect(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerAttach(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerAttachAndWait(BNDebuggerController* controller);

	DEBUGGER_FFI_API bool BNDebuggerGo(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerGoReverse(BNDebuggerController* controller);

	DEBUGGER_FFI_API bool BNDebuggerStepInto(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API bool BNDebuggerStepIntoReverse(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API bool BNDebuggerStepOver(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API bool BNDebuggerStepOverReverse(BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API bool BNDebuggerStepReturn(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerStepReturnReverse(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerRunTo(
		BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);
	DEBUGGER_FFI_API void BNDebuggerPause(BNDebuggerController* controller);

	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGoAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGoReverseAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepIntoAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepIntoReverseAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepOverAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepOverReverseAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepReturnAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepReturnReverseAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRunToAndWait(
		BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerPauseAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRestartAndWait(BNDebuggerController* controller);

	DEBUGGER_FFI_API char* BNDebuggerGetAdapterType(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerSetAdapterType(BNDebuggerController* controller, const char* adapter);

	DEBUGGER_FFI_API BNDebugAdapterConnectionStatus BNDebuggerGetConnectionStatus(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugAdapterTargetStatus BNDebuggerGetTargetStatus(BNDebuggerController* controller);

	DEBUGGER_FFI_API char* BNDebuggerGetRemoteHost(BNDebuggerController* controller);
	DEBUGGER_FFI_API uint32_t BNDebuggerGetRemotePort(BNDebuggerController* controller);
	DEBUGGER_FFI_API int32_t BNDebuggerGetPIDAttach(BNDebuggerController* controller);
	DEBUGGER_FFI_API char* BNDebuggerGetInputFile(BNDebuggerController* controller);
	DEBUGGER_FFI_API char* BNDebuggerGetExecutablePath(BNDebuggerController* controller);
	DEBUGGER_FFI_API char* BNDebuggerGetWorkingDirectory(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerGetRequestTerminalEmulator(BNDebuggerController* controller);
	DEBUGGER_FFI_API char* BNDebuggerGetCommandLineArguments(BNDebuggerController* controller);

	DEBUGGER_FFI_API void BNDebuggerSetRemoteHost(BNDebuggerController* controller, const char* host);
	DEBUGGER_FFI_API void BNDebuggerSetRemotePort(BNDebuggerController* controller, uint32_t port);
	DEBUGGER_FFI_API void BNDebuggerSetPIDAttach(BNDebuggerController* controller, int32_t pid);
	DEBUGGER_FFI_API void BNDebuggerSetInputFile(BNDebuggerController* controller, const char* path);
	DEBUGGER_FFI_API void BNDebuggerSetExecutablePath(BNDebuggerController* controller, const char* path);
	DEBUGGER_FFI_API void BNDebuggerSetWorkingDirectory(BNDebuggerController* controller, const char* path);
	DEBUGGER_FFI_API void BNDebuggerSetRequestTerminalEmulator(BNDebuggerController* controller, bool requestEmulator);
	DEBUGGER_FFI_API void BNDebuggerSetCommandLineArguments(BNDebuggerController* controller, const char* args);

	DEBUGGER_FFI_API BNDebugBreakpoint* BNDebuggerGetBreakpoints(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeBreakpoints(BNDebugBreakpoint* breakpoints, size_t count);

	DEBUGGER_FFI_API void BNDebuggerDeleteAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API void BNDebuggerDeleteRelativeBreakpoint(
		BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API void BNDebuggerAddAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API void BNDebuggerAddRelativeBreakpoint(
		BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API bool BNDebuggerContainsAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API bool BNDebuggerContainsRelativeBreakpoint(
		BNDebuggerController* controller, const char* module, uint64_t offset);

	DEBUGGER_FFI_API uint64_t BNDebuggerGetIP(BNDebuggerController* controller);
	DEBUGGER_FFI_API uint64_t BNDebuggerGetLastIP(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerSetIP(BNDebuggerController* controller, uint64_t address);

	DEBUGGER_FFI_API uint64_t BNDebuggerRelativeAddressToAbsolute(
		BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API BNModuleNameAndOffset BNDebuggerAbsoluteAddressToRelative(
		BNDebuggerController* controller, uint64_t address);

	DEBUGGER_FFI_API uint32_t BNDebuggerGetExitCode(BNDebuggerController* controller);

	DEBUGGER_FFI_API void BNDebuggerWriteStdin(BNDebuggerController* controller, const char* data, size_t len);

	DEBUGGER_FFI_API char* BNDebuggerInvokeBackendCommand(BNDebuggerController* controller, const char* cmd);

	DEBUGGER_FFI_API char* BNDebuggerGetStopReasonString(BNDebugStopReason reason);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGetStopReason(BNDebuggerController* controller);

	DEBUGGER_FFI_API bool BNDebuggerActivateDebugAdapter(BNDebuggerController* controller);

	DEBUGGER_FFI_API char* BNDebuggerGetAddressInformation(BNDebuggerController* controller, uint8_t* value);
	DEBUGGER_FFI_API bool BNDebuggerIsFirstLaunch(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsFirstConnect(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsFirstConnectToDebugServer(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerIsFirstAttach(BNDebuggerController* controller);

	DEBUGGER_FFI_API bool BNDebuggerIsTTD(BNDebuggerController* controller);

	DEBUGGER_FFI_API void BNDebuggerPostDebuggerEvent(BNDebuggerController* controller, BNDebuggerEvent* event);

	DEBUGGER_FFI_API bool BNDebuggerRemoveMemoryRegion(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerReAddMemoryRegion(BNDebuggerController* controller);

	DEBUGGER_FFI_API uint64_t BNDebuggerGetViewFileSegmentsStart(BNDebuggerController* controller);

	// DebugAdapterType
	DEBUGGER_FFI_API BNDebugAdapterType* BNGetDebugAdapterTypeByName(const char* name);
	DEBUGGER_FFI_API bool BNDebugAdapterTypeCanExecute(BNDebugAdapterType* adapter, BNBinaryView* data);
	DEBUGGER_FFI_API bool BNDebugAdapterTypeCanConnect(BNDebugAdapterType* adapter, BNBinaryView* data);
	DEBUGGER_FFI_API char** BNGetAvailableDebugAdapterTypes(BNBinaryView* data, size_t* count);


	// DebugModule
	DEBUGGER_FFI_API bool BNDebuggerIsSameBaseModule(const char* module1, const char* module2);


	// Debugger events
	DEBUGGER_FFI_API size_t BNDebuggerRegisterEventCallback(BNDebuggerController* controller,
		void (*callback)(void* ctx, BNDebuggerEvent* event), const char* name, void* ctx);
	DEBUGGER_FFI_API void BNDebuggerRemoveEventCallback(BNDebuggerController* controller, size_t index);

	DEBUGGER_FFI_API void BNDebuggerSetDebuggerUICallbacks(BNDebuggerController* controller,
		BNDebuggerUICallbacks* cb, void* ctx);

	DEBUGGER_FFI_API BNMetadata* BNDebuggerGetAdapterProperty(BNDebuggerController* controller, const char* name);
	DEBUGGER_FFI_API bool BNDebuggerSetAdapterProperty(
		BNDebuggerController* controller, const char* name, BNMetadata* value);

	// Compute expression values
	DEBUGGER_FFI_API bool BNDebuggerComputeLLILExprValue(BNDebuggerController* controller,
		 BNLowLevelILFunction* function, size_t expr, uint8_t* buffer);
	DEBUGGER_FFI_API bool BNDebuggerComputeMLILExprValue(BNDebuggerController* controller,
		 BNMediumLevelILFunction* function, size_t expr, uint8_t* buffer);
	DEBUGGER_FFI_API bool BNDebuggerComputeHLILExprValue(BNDebuggerController* controller,
		 BNHighLevelILFunction* function, size_t expr, uint8_t* buffer);
	DEBUGGER_FFI_API bool BNDebuggerGetVariableValue(BNDebuggerController* controller,
		BNVariable* variable, uint64_t address, size_t size, uint8_t* buffer);

	DEBUGGER_FFI_API BNSettings* BNDebuggerGetAdapterSettings(BNDebuggerController* controller);

	DEBUGGER_FFI_API bool BNDebuggerFunctionExistsInOldView(BNDebuggerController* controller, uint64_t address);

	// Custom Debug Adapter support
	typedef struct BNCustomDebugAdapter BNCustomDebugAdapter;
	typedef struct BNCustomDebugAdapterType BNCustomDebugAdapterType;

	// Callback function types for custom debug adapter implementations
	typedef bool (*BNCustomDebugAdapterInit)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterExecute)(void* ctxt, const char* path);
	typedef bool (*BNCustomDebugAdapterExecuteWithArgs)(void* ctxt, const char* path, const char* args, const char* workingDir);
	typedef bool (*BNCustomDebugAdapterAttach)(void* ctxt, uint32_t pid);
	typedef bool (*BNCustomDebugAdapterConnect)(void* ctxt, const char* server, uint32_t port);
	typedef bool (*BNCustomDebugAdapterConnectToDebugServer)(void* ctxt, const char* server, uint32_t port);
	typedef bool (*BNCustomDebugAdapterDetach)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterQuit)(void* ctxt);
	typedef BNDebugProcess* (*BNCustomDebugAdapterGetProcessList)(void* ctxt, size_t* count);
	typedef BNDebugThread* (*BNCustomDebugAdapterGetThreadList)(void* ctxt, size_t* count);
	typedef BNDebugThread (*BNCustomDebugAdapterGetActiveThread)(void* ctxt);
	typedef uint32_t (*BNCustomDebugAdapterGetActiveThreadId)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterSetActiveThread)(void* ctxt, BNDebugThread thread);
	typedef bool (*BNCustomDebugAdapterSetActiveThreadId)(void* ctxt, uint32_t tid);
	typedef bool (*BNCustomDebugAdapterSuspendThread)(void* ctxt, uint32_t tid);
	typedef bool (*BNCustomDebugAdapterResumeThread)(void* ctxt, uint32_t tid);
	typedef BNDebugBreakpoint (*BNCustomDebugAdapterAddBreakpoint)(void* ctxt, uint64_t address);
	typedef BNDebugBreakpoint (*BNCustomDebugAdapterAddBreakpointRelative)(void* ctxt, const char* module, uint64_t offset);
	typedef bool (*BNCustomDebugAdapterRemoveBreakpoint)(void* ctxt, uint64_t address);
	typedef bool (*BNCustomDebugAdapterRemoveBreakpointRelative)(void* ctxt, const char* module, uint64_t offset);
	typedef BNDebugBreakpoint* (*BNCustomDebugAdapterGetBreakpointList)(void* ctxt, size_t* count);
	typedef BNDebugRegister* (*BNCustomDebugAdapterReadAllRegisters)(void* ctxt, size_t* count);
	typedef BNDebugRegister (*BNCustomDebugAdapterReadRegister)(void* ctxt, const char* reg);
	typedef bool (*BNCustomDebugAdapterWriteRegister)(void* ctxt, const char* reg, const uint8_t* value);
	typedef BNDataBuffer* (*BNCustomDebugAdapterReadMemory)(void* ctxt, uint64_t address, size_t size);
	typedef bool (*BNCustomDebugAdapterWriteMemory)(void* ctxt, uint64_t address, BNDataBuffer* buffer);
	typedef BNDebugModule* (*BNCustomDebugAdapterGetModuleList)(void* ctxt, size_t* count);
	typedef char* (*BNCustomDebugAdapterGetTargetArchitecture)(void* ctxt);
	typedef BNDebugStopReason (*BNCustomDebugAdapterStopReason)(void* ctxt);
	typedef uint64_t (*BNCustomDebugAdapterExitCode)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterBreakInto)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterGo)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterGoReverse)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterStepInto)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterStepIntoReverse)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterStepOver)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterStepOverReverse)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterStepReturn)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterStepReturnReverse)(void* ctxt);
	typedef char* (*BNCustomDebugAdapterInvokeBackendCommand)(void* ctxt, const char* command);
	typedef uint64_t (*BNCustomDebugAdapterGetInstructionOffset)(void* ctxt);
	typedef uint64_t (*BNCustomDebugAdapterGetStackPointer)(void* ctxt);
	typedef bool (*BNCustomDebugAdapterSupportFeature)(void* ctxt, uint32_t feature);
	typedef void (*BNCustomDebugAdapterWriteStdin)(void* ctxt, const char* msg);
	typedef BNMetadata* (*BNCustomDebugAdapterGetProperty)(void* ctxt, const char* name);
	typedef bool (*BNCustomDebugAdapterSetProperty)(void* ctxt, const char* name, BNMetadata* value);
	typedef BNSettings* (*BNCustomDebugAdapterGetAdapterSettings)(void* ctxt);
	typedef void (*BNCustomDebugAdapterFreeCallback)(void* ctxt);

	// Callback function types for custom debug adapter type implementations  
	typedef BNCustomDebugAdapter* (*BNCustomDebugAdapterTypeCreate)(void* ctxt, BNBinaryView* data);
	typedef bool (*BNCustomDebugAdapterTypeIsValidForData)(void* ctxt, BNBinaryView* data);
	typedef bool (*BNCustomDebugAdapterTypeCanExecute)(void* ctxt, BNBinaryView* data);
	typedef bool (*BNCustomDebugAdapterTypeCanConnect)(void* ctxt, BNBinaryView* data);
	typedef void (*BNCustomDebugAdapterTypeFreeCallback)(void* ctxt);

	// Callback structures
	typedef struct BNCustomDebugAdapterCallbacks
	{
		void* context;
		BNCustomDebugAdapterInit init;
		BNCustomDebugAdapterExecute execute;
		BNCustomDebugAdapterExecuteWithArgs executeWithArgs;
		BNCustomDebugAdapterAttach attach;
		BNCustomDebugAdapterConnect connect;
		BNCustomDebugAdapterConnectToDebugServer connectToDebugServer;
		BNCustomDebugAdapterDetach detach;
		BNCustomDebugAdapterQuit quit;
		BNCustomDebugAdapterGetProcessList getProcessList;
		BNCustomDebugAdapterGetThreadList getThreadList;
		BNCustomDebugAdapterGetActiveThread getActiveThread;
		BNCustomDebugAdapterGetActiveThreadId getActiveThreadId;
		BNCustomDebugAdapterSetActiveThread setActiveThread;
		BNCustomDebugAdapterSetActiveThreadId setActiveThreadId;
		BNCustomDebugAdapterSuspendThread suspendThread;
		BNCustomDebugAdapterResumeThread resumeThread;
		BNCustomDebugAdapterAddBreakpoint addBreakpoint;
		BNCustomDebugAdapterAddBreakpointRelative addBreakpointRelative;
		BNCustomDebugAdapterRemoveBreakpoint removeBreakpoint;
		BNCustomDebugAdapterRemoveBreakpointRelative removeBreakpointRelative;
		BNCustomDebugAdapterGetBreakpointList getBreakpointList;
		BNCustomDebugAdapterReadAllRegisters readAllRegisters;
		BNCustomDebugAdapterReadRegister readRegister;
		BNCustomDebugAdapterWriteRegister writeRegister;
		BNCustomDebugAdapterReadMemory readMemory;
		BNCustomDebugAdapterWriteMemory writeMemory;
		BNCustomDebugAdapterGetModuleList getModuleList;
		BNCustomDebugAdapterGetTargetArchitecture getTargetArchitecture;
		BNCustomDebugAdapterStopReason stopReason;
		BNCustomDebugAdapterExitCode exitCode;
		BNCustomDebugAdapterBreakInto breakInto;
		BNCustomDebugAdapterGo go;
		BNCustomDebugAdapterGoReverse goReverse;
		BNCustomDebugAdapterStepInto stepInto;
		BNCustomDebugAdapterStepIntoReverse stepIntoReverse;
		BNCustomDebugAdapterStepOver stepOver;
		BNCustomDebugAdapterStepOverReverse stepOverReverse;
		BNCustomDebugAdapterStepReturn stepReturn;
		BNCustomDebugAdapterStepReturnReverse stepReturnReverse;
		BNCustomDebugAdapterInvokeBackendCommand invokeBackendCommand;
		BNCustomDebugAdapterGetInstructionOffset getInstructionOffset;
		BNCustomDebugAdapterGetStackPointer getStackPointer;
		BNCustomDebugAdapterSupportFeature supportFeature;
		BNCustomDebugAdapterWriteStdin writeStdin;
		BNCustomDebugAdapterGetProperty getProperty;
		BNCustomDebugAdapterSetProperty setProperty;
		BNCustomDebugAdapterGetAdapterSettings getAdapterSettings;
		BNCustomDebugAdapterFreeCallback freeCallback;
	} BNCustomDebugAdapterCallbacks;

	typedef struct BNCustomDebugAdapterTypeCallbacks
	{
		void* context;
		BNCustomDebugAdapterTypeCreate create;
		BNCustomDebugAdapterTypeIsValidForData isValidForData;
		BNCustomDebugAdapterTypeCanExecute canExecute;
		BNCustomDebugAdapterTypeCanConnect canConnect;
		BNCustomDebugAdapterTypeFreeCallback freeCallback;
	} BNCustomDebugAdapterTypeCallbacks;

	// Functions for registering custom debug adapters
	DEBUGGER_FFI_API BNCustomDebugAdapterType* BNRegisterCustomDebugAdapterType(
		const char* name, BNCustomDebugAdapterTypeCallbacks* callbacks);
	DEBUGGER_FFI_API void BNUnregisterCustomDebugAdapterType(BNCustomDebugAdapterType* adapterType);

	// Functions for custom debug adapter creation
	DEBUGGER_FFI_API BNCustomDebugAdapter* BNCreateCustomDebugAdapter(BNCustomDebugAdapterCallbacks* callbacks);
	DEBUGGER_FFI_API void BNFreeCustomDebugAdapter(BNCustomDebugAdapter* adapter);

#ifdef __cplusplus
}
#endif
