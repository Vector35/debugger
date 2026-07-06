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
		char* m_commandLine;
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

	typedef struct BNDebugMemoryRegion
	{
		char* m_name;
		uint64_t m_start;
		size_t m_size;
		bool m_read;
		bool m_write;
		bool m_execute;
		bool m_shared;
	} BNDebugMemoryRegion;


	typedef struct BNDebugRegister
	{
		char* m_name;
		uint8_t m_value[64] = {0};
		size_t m_width;
		size_t m_registerIndex;
		char* m_hint;
	} BNDebugRegister;


	typedef enum BNDebugBreakpointType
	{
		BNSoftwareBreakpoint = 0,        // Default software breakpoint
		BNHardwareExecuteBreakpoint = 1, // Hardware execution breakpoint
		BNHardwareReadBreakpoint = 2,    // Hardware read watchpoint
		BNHardwareWriteBreakpoint = 3,   // Hardware write watchpoint
		BNHardwareAccessBreakpoint = 4   // Hardware read/write watchpoint
	} BNDebugBreakpointType;


	typedef struct BNDebugBreakpoint
	{
		// TODO: we should add an absolute address to this, along with a boolean telling whether it is valid
		char* module;
		uint64_t offset;
		uint64_t address;
		bool enabled;
		char* condition;  // NULL if no condition
		BNDebugBreakpointType type;
		size_t size;  // Size in bytes for hardware breakpoints/watchpoints (1, 2, 4, 8)
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

		OperationNotSupported,
		TimedOut
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

		// Unified breakpoint change event - use this for all breakpoint changes (add/remove/enable/disable)
		BreakpointChangedEvent,

		ActiveThreadChangedEvent,

		DebuggerAdapterChangedEvent,
		// This event is only emitted when the value of a register is modified explicitly (e.g., using Python API,
		// in the register widget, etc.). It is not emitted when the target executes and then stops.
		RegisterChangedEvent,
		ThreadStateChangedEvent,

		ForceMemoryCacheUpdateEvent,

		TTDBookmarkChangedEvent,
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


	// TTD (Time Travel Debugging) structures
	typedef enum BNDebuggerTTDMemoryAccessType
	{
		DebuggerTTDMemoryRead = 1,
		DebuggerTTDMemoryWrite = 2,
		DebuggerTTDMemoryExecute = 4
	} BNDebuggerTTDMemoryAccessType;

	typedef struct BNDebuggerTTDPosition
	{
		uint64_t sequence;
		uint64_t step;
	} BNDebuggerTTDPosition;

	typedef struct BNDebuggerTTDMemoryEvent
	{
		char* eventType;
		uint32_t threadId;
		uint32_t uniqueThreadId;
		BNDebuggerTTDPosition timeStart;
		BNDebuggerTTDPosition timeEnd;
		uint64_t address;
		uint64_t size;
		uint64_t memoryAddress;
		uint64_t instructionAddress; // IP field
		uint64_t value; // Value field - the value that was read/written/executed
		BNDebuggerTTDMemoryAccessType accessType;
	} BNDebuggerTTDMemoryEvent;

	typedef struct BNDebuggerTTDPositionRangeIndexedMemoryEvent
	{
		BNDebuggerTTDPosition position;
		uint32_t threadId;
		uint32_t uniqueThreadId;
		uint64_t address;
		uint64_t instructionAddress;
		uint64_t size;
		BNDebuggerTTDMemoryAccessType accessType;
		uint64_t value;
		uint8_t data[8];
	} BNDebuggerTTDPositionRangeIndexedMemoryEvent;

	typedef struct BNDebuggerTTDCallEvent
	{
		char* eventType;              // Event type (always "Call" for TTD.Calls objects)
		uint32_t threadId;            // OS thread ID of thread that made the call
		uint32_t uniqueThreadId;      // Unique ID for the thread across the trace
		char* function;               // Symbolic name of the function
		uint64_t functionAddress;     // Function's address in memory
		uint64_t returnAddress;       // Instruction to return to after the call
		uint64_t returnValue;         // Return value of the function (if not void)
		bool hasReturnValue;          // Whether the function has a return value
		char** parameters;            // Array containing parameters passed to the function
		size_t parameterCount;        // Number of parameters
		BNDebuggerTTDPosition timeStart; // Position when call started
		BNDebuggerTTDPosition timeEnd;   // Position when call ended
	} BNDebuggerTTDCallEvent;

	// TTD Event Types - bitfield flags for filtering events
	typedef enum BNDebuggerTTDEventType
	{
		BNDebuggerTTDEventNone = 0,
		BNDebuggerTTDEventThreadCreated = 1,
		BNDebuggerTTDEventThreadTerminated = 2,
		BNDebuggerTTDEventModuleLoaded = 4,
		BNDebuggerTTDEventModuleUnloaded = 8,
		BNDebuggerTTDEventException = 16,
		BNDebuggerTTDEventAll = BNDebuggerTTDEventThreadCreated | BNDebuggerTTDEventThreadTerminated | BNDebuggerTTDEventModuleLoaded | BNDebuggerTTDEventModuleUnloaded | BNDebuggerTTDEventException
	} BNDebuggerTTDEventType;

	// TTD Module
	typedef struct BNDebuggerTTDModule
	{
		char* name;                   // Name and path of the module
		uint64_t address;             // Address where the module was loaded
		uint64_t size;                // Size of the module in bytes
		uint32_t checksum;            // Checksum of the module
		uint32_t timestamp;           // Timestamp of the module
	} BNDebuggerTTDModule;

	// TTD Thread
	typedef struct BNDebuggerTTDThread
	{
		uint32_t uniqueId;            // Unique ID for the thread across the trace
		uint32_t id;                  // TID of the thread
		BNDebuggerTTDPosition lifetimeStart;     // Lifetime start position
		BNDebuggerTTDPosition lifetimeEnd;       // Lifetime end position
		BNDebuggerTTDPosition activeTimeStart;   // Active time start position
		BNDebuggerTTDPosition activeTimeEnd;     // Active time end position
	} BNDebuggerTTDThread;

	// TTD Exception Types
	typedef enum BNDebuggerTTDExceptionType
	{
		BNDebuggerTTDExceptionSoftware,
		BNDebuggerTTDExceptionHardware
	} BNDebuggerTTDExceptionType;

	// TTD Exception
	typedef struct BNDebuggerTTDException
	{
		BNDebuggerTTDExceptionType type;   // Type of exception (Software/Hardware)
		uint64_t programCounter;           // Instruction where exception was thrown
		uint32_t code;                     // Exception code
		uint32_t flags;                    // Exception flags
		uint64_t recordAddress;            // Where in memory the exception record is found
		BNDebuggerTTDPosition position;    // Position where exception occurred
	} BNDebuggerTTDException;

	// TTD Event
	typedef struct BNDebuggerTTDEvent
	{
		BNDebuggerTTDEventType type;       // Type of event
		BNDebuggerTTDPosition position;    // Position where event occurred

		// Optional child objects - existence depends on event type
		BNDebuggerTTDModule* module;       // For ModuleLoaded/ModuleUnloaded events (NULL if not present)
		BNDebuggerTTDThread* thread;       // For ThreadCreated/ThreadTerminated events (NULL if not present)
		BNDebuggerTTDException* exception; // For Exception events (NULL if not present)
	} BNDebuggerTTDEvent;


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

	DEBUGGER_FFI_API uint32_t BNDebuggerGetActivePID(BNDebuggerController* controller);

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

	DEBUGGER_FFI_API BNDebugMemoryRegion* BNDebuggerGetMemoryMap(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeMemoryRegions(BNDebugMemoryRegion* regions, size_t count);

	// Read the symbols the debugger backend knows about for the named module and add them to the
	// BinaryView as auto symbols. Returns the number of symbols added.
	DEBUGGER_FFI_API size_t BNDebuggerLoadSymbolsForModule(BNDebuggerController* controller, const char* module);
	// Load the backend symbols for every currently-loaded module. Returns the total number added.
	DEBUGGER_FFI_API size_t BNDebuggerLoadSymbolsForAllModules(BNDebuggerController* controller);
	// Remove the backend symbols previously added for the named module. Returns the number removed.
	DEBUGGER_FFI_API size_t BNDebuggerRemoveSymbolsForModule(BNDebuggerController* controller, const char* module);
	// Remove every backend symbol the debugger has added. Returns the number removed.
	DEBUGGER_FFI_API size_t BNDebuggerRemoveAllLoadedSymbols(BNDebuggerController* controller);
	// The base names of the modules for which backend symbols have been loaded. Free with
	// BNDebuggerFreeStringList.
	DEBUGGER_FFI_API char** BNDebuggerGetModulesWithLoadedSymbols(BNDebuggerController* controller, size_t* count);

	DEBUGGER_FFI_API BNDebugRegister* BNDebuggerGetRegisters(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API void BNDebuggerFreeRegisters(BNDebugRegister* modules, size_t count);
	DEBUGGER_FFI_API bool BNDebuggerSetRegisterValue(
		BNDebuggerController* controller, const char* name, const uint8_t* value);
	DEBUGGER_FFI_API void BNDebuggerGetRegisterValue(BNDebuggerController* controller, const char* name,
		uint8_t* buffer);

	// target control
	DEBUGGER_FFI_API bool BNDebuggerLaunch(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerLaunchAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerLaunchAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API bool BNDebuggerExecute(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerRestart(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerQuit(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerQuitAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerQuitAndWaitWithTimeout(BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API bool BNDebuggerConnect(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerConnectAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerConnectAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API bool BNDebuggerConnectToDebugServer(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerDisconnectDebugServer(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerDetach(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerDetachAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerDetachAndWaitWithTimeout(BNDebuggerController* controller, uint64_t timeoutMs);
	// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
	DEBUGGER_FFI_API void BNDebuggerLaunchOrConnect(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerAttach(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerAttachAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerAttachAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);

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
	DEBUGGER_FFI_API bool BNDebuggerRunToReverse(
		BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);
	DEBUGGER_FFI_API void BNDebuggerPause(BNDebuggerController* controller);

	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGoAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGoAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGoReverseAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerGoReverseAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepIntoAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepIntoAndWaitWithTimeout(
		BNDebuggerController* controller, BNFunctionGraphType il, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepIntoReverseAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepIntoReverseAndWaitWithTimeout(
		BNDebuggerController* controller, BNFunctionGraphType il, uint64_t timeoutMs);

	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepOverAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepOverAndWaitWithTimeout(
		BNDebuggerController* controller, BNFunctionGraphType il, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepOverReverseAndWait(
		BNDebuggerController* controller, BNFunctionGraphType il);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepOverReverseAndWaitWithTimeout(
		BNDebuggerController* controller, BNFunctionGraphType il, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepReturnAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepReturnAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepReturnReverseAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerStepReturnReverseAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRunToAndWait(
		BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRunToAndWaitWithTimeout(
		BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRunToReverseAndWait(
		BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRunToReverseAndWaitWithTimeout(
		BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerPauseAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerPauseAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRestartAndWait(BNDebuggerController* controller);
	DEBUGGER_FFI_API BNDebugStopReason BNDebuggerRestartAndWaitWithTimeout(
		BNDebuggerController* controller, uint64_t timeoutMs);

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
	DEBUGGER_FFI_API void BNDebuggerEnableAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API void BNDebuggerEnableRelativeBreakpoint(
		BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API void BNDebuggerDisableAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API void BNDebuggerDisableRelativeBreakpoint(
		BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API bool BNDebuggerContainsAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API bool BNDebuggerContainsRelativeBreakpoint(
		BNDebuggerController* controller, const char* module, uint64_t offset);

	DEBUGGER_FFI_API bool BNDebuggerSetBreakpointConditionAbsolute(
		BNDebuggerController* controller, uint64_t address, const char* condition);
	DEBUGGER_FFI_API bool BNDebuggerSetBreakpointConditionRelative(
		BNDebuggerController* controller, const char* module, uint64_t offset, const char* condition);
	DEBUGGER_FFI_API char* BNDebuggerGetBreakpointConditionAbsolute(
		BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API char* BNDebuggerGetBreakpointConditionRelative(
		BNDebuggerController* controller, const char* module, uint64_t offset);

	// Hardware breakpoint and watchpoint support
	DEBUGGER_FFI_API bool BNDebuggerAddHardwareBreakpoint(BNDebuggerController* controller, uint64_t address,
		BNDebugBreakpointType type, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerRemoveHardwareBreakpoint(BNDebuggerController* controller, uint64_t address,
		BNDebugBreakpointType type, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerEnableHardwareBreakpoint(BNDebuggerController* controller, uint64_t address,
		BNDebugBreakpointType type, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerDisableHardwareBreakpoint(BNDebuggerController* controller, uint64_t address,
		BNDebugBreakpointType type, size_t size);

	// Hardware breakpoint methods - module+offset (ASLR-safe)
	DEBUGGER_FFI_API bool BNDebuggerAddRelativeHardwareBreakpoint(BNDebuggerController* controller, const char* module,
		uint64_t offset, BNDebugBreakpointType type, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerRemoveRelativeHardwareBreakpoint(BNDebuggerController* controller, const char* module,
		uint64_t offset, BNDebugBreakpointType type, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerEnableRelativeHardwareBreakpoint(BNDebuggerController* controller, const char* module,
		uint64_t offset, BNDebugBreakpointType type, size_t size);
	DEBUGGER_FFI_API bool BNDebuggerDisableRelativeHardwareBreakpoint(BNDebuggerController* controller, const char* module,
		uint64_t offset, BNDebugBreakpointType type, size_t size);

	DEBUGGER_FFI_API uint64_t BNDebuggerGetIP(BNDebuggerController* controller);
	DEBUGGER_FFI_API uint64_t BNDebuggerGetLastIP(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerSetIP(BNDebuggerController* controller, uint64_t address);

	DEBUGGER_FFI_API uint64_t BNDebuggerRelativeAddressToAbsolute(
		BNDebuggerController* controller, const char* module, uint64_t offset);
	DEBUGGER_FFI_API BNModuleNameAndOffset BNDebuggerAbsoluteAddressToRelative(
		BNDebuggerController* controller, uint64_t address);

	DEBUGGER_FFI_API bool BNDebuggerRebaseToRemoteBase(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerRebaseToAddress(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API bool BNDebuggerGetRemoteBase(BNDebuggerController* controller, uint64_t* address);

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

	// TTD Memory Analysis Functions
	DEBUGGER_FFI_API BNDebuggerTTDMemoryEvent* BNDebuggerGetTTDMemoryAccessForAddress(BNDebuggerController* controller,
		uint64_t address, uint64_t endAddress, BNDebuggerTTDMemoryAccessType accessType, size_t* count);
	DEBUGGER_FFI_API BNDebuggerTTDPositionRangeIndexedMemoryEvent* BNDebuggerGetTTDMemoryAccessForPositionRange(BNDebuggerController* controller,
		uint64_t address, uint64_t endAddress, BNDebuggerTTDMemoryAccessType accessType ,BNDebuggerTTDPosition startPosition, BNDebuggerTTDPosition endPosition,
		size_t* count);
	DEBUGGER_FFI_API BNDebuggerTTDCallEvent* BNDebuggerGetTTDCallsForSymbols(BNDebuggerController* controller,
		const char* symbols, uint64_t startReturnAddress, uint64_t endReturnAddress, size_t* count);
	DEBUGGER_FFI_API BNDebuggerTTDEvent* BNDebuggerGetTTDEvents(BNDebuggerController* controller,
		BNDebuggerTTDEventType eventType, size_t* count);
	DEBUGGER_FFI_API BNDebuggerTTDEvent* BNDebuggerGetAllTTDEvents(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API BNDebuggerTTDPosition BNDebuggerGetCurrentTTDPosition(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerSetTTDPosition(BNDebuggerController* controller, BNDebuggerTTDPosition position);
	DEBUGGER_FFI_API bool BNDebuggerGetTTDNextMemoryAccess(BNDebuggerController* controller,
		uint64_t address, uint64_t size, BNDebuggerTTDMemoryAccessType accessType, BNDebuggerTTDMemoryEvent* result);
	DEBUGGER_FFI_API bool BNDebuggerGetTTDPrevMemoryAccess(BNDebuggerController* controller,
		uint64_t address, uint64_t size, BNDebuggerTTDMemoryAccessType accessType, BNDebuggerTTDMemoryEvent* result);
	DEBUGGER_FFI_API void BNDebuggerFreeTTDMemoryEvents(BNDebuggerTTDMemoryEvent* events, size_t count);
	DEBUGGER_FFI_API void BNDebuggerFreeTTDPositionRangeIndexedMemoryEvents(BNDebuggerTTDPositionRangeIndexedMemoryEvent* events, size_t count);
	DEBUGGER_FFI_API void BNDebuggerFreeTTDCallEvents(BNDebuggerTTDCallEvent* events, size_t count);
	DEBUGGER_FFI_API void BNDebuggerFreeTTDEvents(BNDebuggerTTDEvent* events, size_t count);

	// TTD Bookmark structures and functions
	typedef struct BNDebuggerTTDBookmark
	{
		BNDebuggerTTDPosition position;
		uint64_t viewAddress;
		char* note;
	} BNDebuggerTTDBookmark;

	DEBUGGER_FFI_API BNDebuggerTTDBookmark* BNDebuggerGetTTDBookmarks(BNDebuggerController* controller, size_t* count);
	DEBUGGER_FFI_API bool BNDebuggerAddTTDBookmark(BNDebuggerController* controller, BNDebuggerTTDPosition position, const char* note, uint64_t viewAddress);
	DEBUGGER_FFI_API bool BNDebuggerRemoveTTDBookmark(BNDebuggerController* controller, BNDebuggerTTDPosition position);
	DEBUGGER_FFI_API bool BNDebuggerUpdateTTDBookmark(BNDebuggerController* controller, BNDebuggerTTDPosition position, const char* note, uint64_t viewAddress);
	DEBUGGER_FFI_API void BNDebuggerClearTTDBookmarks(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerFreeTTDBookmarks(BNDebuggerTTDBookmark* bookmarks, size_t count);

	// TTD Position History Navigation
	DEBUGGER_FFI_API bool BNDebuggerTTDNavigateBack(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerTTDNavigateForward(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerCanTTDNavigateBack(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerCanTTDNavigateForward(BNDebuggerController* controller);
	DEBUGGER_FFI_API void BNDebuggerClearTTDPositionHistory(BNDebuggerController* controller);

	// TTD Code Coverage Analysis Functions
	DEBUGGER_FFI_API bool BNDebuggerIsInstructionExecuted(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API bool BNDebuggerRunCodeCoverageAnalysisRange(BNDebuggerController* controller, uint64_t startAddress, uint64_t endAddress, BNDebuggerTTDPosition startTime, BNDebuggerTTDPosition endTime);
	DEBUGGER_FFI_API size_t BNDebuggerGetInstructionExecutionCount(BNDebuggerController* controller, uint64_t address);
	DEBUGGER_FFI_API size_t BNDebuggerGetExecutedInstructionCount(BNDebuggerController* controller);
	DEBUGGER_FFI_API bool BNDebuggerSaveCodeCoverageToFile(BNDebuggerController* controller, const char* filePath);
	DEBUGGER_FFI_API bool BNDebuggerLoadCodeCoverageFromFile(BNDebuggerController* controller, const char* filePath);

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

	// WinDbg Installer (Windows only)
	typedef struct BNDebuggerInstallResult
	{
		bool success;
		char* errorMessage;  // NULL if success, otherwise error description (caller must free)
	} BNDebuggerInstallResult;

	DEBUGGER_FFI_API BNDebuggerInstallResult BNDebuggerInstallWinDbg(const char* installPath, bool isUpdate);
	DEBUGGER_FFI_API void BNDebuggerFreeInstallResult(BNDebuggerInstallResult* result);
	DEBUGGER_FFI_API bool BNDebuggerIsWinDbgInstalled(const char* installPath);
	DEBUGGER_FFI_API char* BNDebuggerGetWinDbgInstallerPath(void);
	DEBUGGER_FFI_API char* BNDebuggerGetWinDbgInstalledVersion(const char* installPath);
	DEBUGGER_FFI_API char* BNDebuggerGetWinDbgLatestVersion(void);

#ifdef __cplusplus
}
#endif
