#pragma once
#include "binaryninjaapi.h"

using namespace BinaryNinja;

// Define macros for defining objects exposed by the API
#define DECLARE_DEBUGGER_API_OBJECT(handle, cls) \
	namespace BinaryNinjaDebugger{ class cls; } struct handle { BinaryNinjaDebugger::cls* object; }
#define IMPLEMENT_DEBUGGER_API_OBJECT(handle) \
	private: handle m_apiObject; public: typedef handle* APIHandle; handle* GetAPIObject() { return &m_apiObject; } private:
#define INIT_DEBUGGER_API_OBJECT() \
	m_apiObject.object = this;

DECLARE_DEBUGGER_API_OBJECT(BNDebuggerController, DebuggerController);
DECLARE_DEBUGGER_API_OBJECT(BNDebugAdapterType, DebugAdapterType);
DECLARE_DEBUGGER_API_OBJECT(BNDebugAdapter, DebugAdapter);
DECLARE_DEBUGGER_API_OBJECT(BNDebuggerState, DebuggerState);

#ifdef __cplusplus
extern "C"
{
#endif
	struct BNDebugThread
	{
		uint32_t m_tid{};
		uint64_t m_rip{};
	};


	struct BNDebugModule
	{
		std::string m_name{}, m_short_name{};
		std::uintptr_t m_address{};
		std::size_t m_size{};
		bool m_loaded{};
	};


	struct BNDebugRegister
	{
		std::string m_name{};
		std::uintptr_t m_value{};
		std::size_t m_width{}, m_registerIndex{};
		std::string m_hint{};
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


	enum class BNDebugStopReason {
		UnknownReason = 0,
		InitialBreakpoint,
		StdoutMessage,
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

		UserRequestedBreak
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


	BNDebuggerController* BNGetDebuggerController(BinaryNinja::BinaryView* data);
	BNBinaryView* BNDebuggerGetLiveView(BNDebuggerController* controller);
	BNBinaryView* BNDebuggerGetData(BNDebuggerController* controller);
	BNArchitecture* BNDebuggerGetRemoteArchitecture(BNDebuggerController* controller);
	bool BNDebuggerIsConnected(BNDebuggerController* controller);
	bool BNDebuggerIsRunning(BNDebuggerController* controller);

	uint64_t BNDebuggerGetStackPointer(BNDebuggerController* controller);

	BNDataBuffer* BNDebuggerReadMemory(BNDebuggerController* controller, uint64_t address, size_t size);
	bool BNDebuggerWriteMemory(BNDebuggerController* controller, uint64_t address, const BNDataBuffer* buffer);

	BNDebugThread* BNDebuggerGetThreads(BNDebuggerController* controller, size_t* count);
	void BNDebuggerFreeThreads(BNDebugThread* threads, size_t count);

	BNDebugThread BNDebuggerGetActiveThread(BNDebuggerController* controller);
	void BNDebuggerSetActiveThread(BNDebuggerController* controller, BNDebugThread thread);

	BNDebugModule* BNDebuggerGetModules(BNDebuggerController* controller, size_t* count);
	void BNDebuggerFreeModules(BNDebugModule* modules, size_t count);

	BNDebugRegister* BNDebuggerGetRegisters(BNDebuggerController* controller, size_t* count);
	void BNDebuggerFreeRegisters(BNDebugRegister* modules, size_t count);
	bool BNDebuggerSetRegisterValue(BNDebuggerController* controller, const char* name, size_t len, uint64_t value);

	// target control
	bool BNDebuggerLaunch(BNDebuggerController* controller);
	bool BNDebuggerExecute(BNDebuggerController* controller);
	void BNDebuggerRestart(BNDebuggerController* controller);
	void BNDebuggerQuit(BNDebuggerController* controller);
	void BNDebuggerConnect(BNDebuggerController* controller);
	void BNDebuggerDetach(BNDebuggerController* controller);
	void BNDebuggerPause(BNDebuggerController* controller);
	// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
	void BNDebuggerLaunchOrConnect(BNDebuggerController* controller);

	BNDebugStopReason BNDebuggerGo(BNDebuggerController* controller);
	BNDebugStopReason BNDebuggerStepInto(BNDebuggerController* controller, BNFunctionGraphType il = NormalFunctionGraph);
	BNDebugStopReason BNDebuggerStepOver(BNDebuggerController* controller, BNFunctionGraphType il = NormalFunctionGraph);
	BNDebugStopReason BNDebuggerStepReturn(BNDebuggerController* controller);
	BNDebugStopReason BNDebuggerStepTo(BNDebuggerController* controller, const uint64_t* remoteAddresses, size_t count);

	char* BNDebuggerGetAdapterType(BNDebuggerController* controller);
	void BNDebuggerSetAdapterType(BNDebuggerController* controller, const char* adapter);

	BNDebugAdapterConnectionStatus BNDebuggerGetConnectionStatus(BNDebuggerController* controller);
	BNDebugAdapterTargetStatus BNDebuggerGetTargetStatus(BNDebuggerController* controller);

	char* BNDebuggerGetRemoteHost(BNDebuggerController* controller);
	uint32_t BNDebuggerGetRemotePort(BNDebuggerController* controller);
	char* BNDebuggerGetExecutablePath(BNDebuggerController* controller);
	bool BNDebuggerGetRequestTerminalEmulator(BNDebuggerController* controller);
	char* BNDebuggerGetCommandLineArguments(BNDebuggerController* controller);

	void BNDebuggerSetRemoteHost(BNDebuggerController* controller, const char* host);
	void BNDebuggerSetRemotePort(BNDebuggerController* controller, uint32_t port);
	void BNDebuggerSetExecutablePath(BNDebuggerController* controller, const char* path);
	void BNDebuggerSetRequestTerminalEmulator(BNDebuggerController* controller, bool requestEmulator);
	void BNDebuggerSetCommandLineArguments(BNDebuggerController* controller, const char* args);

	BNDebugBreakpoint* BNDebuggerGetBreakpoints(BNDebuggerController* controller, size_t* count);
	void BNDebuggerFreeBreakpoints(BNDebugBreakpoint* breakpoints, size_t count);

	void BNDebuggerDeleteAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	void BNDebuggerDeleteRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset);
	void BNDebuggerAddAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	void BNDebuggerAddRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset);
	bool BNDebuggerContainsAbsoluteBreakpoint(BNDebuggerController* controller, uint64_t address);
	bool BNDebuggerContainsRelativeBreakpoint(BNDebuggerController* controller, const char* module, uint64_t offset);

	uint64_t BNDebuggerGetIP(BNDebuggerController* controller);
	uint64_t BNDebuggerGetLastIP(BNDebuggerController* controller);

	uint64_t BNDebuggerRelativeAddressToAbsolute(BNDebuggerController* controller, const char* module, uint64_t offset);
	BNModuleNameAndOffset BNDebuggerAbsoluteAddressToRelative(BNDebuggerController* controller, uint64_t address);


	// DebugAdapterType
	BNDebugAdapterType* BNGetDebugAdapterTypeByName(const char* name);
	bool BNDebugAdapterTypeCanExecute(BNDebugAdapterType* adapter, Ref<BinaryView> data);
	bool BNDebugAdapterTypeCanConnect(BNDebugAdapterType* adapter, Ref<BinaryView> data);
	char** BNGetAvailableDebugAdapterTypes(Ref<BinaryView> data, size_t* count);


	// DebugModule
	bool BNDebuggerIsSameBaseModule(const char* module1, const char* module2);

#ifdef __cplusplus
}
#endif
