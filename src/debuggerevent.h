#pragma once
#include "cstddef"
#include <string>
#include "debuggercommon.h"

enum DebuggerEventType
{
	LaunchEventType,
	ResumeEventType,
	StepIntoEventType,
	StepOverEventType,
	StepReturnEventType,
	StepToEventType,
	RestartEventType,
	AttachEventType,

	AdapterStoppedEventType,
	AdapterTargetExitedEventType,

	InvalidOperationEventType,
	InternalErrorEventType,

    TargetStoppedEventType,
    ErrorEventType,
    GeneralEventType,

	StdoutMessageEventType,

	TargetExitedEventType,
	DetachedEventType,
	QuitDebuggingEventType,
	BackEndDisconnectedEventType,

    InitialViewRebasedEventType,

    AbsoluteBreakpointAddedEvent,
    RelativeBreakpointAddedEvent,
    AbsoluteBreakpointRemovedEvent,
    RelativeBreakpointRemovedEvent,

	ActiveThreadChangedEvent
};


enum class DebugStopReason {
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
	InvalidStatusOrOperation
};


struct TargetStoppedEventData
{
    DebugStopReason reason;
	std::uint32_t lastActiveThread;
    size_t exitCode;
    void* data;
};


struct StoppedEventData
{
    DebugStopReason reason;
    void* data;
};


struct ErrorEventData
{
    std::string error;
    void* data;
};


// TODO: This has become useless, remote it later
struct GeneralEventData
{
    std::string event;
    void* data;
};


struct TargetExitedEventData
{
	uint64_t exitCode;
};


struct StdoutMessageEventData
{
	std::string message;
};


// This should really be a union, but gcc complains...
struct DebuggerEventData
{
    TargetStoppedEventData targetStoppedData;
    ErrorEventData errorData;
    GeneralEventData generalData;
    uint64_t absoluteAddress;
    ModuleNameAndOffset relativeAddress;
	TargetExitedEventData exitData;
	StdoutMessageEventData messageData;
};


struct DebuggerEvent
{
    DebuggerEventType type;
    DebuggerEventData data;
};