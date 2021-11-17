#pragma once
#include "cstddef"
#include <string>
#include "debuggercommon.h"

enum DebuggerEventType
{
    TargetStoppedEventType,
    ErrorEventType,
    GeneralEventType,

	DetachedEventType,
	QuitDebuggingEventType,
	BackEndDisconnectedEventType,

    InitialViewRebasedEventType,

    AbsoluteBreakpointAddedEvent,
    RelativeBreakpointAddedEvent,
    AbsoluteBreakpointRemovedEvent,
    RelativeBreakpointRemovedEvent
};


enum class DebugStopReason {
    UknownReason = 0,
    InitalBreakpoint,
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
};


struct TargetStoppedEventData
{
    DebugStopReason reason;
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


// This should really be a union, but gcc complains...
struct DebuggerEventData
{
    TargetStoppedEventData targetStoppedData;
    ErrorEventData errorData;
    GeneralEventData generalData;
    uint64_t absoluteAddress;
    ModuleNameAndOffset relativeAddress;
};


struct DebuggerEvent
{
    DebuggerEventType type;
    DebuggerEventData data;
};