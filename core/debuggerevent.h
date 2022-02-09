#pragma once
#include "cstddef"
#include <string>
#include "debuggercommon.h"
#include "../api/ffi.h"

namespace BinaryNinjaDebugger
{
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
		DetachEventType,

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

		AbsoluteBreakpointAddedEvent,
		RelativeBreakpointAddedEvent,
		AbsoluteBreakpointRemovedEvent,
		RelativeBreakpointRemovedEvent,

		ActiveThreadChangedEvent
	};

	struct TargetStoppedEventData
	{
		BNDebugStopReason reason;
		std::uint32_t lastActiveThread;
		size_t exitCode;
		void* data;
	};


	struct StoppedEventData
	{
		BNDebugStopReason reason;
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
};
