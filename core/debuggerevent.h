#pragma once
#include "cstddef"
#include <string>
#include "debuggercommon.h"
#include "../api/ffi.h"

namespace BinaryNinjaDebugger
{
	typedef BNDebuggerEventType DebuggerEventType;
	typedef BNDebugStopReason DebugStopReason;

	struct TargetStoppedEventData
	{
		DebugStopReason reason;
		std::uint32_t lastActiveThread;
		size_t exitCode;
		void* data;
	};


	struct ErrorEventData
	{
		std::string error{};
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
