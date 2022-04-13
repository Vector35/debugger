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
