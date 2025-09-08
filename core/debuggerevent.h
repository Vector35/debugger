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
#include "cstddef"
#include <string>
#include <unordered_map>
#include "debuggercommon.h"
#include "../api/ffi.h"

namespace BinaryNinjaDebugger {
	typedef BNDebuggerEventType DebuggerEventType;
    typedef BNDebugStopReason DebugStopReason;
    typedef BNDebuggerAdapterOperation DebugAdapterOperation;

	// Helper function to convert signal number to DebugStopReason
	inline DebugStopReason SignalToDebugStopReason(uint64_t signal)
	{
		static std::unordered_map<uint64_t, DebugStopReason> signal_lookup = {
			{1, DebugStopReason::SignalHup},
			{2, DebugStopReason::SignalInt},
			{3, DebugStopReason::SignalQuit},
			{4, DebugStopReason::IllegalInstruction},
			{5, DebugStopReason::SingleStep},
			{6, DebugStopReason::SignalAbrt},
			{7, DebugStopReason::SignalBux},
			{8, DebugStopReason::Calculation},
			{9, DebugStopReason::SignalKill},
			{10, DebugStopReason::SignalUsr1},
			{11, DebugStopReason::AccessViolation},
			{12, DebugStopReason::SignalUsr2},
			{13, DebugStopReason::SignalPipe},
			{14, DebugStopReason::SignalAlrm},
			{15, DebugStopReason::SignalTerm},
			{16, DebugStopReason::SignalStkflt},
			{17, DebugStopReason::SignalChld},
			{18, DebugStopReason::SignalCont},
			{19, DebugStopReason::SignalStop},
			{20, DebugStopReason::SignalTstp},
			{21, DebugStopReason::SignalTtin},
			{22, DebugStopReason::SignalTtou},
			{23, DebugStopReason::SignalUrg},
			{24, DebugStopReason::SignalXcpu},
			{25, DebugStopReason::SignalXfsz},
			{26, DebugStopReason::SignalVtalrm},
			{27, DebugStopReason::SignalProf},
			{28, DebugStopReason::SignalWinch},
			{29, DebugStopReason::SignalPoll},
			{30, DebugStopReason::SignalStkflt},
			{31, DebugStopReason::SignalSys}
		};

		auto it = signal_lookup.find(signal);
		return (it != signal_lookup.end()) ? it->second : DebugStopReason::UnknownReason;
	}

	struct TargetStoppedEventData
	{
		DebugStopReason reason;
		std::uint32_t lastActiveThread;
		size_t exitCode;
		void* data;
	};


	struct ErrorEventData
	{
		std::string shortError {};
		std::string error {};
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
};  // namespace BinaryNinjaDebugger
