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
#include <cstdint>
#include <functional>
#include <string>

namespace BinaryNinjaDebugger {
	enum class DbgEngLogLevel
	{
		Debug,
		Info,
		Warn,
		Error
	};

	using DbgEngLogCallback = std::function<void(DbgEngLogLevel, const std::string&)>;

	void SetDbgEngLogCallback(DbgEngLogCallback callback);

	// Same values as BNDebugStopReason, which can't be used here because api/ffi.h needs binaryninjacore.h.
	enum class DbgEngStopReason : uint32_t
	{
		UnknownReason = 0,
		ProcessExited = 2,
		AccessViolation = 3,
		SingleStep = 4,
		Calculation = 5,
		Breakpoint = 6
	};

	enum class DbgEngEventType
	{
		LaunchFailure,
		TargetExited,
		TargetStopped,
		Resumed,
		StepIntoComplete,
		BackendMessage
	};

	struct DbgEngEvent
	{
		DbgEngEventType type = DbgEngEventType::TargetStopped;
		DbgEngStopReason stopReason = DbgEngStopReason::UnknownReason;
		uint64_t exitCode = 0;
		std::string error;
		std::string shortError;
		std::string message;
	};
}  // namespace BinaryNinjaDebugger
