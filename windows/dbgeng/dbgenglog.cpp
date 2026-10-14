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

#include "dbgenglog.h"
#include <cstdarg>
#include <cstdio>
#include <utility>

using namespace BinaryNinjaDebugger;

static DbgEngLogCallback g_logCallback;

static std::string FormatLogMessage(const char* fmt, va_list args)
{
	va_list copy;
	va_copy(copy, args);
	const int length = vsnprintf(nullptr, 0, fmt, copy);
	va_end(copy);
	if (length <= 0)
		return {};

	std::string message(length, '\0');
	vsnprintf(message.data(), message.size() + 1, fmt, args);
	return message;
}

void BinaryNinjaDebugger::SetDbgEngLogCallback(DbgEngLogCallback callback)
{
	g_logCallback = std::move(callback);
}

static void LogMessage(DbgEngLogLevel level, const std::string& message)
{
	if (g_logCallback)
		g_logCallback(level, message);
}

void BinaryNinjaDebugger::LogDebug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	LogMessage(DbgEngLogLevel::Debug, FormatLogMessage(fmt, args));
	va_end(args);
}

void BinaryNinjaDebugger::LogInfo(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	LogMessage(DbgEngLogLevel::Info, FormatLogMessage(fmt, args));
	va_end(args);
}

void BinaryNinjaDebugger::LogWarn(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	LogMessage(DbgEngLogLevel::Warn, FormatLogMessage(fmt, args));
	va_end(args);
}

void BinaryNinjaDebugger::LogError(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	LogMessage(DbgEngLogLevel::Error, FormatLogMessage(fmt, args));
	va_end(args);
}
