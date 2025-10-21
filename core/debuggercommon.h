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
#include <string.h>
#include <optional>
#ifndef WIN32
	#include "libgen.h"
#endif

namespace BinaryNinjaDebugger {
	struct ModuleNameAndOffset
	{
		// TODO: maybe we should use DebugModule instead of its name
		// Update: We are not using a DebugModule here because the base address information of it can be outdated;
		// instead, we only keep a name and an offset.
		std::string module;
		uint64_t offset;

		ModuleNameAndOffset() : module(""), offset(0) {}
		ModuleNameAndOffset(std::string mod, uint64_t off) : module(mod), offset(off) {}
		bool operator==(const ModuleNameAndOffset& other) const
		{
			return IsSameBaseModule(other) && (offset == other.offset);
		}
		bool operator<(const ModuleNameAndOffset& other) const
		{
			if (module < other.module)
				return true;
			if (module > other.module)
				return false;
			return offset < other.offset;
		}
		bool operator>(const ModuleNameAndOffset& other) const
		{
			if (module > other.module)
				return true;
			if (module < other.module)
				return false;
			return offset > other.offset;
		}


		static std::string GetPathBaseName(const std::string& path)
		{
#ifdef WIN32
			// TODO: someone please write it on Windows!
			char baseName[MAX_PATH];
			_splitpath(path.c_str(), NULL, NULL, baseName, NULL);
			return std::string(baseName);
#else
			return basename(strdup(path.c_str()));
#endif
		}


		bool IsSameBaseModule(const ModuleNameAndOffset& other) const
		{
			return ((module == other.module) || (GetPathBaseName(module) == GetPathBaseName(other.module)));
		}


		bool IsSameBaseModule(const std::string& other) const
		{
			return ((module == other) || (GetPathBaseName(module) == GetPathBaseName(other)));
		}


		static bool IsSameBaseModule(const std::string& module1, const std::string& module2)
		{
			return ((module1 == module2) || (GetPathBaseName(module1) == GetPathBaseName(module2)));
		}
	};

	// TTD Memory Access Types - bitfield flags that can be combined
	enum TTDMemoryAccessType
	{
		TTDMemoryRead = 1,
		TTDMemoryWrite = 2,
		TTDMemoryExecute = 4,
		TTDMemoryAll = TTDMemoryRead | TTDMemoryWrite | TTDMemoryExecute
	};

	// TTD Position - represents a position in the TTD trace
	struct TTDPosition
	{
		uint64_t sequence;  // Sequence number in trace
		uint64_t step;      // Step within sequence
		
		TTDPosition() : sequence(0), step(0) {}
		TTDPosition(uint64_t seq, uint64_t st) : sequence(seq), step(st) {}
		
		bool operator==(const TTDPosition& other) const
		{
			return sequence == other.sequence && step == other.step;
		}
		
		bool operator<(const TTDPosition& other) const
		{
			if (sequence < other.sequence)
				return true;
			if (sequence > other.sequence)
				return false;
			return step < other.step;
		}
	};

	// TTD Memory Access Event - complete set of fields from Microsoft documentation
	struct TTDMemoryEvent
	{
		std::string eventType;         // Event type (e.g., "MemoryAccess")
		uint32_t threadId;             // Thread ID that performed the access
		uint32_t uniqueThreadId;       // Unique thread identifier
		TTDPosition timeStart;         // Position when event started
		TTDPosition timeEnd;           // Position when event ended
		uint64_t address;              // Memory address accessed
		uint64_t size;                 // Size of memory access
		uint64_t memoryAddress;        // Memory address (may be same as address)
		uint64_t instructionAddress;   // IP - Address of instruction that caused the access
		uint64_t value;                // Value that was read/written/executed
		TTDMemoryAccessType accessType; // Type of memory access (parsed from object)
		
		TTDMemoryEvent() : threadId(0), uniqueThreadId(0), address(0), size(0), memoryAddress(0), instructionAddress(0), value(0), accessType(TTDMemoryRead) {}
	};

	// TTD Call Event - complete set of fields from Microsoft documentation for TTD.Calls
	struct TTDCallEvent
	{
		std::string eventType;         // Event type (always "Call" for TTD.Calls objects)
		uint32_t threadId;             // OS thread ID of thread that made the call
		uint32_t uniqueThreadId;       // Unique ID for the thread across the trace
		std::string function;          // Symbolic name of the function
		uint64_t functionAddress;      // Function's address in memory
		uint64_t returnAddress;        // Instruction to return to after the call
		uint64_t returnValue;          // Return value of the function (if not void)
		bool hasReturnValue;           // Whether the function has a return value
		std::vector<std::string> parameters; // Array containing parameters passed to the function
		TTDPosition timeStart;         // Position when call started
		TTDPosition timeEnd;           // Position when call ended
		
		TTDCallEvent() : threadId(0), uniqueThreadId(0), functionAddress(0), returnAddress(0), returnValue(0), hasReturnValue(false) {}
	};

	// TTD Event Types - bitfield flags for filtering events
	enum TTDEventType
	{
		TTDEventNone = 0,
		TTDEventThreadCreated = 1,
		TTDEventThreadTerminated = 2,
		TTDEventModuleLoaded = 4,
		TTDEventModuleUnloaded = 8,
		TTDEventException = 16,
		TTDEventAll = TTDEventThreadCreated | TTDEventThreadTerminated | TTDEventModuleLoaded | TTDEventModuleUnloaded | TTDEventException
	};

	// TTD Module - information about modules that were loaded/unloaded during trace
	struct TTDModule
	{
		std::string name;              // Name and path of the module
		uint64_t address;              // Address where the module was loaded
		uint64_t size;                 // Size of the module in bytes
		uint32_t checksum;             // Checksum of the module
		uint32_t timestamp;            // Timestamp of the module
		
		TTDModule() : address(0), size(0), checksum(0), timestamp(0) {}
	};

	// TTD Thread - information about threads and their lifetime during trace
	struct TTDThread
	{
		uint32_t uniqueId;             // Unique ID for the thread across the trace
		uint32_t id;                   // TID of the thread
		TTDPosition lifetimeStart;     // Lifetime start position
		TTDPosition lifetimeEnd;       // Lifetime end position
		TTDPosition activeTimeStart;   // Active time start position
		TTDPosition activeTimeEnd;     // Active time end position
		
		TTDThread() : uniqueId(0), id(0) {}
	};

	// TTD Exception Types
	enum TTDExceptionType
	{
		TTDExceptionSoftware,
		TTDExceptionHardware
	};

	// TTD Exception - information about exceptions that occurred during trace
	struct TTDException
	{
		TTDExceptionType type;         // Type of exception (Software/Hardware)
		uint64_t programCounter;       // Instruction where exception was thrown
		uint32_t code;                 // Exception code
		uint32_t flags;                // Exception flags
		uint64_t recordAddress;        // Where in memory the exception record is found
		TTDPosition position;          // Position where exception occurred
		
		TTDException() : type(TTDExceptionSoftware), programCounter(0), code(0), flags(0), recordAddress(0) {}
	};

	// TTD Event - represents important events that happened during trace
	struct TTDEvent
	{
		TTDEventType type;             // Type of event
		TTDPosition position;          // Position where event occurred
		
		// Optional child objects - existence depends on event type
		std::optional<TTDModule> module;      // For ModuleLoaded/ModuleUnloaded events
		std::optional<TTDThread> thread;      // For ThreadCreated/ThreadTerminated events
		std::optional<TTDException> exception; // For Exception events
		
		TTDEvent() : type(TTDEventThreadCreated) {}
		TTDEvent(TTDEventType eventType) : type(eventType) {}
	};
};  // namespace BinaryNinjaDebugger
