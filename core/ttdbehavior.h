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

#include <string>
#include <vector>
#include <map>
#include <optional>
#include "debuggercommon.h"
#include "binaryninjaapi.h"

namespace BinaryNinjaDebugger {

// Categories of API behavior analysis
enum class TTDBehaviorCategory
{
	Heap,
	File,
	Registry,
	Network,
	Process,
	Thread,
	Module,
	Memory,
	Crypto,
	Custom
};

std::string TTDBehaviorCategoryToString(TTDBehaviorCategory category);
TTDBehaviorCategory StringToTTDBehaviorCategory(const std::string& str);

// How to read a value from a call
enum class TTDValueSource
{
	Parameter,      // Read from call parameters (by index)
	ReturnValue,    // Read from return value
	Dereference,    // Dereference a pointer parameter to read memory
};

enum class TTDValueType
{
	Integer,        // Plain integer value
	Pointer,        // Pointer/address value
	Handle,         // Handle value (special display)
	Size,           // Size value
	Flags,          // Flags value (could be decoded later)
	StringA,        // ANSI string (requires dereference)
	StringW,        // Unicode string (requires dereference)
	Boolean,        // Boolean result
};

// When to collect the value
enum class TTDCollectTime
{
	AtStart,        // Collect when call starts (input parameters)
	AtEnd,          // Collect when call ends (output parameters, return value)
};

// Definition of a single value to extract from an API call
struct TTDValueDefinition
{
	std::string name;           // Display name for this value
	TTDValueSource source;      // Where to get the value
	int parameterIndex;         // Parameter index (if source is Parameter or Dereference)
	TTDValueType type;          // How to interpret the value
	TTDCollectTime collectTime; // When to collect
	size_t maxStringLength;     // Max string length for string types (default 260)

	TTDValueDefinition() : parameterIndex(0), maxStringLength(260) {}
};

// Definition of an API to analyze
struct TTDApiDefinition
{
	std::string symbol;         // Full symbol name (e.g., "kernel32!CreateFileA")
	std::string action;         // Action name for display (e.g., "Open", "Alloc")
	std::vector<TTDValueDefinition> values;  // Values to extract
};

// Definition of a behavior analysis set
struct TTDBehaviorAnalysisSet
{
	std::string name;           // Display name (e.g., "Heap Operations")
	std::string description;    // Description of what this analyzes
	TTDBehaviorCategory category;
	std::vector<TTDApiDefinition> apis;
};

// A single extracted behavior event
struct TTDBehaviorEvent
{
	std::string apiSymbol;      // The API that was called
	std::string action;         // The action (e.g., "Alloc", "Open")
	TTDPosition timeStart;
	TTDPosition timeEnd;
	uint32_t threadId;
	uint64_t returnAddress;

	// Extracted values as key-value pairs
	std::map<std::string, std::string> values;
};

// Result of behavior analysis
struct TTDBehaviorAnalysisResult
{
	TTDBehaviorCategory category;
	std::string setName;
	std::vector<TTDBehaviorEvent> events;
	std::string errorMessage;
	bool success;
};

// JSON parsing/serialization for analysis sets
class TTDBehaviorAnalysisSetManager
{
public:
	// Load analysis set from JSON string
	static std::optional<TTDBehaviorAnalysisSet> ParseFromJson(const std::string& json);

	// Load analysis set from file
	static std::optional<TTDBehaviorAnalysisSet> LoadFromFile(const std::string& path);

	// Serialize analysis set to JSON
	static std::string ToJson(const TTDBehaviorAnalysisSet& set);

	// Get built-in analysis sets
	static TTDBehaviorAnalysisSet GetHeapAnalysisSet();
	static TTDBehaviorAnalysisSet GetFileAnalysisSet();

	// Get all built-in sets
	static std::vector<TTDBehaviorAnalysisSet> GetBuiltinSets();
};

}  // namespace BinaryNinjaDebugger
