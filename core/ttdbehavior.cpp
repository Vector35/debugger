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

#include "ttdbehavior.h"
#include <fstream>
#include <sstream>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"

using namespace BinaryNinjaDebugger;
using namespace rapidjson;

std::string BinaryNinjaDebugger::TTDBehaviorCategoryToString(TTDBehaviorCategory category)
{
	switch (category)
	{
	case TTDBehaviorCategory::Heap: return "Heap";
	case TTDBehaviorCategory::File: return "File";
	case TTDBehaviorCategory::Registry: return "Registry";
	case TTDBehaviorCategory::Network: return "Network";
	case TTDBehaviorCategory::Process: return "Process";
	case TTDBehaviorCategory::Thread: return "Thread";
	case TTDBehaviorCategory::Module: return "Module";
	case TTDBehaviorCategory::Memory: return "Memory";
	case TTDBehaviorCategory::Crypto: return "Crypto";
	case TTDBehaviorCategory::Custom: return "Custom";
	default: return "Unknown";
	}
}

TTDBehaviorCategory BinaryNinjaDebugger::StringToTTDBehaviorCategory(const std::string& str)
{
	if (str == "Heap") return TTDBehaviorCategory::Heap;
	if (str == "File") return TTDBehaviorCategory::File;
	if (str == "Registry") return TTDBehaviorCategory::Registry;
	if (str == "Network") return TTDBehaviorCategory::Network;
	if (str == "Process") return TTDBehaviorCategory::Process;
	if (str == "Thread") return TTDBehaviorCategory::Thread;
	if (str == "Module") return TTDBehaviorCategory::Module;
	if (str == "Memory") return TTDBehaviorCategory::Memory;
	if (str == "Crypto") return TTDBehaviorCategory::Crypto;
	return TTDBehaviorCategory::Custom;
}

static TTDValueSource ParseValueSource(const std::string& str)
{
	if (str == "parameter") return TTDValueSource::Parameter;
	if (str == "return") return TTDValueSource::ReturnValue;
	if (str == "dereference") return TTDValueSource::Dereference;
	return TTDValueSource::Parameter;
}

static std::string ValueSourceToString(TTDValueSource source)
{
	switch (source)
	{
	case TTDValueSource::Parameter: return "parameter";
	case TTDValueSource::ReturnValue: return "return";
	case TTDValueSource::Dereference: return "dereference";
	default: return "parameter";
	}
}

static TTDValueType ParseValueType(const std::string& str)
{
	if (str == "integer") return TTDValueType::Integer;
	if (str == "pointer") return TTDValueType::Pointer;
	if (str == "handle") return TTDValueType::Handle;
	if (str == "size") return TTDValueType::Size;
	if (str == "flags") return TTDValueType::Flags;
	if (str == "string_a") return TTDValueType::StringA;
	if (str == "string_w") return TTDValueType::StringW;
	if (str == "boolean") return TTDValueType::Boolean;
	return TTDValueType::Integer;
}

static std::string ValueTypeToString(TTDValueType type)
{
	switch (type)
	{
	case TTDValueType::Integer: return "integer";
	case TTDValueType::Pointer: return "pointer";
	case TTDValueType::Handle: return "handle";
	case TTDValueType::Size: return "size";
	case TTDValueType::Flags: return "flags";
	case TTDValueType::StringA: return "string_a";
	case TTDValueType::StringW: return "string_w";
	case TTDValueType::Boolean: return "boolean";
	default: return "integer";
	}
}

static TTDCollectTime ParseCollectTime(const std::string& str)
{
	if (str == "start") return TTDCollectTime::AtStart;
	if (str == "end") return TTDCollectTime::AtEnd;
	return TTDCollectTime::AtStart;
}

static std::string CollectTimeToString(TTDCollectTime time)
{
	switch (time)
	{
	case TTDCollectTime::AtStart: return "start";
	case TTDCollectTime::AtEnd: return "end";
	default: return "start";
	}
}

std::optional<TTDBehaviorAnalysisSet> TTDBehaviorAnalysisSetManager::ParseFromJson(const std::string& json)
{
	Document doc;
	doc.Parse(json.c_str());

	if (doc.HasParseError())
		return std::nullopt;

	TTDBehaviorAnalysisSet set;

	if (doc.HasMember("name") && doc["name"].IsString())
		set.name = doc["name"].GetString();

	if (doc.HasMember("description") && doc["description"].IsString())
		set.description = doc["description"].GetString();

	if (doc.HasMember("category") && doc["category"].IsString())
		set.category = StringToTTDBehaviorCategory(doc["category"].GetString());

	if (doc.HasMember("apis") && doc["apis"].IsArray())
	{
		for (const auto& apiObj : doc["apis"].GetArray())
		{
			TTDApiDefinition api;

			if (apiObj.HasMember("symbol") && apiObj["symbol"].IsString())
				api.symbol = apiObj["symbol"].GetString();

			if (apiObj.HasMember("action") && apiObj["action"].IsString())
				api.action = apiObj["action"].GetString();

			if (apiObj.HasMember("values") && apiObj["values"].IsArray())
			{
				for (const auto& valObj : apiObj["values"].GetArray())
				{
					TTDValueDefinition value;

					if (valObj.HasMember("name") && valObj["name"].IsString())
						value.name = valObj["name"].GetString();

					if (valObj.HasMember("source") && valObj["source"].IsString())
						value.source = ParseValueSource(valObj["source"].GetString());

					if (valObj.HasMember("parameterIndex") && valObj["parameterIndex"].IsInt())
						value.parameterIndex = valObj["parameterIndex"].GetInt();

					if (valObj.HasMember("type") && valObj["type"].IsString())
						value.type = ParseValueType(valObj["type"].GetString());

					if (valObj.HasMember("collectTime") && valObj["collectTime"].IsString())
						value.collectTime = ParseCollectTime(valObj["collectTime"].GetString());

					if (valObj.HasMember("maxStringLength") && valObj["maxStringLength"].IsUint())
						value.maxStringLength = valObj["maxStringLength"].GetUint();

					api.values.push_back(value);
				}
			}

			set.apis.push_back(api);
		}
	}

	return set;
}

std::optional<TTDBehaviorAnalysisSet> TTDBehaviorAnalysisSetManager::LoadFromFile(const std::string& path)
{
	std::ifstream file(path);
	if (!file.is_open())
		return std::nullopt;

	std::stringstream buffer;
	buffer << file.rdbuf();
	return ParseFromJson(buffer.str());
}

std::string TTDBehaviorAnalysisSetManager::ToJson(const TTDBehaviorAnalysisSet& set)
{
	Document doc;
	doc.SetObject();
	auto& allocator = doc.GetAllocator();

	doc.AddMember("name", Value(set.name.c_str(), allocator), allocator);
	doc.AddMember("description", Value(set.description.c_str(), allocator), allocator);
	doc.AddMember("category", Value(TTDBehaviorCategoryToString(set.category).c_str(), allocator), allocator);

	Value apis(kArrayType);
	for (const auto& api : set.apis)
	{
		Value apiObj(kObjectType);
		apiObj.AddMember("symbol", Value(api.symbol.c_str(), allocator), allocator);
		apiObj.AddMember("action", Value(api.action.c_str(), allocator), allocator);

		Value values(kArrayType);
		for (const auto& val : api.values)
		{
			Value valObj(kObjectType);
			valObj.AddMember("name", Value(val.name.c_str(), allocator), allocator);
			valObj.AddMember("source", Value(ValueSourceToString(val.source).c_str(), allocator), allocator);
			valObj.AddMember("parameterIndex", val.parameterIndex, allocator);
			valObj.AddMember("type", Value(ValueTypeToString(val.type).c_str(), allocator), allocator);
			valObj.AddMember("collectTime", Value(CollectTimeToString(val.collectTime).c_str(), allocator), allocator);
			if (val.type == TTDValueType::StringA || val.type == TTDValueType::StringW)
				valObj.AddMember("maxStringLength", (unsigned)val.maxStringLength, allocator);
			values.PushBack(valObj, allocator);
		}
		apiObj.AddMember("values", values, allocator);
		apis.PushBack(apiObj, allocator);
	}
	doc.AddMember("apis", apis, allocator);

	StringBuffer buffer;
	PrettyWriter<StringBuffer> writer(buffer);
	doc.Accept(writer);

	return buffer.GetString();
}

TTDBehaviorAnalysisSet TTDBehaviorAnalysisSetManager::GetHeapAnalysisSet()
{
	// JSON definition for heap analysis (similar to Microsoft's HeapAnalysis.js)
	const char* json = R"({
		"name": "Heap Operations",
		"description": "Analyzes heap allocation, reallocation, and free operations",
		"category": "Heap",
		"apis": [
			{
				"symbol": "ntdll!RtlAllocateHeap",
				"action": "Alloc",
				"values": [
					{"name": "Heap", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Flags", "source": "parameter", "parameterIndex": 1, "type": "flags", "collectTime": "start"},
					{"name": "Size", "source": "parameter", "parameterIndex": 2, "type": "size", "collectTime": "start"},
					{"name": "Address", "source": "return", "parameterIndex": 0, "type": "pointer", "collectTime": "end"}
				]
			},
			{
				"symbol": "ntdll!RtlReAllocateHeap",
				"action": "ReAlloc",
				"values": [
					{"name": "Heap", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Flags", "source": "parameter", "parameterIndex": 1, "type": "flags", "collectTime": "start"},
					{"name": "OldAddress", "source": "parameter", "parameterIndex": 2, "type": "pointer", "collectTime": "start"},
					{"name": "Size", "source": "parameter", "parameterIndex": 3, "type": "size", "collectTime": "start"},
					{"name": "NewAddress", "source": "return", "parameterIndex": 0, "type": "pointer", "collectTime": "end"}
				]
			},
			{
				"symbol": "ntdll!RtlFreeHeap",
				"action": "Free",
				"values": [
					{"name": "Heap", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Flags", "source": "parameter", "parameterIndex": 1, "type": "flags", "collectTime": "start"},
					{"name": "Address", "source": "parameter", "parameterIndex": 2, "type": "pointer", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "ntdll!RtlCreateHeap",
				"action": "Create",
				"values": [
					{"name": "Flags", "source": "parameter", "parameterIndex": 0, "type": "flags", "collectTime": "start"},
					{"name": "BaseAddress", "source": "parameter", "parameterIndex": 1, "type": "pointer", "collectTime": "start"},
					{"name": "ReserveSize", "source": "parameter", "parameterIndex": 2, "type": "size", "collectTime": "start"},
					{"name": "CommitSize", "source": "parameter", "parameterIndex": 3, "type": "size", "collectTime": "start"},
					{"name": "Heap", "source": "return", "parameterIndex": 0, "type": "handle", "collectTime": "end"}
				]
			},
			{
				"symbol": "ntdll!RtlDestroyHeap",
				"action": "Destroy",
				"values": [
					{"name": "Heap", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "pointer", "collectTime": "end"}
				]
			},
			{
				"symbol": "ntdll!RtlLockHeap",
				"action": "Lock",
				"values": [
					{"name": "Heap", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "ntdll!RtlUnlockHeap",
				"action": "Unlock",
				"values": [
					{"name": "Heap", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			}
		]
	})";

	auto result = ParseFromJson(json);
	return result.value_or(TTDBehaviorAnalysisSet{});
}

TTDBehaviorAnalysisSet TTDBehaviorAnalysisSetManager::GetFileAnalysisSet()
{
	// JSON definition for file operations analysis
	const char* json = R"({
		"name": "File Operations",
		"description": "Analyzes file open, read, write, and close operations",
		"category": "File",
		"apis": [
			{
				"symbol": "kernel32!CreateFileA",
				"action": "Open",
				"values": [
					{"name": "FileName", "source": "dereference", "parameterIndex": 0, "type": "string_a", "collectTime": "start", "maxStringLength": 260},
					{"name": "DesiredAccess", "source": "parameter", "parameterIndex": 1, "type": "flags", "collectTime": "start"},
					{"name": "ShareMode", "source": "parameter", "parameterIndex": 2, "type": "flags", "collectTime": "start"},
					{"name": "CreationDisposition", "source": "parameter", "parameterIndex": 4, "type": "flags", "collectTime": "start"},
					{"name": "Handle", "source": "return", "parameterIndex": 0, "type": "handle", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!CreateFileW",
				"action": "Open",
				"values": [
					{"name": "FileName", "source": "dereference", "parameterIndex": 0, "type": "string_w", "collectTime": "start", "maxStringLength": 260},
					{"name": "DesiredAccess", "source": "parameter", "parameterIndex": 1, "type": "flags", "collectTime": "start"},
					{"name": "ShareMode", "source": "parameter", "parameterIndex": 2, "type": "flags", "collectTime": "start"},
					{"name": "CreationDisposition", "source": "parameter", "parameterIndex": 4, "type": "flags", "collectTime": "start"},
					{"name": "Handle", "source": "return", "parameterIndex": 0, "type": "handle", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernelbase!CreateFileA",
				"action": "Open",
				"values": [
					{"name": "FileName", "source": "dereference", "parameterIndex": 0, "type": "string_a", "collectTime": "start", "maxStringLength": 260},
					{"name": "DesiredAccess", "source": "parameter", "parameterIndex": 1, "type": "flags", "collectTime": "start"},
					{"name": "ShareMode", "source": "parameter", "parameterIndex": 2, "type": "flags", "collectTime": "start"},
					{"name": "CreationDisposition", "source": "parameter", "parameterIndex": 4, "type": "flags", "collectTime": "start"},
					{"name": "Handle", "source": "return", "parameterIndex": 0, "type": "handle", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernelbase!CreateFileW",
				"action": "Open",
				"values": [
					{"name": "FileName", "source": "dereference", "parameterIndex": 0, "type": "string_w", "collectTime": "start", "maxStringLength": 260},
					{"name": "DesiredAccess", "source": "parameter", "parameterIndex": 1, "type": "flags", "collectTime": "start"},
					{"name": "ShareMode", "source": "parameter", "parameterIndex": 2, "type": "flags", "collectTime": "start"},
					{"name": "CreationDisposition", "source": "parameter", "parameterIndex": 4, "type": "flags", "collectTime": "start"},
					{"name": "Handle", "source": "return", "parameterIndex": 0, "type": "handle", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!ReadFile",
				"action": "Read",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Buffer", "source": "parameter", "parameterIndex": 1, "type": "pointer", "collectTime": "start"},
					{"name": "BytesToRead", "source": "parameter", "parameterIndex": 2, "type": "size", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernelbase!ReadFile",
				"action": "Read",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Buffer", "source": "parameter", "parameterIndex": 1, "type": "pointer", "collectTime": "start"},
					{"name": "BytesToRead", "source": "parameter", "parameterIndex": 2, "type": "size", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!WriteFile",
				"action": "Write",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Buffer", "source": "parameter", "parameterIndex": 1, "type": "pointer", "collectTime": "start"},
					{"name": "BytesToWrite", "source": "parameter", "parameterIndex": 2, "type": "size", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernelbase!WriteFile",
				"action": "Write",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Buffer", "source": "parameter", "parameterIndex": 1, "type": "pointer", "collectTime": "start"},
					{"name": "BytesToWrite", "source": "parameter", "parameterIndex": 2, "type": "size", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!CloseHandle",
				"action": "Close",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernelbase!CloseHandle",
				"action": "Close",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!DeleteFileA",
				"action": "Delete",
				"values": [
					{"name": "FileName", "source": "dereference", "parameterIndex": 0, "type": "string_a", "collectTime": "start", "maxStringLength": 260},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!DeleteFileW",
				"action": "Delete",
				"values": [
					{"name": "FileName", "source": "dereference", "parameterIndex": 0, "type": "string_w", "collectTime": "start", "maxStringLength": 260},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!CopyFileA",
				"action": "Copy",
				"values": [
					{"name": "SourceFileName", "source": "dereference", "parameterIndex": 0, "type": "string_a", "collectTime": "start", "maxStringLength": 260},
					{"name": "DestFileName", "source": "dereference", "parameterIndex": 1, "type": "string_a", "collectTime": "start", "maxStringLength": 260},
					{"name": "FailIfExists", "source": "parameter", "parameterIndex": 2, "type": "boolean", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!CopyFileW",
				"action": "Copy",
				"values": [
					{"name": "SourceFileName", "source": "dereference", "parameterIndex": 0, "type": "string_w", "collectTime": "start", "maxStringLength": 260},
					{"name": "DestFileName", "source": "dereference", "parameterIndex": 1, "type": "string_w", "collectTime": "start", "maxStringLength": 260},
					{"name": "FailIfExists", "source": "parameter", "parameterIndex": 2, "type": "boolean", "collectTime": "start"},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!MoveFileA",
				"action": "Move",
				"values": [
					{"name": "SourceFileName", "source": "dereference", "parameterIndex": 0, "type": "string_a", "collectTime": "start", "maxStringLength": 260},
					{"name": "DestFileName", "source": "dereference", "parameterIndex": 1, "type": "string_a", "collectTime": "start", "maxStringLength": 260},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!MoveFileW",
				"action": "Move",
				"values": [
					{"name": "SourceFileName", "source": "dereference", "parameterIndex": 0, "type": "string_w", "collectTime": "start", "maxStringLength": 260},
					{"name": "DestFileName", "source": "dereference", "parameterIndex": 1, "type": "string_w", "collectTime": "start", "maxStringLength": 260},
					{"name": "Result", "source": "return", "parameterIndex": 0, "type": "boolean", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!SetFilePointer",
				"action": "Seek",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Distance", "source": "parameter", "parameterIndex": 1, "type": "integer", "collectTime": "start"},
					{"name": "MoveMethod", "source": "parameter", "parameterIndex": 3, "type": "flags", "collectTime": "start"},
					{"name": "NewPosition", "source": "return", "parameterIndex": 0, "type": "integer", "collectTime": "end"}
				]
			},
			{
				"symbol": "kernel32!GetFileSize",
				"action": "GetSize",
				"values": [
					{"name": "Handle", "source": "parameter", "parameterIndex": 0, "type": "handle", "collectTime": "start"},
					{"name": "Size", "source": "return", "parameterIndex": 0, "type": "size", "collectTime": "end"}
				]
			}
		]
	})";

	auto result = ParseFromJson(json);
	return result.value_or(TTDBehaviorAnalysisSet{});
}

std::vector<TTDBehaviorAnalysisSet> TTDBehaviorAnalysisSetManager::GetBuiltinSets()
{
	return {
		GetHeapAnalysisSet(),
		GetFileAnalysisSet()
	};
}
