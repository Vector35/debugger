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
#include <vector>
#include "ptraceengine.h"

namespace BinaryNinjaDebugger {
	struct PtraceModuleInfo
	{
		std::string path;
		// The base name, made unique if two modules have the same one
		std::string shortName;
		uint64_t base = 0;
		uint64_t size = 0;
	};

	// Groups the file mappings of a process into the modules that they belong to. `isElf` tells whether the file
	// mapped at an address is an ELF object, which leaves out the data files that are mapped too.
	std::vector<PtraceModuleInfo> BuildModules(
		const std::vector<PtraceEngine::MapEntry>& maps, const std::function<bool(uint64_t)>& isElf);

	struct PtraceFrameRecord
	{
		uint64_t pc = 0;
		uint64_t sp = 0;
		uint64_t fp = 0;
	};

	// Follows the chain of saved frame pointers. Every frame is expected to keep the caller's frame pointer and its
	// return address next to each other, where its own frame pointer points. It stops at the first frame that does not
	// look right, so code that does not keep frame pointers ends the trace early.
	std::vector<PtraceFrameRecord> UnwindFramePointers(uint64_t pc, uint64_t sp, uint64_t fp, size_t wordSize,
		const std::function<bool(uint64_t, uint64_t&)>& readWord, const std::function<bool(uint64_t)>& isExecutable,
		size_t maxFrames = 256);

	struct PtraceProcessInfo
	{
		uint32_t pid = 0;
		std::string name;
		std::string commandLine;
	};

	std::vector<PtraceProcessInfo> ListProcesses();
}  // namespace BinaryNinjaDebugger
