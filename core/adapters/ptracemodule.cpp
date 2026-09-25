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

#include "ptracemodule.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>

namespace BinaryNinjaDebugger {

	// The segments of a module sit right next to each other, apart from the gaps that the loader leaves in between
	static constexpr uint64_t ModuleSegmentGapLimit = 0x4000000;


	std::vector<PtraceModuleInfo> BuildModules(
		const std::vector<PtraceEngine::MapEntry>& maps, const std::function<bool(uint64_t)>& isElf)
	{
		auto sorted = maps;
		std::sort(sorted.begin(), sorted.end(),
			[](const PtraceEngine::MapEntry& a, const PtraceEngine::MapEntry& b) { return a.start < b.start; });

		std::vector<PtraceModuleInfo> modules;
		// The module of each path that is still being extended
		std::map<std::string, size_t> open;

		for (size_t i = 0; i < sorted.size(); i++)
		{
			const auto& map = sorted[i];
			if (map.path.empty() || map.path[0] != '/')
				continue;

			auto it = open.find(map.path);
			if (it != open.end())
			{
				auto& module = modules[it->second];
				uint64_t moduleEnd = module.base + module.size;
				if (map.start >= moduleEnd && map.start - moduleEnd <= ModuleSegmentGapLimit)
				{
					module.size = map.end - module.base;
					continue;
				}
			}

			// A module begins where its file is mapped from the start
			if (map.offset != 0 || !isElf(map.start))
				continue;

			PtraceModuleInfo module;
			module.path = map.path;
			module.base = map.start;
			module.size = map.end - map.start;
			open[map.path] = modules.size();
			modules.push_back(module);
		}

		// The zero-filled memory that follows the last segment belongs to the module as well
		for (auto& module : modules)
		{
			for (const auto& map : sorted)
			{
				if (map.start == module.base + module.size && map.path.empty())
				{
					module.size = map.end - module.base;
					break;
				}
			}
		}

		std::map<std::string, int> seen;
		for (auto& module : modules)
		{
			module.shortName = std::filesystem::path(module.path).filename().string();
			int count = seen[module.shortName]++;
			if (count > 0)
				module.shortName += "-" + std::to_string(count);
		}
		return modules;
	}


	std::vector<PtraceFrameRecord> UnwindFramePointers(uint64_t pc, uint64_t sp, uint64_t fp, size_t wordSize,
		const std::function<bool(uint64_t, uint64_t&)>& readWord,
		const std::function<bool(uint64_t)>& isExecutable, size_t maxFrames)
	{
		std::vector<PtraceFrameRecord> frames;
		frames.push_back({pc, sp, fp});

		while (frames.size() < maxFrames)
		{
			const auto current = frames.back();
			// The stack grows down, so a frame pointer is never below the stack pointer
			if (current.fp == 0 || current.fp % wordSize != 0 || current.fp < current.sp)
				break;

			uint64_t callerFp, returnAddress;
			if (!readWord(current.fp, callerFp) || !readWord(current.fp + wordSize, returnAddress))
				break;
			if (returnAddress == 0 || !isExecutable(returnAddress))
				break;
			// The caller's frame is further up the stack
			if (callerFp != 0 && callerFp <= current.fp)
				break;

			frames.push_back({returnAddress, current.fp + 2 * wordSize, callerFp});
		}
		return frames;
	}


	static std::string ReadSmallFile(const std::filesystem::path& path)
	{
		std::ifstream file(path, std::ios::binary);
		std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		return contents;
	}


	std::vector<PtraceProcessInfo> ListProcesses()
	{
		std::vector<PtraceProcessInfo> processes;
		std::error_code error;
		for (const auto& entry : std::filesystem::directory_iterator("/proc", error))
		{
			std::string name = entry.path().filename().string();
			if (name.empty() || !std::all_of(name.begin(), name.end(), [](char c) { return c >= '0' && c <= '9'; }))
				continue;

			PtraceProcessInfo process;
			process.pid = std::stoul(name);
			process.name = ReadSmallFile(entry.path() / "comm");
			while (!process.name.empty() && process.name.back() == '\n')
				process.name.pop_back();

			// The arguments are separated by null characters
			std::string commandLine = ReadSmallFile(entry.path() / "cmdline");
			std::replace(commandLine.begin(), commandLine.end(), '\0', ' ');
			while (!commandLine.empty() && commandLine.back() == ' ')
				commandLine.pop_back();
			process.commandLine = commandLine;

			// The process may have gone away since it was listed
			if (process.name.empty())
				continue;
			processes.push_back(std::move(process));
		}

		std::sort(processes.begin(), processes.end(),
			[](const PtraceProcessInfo& a, const PtraceProcessInfo& b) { return a.pid < b.pid; });
		return processes;
	}

}  // namespace BinaryNinjaDebugger
