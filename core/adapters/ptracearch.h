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
#include <sys/types.h>
#include <cstddef>
#include <string>
#include <vector>

namespace BinaryNinjaDebugger {
	// Where a register lives inside one of the register sets that PTRACE_GETREGSET returns
	struct PtraceRegister
	{
		std::string name;
		int regset;
		size_t offset;
		size_t size;
	};

	// Describes the registers of one target architecture. Nothing outside of this table and DetectPtraceArch needs to
	// know how a particular architecture lays its registers out.
	struct PtraceArch
	{
		std::string name;
		std::string pc;
		std::string sp;
		std::vector<PtraceRegister> registers;
		std::vector<int> regsets;

		const PtraceRegister* Find(const std::string& registerName) const;
	};

	const PtraceArch& PtraceArchX86_64();
	const PtraceArch& PtraceArchX86();

	// Returns nullptr if the architecture of the process is not supported
	const PtraceArch* DetectPtraceArch(pid_t pid);
}  // namespace BinaryNinjaDebugger
