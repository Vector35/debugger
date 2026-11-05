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
#include <string>
#include "ptraceengine.h"

namespace BinaryNinjaDebugger {
	// The AUDIT_ARCH_* values that PTRACE_GET_SYSCALL_INFO reports. They say which system call table a number belongs
	// to, which is not always the architecture of the debugger's table: a 32-bit program on a 64-bit kernel makes the
	// system calls of i386.
	constexpr uint32_t AuditArchX86_64 = 0xC000003E;
	constexpr uint32_t AuditArchI386 = 0x40000003;

	// The name of a system call, or nullptr if there is no table for the architecture, or no such number in it
	const char* SyscallName(uint32_t auditArch, uint64_t number);

	// One line that tells what the stop was: `openat(0xffffff9c, 0x7ffc1000, 0x0, 0x0, 0x0, 0x0)` at an entry, and
	// `= 3` or `= -2 (No such file or directory)` at an exit. With `verbose` the line has the registers and the kind of
	// the stop in front. The arguments are all six registers, because the number of them is not in the table.
	std::string DescribeSyscall(const PtraceEngine::SyscallInfo& info, bool verbose = false);
}  // namespace BinaryNinjaDebugger
