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

#include "../debugadapter.h"
#include <mach/mach.h>

namespace BinaryNinjaDebugger::MacOSNativeArch {
	std::unordered_map<std::string, DebugRegister> ReadRegisters(thread_t thread);
	bool WriteRegister(thread_t thread, const std::string& name, intx::uint512 value);
	bool SetSingleStep(thread_t thread, bool enabled);
	bool SetHardwareBreakpoint(
		thread_t thread, unsigned slot, uint64_t address, DebugBreakpointType type, size_t size, bool enabled);
	uint64_t InstructionPointer(thread_t thread);
	uint64_t StackPointer(thread_t thread);
	uint64_t FramePointer(thread_t thread);
	uint64_t LinkRegister(thread_t thread);
	constexpr uint32_t SoftwareTrap = 0xd4200000;  // brk #0
	constexpr size_t SoftwareTrapSize = 4;
}  // namespace BinaryNinjaDebugger::MacOSNativeArch
