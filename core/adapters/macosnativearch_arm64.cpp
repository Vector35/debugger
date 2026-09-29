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

#include "macosnativearch.h"
#include <mach/arm/thread_status.h>
#include <cstring>

using namespace BinaryNinjaDebugger;

namespace {
	bool GeneralState(thread_t thread, arm_thread_state64_t& state)
	{
		mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
		return thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count) == KERN_SUCCESS;
	}
	bool DebugState(thread_t thread, arm_debug_state64_t& state)
	{
		mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
		return thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state, &count) == KERN_SUCCESS;
	}
}  // namespace

std::unordered_map<std::string, DebugRegister> MacOSNativeArch::ReadRegisters(thread_t thread)
{
	std::unordered_map<std::string, DebugRegister> result;
	arm_thread_state64_t state {};
	if (!GeneralState(thread, state))
		return result;
	for (size_t i = 0; i < 29; ++i)
	{
		auto name = "x" + std::to_string(i);
		result.emplace(name, DebugRegister(name, state.__x[i], 64, i));
	}
	auto add = [&](const std::string& name, uint64_t value, size_t bits, size_t index) {
		result.emplace(name, DebugRegister(name, value, bits, index));
	};
	add("fp", arm_thread_state64_get_fp(state), 64, 29);
	add("lr", arm_thread_state64_get_lr(state), 64, 30);
	add("sp", arm_thread_state64_get_sp(state), 64, 31);
	add("pc", arm_thread_state64_get_pc(state), 64, 32);
	add("cpsr", state.__cpsr, 32, 33);
	arm_neon_state64_t neon {};
	mach_msg_type_number_t count = ARM_NEON_STATE64_COUNT;
	if (thread_get_state(thread, ARM_NEON_STATE64, (thread_state_t)&neon, &count) == KERN_SUCCESS)
	{
		for (size_t i = 0; i < 32; ++i)
		{
			intx::uint512 value {};
			memcpy(&value, &neon.__v[i], 16);
			auto name = "v" + std::to_string(i);
			result.emplace(name, DebugRegister(name, value, 128, 34 + i));
		}
		add("fpsr", neon.__fpsr, 32, 66);
		add("fpcr", neon.__fpcr, 32, 67);
	}
	return result;
}

bool MacOSNativeArch::WriteRegister(thread_t thread, const std::string& name, intx::uint512 value)
{
	arm_thread_state64_t state {};
	if (!GeneralState(thread, state))
		return false;
	uint64_t v = (uint64_t)value;
	if (name == "pc")
		arm_thread_state64_set_pc_fptr(state, (void*)v);
	else if (name == "sp")
		arm_thread_state64_set_sp(state, v);
	else if (name == "fp" || name == "x29")
		arm_thread_state64_set_fp(state, v);
	else if (name == "lr" || name == "x30")
		arm_thread_state64_set_lr_fptr(state, (void*)v);
	else if (name == "cpsr")
		state.__cpsr = (uint32_t)v;
	else if (name.size() > 1 && name[0] == 'x')
	{
		char* end = nullptr;
		unsigned long index = strtoul(name.c_str() + 1, &end, 10);
		if (*end || index >= 29)
			return false;
		state.__x[index] = v;
	}
	else
	{
		arm_neon_state64_t neon {};
		mach_msg_type_number_t count = ARM_NEON_STATE64_COUNT;
		if (thread_get_state(thread, ARM_NEON_STATE64, (thread_state_t)&neon, &count) != KERN_SUCCESS)
			return false;
		if (name == "fpsr")
			neon.__fpsr = (uint32_t)v;
		else if (name == "fpcr")
			neon.__fpcr = (uint32_t)v;
		else if (name.size() > 1 && name[0] == 'v')
		{
			char* end = nullptr;
			unsigned long index = strtoul(name.c_str() + 1, &end, 10);
			if (*end || index >= 32)
				return false;
			memcpy(&neon.__v[index], &value, 16);
		}
		else
			return false;
		return thread_set_state(thread, ARM_NEON_STATE64, (thread_state_t)&neon, count) == KERN_SUCCESS;
	}
	return thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT)
		== KERN_SUCCESS;
}

bool MacOSNativeArch::SetSingleStep(thread_t thread, bool enabled)
{
	arm_debug_state64_t state {};
	if (!DebugState(thread, state))
		return false;
	if (enabled)
		state.__mdscr_el1 |= 1;
	else
		state.__mdscr_el1 &= ~uint64_t(1);
	return thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state, ARM_DEBUG_STATE64_COUNT) == KERN_SUCCESS;
}

bool MacOSNativeArch::SetHardwareBreakpoint(
	thread_t thread, unsigned slot, uint64_t address, DebugBreakpointType type, size_t size, bool enabled)
{
	if (slot >= 16)
		return false;
	arm_debug_state64_t state {};
	if (!DebugState(thread, state))
		return false;
	if (type == HardwareExecuteBreakpoint)
	{
		if (address & 3)
			return false;
		state.__bvr[slot] = enabled ? address : 0;
		state.__bcr[slot] = enabled ? (1 | (2 << 1) | (15 << 5)) : 0;
	}
	else
	{
		if ((size != 1 && size != 2 && size != 4 && size != 8) || (address & 7) + size > 8)
			return false;
		unsigned access = type == HardwareWriteBreakpoint ? 2 : type == HardwareReadBreakpoint ? 1 : 3;
		state.__wvr[slot] = enabled ? address & ~uint64_t(7) : 0;
		state.__wcr[slot] =
			enabled ? 1 | (2 << 1) | (access << 3) | (((uint64_t(1) << size) - 1) << (5 + (address & 7))) : 0;
	}
	return thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state, ARM_DEBUG_STATE64_COUNT) == KERN_SUCCESS;
}

uint64_t MacOSNativeArch::InstructionPointer(thread_t thread)
{
	arm_thread_state64_t state {};
	return GeneralState(thread, state) ? arm_thread_state64_get_pc(state) : 0;
}
uint64_t MacOSNativeArch::StackPointer(thread_t thread)
{
	arm_thread_state64_t state {};
	return GeneralState(thread, state) ? arm_thread_state64_get_sp(state) : 0;
}
uint64_t MacOSNativeArch::FramePointer(thread_t thread)
{
	arm_thread_state64_t state {};
	return GeneralState(thread, state) ? arm_thread_state64_get_fp(state) : 0;
}
uint64_t MacOSNativeArch::LinkRegister(thread_t thread)
{
	arm_thread_state64_t state {};
	return GeneralState(thread, state) ? arm_thread_state64_get_lr(state) : 0;
}
