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

#include "ptracearch.h"
#include <elf.h>
#include <fstream>

namespace BinaryNinjaDebugger {

	const PtraceRegister* PtraceArch::Find(const std::string& registerName) const
	{
		for (const auto& reg : registers)
		{
			if (reg.name == registerName)
				return &reg;
		}
		return nullptr;
	}


	static void AddRegisters(PtraceArch& arch, int regset, size_t size, const std::vector<const char*>& names,
		const std::vector<size_t>& indices)
	{
		for (size_t i = 0; i < names.size(); i++)
			arch.registers.push_back({names[i], regset, indices[i] * size, size});
	}


	static PtraceArch BuildX86_64()
	{
		PtraceArch arch;
		arch.name = "x86_64";
		arch.pc = "rip";
		arch.sp = "rsp";
		arch.regsets = {NT_PRSTATUS, NT_PRFPREG};

		// The order of user_regs_struct: r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs
		// eflags rsp ss fs_base gs_base ds es fs gs. The registers are listed in the order GDB uses.
		AddRegisters(arch, NT_PRSTATUS, 8,
			{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
				"r15", "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs", "fs_base", "gs_base", "orig_rax"},
			{10, 5, 11, 12, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16, 18, 17, 20, 23, 24, 25, 26, 21, 22, 15});

		// user_fpregs_struct, which is the FXSAVE area
		arch.registers.push_back({"fctrl", NT_PRFPREG, 0, 2});
		arch.registers.push_back({"fstat", NT_PRFPREG, 2, 2});
		arch.registers.push_back({"fop", NT_PRFPREG, 6, 2});
		arch.registers.push_back({"mxcsr", NT_PRFPREG, 24, 4});
		for (size_t i = 0; i < 8; i++)
			arch.registers.push_back({"st" + std::to_string(i), NT_PRFPREG, 32 + i * 16, 10});
		for (size_t i = 0; i < 16; i++)
			arch.registers.push_back({"xmm" + std::to_string(i), NT_PRFPREG, 160 + i * 16, 16});
		return arch;
	}


	static PtraceArch BuildX86()
	{
		PtraceArch arch;
		arch.name = "x86";
		arch.pc = "eip";
		arch.sp = "esp";
		arch.regsets = {NT_PRSTATUS};

		// The order of the 32-bit user_regs_struct: ebx ecx edx esi edi ebp eax xds xes xfs xgs orig_eax eip xcs
		// eflags esp xss
		AddRegisters(arch, NT_PRSTATUS, 4,
			{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags", "cs", "ss", "ds", "es", "fs",
				"gs", "orig_eax"},
			{6, 1, 2, 0, 15, 5, 3, 4, 12, 14, 13, 16, 7, 8, 9, 10, 11});
		return arch;
	}


	const PtraceArch& PtraceArchX86_64()
	{
		static const PtraceArch arch = BuildX86_64();
		return arch;
	}


	const PtraceArch& PtraceArchX86()
	{
		static const PtraceArch arch = BuildX86();
		return arch;
	}


	const PtraceArch* DetectPtraceArch(pid_t pid)
	{
		std::ifstream file("/proc/" + std::to_string(pid) + "/exe", std::ios::binary);
		unsigned char header[20] = {};
		if (!file.read(reinterpret_cast<char*>(header), sizeof(header)))
			return nullptr;
		if (header[EI_MAG0] != ELFMAG0 || header[EI_MAG1] != ELFMAG1 || header[EI_MAG2] != ELFMAG2
			|| header[EI_MAG3] != ELFMAG3 || header[EI_DATA] != ELFDATA2LSB)
			return nullptr;

		// e_machine follows e_type, and both are 16 bits
		unsigned int machine = header[18] | (header[19] << 8);
		switch (machine)
		{
		case EM_X86_64:
			return &PtraceArchX86_64();
		case EM_386:
			return &PtraceArchX86();
		default:
			return nullptr;
		}
	}

}  // namespace BinaryNinjaDebugger
