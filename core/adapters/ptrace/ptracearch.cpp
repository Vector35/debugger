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
#include <cerrno>
#include <fstream>
#include <set>
#include <sys/ptrace.h>
#if defined(__i386__) || defined(__x86_64__)
#include <sys/user.h>
#endif

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


	// PTRACE_PEEKUSER and PTRACE_POKEUSER use the ptracer's syscall ABI. A 64-bit debugger therefore uses its native
	// struct user layout even when the tracee is a 32-bit process.
	class X86HwDebug : public PtraceHwDebug
	{
		size_t m_offset;
		size_t m_stride;

		bool ReadDr(pid_t tid, size_t index, unsigned long& value)
		{
			errno = 0;
			value = ptrace(PTRACE_PEEKUSER, tid, (void*)(m_offset + index * m_stride), nullptr);
			return errno == 0;
		}

		bool WriteDr(pid_t tid, size_t index, unsigned long value)
		{
			return ptrace(PTRACE_POKEUSER, tid, (void*)(m_offset + index * m_stride), (void*)value) == 0;
		}

	public:
		X86HwDebug(size_t offset, size_t stride) : m_offset(offset), m_stride(stride) {}

		size_t SlotCount() const override { return 4; }

		bool SlotSupports(size_t slot, PtraceHwType type) const override { return slot < 4; }

		bool Set(pid_t tid, size_t slot, uint64_t address, PtraceHwType type, size_t size) override
		{
			// x86 has no read-only watchpoint, so a read watches for any access
			unsigned long rw = type == PtraceHwType::Execute ? 0 : (type == PtraceHwType::Write ? 1 : 3);
			unsigned long len;
			switch (type == PtraceHwType::Execute ? 1 : size)
			{
			case 1:
				len = 0;
				break;
			case 2:
				len = 1;
				break;
			case 4:
				len = 3;
				break;
			case 8:
				len = 2;
				break;
			default:
				return false;
			}

			unsigned long control;
			if (!ReadDr(tid, 7, control) || !WriteDr(tid, slot, address))
				return false;

			control &= ~((3ul << (16 + slot * 4)) | (3ul << (18 + slot * 4)) | (1ul << (slot * 2)));
			control |= (1ul << (slot * 2)) | (rw << (16 + slot * 4)) | (len << (18 + slot * 4));
			return WriteDr(tid, 7, control);
		}

		bool Clear(pid_t tid, size_t slot) override
		{
			unsigned long control;
			if (!ReadDr(tid, 7, control))
				return false;

			control &= ~((3ul << (16 + slot * 4)) | (3ul << (18 + slot * 4)) | (1ul << (slot * 2)));
			return WriteDr(tid, 7, control) && WriteDr(tid, slot, 0);
		}

		void OnTrap(pid_t tid) override { WriteDr(tid, 6, 0); }
	};


	std::vector<PtraceRegister> DeriveSubRegisters(
		const PtraceArch& arch, const std::vector<PtraceRegisterDescription>& described)
	{
		std::vector<PtraceRegister> result;
		// What is at the low end of a register is at its first byte only on a little-endian one
		if (!arch.littleEndian)
			return result;

		std::set<std::string> seen;
		for (const auto& description : described)
		{
			if (description.name.empty() || description.parent.empty() || description.parent == description.name
				|| description.size == 0 || arch.Find(description.name) || !seen.insert(description.name).second)
				continue;

			auto parent = arch.Find(description.parent);
			if (!parent || description.offset + description.size > parent->size)
				continue;

			result.push_back({description.name, parent->regset, parent->offset + description.offset, description.size});
		}
		return result;
	}


	std::vector<std::string> CheckRegisterSizes(
		const PtraceArch& arch, const std::vector<PtraceRegisterDescription>& described)
	{
		std::vector<std::string> result;
		for (const auto& description : described)
		{
			if (description.name.empty() || description.parent != description.name)
				continue;

			auto reg = arch.Find(description.name);
			if (reg && reg->size != description.size)
				result.push_back(description.name + " is " + std::to_string(reg->size) + " bytes in the table, and "
					+ std::to_string(description.size) + " for the architecture");
		}
		return result;
	}


	static PtraceHwDebug* NativeX86HwDebug()
	{
#if defined(__i386__) || defined(__x86_64__)
		static X86HwDebug hwDebug(
			offsetof(struct user, u_debugreg), sizeof(((struct user*)nullptr)->u_debugreg[0]));
		return &hwDebug;
#else
		return nullptr;
#endif
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
		arch.fp = "rbp";
		arch.regsets = {NT_PRSTATUS, NT_PRFPREG};
		arch.breakpointInstruction = {0xcc};
		arch.breakpointPcAdjust = 1;
		arch.hwDebug = NativeX86HwDebug();
		arch.sysemu = true;

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
		arch.fp = "ebp";
		arch.regsets = {NT_PRSTATUS};
		arch.breakpointInstruction = {0xcc};
		arch.breakpointPcAdjust = 1;
		arch.hwDebug = NativeX86HwDebug();
		arch.sysemu = true;

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
