#include "ptracearch.h"
#include <sys/user.h>
#include <elf.h>
#include <cstdio>
#include <cstddef>
#include <map>
using namespace BinaryNinjaDebugger;
static int bad = 0;
static void check(const PtraceArch& a, const std::map<std::string, size_t>& gpr, const std::map<std::string, size_t>& fp, size_t gprSize, size_t fpSize, size_t gprExpected)
{
	printf("%s: %zu registers, gpr struct %zu bytes\n", a.name.c_str(), a.registers.size(), gprSize);
	size_t seen = 0;
	for (auto& r : a.registers)
	{
		auto& m = r.regset == NT_PRSTATUS ? gpr : fp; auto it = m.find(r.name);
		if (it == m.end()) { printf("  no reference for %s\n", r.name.c_str()); bad++; continue; }
		if (it->second != r.offset) { printf("  MISMATCH %s: table %zu, kernel %zu\n", r.name.c_str(), r.offset, it->second); bad++; }
		if (r.offset + r.size > (r.regset == NT_PRSTATUS ? gprSize : fpSize)) { printf("  %s out of bounds\n", r.name.c_str()); bad++; }
		seen++;
	}
	printf("  checked %zu\n", seen);
	size_t gprCount = 0; for (auto& r : a.registers) if (r.regset == NT_PRSTATUS) gprCount++;
	if (gprCount != gprExpected) { printf("  gpr count %zu != %zu\n", gprCount, gprExpected); bad++; }
	if (!a.Find(a.pc) || !a.Find(a.sp)) { printf("  pc/sp missing\n"); bad++; }
}
#define G(n) {#n, offsetof(user_regs_struct, n)}
static void hw(const PtraceArch& a, size_t expected)
{
	printf("%s: hw debug %s, breakpoint %zu byte(s) 0x%02x adjust %zu, u_debugreg offset %zu (table)\n", a.name.c_str(), a.hwDebug ? "yes" : "NO", a.breakpointInstruction.size(), a.breakpointInstruction.empty() ? 0 : a.breakpointInstruction[0], a.breakpointPcAdjust, expected);
	if (!a.hwDebug || a.hwDebug->SlotCount() != 4 || a.breakpointInstruction != std::vector<uint8_t>{0xcc} || a.breakpointPcAdjust != 1) { printf("  PROBLEM\n"); bad++; }
}
int main()
{
#if defined(__x86_64__)
	std::map<std::string, size_t> gpr = {G(rax),G(rbx),G(rcx),G(rdx),G(rsi),G(rdi),G(rbp),G(rsp),G(r8),G(r9),G(r10),G(r11),G(r12),G(r13),G(r14),G(r15),G(rip),G(eflags),G(cs),G(ss),G(ds),G(es),G(fs),G(gs),G(fs_base),G(gs_base),G(orig_rax)};
	std::map<std::string, size_t> fp = {{"fctrl", offsetof(user_fpregs_struct, cwd)},{"fstat", offsetof(user_fpregs_struct, swd)},{"fop", offsetof(user_fpregs_struct, fop)},{"mxcsr", offsetof(user_fpregs_struct, mxcsr)}};
	for (int i = 0; i < 8; i++) fp["st" + std::to_string(i)] = offsetof(user_fpregs_struct, st_space) + i * 16;
	for (int i = 0; i < 16; i++) fp["xmm" + std::to_string(i)] = offsetof(user_fpregs_struct, xmm_space) + i * 16;
	printf("sizeof user_regs_struct=%zu user_fpregs_struct=%zu\n", sizeof(user_regs_struct), sizeof(user_fpregs_struct));
	check(PtraceArchX86_64(), gpr, fp, sizeof(user_regs_struct), sizeof(user_fpregs_struct), 27);
	printf("offsetof(user, u_debugreg) = %zu\n", offsetof(struct user, u_debugreg)); if (offsetof(struct user, u_debugreg) != 848) { printf("  MISMATCH with 848\n"); bad++; }
	hw(PtraceArchX86_64(), 848);
#elif defined(__i386__)
	std::map<std::string, size_t> gpr = {{"eax",offsetof(user_regs_struct,eax)},{"ecx",offsetof(user_regs_struct,ecx)},{"edx",offsetof(user_regs_struct,edx)},{"ebx",offsetof(user_regs_struct,ebx)},{"esp",offsetof(user_regs_struct,esp)},{"ebp",offsetof(user_regs_struct,ebp)},{"esi",offsetof(user_regs_struct,esi)},{"edi",offsetof(user_regs_struct,edi)},{"eip",offsetof(user_regs_struct,eip)},{"eflags",offsetof(user_regs_struct,eflags)},{"cs",offsetof(user_regs_struct,xcs)},{"ss",offsetof(user_regs_struct,xss)},{"ds",offsetof(user_regs_struct,xds)},{"es",offsetof(user_regs_struct,xes)},{"fs",offsetof(user_regs_struct,xfs)},{"gs",offsetof(user_regs_struct,xgs)},{"orig_eax",offsetof(user_regs_struct,orig_eax)}};
	printf("sizeof user_regs_struct=%zu\n", sizeof(user_regs_struct));
	check(PtraceArchX86(), gpr, {}, sizeof(user_regs_struct), 0, 17);
	printf("offsetof(user, u_debugreg) = %zu\n", offsetof(struct user, u_debugreg)); if (offsetof(struct user, u_debugreg) != 252) { printf("  MISMATCH with 252\n"); bad++; }
	hw(PtraceArchX86(), 252);
#endif
	printf(bad ? "%d PROBLEMS\n" : "layout ok\n", bad);
	return bad != 0;
}
