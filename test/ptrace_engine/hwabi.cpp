#include "ptracearch.h"
#include <cstdarg>
#include <cstdio>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <vector>
using namespace BinaryNinjaDebugger;

static std::vector<uintptr_t> g_addresses;

extern "C" long ptrace(enum __ptrace_request request, ...)
{
	va_list args;
	va_start(args, request);
	(void)va_arg(args, pid_t);
	void* address = va_arg(args, void*);
	(void)va_arg(args, void*);
	va_end(args);
	if (request == PTRACE_PEEKUSER || request == PTRACE_POKEUSER)
		g_addresses.push_back(reinterpret_cast<uintptr_t>(address));
	return 0;
}

int main()
{
#if defined(__x86_64__)
	const size_t nativeOffset = offsetof(struct user, u_debugreg);
	bool programmed = PtraceArchX86().hwDebug->Set(123, 0, 0x1234, PtraceHwType::Execute, 1);
	bool good = programmed && g_addresses.size() == 3
		&& g_addresses[0] == nativeOffset + 7 * sizeof(long)
		&& g_addresses[1] == nativeOffset
		&& g_addresses[2] == nativeOffset + 7 * sizeof(long);
	printf("64-bit ptracer programmed x86 debug registers at:");
	for (auto address : g_addresses)
		printf(" %zu", static_cast<size_t>(address));
	printf("; native u_debugreg offset is %zu\n", nativeOffset);
	if (!good)
	{
		printf("hardware-breakpoint ptrace offsets use the tracee ABI instead of the ptracer ABI\n");
		return 1;
	}
#else
	printf("SKIP: this regression requires a 64-bit x86 ptracer build\n");
#endif
	return 0;
}
