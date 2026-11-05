// libFuzzer target: ELF metadata reader and symbol lookups on arbitrary bytes.
#include "ptraceelf.h"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

using namespace BinaryNinjaDebugger;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	static char path[] = "/tmp/fuzz_elf_XXXXXX";
	static int fd = mkstemp(path);
	if (fd < 0)
		abort();
	if (ftruncate(fd, 0) != 0 || pwrite(fd, data, size, 0) != (ssize_t)size)
		abort();
	ElfInfo info;
	if (ReadElfFile(path, info))
	{
		// Exercise lookups on whatever was parsed, including boundary addresses.
		for (uint64_t a : {uint64_t(0), info.entry, info.linkBase, UINT64_MAX, info.entry + 1})
			FindElfSymbol(info, a);
		for (const auto& s : info.symbols)
		{
			FindElfSymbol(info, s.address);
			FindElfSymbol(info, s.address + s.size);
			bool amb;
			FindElfFunctionByName(info, s.name, &amb);
		}
	}
	return 0;
}
