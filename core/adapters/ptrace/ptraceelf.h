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
#include <vector>

namespace BinaryNinjaDebugger {
	struct ElfSymbol
	{
		std::string name;
		// As it is in the file. Add the load bias of the module to get the address in the target.
		uint64_t address = 0;
		uint64_t size = 0;
		bool isFunction = false;
	};

	struct ElfInfo
	{
		uint16_t type = 0;
		bool is64 = false;
		uint64_t entry = 0;
		// The address the first loadable segment is linked at, rounded down to a page. The load bias of a module
		// is where that segment is mapped minus this.
		uint64_t linkBase = 0;
		std::string interpreter;
		// Sorted by address
		std::vector<ElfSymbol> symbols;
	};

	// Reads the headers and the symbol tables (.symtab and .dynsym) of a little-endian ELF file
	bool ReadElfFile(const std::string& path, ElfInfo& info);

	// The symbol that contains an address of the file, or nullptr
	const ElfSymbol* FindElfSymbol(const ElfInfo& info, uint64_t address);

	// The function with this name, if there is exactly one. `ambiguous` says that there are several, at different
	// addresses.
	const ElfSymbol* FindElfFunctionByName(const ElfInfo& info, const std::string& name, bool* ambiguous = nullptr);
}  // namespace BinaryNinjaDebugger
