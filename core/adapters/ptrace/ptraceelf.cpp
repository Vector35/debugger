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

#include "ptraceelf.h"
#include <algorithm>
#include <cstring>
#include <elfio/elfio.hpp>
#include <fstream>

namespace BinaryNinjaDebugger {

	static bool ReadSymbols(const ELFIO::elfio& file, const ELFIO::section* section, std::vector<ElfSymbol>& symbols)
	{
		if (section->get_size() == 0)
			return true;

		size_t entrySize = file.get_class() == ELFIO::ELFCLASS64 ? sizeof(ELFIO::Elf64_Sym) : sizeof(ELFIO::Elf32_Sym);
		if (section->get_entry_size() != entrySize || section->get_size() % entrySize != 0
			|| section->get_link() >= file.sections.size())
			return false;
		auto strings = file.sections[section->get_link()];
		const char* data = section->get_data();
		if (!data || !strings || strings->get_type() != ELFIO::SHT_STRTAB || !strings->get_data())
			return false;

		ELFIO::const_symbol_section_accessor table(file, section);
		ELFIO::const_string_section_accessor names(strings);
		if (table.get_symbols_num() != section->get_size() / entrySize)
			return false;
		for (ELFIO::Elf_Xword index = 0; index < table.get_symbols_num(); index++)
		{
			ElfSymbol result;
			ELFIO::Elf64_Addr value;
			ELFIO::Elf_Xword size;
			unsigned char binding, type, other;
			ELFIO::Elf_Half sectionIndex;
			if (!table.get_symbol(index, result.name, value, size, binding, type, sectionIndex, other))
				return false;
			// GNU IFUNC uses the first OS-specific symbol type; ELFIO does not name this extension.
			constexpr unsigned char SttGnuIfunc = ELFIO::STT_LOOS;
			bool isFunction = type == ELFIO::STT_FUNC || type == SttGnuIfunc;
			if ((!isFunction && type != ELFIO::STT_OBJECT) || sectionIndex == ELFIO::SHN_UNDEF
				|| sectionIndex >= ELFIO::SHN_LORESERVE || value == 0)
				continue;

			// ELFIO can report success without a valid name. st_name is the first Elf_Word in both ELF classes.
			ELFIO::Elf_Word nameOffset;
			memcpy(&nameOffset, data + index * entrySize, sizeof(nameOffset));
			nameOffset = (*file.get_convertor())(nameOffset);
			if (nameOffset == 0)
				continue;
			if (!names.get_string(nameOffset))
				return false;

			// The linker writes the version into some .symtab names, e.g. stdin@@GLIBC_2.2.5.
			auto version = result.name.find('@');
			if (version != std::string::npos && version > 0)
				result.name.resize(version);
			result.address = value;
			result.size = size;
			result.isFunction = isFunction;
			symbols.push_back(std::move(result));
		}
		return true;
	}


	bool ReadElfFile(const std::string& path, ElfInfo& info)
	{
		std::ifstream stream(path, std::ios::binary);
		ELFIO::elfio file;
		// Keep the stream alive while reading lazy section/segment data; avoid loading entire PT_LOAD segments.
		if (!file.load(stream, true) || !stream || file.get_encoding() != ELFIO::ELFDATA2LSB)
			return false;

		ElfInfo result;
		result.type = file.get_type();
		result.is64 = file.get_class() == ELFIO::ELFCLASS64;
		result.entry = file.get_entry();

		bool haveLoad = false;
		uint64_t lowest = 0;
		for (const auto& segment : file.segments)
		{
			if (segment->get_type() == ELFIO::PT_LOAD && (!haveLoad || segment->get_virtual_address() < lowest))
			{
				lowest = segment->get_virtual_address();
				haveLoad = true;
			}
			else if (segment->get_type() == ELFIO::PT_INTERP && segment->get_file_size() > 0
				&& segment->get_file_size() < 4096)
			{
				const char* interpreter = segment->get_data();
				if (!interpreter)
					return false;
				const char* end = static_cast<const char*>(memchr(interpreter, 0, segment->get_file_size()));
				if (!end)
					return false;
				result.interpreter.assign(interpreter, end);
			}
		}
		result.linkBase = lowest & ~0xfffull;

		for (const auto& section : file.sections)
		{
			if ((section->get_type() == ELFIO::SHT_SYMTAB || section->get_type() == ELFIO::SHT_DYNSYM)
				&& !ReadSymbols(file, section.get(), result.symbols))
				return false;
		}

		std::stable_sort(result.symbols.begin(), result.symbols.end(), [](const ElfSymbol& a, const ElfSymbol& b) {
			return a.address < b.address;
		});
		// The dynamic symbols repeat in the full table.
		result.symbols.erase(
			std::unique(result.symbols.begin(), result.symbols.end(),
				[](const ElfSymbol& a, const ElfSymbol& b) { return a.address == b.address && a.name == b.name; }),
			result.symbols.end());
		info = std::move(result);
		return true;
	}

	const ElfSymbol* FindElfSymbol(const ElfInfo& info, uint64_t address)
	{
		// The last symbols that start at or before the address are the candidates
		auto end = std::upper_bound(info.symbols.begin(), info.symbols.end(), address,
			[](uint64_t value, const ElfSymbol& symbol) { return value < symbol.address; });

		const ElfSymbol* fallback = nullptr;
		size_t checked = 0;
		while (end != info.symbols.begin() && checked++ < 32)
		{
			--end;
			if (address - end->address < end->size)
				return &*end;
			// A symbol without a size is only a guess, and a function is a better one than data
			if (!fallback && end->size == 0 && end->isFunction)
				fallback = &*end;
		}
		return fallback;
	}

	const ElfSymbol* FindElfFunctionByName(const ElfInfo& info, const std::string& name, bool* ambiguous)
	{
		if (ambiguous)
			*ambiguous = false;

		const ElfSymbol* found = nullptr;
		for (const auto& symbol : info.symbols)
		{
			if (!symbol.isFunction || symbol.name != name)
				continue;

			if (found && found->address != symbol.address)
			{
				if (ambiguous)
					*ambiguous = true;
				return nullptr;
			}
			found = &symbol;
		}
		return found;
	}

}  // namespace BinaryNinjaDebugger
