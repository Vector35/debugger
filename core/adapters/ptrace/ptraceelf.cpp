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
#include <elf.h>
#include <algorithm>
#include <cstring>
#include <fstream>

namespace BinaryNinjaDebugger {

	struct Elf32Types
	{
		using Ehdr = Elf32_Ehdr;
		using Phdr = Elf32_Phdr;
		using Shdr = Elf32_Shdr;
		using Sym = Elf32_Sym;
	};

	struct Elf64Types
	{
		using Ehdr = Elf64_Ehdr;
		using Phdr = Elf64_Phdr;
		using Shdr = Elf64_Shdr;
		using Sym = Elf64_Sym;
	};


	static bool ReadAt(std::ifstream& file, uint64_t offset, void* buffer, size_t size)
	{
		file.clear();
		file.seekg(offset);
		return file.read(reinterpret_cast<char*>(buffer), size).gcount() == (std::streamsize)size;
	}


	template <typename T>
	static void ReadSymbols(std::ifstream& file, uint64_t fileSize, const typename T::Shdr& table,
		const typename T::Shdr& strings, std::vector<ElfSymbol>& symbols)
	{
		if (table.sh_offset > fileSize || table.sh_size > fileSize - table.sh_offset || strings.sh_offset > fileSize
			|| strings.sh_size > fileSize - strings.sh_offset)
			return;

		std::vector<uint8_t> tableData(table.sh_size);
		std::vector<char> stringData(strings.sh_size);
		if (!ReadAt(file, table.sh_offset, tableData.data(), tableData.size())
			|| !ReadAt(file, strings.sh_offset, stringData.data(), stringData.size()))
			return;

		size_t entrySize = table.sh_entsize ? table.sh_entsize : sizeof(typename T::Sym);
		if (entrySize < sizeof(typename T::Sym))
			return;

		for (size_t offset = 0; offset + sizeof(typename T::Sym) <= tableData.size(); offset += entrySize)
		{
			typename T::Sym symbol;
			memcpy(&symbol, tableData.data() + offset, sizeof(symbol));

			unsigned type = ELF32_ST_TYPE(symbol.st_info);
			bool isFunction = type == STT_FUNC || type == STT_GNU_IFUNC;
			if (!isFunction && type != STT_OBJECT)
				continue;
			if (symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= SHN_LORESERVE || symbol.st_value == 0)
				continue;
			if (symbol.st_name == 0 || symbol.st_name >= stringData.size())
				continue;

			// The string table is terminated, but the file may not be
			size_t length = strnlen(stringData.data() + symbol.st_name, stringData.size() - symbol.st_name);
			ElfSymbol result;
			result.name.assign(stringData.data() + symbol.st_name, length);
			// The linker writes the version into the name of some symbols of .symtab, `stdin@@GLIBC_2.2.5`
			auto version = result.name.find('@');
			if (version != std::string::npos && version > 0)
				result.name.resize(version);
			result.address = symbol.st_value;
			result.size = symbol.st_size;
			result.isFunction = isFunction;
			symbols.push_back(std::move(result));
		}
	}


	template <typename T>
	static bool ParseElf(std::ifstream& file, uint64_t fileSize, ElfInfo& info)
	{
		typename T::Ehdr header;
		if (!ReadAt(file, 0, &header, sizeof(header)))
			return false;

		info.type = header.e_type;
		info.entry = header.e_entry;

		bool haveLoad = false;
		uint64_t lowest = 0;
		for (unsigned i = 0; i < header.e_phnum && header.e_phentsize >= sizeof(typename T::Phdr); i++)
		{
			typename T::Phdr segment;
			if (!ReadAt(file, header.e_phoff + (uint64_t)i * header.e_phentsize, &segment, sizeof(segment)))
				break;

			if (segment.p_type == PT_LOAD && (!haveLoad || segment.p_vaddr < lowest))
			{
				lowest = segment.p_vaddr;
				haveLoad = true;
			}
			else if (segment.p_type == PT_INTERP && segment.p_filesz > 0 && segment.p_filesz < 4096)
			{
				std::string path(segment.p_filesz, '\0');
				if (ReadAt(file, segment.p_offset, path.data(), path.size()))
					info.interpreter = path.c_str();
			}
		}
		info.linkBase = lowest & ~0xfffull;

		if (header.e_shoff == 0 || header.e_shnum == 0 || header.e_shentsize < sizeof(typename T::Shdr))
			return true;

		std::vector<typename T::Shdr> sections;
		for (unsigned i = 0; i < header.e_shnum; i++)
		{
			typename T::Shdr section;
			if (!ReadAt(file, header.e_shoff + (uint64_t)i * header.e_shentsize, &section, sizeof(section)))
				break;
			sections.push_back(section);
		}

		for (const auto& section : sections)
		{
			if ((section.sh_type == SHT_SYMTAB || section.sh_type == SHT_DYNSYM) && section.sh_link < sections.size())
				ReadSymbols<T>(file, fileSize, section, sections[section.sh_link], info.symbols);
		}

		std::stable_sort(info.symbols.begin(), info.symbols.end(), [](const ElfSymbol& a, const ElfSymbol& b) {
			return a.address < b.address;
		});
		// The dynamic symbols repeat in the full table
		info.symbols.erase(
			std::unique(info.symbols.begin(), info.symbols.end(),
				[](const ElfSymbol& a, const ElfSymbol& b) { return a.address == b.address && a.name == b.name; }),
			info.symbols.end());
		return true;
	}


	bool ReadElfFile(const std::string& path, ElfInfo& info)
	{
		std::ifstream file(path, std::ios::binary);
		unsigned char ident[EI_NIDENT] = {};
		if (!file || !file.read(reinterpret_cast<char*>(ident), sizeof(ident)))
			return false;
		if (memcmp(ident, ELFMAG, SELFMAG) != 0 || ident[EI_DATA] != ELFDATA2LSB)
			return false;

		file.seekg(0, std::ios::end);
		uint64_t fileSize = file.tellg();

		info = ElfInfo();
		if (ident[EI_CLASS] == ELFCLASS64)
		{
			info.is64 = true;
			return ParseElf<Elf64Types>(file, fileSize, info);
		}
		if (ident[EI_CLASS] == ELFCLASS32)
			return ParseElf<Elf32Types>(file, fileSize, info);
		return false;
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
