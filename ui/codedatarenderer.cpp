/*
Copyright 2020-2024 Vector 35 Inc.

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

#include "codedatarenderer.h"
using namespace BinaryNinja;


CodeDataRenderer::CodeDataRenderer() {}


bool CodeDataRenderer::IsValidForData(
	BinaryView* data, uint64_t addr, Type* type, std::vector<std::pair<BinaryNinja::Type*, size_t>>& context)
{
	auto sym = data->GetSymbolByAddress(addr);
	if (!sym)
		return false;

	auto name = sym->GetFullName();
	if (name.substr(0, 14) != "BN_CODE_start_")
		return false;

	return type->GetClass() == ArrayTypeClass;
}


std::vector<DisassemblyTextLine> CodeDataRenderer::GetLinesForData(BinaryView* data, uint64_t addr, Type* type,
	const std::vector<InstructionTextToken>& prefix, size_t width, std::vector<std::pair<Type*, size_t>>& context)
{
	std::vector<DisassemblyTextLine> result;
	DisassemblyTextLine contents;

	auto sym = data->GetSymbolByAddress(addr);
	if (!sym)
		return result;

	auto name = sym->GetFullName();
	if (name.substr(0, 14) != "BN_CODE_start_")
		return result;

	if (type->GetClass() != ArrayTypeClass)
		return result;

	auto codeSize = type->GetElementCount();
	auto arch = data->GetDefaultArchitecture();
	auto buffer = data->ReadBuffer(addr, codeSize);
	if (buffer.GetLength() == 0)
		return result;

	size_t totalRead = 0;
	while (totalRead < codeSize)
	{
		uint64_t lineAddr = addr + totalRead;
		size_t length = codeSize - totalRead;
		std::vector<InstructionTextToken> insnTokens;
		auto ok = arch->GetInstructionText((uint8_t*)buffer.GetDataAt(totalRead), lineAddr, length, insnTokens);
		if ((!ok) || (insnTokens.empty()))
		{
			insnTokens = {InstructionTextToken(TextToken, "??")};
			length = arch->GetInstructionAlignment();
			if (length == 0)
				length = 1;
		}

		contents.addr = lineAddr;
		contents.tokens = insnTokens;

		result.push_back(contents);
		totalRead += length;
	}

	return result;
}
