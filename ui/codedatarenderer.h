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

#pragma once

#include "binaryninjaapi.h"

class CodeDataRenderer : public BinaryNinja::DataRenderer
{
public:
	CodeDataRenderer();
	virtual bool IsValidForData(BinaryNinja::BinaryView* data, uint64_t addr, BinaryNinja::Type* type,
		std::vector<std::pair<BinaryNinja::Type*, size_t>>& context) override;
	virtual std::vector<BinaryNinja::DisassemblyTextLine> GetLinesForData(BinaryNinja::BinaryView* data, uint64_t addr,
		BinaryNinja::Type* type, const std::vector<BinaryNinja::InstructionTextToken>& prefix, size_t width,
		std::vector<std::pair<BinaryNinja::Type*, size_t>>& context) override;
};