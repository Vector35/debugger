/*
Copyright 2020-2022 Vector 35 Inc.

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

namespace BinaryNinjaDebugger
{
	struct ModuleNameAndOffset
	{
		// TODO: maybe we should use DebugModule instead of its name
		// Update: We are not using a DebugModule here because the base address information of it can be outdated;
		// instead, we only keep a name and an offset.
		std::string module;
		uint64_t offset;

		ModuleNameAndOffset(): module(""), offset(0) {}
		ModuleNameAndOffset(std::string mod, uint64_t off): module(mod), offset(off) {}
		bool operator==(const ModuleNameAndOffset& other) const
		{
			return (module == other.module) && (offset == other.offset);
		}
		bool operator<(const ModuleNameAndOffset& other) const
		{
			if (module < other.module)
				return true;
			if (module > other.module)
				return false;
			return offset < other.offset;
		}
		bool operator>(const ModuleNameAndOffset& other) const
		{
			if (module > other.module)
				return true;
			if (module < other.module)
				return false;
			return offset > other.offset;
		}
	};
};
