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
#include <string.h>
#ifndef WIN32
	#include "libgen.h"
#endif

namespace BinaryNinjaDebugger {
	struct ModuleNameAndOffset
	{
		// TODO: maybe we should use DebugModule instead of its name
		// Update: We are not using a DebugModule here because the base address information of it can be outdated;
		// instead, we only keep a name and an offset.
		std::string module;
		uint64_t offset;

		ModuleNameAndOffset() : module(""), offset(0) {}
		ModuleNameAndOffset(std::string mod, uint64_t off) : module(mod), offset(off) {}
		bool operator==(const ModuleNameAndOffset& other) const
		{
			return IsSameBaseModule(other) && (offset == other.offset);
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


		static std::string GetPathBaseName(const std::string& path)
		{
#ifdef WIN32
			// TODO: someone please write it on Windows!
			char baseName[MAX_PATH];
			_splitpath(path.c_str(), NULL, NULL, baseName, NULL);
			return std::string(baseName);
#else
			return basename(strdup(path.c_str()));
#endif
		}


		bool IsSameBaseModule(const ModuleNameAndOffset& other) const
		{
			return ((module == other.module) || (GetPathBaseName(module) == GetPathBaseName(other.module)));
		}


		bool IsSameBaseModule(const std::string& other) const
		{
			return ((module == other) || (GetPathBaseName(module) == GetPathBaseName(other)));
		}


		static bool IsSameBaseModule(const std::string& module1, const std::string& module2)
		{
			return ((module1 == module2) || (GetPathBaseName(module1) == GetPathBaseName(module2)));
		}
	};
};  // namespace BinaryNinjaDebugger
