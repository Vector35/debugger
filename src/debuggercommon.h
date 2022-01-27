#pragma once

namespace BinaryNinjaDebugger
{
	struct ModuleNameAndOffset
	{
		// TODO: maybe we should use DebugModule instead of its name
		// Update: We are not using a DebugModule here because the base adress information of it can be outdated;
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
