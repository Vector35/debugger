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
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include "debuggercommon.h"
#include "../vendor/intx/intx.hpp"

namespace BinaryNinjaDebugger {
	// Used by the DebuggerState to query the capacities of the DebugAdapter, and take different actions accordingly.
	enum DebugAdapterCapacity
	{
		DebugAdapterSupportStepOver,
		DebugAdapterSupportStepReturn,
		DebugAdapterSupportStepOverReverse,
		DebugAdapterSupportModules,
		DebugAdapterSupportThreads,
		DebugAdapterSupportTTD,
		// The adapter can read the symbols a debugger backend knows about for a module. See
		// DebugAdapter::GetSymbolsForModule.
		DebugAdapterSupportSymbols,
	};


	struct LaunchConfigurations
	{
		bool requestTerminalEmulator;
		std::string inputFile;
		bool connectedToDebugServer;

		LaunchConfigurations() : requestTerminalEmulator(true) {}

		LaunchConfigurations(bool terminal, const std::string& file, bool debugServer) :
			requestTerminalEmulator(terminal), inputFile(file), connectedToDebugServer(debugServer)
		{}
	};


	struct DebugProcess
	{
		std::uint32_t m_pid {};
		std::string m_processName {};
		std::string m_commandLine {};

		DebugProcess() {}

		DebugProcess(std::uint32_t pid) : m_pid(pid) {}

		DebugProcess(std::uint32_t pid, std::string name) : m_pid(pid), m_processName(name) {}

		DebugProcess(std::uint32_t pid, std::string name, std::string commandLine) :
			m_pid(pid), m_processName(name), m_commandLine(commandLine) {}

		bool operator==(const DebugProcess& rhs) const
		{
			return (m_pid == rhs.m_pid) && (m_processName == rhs.m_processName);
		}

		bool operator!=(const DebugProcess& rhs) const { return !(*this == rhs); }
	};


	struct DebugThread
	{
		std::uint32_t m_tid {};
		std::uintptr_t m_rip {};
		bool m_isFrozen {};

		DebugThread() {}

		DebugThread(std::uint32_t tid) : m_tid(tid) {}

		DebugThread(std::uint32_t tid, std::uintptr_t rip) : m_tid(tid), m_rip(rip) {}

		bool operator==(const DebugThread& rhs) const { return (m_tid == rhs.m_tid) && (m_rip == rhs.m_rip); }

		bool operator!=(const DebugThread& rhs) const { return !(*this == rhs); }
	};


	struct DebugBreakpoint
	{
		std::uintptr_t m_address {};
		unsigned long m_id {};
		bool m_is_active {};
		DebugBreakpointType m_type = SoftwareBreakpoint;

		DebugBreakpoint(std::uintptr_t address, unsigned long id, bool active, DebugBreakpointType type = SoftwareBreakpoint) :
			m_address(address), m_id(id), m_is_active(active), m_type(type)
		{}

		DebugBreakpoint(std::uintptr_t address, DebugBreakpointType type = SoftwareBreakpoint) : 
			m_address(address), m_type(type) {}

		DebugBreakpoint() {}

		bool operator==(const DebugBreakpoint& rhs) const { return this->m_address == rhs.m_address; }

		bool operator!() const { return !this->m_address && !this->m_id && !this->m_is_active; }
	};

	// Pending hardware breakpoint info (to be applied when target becomes active)
	struct PendingHardwareBreakpoint
	{
		ModuleNameAndOffset location;  // Module + offset (for relative addressing)
		uint64_t address;              // Absolute address (for absolute addressing or resolved relative)
		DebugBreakpointType type;
		size_t size;
		bool isRelative;               // True if using module+offset, false if using absolute address

		// Constructor for absolute address
		PendingHardwareBreakpoint(uint64_t addr, DebugBreakpointType bpType, size_t bpSize)
			: location(), address(addr), type(bpType), size(bpSize), isRelative(false) {}

		// Constructor for module+offset
		PendingHardwareBreakpoint(const ModuleNameAndOffset& loc, DebugBreakpointType bpType, size_t bpSize)
			: location(loc), address(0), type(bpType), size(bpSize), isRelative(true) {}

		bool operator==(const PendingHardwareBreakpoint& other) const
		{
			if (isRelative != other.isRelative)
				return false;

			if (isRelative)
			{
				// Compare by module+offset
				return location == other.location && type == other.type && size == other.size;
			}
			else
			{
				// Compare by absolute address
				return address == other.address && type == other.type && size == other.size;
			}
		}
	};

	struct DebugRegister
	{
		std::string m_name {};
		intx::uint512 m_value {};
		std::size_t m_width {}, m_registerIndex {};
		std::string m_hint {};

		DebugRegister() = default;

		DebugRegister(std::string name, intx::uint512 value, std::size_t width, std::size_t register_index) :
			m_name(std::move(name)), m_value(value), m_width(width), m_registerIndex(register_index)
		{}
	};

	struct DebugModule
	{
		std::string m_name {}, m_short_name {};
		std::uintptr_t m_address {};
		std::size_t m_size {};
		bool m_loaded {};
		bool m_caseInsensitive {};

		inline static std::function<bool()> m_caseInsensitiveCallback;

		DebugModule() : m_name(""), m_short_name(""), m_address(0), m_size(0), m_loaded(false)
		{
			m_caseInsensitive = IsCaseInsensitive();
		}

		DebugModule(std::string name, std::string short_name, std::uintptr_t address, std::size_t size, bool loaded) :
			m_name(std::move(name)), m_short_name(std::move(short_name)), m_address(address), m_size(size),
			m_loaded(loaded)
		{
			m_caseInsensitive = IsCaseInsensitive();
		}

		// These are useful for remote debugging. Paths can be different on the host and guest systems, e.g.,
		// /usr/bin/ls, and C:\Users\user\Desktop\ls. So we must compare the base file name, rather than the full path.
		bool IsSameBaseModule(const DebugModule& other) const
		{
			return (StringsEqual(m_name, other.m_name, m_caseInsensitive)
				|| StringsEqual(m_short_name, other.m_short_name, m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_name), GetPathBaseName(other.m_name), m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_short_name), GetPathBaseName(other.m_short_name), m_caseInsensitive));
		}

		bool IsSameBaseModule(const std::string& name) const
		{
			return (StringsEqual(m_name, name, m_caseInsensitive)
				|| StringsEqual(m_short_name, name, m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_name), GetPathBaseName(name), m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_short_name), GetPathBaseName(name), m_caseInsensitive));
		}

		static bool IsSameBaseModule(const std::string& module1, const std::string& module2)
		{
			// Cache the setting value on first call. Note: This will not update if the setting changes during
			// runtime, but settings rarely change during a debugging session, and this avoids expensive
			// Settings::Instance() calls.
			static bool caseInsensitive = IsCaseInsensitive();
			return (StringsEqual(module1, module2, caseInsensitive)
				|| StringsEqual(GetPathBaseName(module1), GetPathBaseName(module2), caseInsensitive));
		}

		static std::string GetPathBaseName(const std::string& path)
		{
#ifdef WIN32
			// TODO: someone please write it on Windows!
			char baseName[_MAX_PATH];
			char ext[_MAX_PATH];
			_splitpath_s(path.c_str(), NULL, 0, NULL, 0, baseName, _MAX_PATH, ext, _MAX_PATH);
			return std::string(baseName) + std::string(ext);
#else
			std::filesystem::path fs_path(path);
			return fs_path.filename().string();
#endif
		}

		static bool IsCaseInsensitive() { return m_caseInsensitiveCallback ? m_caseInsensitiveCallback() : true; }

		static bool StringsEqual(const std::string& str1, const std::string& str2, bool caseInsensitive)
		{
			if (!caseInsensitive)
				return str1 == str2;

			if (str1.size() != str2.size())
				return false;

			return std::equal(str1.begin(), str1.end(), str2.begin(),
				[](char c1, char c2) { return std::tolower(c1) == std::tolower(c2); });
		}
	};

	// A single mapped region of the target's virtual address space (a memory-map entry), e.g. the
	// backing of one segment of a module, an anonymous mapping, the stack, or the heap. Unlike a
	// DebugModule (one entry per loaded binary), a memory region is the OS page-protection view: a
	// module typically spans several regions with different permissions, and many regions (stack,
	// heap, anonymous mmap) belong to no module at all.
	struct DebugMemoryRegion
	{
		std::uintptr_t m_start {};
		std::size_t m_size {};
		// The backing of the region: a file path for file-backed mappings, a well-known name such as
		// "[stack]" or "[heap]" where the backend provides one, or empty for anonymous mappings.
		std::string m_name {};
		bool m_read {};
		bool m_write {};
		bool m_execute {};
		// Whether the mapping is shared between processes (as opposed to a private/copy-on-write map).
		bool m_shared {};

		DebugMemoryRegion() = default;
		DebugMemoryRegion(std::uintptr_t start, std::size_t size, std::string name, bool read, bool write,
			bool execute, bool shared) :
			m_start(start), m_size(size), m_name(std::move(name)), m_read(read), m_write(write),
			m_execute(execute), m_shared(shared)
		{}

		// Value equality, used to detect whether the target's memory map changed between stops so the
		// debugger can avoid rebuilding the BinaryView memory regions when nothing has moved.
		bool operator==(const DebugMemoryRegion& other) const
		{
			return m_start == other.m_start && m_size == other.m_size && m_name == other.m_name
				&& m_read == other.m_read && m_write == other.m_write && m_execute == other.m_execute
				&& m_shared == other.m_shared;
		}
		bool operator!=(const DebugMemoryRegion& other) const { return !(*this == other); }
	};

	// A symbol the debugger backend (e.g. LLDB, dbgeng) knows about for a loaded module, but which the
	// static BinaryView analysis is not aware of. These are read on demand (see
	// DebugAdapter::GetSymbolsForModule and DebuggerController::LoadSymbolsForModule) and added to the
	// debugger BinaryView as auto symbols so that the annotation process becomes aware of them.
	struct DebugSymbol
	{
		// Short name, e.g. "CreateFileA"
		std::string m_name {};
		// Fully-qualified name, e.g. "kernel32!CreateFileA"
		std::string m_fullName {};
		// Raw (possibly mangled) name. May be empty if the backend does not provide one.
		std::string m_rawName {};
		// Absolute load address of the symbol in the target.
		std::uintptr_t m_address {};
		std::size_t m_size {};
		// True if the symbol refers to code (a function), false if it refers to data.
		bool m_isFunction {};

		DebugSymbol() = default;

		DebugSymbol(std::string name, std::string fullName, std::string rawName, std::uintptr_t address,
			std::size_t size, bool isFunction) :
			m_name(std::move(name)), m_fullName(std::move(fullName)), m_rawName(std::move(rawName)),
			m_address(address), m_size(size), m_isFunction(isFunction)
		{}
	};

	struct DebugFrame
	{
		size_t m_index = 0;
		uint64_t m_pc = 0;
		uint64_t m_sp = 0;
		uint64_t m_fp = 0;
		std::string m_functionName;
		uint64_t m_functionStart = 0;
		std::string m_module = "<unknown>";

		DebugFrame() = default;
		DebugFrame(size_t index, uint64_t pc, uint64_t sp, uint64_t fp, const std::string& functionName,
			uint64_t functionStart, const std::string& module) :
			m_index(index),
			m_pc(pc), m_sp(sp), m_fp(fp), m_functionName(functionName), m_functionStart(functionStart), m_module(module)
		{}
	};
}  // namespace BinaryNinjaDebugger
