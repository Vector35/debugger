#pragma once
// Plain data types used by WindowsDebugEngine, copied from core/debugadapter.h and
// core/debuggercommon.h. Those headers are BN-API-free themselves, but they transitively pull in
// binaryninjaapi.h through core/debugadapter.h, so the types are copied here rather than included,
// to keep x2winstub entirely independent of Binary Ninja.
#include <cstdint>
#include <string>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#endif

namespace x2win {

	struct ModuleNameAndOffset
	{
		std::string module;
		uint64_t offset;

		ModuleNameAndOffset() : module(""), offset(0) {}
		ModuleNameAndOffset(std::string mod, uint64_t off) : module(mod), offset(off) {}

		bool operator==(const ModuleNameAndOffset& other) const
		{
			return IsSameBaseModule(other) && (offset == other.offset);
		}

		static std::string GetPathBaseName(const std::string& path)
		{
#ifdef _WIN32
			char baseName[MAX_PATH];
			char ext[MAX_PATH];
			_splitpath_s(path.c_str(), NULL, 0, NULL, 0, baseName, MAX_PATH, ext, MAX_PATH);
			return std::string(baseName) + std::string(ext);
#else
			auto slash = path.find_last_of("/\\");
			return slash == std::string::npos ? path : path.substr(slash + 1);
#endif
		}

		bool IsSameBaseModule(const ModuleNameAndOffset& other) const
		{
			return (module == other.module) || (GetPathBaseName(module) == GetPathBaseName(other.module));
		}

		bool IsSameBaseModule(const std::string& other) const
		{
			return (module == other) || (GetPathBaseName(module) == GetPathBaseName(other));
		}
	};

	// Breakpoint types - used to specify the type of breakpoint to set
	enum DebugBreakpointType
	{
		SoftwareBreakpoint = 0,
		HardwareExecuteBreakpoint = 1,
		HardwareReadBreakpoint = 2,
		HardwareWriteBreakpoint = 3,
		HardwareAccessBreakpoint = 4
	};

	// Subset of BNDebugStopReason (core/api/ffi.h) actually produced by WindowsDebugEngine.
	enum DebugStopReason
	{
		UnknownReason,
		InitialBreakpoint,
		ProcessExited,
		AccessViolation,
		SingleStep,
		Calculation,
		Breakpoint,
		IllegalInstruction
	};

	struct LaunchConfigurations
	{
		bool requestTerminalEmulator;
		std::string inputFile;
		bool connectedToDebugServer;

		LaunchConfigurations() : requestTerminalEmulator(true), connectedToDebugServer(false) {}
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
	};

	struct DebugThread
	{
		std::uint32_t m_tid {};
		std::uintptr_t m_rip {};
		bool m_isFrozen {};

		DebugThread() {}
		DebugThread(std::uint32_t tid) : m_tid(tid) {}
		DebugThread(std::uint32_t tid, std::uintptr_t rip) : m_tid(tid), m_rip(rip) {}
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

		bool operator==(const DebugBreakpoint& rhs) const { return m_address == rhs.m_address; }
	};

	// Pending hardware breakpoint info (to be applied when target becomes active)
	struct PendingHardwareBreakpoint
	{
		ModuleNameAndOffset location;
		uint64_t address;
		DebugBreakpointType type;
		size_t size;
		bool isRelative;

		PendingHardwareBreakpoint(uint64_t addr, DebugBreakpointType bpType, size_t bpSize)
			: location(), address(addr), type(bpType), size(bpSize), isRelative(false) {}
		PendingHardwareBreakpoint(const ModuleNameAndOffset& loc, DebugBreakpointType bpType, size_t bpSize)
			: location(loc), address(0), type(bpType), size(bpSize), isRelative(true) {}
	};

	struct DebugRegister
	{
		std::string m_name {};
		uint64_t m_value {};
		std::size_t m_width {}, m_registerIndex {};

		DebugRegister() = default;
		DebugRegister(std::string name, uint64_t value, std::size_t width, std::size_t register_index) :
			m_name(std::move(name)), m_value(value), m_width(width), m_registerIndex(register_index)
		{}
	};

	struct DebugModule
	{
		std::string m_name {}, m_short_name {};
		std::uintptr_t m_address {};
		std::size_t m_size {};
		bool m_loaded {};
		// Matches BN's "debugger.caseInsensitiveModuleName" setting, default true.
		bool m_caseInsensitive {true};

		DebugModule() = default;
		DebugModule(std::string name, std::string short_name, std::uintptr_t address, std::size_t size, bool loaded) :
			m_name(std::move(name)), m_short_name(std::move(short_name)), m_address(address), m_size(size), m_loaded(loaded)
		{}

		static std::string GetPathBaseName(const std::string& path)
		{
			return ModuleNameAndOffset::GetPathBaseName(path);
		}

		static bool StringsEqual(const std::string& a, const std::string& b, bool caseInsensitive)
		{
			if (!caseInsensitive)
				return a == b;
			if (a.size() != b.size())
				return false;
			return std::equal(a.begin(), a.end(), b.begin(),
				[](char c1, char c2) { return std::tolower((unsigned char)c1) == std::tolower((unsigned char)c2); });
		}

		bool IsSameBaseModule(const DebugModule& other) const
		{
			return StringsEqual(m_name, other.m_name, m_caseInsensitive)
				|| StringsEqual(m_short_name, other.m_short_name, m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_name), GetPathBaseName(other.m_name), m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_short_name), GetPathBaseName(other.m_short_name), m_caseInsensitive);
		}

		bool IsSameBaseModule(const std::string& name) const
		{
			return StringsEqual(m_name, name, m_caseInsensitive)
				|| StringsEqual(m_short_name, name, m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_name), GetPathBaseName(name), m_caseInsensitive)
				|| StringsEqual(GetPathBaseName(m_short_name), GetPathBaseName(name), m_caseInsensitive);
		}
	};

	struct DebugMemoryRegion
	{
		std::uintptr_t m_start {};
		std::size_t m_size {};
		std::string m_name {};
		bool m_read {};
		bool m_write {};
		bool m_execute {};
		bool m_shared {};

		DebugMemoryRegion() = default;
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
	};

	// Used by WindowsDebugEngine to query capacities; mirrors DebugAdapterCapacity from
	// core/debugadapter.h (subset actually referenced by SupportFeature()).
	enum DebugAdapterCapacity
	{
		DebugAdapterSupportStepOver,
		DebugAdapterSupportStepReturn,
		DebugAdapterSupportStepOverReverse,
		DebugAdapterSupportModules,
		DebugAdapterSupportThreads,
		DebugAdapterSupportTTD,
	};

	// Replaces DebugAdapter::PostDebuggerEvent()/DebuggerEvent from core/debugadapter.h -- only the
	// subset of fields WindowsDebugEngine actually populates across its 8 event call sites.
	enum class EngineEventType
	{
		LaunchFailure,
		TargetExited,
		TargetStopped,
		Resumed,
		StepIntoComplete
	};

	struct EngineEvent
	{
		EngineEventType type = EngineEventType::TargetStopped;

		// TargetStopped
		DebugStopReason stopReason = UnknownReason;
		uint32_t lastActiveThread = 0;

		// TargetExited
		uint64_t exitCode = 0;

		// LaunchFailure
		std::string error;
		std::string shortError;
	};

}  // namespace x2win
