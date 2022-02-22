#pragma once

#include "binaryninjaapi.h"
#include "ffi.h"

using namespace BinaryNinja;

namespace BinaryNinjaDebuggerAPI
{
	template <class T>
	class DebuggerObject
	{
		void AddRefInternal()
		{
			m_refs.fetch_add(1);
		}

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	public:
		std::atomic<int> m_refs;
		T* m_object;
		DebuggerObject(): m_refs(0), m_object(nullptr) {}
		virtual ~DebuggerObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(DebuggerObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef()
		{
			AddRefInternal();
		}

		void Release()
		{
			ReleaseInternal();
		}

		void AddRefForRegistration()
		{
			AddRefInternal();
		}
	};


	struct DebugThread
	{
		std::uint32_t m_tid{};
		std::uintptr_t m_rip{};

		DebugThread() {}
		DebugThread(std::uint32_t tid) : m_tid(tid) {}
		DebugThread(std::uint32_t tid, std::uintptr_t rip) : m_tid(tid), m_rip(rip) {}

		bool operator==(const DebugThread &rhs) const {
			return (m_tid == rhs.m_tid) && (m_rip == rhs.m_rip);
		}

		bool operator!=(const DebugThread &rhs) const {
			return !(*this == rhs);
		}
	};


	struct DebugModule
	{
		std::string m_name{}, m_short_name{};
		std::uintptr_t m_address{};
		std::size_t m_size{};
		bool m_loaded{};

		// These are useful for remote debugging. Paths can be different on the host and guest systems, e.g., /usr/bin/ls,
		// and C:\Users\user\Desktop\ls. So we must compare the base file name, rather than the full path.
		bool IsSameBaseModule(const DebugModule &other) const;
		bool IsSameBaseModule(const std::string &name) const;
		static bool IsSameBaseModule(const std::string &module, const std::string &module2);
		static std::string GetPathBaseName(const std::string &path);
	};


	struct DebugRegister
	{
		std::string m_name{};
		std::uintptr_t m_value{};
		std::size_t m_width{}, m_registerIndex{};
		std::string m_hint{};
	};


	struct DebugBreakpoint
	{
		std::string module;
		uint64_t offset;
		uint64_t address;
		bool enabled;
	};


	struct ModuleNameAndOffset
	{
		std::string module;
		uint64_t offset;

		bool operator==(const ModuleNameAndOffset& other) const
		{
			return (module == other.module) && (offset == other.offset);
		}
		bool operator!=(const ModuleNameAndOffset& other) const
		{
			return !(*this == other);
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

	typedef BNDebuggerEventType DebuggerEventType;
	typedef BNDebugStopReason DebugStopReason;

	struct TargetStoppedEventData
	{
		DebugStopReason reason;
		std::uint32_t lastActiveThread;
		size_t exitCode;
		void* data;
	};


	struct ErrorEventData
	{
		std::string error;
		void* data;
	};


	struct TargetExitedEventData
	{
		uint64_t exitCode;
	};


	struct StdoutMessageEventData
	{
		std::string message;
	};


	// This should really be a union, but gcc complains...
	struct DebuggerEventData
	{
		TargetStoppedEventData targetStoppedData;
		ErrorEventData errorData;
		uint64_t absoluteAddress;
		ModuleNameAndOffset relativeAddress;
		TargetExitedEventData exitData;
		StdoutMessageEventData messageData;
	};


	struct DebuggerEvent
	{
		DebuggerEventType type;
		DebuggerEventData data;
	};


	typedef BNDebugAdapterConnectionStatus DebugAdapterConnectionStatus;
	typedef BNDebugAdapterTargetStatus DebugAdapterTargetStatus;

	class DebuggerController: public DebuggerObject<BNDebuggerController>
	{
		struct DebuggerEventCallbackObject
		{
			std::function<void(const DebuggerEvent&)> action;
		};

	public:
		DebuggerController(BNDebuggerController* controller);
		static DebuggerController* GetController(Ref<BinaryNinja::BinaryView> data);
		Ref<BinaryView> GetLiveView();
		Ref<BinaryView> GetData();
		Ref<Architecture> GetRemoteArchitecture();

		bool IsConnected();
		bool IsRunning();

		uint64_t StackPointer();

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size);
		bool WriteMemory(std::uintptr_t address, const DataBuffer &buffer);

		std::vector<DebugThread> GetThreads();
		DebugThread GetActiveThread();
		void SetActiveThread(const DebugThread& thread);

		std::vector<DebugModule> GetModules();
		std::vector<DebugRegister> GetRegisters();
		bool SetRegisterValue(const std::string& name, uint64_t value);

		// target control
		bool Launch();
		bool Execute();
		void Restart();
		void Quit();
		void Connect();
		void Detach();
		void Pause();
		// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
		void LaunchOrConnect();

		DebugStopReason Go();
		DebugStopReason StepInto(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepOver(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepReturn();
		DebugStopReason StepTo(const std::vector<uint64_t> &remoteAddresses);

		std::string GetAdapterType();
		void SetAdapterType(const std::string& adapter);

		DebugAdapterConnectionStatus GetConnectionStatus();
		DebugAdapterTargetStatus GetTargetStatus();

		std::string GetRemoteHost();
		uint32_t GetRemotePort();
		std::string GetExecutablePath();
		bool GetRequestTerminalEmulator();
		std::string GetCommandLineArguments();

		void SetExecutablePath(const std::string& path);
		void SetCommandLineArguments(const std::string& arguments);
		void SetRemoteHost(const std::string& host);
		void SetRemotePort(uint32_t port);
		void SetRequestTerminalEmulator(bool requested);

		std::vector<DebugBreakpoint> GetBreakpoints();
		void DeleteBreakpoint(uint64_t address);
		void DeleteBreakpoint(const ModuleNameAndOffset& breakpoint);
		void AddBreakpoint(uint64_t address);
		void AddBreakpoint(const ModuleNameAndOffset& breakpoint);
		bool ContainsBreakpoint(uint64_t address);
		bool ContainsBreakpoint(const ModuleNameAndOffset& breakpoint);

		uint64_t IP();
		uint64_t GetLastIP();

		uint64_t RelativeAddressToAbsolute(const ModuleNameAndOffset& address);
		ModuleNameAndOffset AbsoluteAddressToRelative(uint64_t address);

		size_t RegisterEventCallback(std::function<void(const DebuggerEvent &event)> callback);
		static void DebuggerEventCallback(void* ctxt, BNDebuggerEvent* view);

		void RemoveEventCallback(size_t index);
	};


	class DebugAdapterType: public DebuggerObject<BNDebugAdapterType>
	{
	public:
		DebugAdapterType(BNDebugAdapterType* adapterType);
		static DebugAdapterType* GetByName(const std::string& name);
		bool CanExecute(Ref<BinaryView> data);
		bool CanConnect(Ref<BinaryView> data);
		static std::vector<std::string> GetAvailableAdapters(Ref<BinaryView> data);
	};
};
