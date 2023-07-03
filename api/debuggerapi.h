/*
Copyright 2020-2023 Vector 35 Inc.

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
#include "ffi.h"

using namespace BinaryNinja;

namespace BinaryNinjaDebuggerAPI {
	template <class T>
	class DbgRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	public:
		std::atomic<int> m_refs;
		T* m_object;
		DbgRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~DbgRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(DbgRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
	};


	template <class T, T* (*AddObjectReference)(T*), void (*FreeObjectReference)(T*)>
	class DbgCoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
			{
				if (!m_registeredRef)
					delete this;
			}
		}

	public:
		std::atomic<int> m_refs;
		bool m_registeredRef = false;
		T* m_object;
		DbgCoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~DbgCoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(DbgCoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef()
		{
			if (m_object && (m_refs != 0))
				AddObjectReference(m_object);
			AddRefInternal();
		}

		void Release()
		{
			if (m_object)
				FreeObjectReference(m_object);
			ReleaseInternal();
		}

		void AddRefForRegistration() { m_registeredRef = true; }

		void ReleaseForRegistration()
		{
			m_object = nullptr;
			m_registeredRef = false;
			if (m_refs == 0)
				delete this;
		}
	};


	template <class T>
	class DbgStaticCoreRefCountObject
	{
		void AddRefInternal() { m_refs.fetch_add(1); }

		void ReleaseInternal()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

	public:
		std::atomic<int> m_refs;
		T* m_object;
		DbgStaticCoreRefCountObject() : m_refs(0), m_object(nullptr) {}
		virtual ~DbgStaticCoreRefCountObject() {}

		T* GetObject() const { return m_object; }

		static T* GetObject(DbgStaticCoreRefCountObject* obj)
		{
			if (!obj)
				return nullptr;
			return obj->GetObject();
		}

		void AddRef() { AddRefInternal(); }

		void Release() { ReleaseInternal(); }

		void AddRefForRegistration() { AddRefInternal(); }
		void AddRefForCallback() {}
		void ReleaseForCallback() {}
	};


	template <class T>
	class DbgRef
	{
		T* m_obj;
#ifdef BN_REF_COUNT_DEBUG
		void* m_assignmentTrace = nullptr;
#endif

	public:
		DbgRef<T>() : m_obj(NULL) {}

		DbgRef<T>(T* obj) : m_obj(obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		DbgRef<T>(const DbgRef<T>& obj) : m_obj(obj.m_obj)
		{
			if (m_obj)
			{
				m_obj->AddRef();
#ifdef BN_REF_COUNT_DEBUG
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			}
		}

		DbgRef<T>(DbgRef<T>&& other) : m_obj(other.m_obj)
		{
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
		}

		~DbgRef<T>()
		{
			if (m_obj)
			{
				m_obj->Release();
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
			}
		}

		DbgRef<T>& operator=(const Ref<T>& obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj.m_obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj.m_obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		DbgRef<T>& operator=(DbgRef<T>&& other)
		{
			if (m_obj)
			{
#ifdef BN_REF_COUNT_DEBUG
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
#endif
				m_obj->Release();
			}
			m_obj = other.m_obj;
			other.m_obj = 0;
#ifdef BN_REF_COUNT_DEBUG
			m_assignmentTrace = other.m_assignmentTrace;
#endif
			return *this;
		}

		DbgRef<T>& operator=(T* obj)
		{
#ifdef BN_REF_COUNT_DEBUG
			if (m_obj)
				BNUnregisterObjectRefDebugTrace(typeid(T).name(), m_assignmentTrace);
			if (obj)
				m_assignmentTrace = BNRegisterObjectRefDebugTrace(typeid(T).name());
#endif
			T* oldObj = m_obj;
			m_obj = obj;
			if (m_obj)
				m_obj->AddRef();
			if (oldObj)
				oldObj->Release();
			return *this;
		}

		operator T*() const
		{
			return m_obj;
		}

		T* operator->() const
		{
			return m_obj;
		}

		T& operator*() const
		{
			return *m_obj;
		}

		bool operator!() const
		{
			return m_obj == NULL;
		}

		bool operator==(const T* obj) const
		{
			return T::GetObject(m_obj) == T::GetObject(obj);
		}

		bool operator==(const DbgRef<T>& obj) const
		{
			return T::GetObject(m_obj) == T::GetObject(obj.m_obj);
		}

		bool operator!=(const T* obj) const
		{
			return T::GetObject(m_obj) != T::GetObject(obj);
		}

		bool operator!=(const DbgRef<T>& obj) const
		{
			return T::GetObject(m_obj) != T::GetObject(obj.m_obj);
		}

		bool operator<(const T* obj) const
		{
			return T::GetObject(m_obj) < T::GetObject(obj);
		}

		bool operator<(const DbgRef<T>& obj) const
		{
			return T::GetObject(m_obj) < T::GetObject(obj.m_obj);
		}

		T* GetPtr() const
		{
			return m_obj;
		}
	};


	struct DebugProcess
	{
		uint32_t m_pid {};
		std::string m_processName {};

		DebugProcess() {}

		DebugProcess(uint32_t pid) : m_pid(pid) {}

		DebugProcess(uint32_t pid, std::string name) : m_pid(pid), m_processName(name) {}

		bool operator==(const DebugProcess& rhs) const
		{
			return (m_pid == rhs.m_pid) && (m_processName == rhs.m_processName);
		}

		bool operator!=(const DebugProcess& rhs) const { return !(*this == rhs); }
	};


	struct DebugThread
	{
		uint32_t m_tid {};
		uint64_t m_rip {};
		bool m_isFrozen {};

		DebugThread() {}
		DebugThread(uint32_t tid) : m_tid(tid) {}
		DebugThread(uint32_t tid, uint64_t rip) : m_tid(tid), m_rip(rip) {}

		bool operator==(const DebugThread& rhs) const { return (m_tid == rhs.m_tid) && (m_rip == rhs.m_rip); }

		bool operator!=(const DebugThread& rhs) const { return !(*this == rhs); }
	};


	struct DebugFrame
	{
		size_t m_index;
		uint64_t m_pc;
		uint64_t m_sp;
		uint64_t m_fp;
		std::string m_functionName;
		uint64_t m_functionStart;
		std::string m_module;

		DebugFrame() = default;
		DebugFrame(size_t index, uint64_t pc, uint64_t sp, uint64_t fp, const std::string& functionName,
			uint64_t functionStart, const std::string& module) :
			m_index(index),
			m_pc(pc), m_sp(sp), m_fp(fp), m_functionName(functionName), m_functionStart(functionStart), m_module(module)
		{}
	};


	struct DebugModule
	{
		std::string m_name {}, m_short_name {};
		uint64_t m_address {};
		size_t m_size {};
		bool m_loaded {};

		// These are useful for remote debugging. Paths can be different on the host and guest systems, e.g.,
		// /usr/bin/ls, and C:\Users\user\Desktop\ls. So we must compare the base file name, rather than the full path.
		bool IsSameBaseModule(const DebugModule& other) const;
		bool IsSameBaseModule(const std::string& name) const;
		static bool IsSameBaseModule(const std::string& module, const std::string& module2);
		static std::string GetPathBaseName(const std::string& path);
	};


	struct DebugRegister
	{
		std::string m_name {};
		uint64_t m_value {};
		size_t m_width {}, m_registerIndex {};
		std::string m_hint {};
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
		bool operator!=(const ModuleNameAndOffset& other) const { return !(*this == other); }
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
		uint32_t lastActiveThread;
		size_t exitCode;
		void* data;
	};


	struct ErrorEventData
	{
		std::string error;
		std::string shortError;
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


	struct LaunchConfigurations
	{
		bool requestTerminalEmulator;
		std::string inputFile;
	};


	typedef BNDebugAdapterConnectionStatus DebugAdapterConnectionStatus;
	typedef BNDebugAdapterTargetStatus DebugAdapterTargetStatus;

	class DebuggerController :
		public DbgCoreRefCountObject<BNDebuggerController, BNDebuggerNewControllerReference, BNDebuggerFreeController>
	{
		struct DebuggerEventCallbackObject
		{
			std::function<void(const DebuggerEvent&)> action;
		};

	public:
		DebuggerController(BNDebuggerController* controller);
		static DbgRef<DebuggerController> GetController(Ref<BinaryNinja::BinaryView> data);
		static bool ControllerExists(Ref<BinaryNinja::BinaryView> data);
		void Destroy();
		Ref<BinaryView> GetLiveView();
		Ref<BinaryView> GetData();
		void SetData(const Ref<BinaryView>& data);
		Ref<Architecture> GetRemoteArchitecture();

		bool IsConnected();
		bool IsConnectedToDebugServer();
		bool IsRunning();

		uint64_t StackPointer();

		DataBuffer ReadMemory(uint64_t address, size_t size);
		bool WriteMemory(uint64_t address, const DataBuffer& buffer);

		std::vector<DebugProcess> GetProcessList();

		std::vector<DebugThread> GetThreads();
		DebugThread GetActiveThread();
		void SetActiveThread(const DebugThread& thread);
		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid);
		bool SuspendThread(uint32_t tid);
		bool ResumeThread(uint32_t tid);

		std::vector<DebugModule> GetModules();
		std::vector<DebugRegister> GetRegisters();
		uint64_t GetRegisterValue(const std::string& name);
		bool SetRegisterValue(const std::string& name, uint64_t value);

		// target control
		bool Launch();
		BNDebugStopReason LaunchAndWait();
		bool Execute();
		void Restart();
		void Quit();
		void QuitAndWait();
		bool Connect();
		DebugStopReason ConnectAndWait();
		bool ConnectToDebugServer();
		bool DisconnectDebugServer();
		void Detach();
		// Convenience function, either launch the target process or connect to a remote, depending on the selected
		// adapter
		void LaunchOrConnect();
		bool Attach();
		DebugStopReason AttachAndWait();

		bool Go();
		bool StepInto(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepOver(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepReturn();
		bool RunTo(uint64_t remoteAddresses);
		bool RunTo(const std::vector<uint64_t>& remoteAddresses);
		void Pause();

		DebugStopReason GoAndWait();
		DebugStopReason StepIntoAndWait(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepOverAndWait(BNFunctionGraphType il = NormalFunctionGraph);
		DebugStopReason StepReturnAndWait();
		DebugStopReason RunToAndWait(uint64_t remoteAddresses);
		DebugStopReason RunToAndWait(const std::vector<uint64_t>& remoteAddresses);
		DebugStopReason PauseAndWait();

		std::string GetAdapterType();
		void SetAdapterType(const std::string& adapter);

		DebugAdapterConnectionStatus GetConnectionStatus();
		DebugAdapterTargetStatus GetTargetStatus();

		std::string GetRemoteHost();
		uint32_t GetRemotePort();
		std::string GetInputFile();
		std::string GetExecutablePath();
		std::string GetWorkingDirectory();
		bool GetRequestTerminalEmulator();
		std::string GetCommandLineArguments();
		int32_t GetPIDAttach();

		void SetInputFile(const std::string& path);
		void SetExecutablePath(const std::string& path);
		void SetWorkingDirectory(const std::string& directory);
		void SetCommandLineArguments(const std::string& arguments);
		void SetRemoteHost(const std::string& host);
		void SetRemotePort(uint32_t port);
		void SetRequestTerminalEmulator(bool requested);
		void SetPIDAttach(int32_t pid);

		std::vector<DebugBreakpoint> GetBreakpoints();
		void DeleteBreakpoint(uint64_t address);
		void DeleteBreakpoint(const ModuleNameAndOffset& breakpoint);
		void AddBreakpoint(uint64_t address);
		void AddBreakpoint(const ModuleNameAndOffset& breakpoint);
		bool ContainsBreakpoint(uint64_t address);
		bool ContainsBreakpoint(const ModuleNameAndOffset& breakpoint);

		uint64_t IP();
		uint64_t GetLastIP();
		bool SetIP(uint64_t address);
		uint32_t GetExitCode();

		uint64_t RelativeAddressToAbsolute(const ModuleNameAndOffset& address);
		ModuleNameAndOffset AbsoluteAddressToRelative(uint64_t address);

		size_t RegisterEventCallback(
			std::function<void(const DebuggerEvent& event)> callback, const std::string& name = "");
		static void DebuggerEventCallback(void* ctxt, BNDebuggerEvent* view);

		void RemoveEventCallback(size_t index);

		void WriteStdin(const std::string& msg);

		std::string InvokeBackendCommand(const std::string& command);

		static std::string GetDebugStopReasonString(DebugStopReason reason);
		DebugStopReason StopReason();

		BinaryNinja::Ref<Metadata> GetAdapterProperty(const std::string& name);
		bool SetAdapterProperty(const std::string& name, const BinaryNinja::Ref<Metadata>& value);

		bool ActivateDebugAdapter();

		std::string GetAddressInformation(uint64_t address);
		bool IsFirstLaunch();

		void PostDebuggerEvent(const DebuggerEvent& event);
	};


	class DebugAdapter;


	class DebugAdapterType: public DbgStaticCoreRefCountObject<BNDebugAdapterType>
	{
	private:
		std::string m_nameForRegister;

		static BNDebugAdapter* CreateCallback(void* ctxt, BNBinaryView* data);
		static bool IsvalidForDataCallback(void* ctxt, BNBinaryView* data);
		static bool CanExecuteCallback(void* ctxt, BNBinaryView* data);
		static bool CanConnectCallback(void* ctxt, BNBinaryView* data);

	protected:
		explicit DebugAdapterType(BNDebugAdapterType* adapterType);

	public:
		explicit DebugAdapterType(const std::string& name);
		void Register(DebugAdapterType* type);

		static DebugAdapterType* GetByName(const std::string& name);
		static std::vector<std::string> GetAvailableAdapters(Ref<BinaryView> data);

		virtual bool IsValidForData(Ref<BinaryView> data) = 0;
		virtual bool CanExecute(Ref<BinaryView> data) = 0;
		virtual bool CanConnect(Ref<BinaryView> data) = 0;
		virtual DbgRef<DebugAdapter> Create(BinaryNinja::BinaryView* data) = 0;
	};


	class DbgCoreDebugAdapterType: public DebugAdapterType
	{
	public:
		DbgCoreDebugAdapterType(BNDebugAdapterType* type);
		bool IsValidForData(Ref<BinaryView> data) override;
		bool CanExecute(Ref<BinaryView> data) override;
		bool CanConnect(Ref<BinaryView> data) override;
		DbgRef<DebugAdapter> Create(BinaryNinja::BinaryView* data) override;
	};


	class DebugAdapter: public DbgCoreRefCountObject<BNDebugAdapter, BNDebuggerNewDebugAdapterReference,
			BNDebuggerFreeDebugAdapter>
	{
	private:
		static bool InitCallback(void* ctxt);
		static void FreeCallback(void* ctxt);
		static bool ExecuteWithArgsCallback(void* ctxt, const char* path, const char* args, const char* workingDir,
											const BNLaunchConfigurations* configs);
		static bool AttachCallback(void* ctxt, uint32_t pid);
		static bool ConnectCallback(void* ctxt, const char* server, uint32_t port);
		static bool ConnectToDebugServerCallback(void* ctxt, const char* server, uint32_t port);
		static bool DisconnectDebugServerCallback(void* ctxt);
		static bool DetachCallback(void* ctxt);
		static bool QuitCallback(void* ctxt);
		static BNDebugProcess* GetProcessListCallback(void* ctxt, size_t* count);
		static BNDebugThread* GetThreadListCallback(void* ctxt, size_t* count);
		static BNDebugThread GetActiveThreadCallback(void* ctxt);
		static uint32_t GetActiveThreadIdCallback(void* ctxt);
		static bool SetActiveThreadCallback(void* ctxt, BNDebugThread thread);
		static bool SetActiveThreadIdCallback(void* ctxt, uint32_t tid);
		static bool SuspendThreadCallback(void* ctxt, uint32_t tid);
		static bool ResumeThreadCallback(void* ctxt, uint32_t tid);
		static BNDebugFrame* GetFramesOfThreadCallback(void* ctxt, uint32_t tid, size_t* count);
		static BNDebugBreakpoint AddBreakpointWithAddressCallback(void* ctxt, const uint64_t address, unsigned long breakpoint_type);
		static BNDebugBreakpoint AddBreakpointWithModuleAndOffsetCallback(void* ctxt, const char* module, uint64_t offset,
																		  unsigned long type);
		static bool RemoveBreakpointCallback(void* ctxt, BNDebugBreakpoint breakpoint);
		static bool RemoveBreakpointWithModuleAndOffsetCallback(void* ctxt, const char* module, uint64_t offset);
		static BNDebugBreakpoint* GetBreakpointListCallback(void* ctxt, size_t* count);
		static BNDebugRegister* ReadAllRegistersCallback(void* ctxt, size_t* count);
		static BNDebugRegister* ReadRegisterCallback(void* ctxt, const char* reg);
		static bool WriteRegisterCallback(void* ctxt, const char* reg, uint64_t value);
		static BNDataBuffer* ReadMemoryCallback(void* ctxt, uint64_t address, size_t size);
		static bool WriteMemoryCallback(void* ctxt, uint64_t address, BNDataBuffer* buffer);
		static BNDebugModule* GetModuleListCallback(void* ctxt, size_t* count);
		static char* GetTargetArchitectureCallback(void* ctxt);
		static DebugStopReason StopReasonCallback(void* ctxt);
		static uint64_t ExitCodeCallback(void* ctxt);
		static bool BreakIntoCallback(void* ctxt);
		static bool GoCallback(void* ctxt);
		static bool StepIntoCallback(void* ctxt);
		static bool StepOverCallback(void* ctxt);
		static bool StepReturnCallback(void* ctxt);
		static char* InvokeBackendCommandCallback(void* ctxt, const char*command);
		static uint64_t GetInstructionOffsetCallback(void* ctxt);
		static uint64_t GetStackPointerCallback(void* ctxt);
//		bool SupportFeature(DebugAdapterCapacity feature);
		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
		void PostDebuggerEvent(const DebuggerEvent& event);
		static void WriteStdinCallback(void* ctxt, const char* msg);
//		BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name);
//		bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);
	public:
		DebugAdapter(BinaryView* data);
		DebugAdapter(BNDebugAdapter* adapter);
		~DebugAdapter();

		virtual bool Init()
		{
			return true;
		}

		virtual bool ExecuteWithArgs(const std::string& path, const std::string& args,
									 const std::string& workingDir, const LaunchConfigurations& configs = {})
		{
			return false;
		}

		virtual bool Attach(uint32_t pid)
		{
			return false;
		}

		virtual bool Connect(const std::string& server, uint32_t port)
		{
			return false;
		}

		virtual bool ConnectToDebugServer(const std::string& server, uint32_t port)
		{
			return false;
		}

		virtual bool DisconnectDebugServer()
		{
			return false;
		}

		virtual bool Detach()
		{
			return false;
		}

		virtual bool Quit()
		{
			return false;
		}

		virtual std::vector<DebugProcess> GetProcessList()
		{
			return {};
		}

		virtual std::vector<DebugThread> GetThreadList()
		{
			return {};
		}

		virtual DebugThread GetActiveThread()
		{
			return {};
		}

		virtual uint32_t GetActiveThreadId()
		{
			return 0;
		}

		virtual bool SetActiveThread(const DebugThread& thread)
		{
			return 0;
		}

		virtual bool SetActiveThreadId(uint32_t tid)
		{
			return false;
		}

		virtual bool SuspendThread(uint32_t tid)
		{
			return false;
		}

		virtual bool ResumeThread(uint32_t tid)
		{
			return false;
		}

		virtual std::vector<DebugFrame> GetFramesOfThread(uint32_t tid)
		{
			return {};
		}

		virtual DebugBreakpoint AddBreakpoint(const uint64_t address, unsigned long breakpoint_type = 0)
		{
			return {};
		}

		virtual DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0)
		{
			return {};
		}

		virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint)
		{
			return false;
		}

		virtual bool RemoveBreakpoint(const ModuleNameAndOffset& address)
		{
			return false;
		}

		virtual std::vector<DebugBreakpoint> GetBreakpointList()
		{
			return {};
		}

		virtual std::map<std::string, DebugRegister> ReadAllRegisters()
		{
			return {};
		}

		virtual DebugRegister ReadRegister(const std::string& reg)
		{
			return {};
		}

		virtual bool WriteRegister(const std::string& reg, uint64_t value)
		{
			return false;
		}

		virtual DataBuffer ReadMemory(uint64_t address, size_t size)
		{
			return {};
		}

		virtual bool WriteMemory(uint64_t address, const DataBuffer& buffer)
		{
			return false;
		}

		virtual std::vector<DebugModule> GetModuleList()
		{
			return {};
		}

		virtual std::string GetTargetArchitecture()
		{
			return "";
		}

		virtual DebugStopReason StopReason()
		{
			return UnknownReason;
		}

		virtual uint64_t ExitCode()
		{
			return 0;
		}

		virtual bool BreakInto()
		{
			return false;
		}

		virtual bool Go()
		{
			return false;
		}

		virtual bool StepInto()
		{
			return false;
		}

		virtual bool StepOver()
		{
			return false;
		}

		virtual bool StepReturn()
		{
			return false;
		}

		virtual std::string InvokeBackendCommand(const std::string& command)
		{
			return "";
		}

		virtual uint64_t GetInstructionOffset()
		{
			return 0;
		}

		virtual uint64_t GetStackPointer()
		{
			return 0;
		}

//		bool SupportFeature(DebugAdapterCapacity feature);
		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
//		void PostDebuggerEvent(const DebuggerEvent& event);
		virtual void WriteStdin(const std::string& msg)
		{
		}
//		BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name);
//		bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);

	};
};  // namespace BinaryNinjaDebuggerAPI
