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
#include "debugadaptertypes.h"
#include "dbgengtypes.h"

#define NOMINMAX
#include <windows.h>
#include <dbgeng.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace BinaryNinjaDebugger {
	#define SAFE_RELEASE(ptr) \
		if (ptr) \
		{ \
			ptr->Release(); \
			ptr = nullptr; \
		}

	#define QUERY_DEBUG_INTERFACE(query, out) \
		if (const auto result = this->m_debugClient->QueryInterface(__uuidof(query), reinterpret_cast<void**>(out)); \
			result != S_OK) \
		throw std::runtime_error("Failed to create " #query)

	struct ProcessCallbackInformation
	{
		DebugBreakpoint m_lastBreakpoint {};
		EXCEPTION_RECORD64 m_lastException {};
		unsigned long m_exitCode {};
	};

	class DbgEngEngine;
#define CALLBACK_METHOD(return_type) return_type __declspec(nothrow) __stdcall
	class DbgEngOutputCallbacks : public IDebugOutputCallbacks
	{
	private:
		DbgEngEngine* m_engine;
		std::string m_output;

	public:
		CALLBACK_METHOD(unsigned long) AddRef() override;
		CALLBACK_METHOD(unsigned long) Release() override;
		CALLBACK_METHOD(HRESULT) QueryInterface(const IID& interface_id, void** _interface) override;
		CALLBACK_METHOD(HRESULT) Output(unsigned long mask, const char* text);
		void SetEngine(DbgEngEngine* engine);
		void StartOutput();
		std::string EndOutput();
	};

    class DbgEngInputCallbacks : public IDebugInputCallbacks
    {
    private:
        IDebugControl7* m_control;

    public:
        CALLBACK_METHOD(unsigned long) AddRef() override;
        CALLBACK_METHOD(unsigned long) Release() override;
        CALLBACK_METHOD(HRESULT) QueryInterface(const IID& interface_id, void** _interface) override;
        CALLBACK_METHOD(HRESULT) StartInput(ULONG BufferSize);
        CALLBACK_METHOD(HRESULT) EndInput();
        void SetDbgControl(IDebugControl7* control);
    };

	class DbgEngEventCallbacks : public DebugBaseEventCallbacks
	{
	private:
		DbgEngEngine* m_engine;

	public:
		void SetEngine(DbgEngEngine* engine) { m_engine = engine; }
		CALLBACK_METHOD(unsigned long) AddRef() override;
		CALLBACK_METHOD(unsigned long) Release() override;
		CALLBACK_METHOD(HRESULT) GetInterestMask(unsigned long* mask) override;
		CALLBACK_METHOD(HRESULT) Breakpoint(IDebugBreakpoint* breakpoint) override;
		CALLBACK_METHOD(HRESULT) Exception(EXCEPTION_RECORD64* exception, unsigned long first_chance) override;
		CALLBACK_METHOD(HRESULT) CreateThread(std::uint64_t handle, std::uint64_t data_offset, std::uint64_t start_offset) override;
		CALLBACK_METHOD(HRESULT) ExitThread(unsigned long exit_code) override;
		CALLBACK_METHOD(HRESULT) CreateProcess(
			std::uint64_t image_file_handle,
			std::uint64_t handle,
			std::uint64_t base_offset,
			unsigned long module_size,
			const char* module_name,
			const char* image_name,
			unsigned long check_sum,
			unsigned long time_date_stamp,
			std::uint64_t initial_thread_handle,
			std::uint64_t thread_data_offset,
			std::uint64_t start_offset) override;
		CALLBACK_METHOD(HRESULT) ExitProcess(unsigned long exit_code) override;
		CALLBACK_METHOD(HRESULT) LoadModule(
			std::uint64_t image_file_handle,
			std::uint64_t base_offset,
			unsigned long module_size,
			const char* module_name,
			const char* image_name,
			unsigned long check_sum,
			unsigned long time_date_stamp) override;
		CALLBACK_METHOD(HRESULT) UnloadModule(const char* image_base_name, std::uint64_t base_offset) override;
		CALLBACK_METHOD(HRESULT) SystemError(unsigned long error, unsigned long level) override;
		CALLBACK_METHOD(HRESULT) SessionStatus(unsigned long session_status) override;
		CALLBACK_METHOD(HRESULT) ChangeDebuggeeState(unsigned long flags, std::uint64_t argument) override;
		CALLBACK_METHOD(HRESULT) ChangeEngineState(unsigned long flags, std::uint64_t argument) override;
		CALLBACK_METHOD(HRESULT) ChangeSymbolState(unsigned long flags, std::uint64_t argument) override;
	};
#undef CALLBACK_METHOD

	class DbgEngEngine
	{
    public:
		DbgEngEventCallbacks m_debugEventCallbacks {};
        DbgEngOutputCallbacks m_outputCallbacks {};
        DbgEngInputCallbacks m_inputCallbacks {};
		IDebugClient7* m_debugClient {nullptr};
		IDebugControl7* m_debugControl {nullptr};
		IDebugDataSpaces* m_debugDataSpaces {nullptr};
		IDebugDataSpaces2* m_debugDataSpaces2 {nullptr};
		IDebugRegisters* m_debugRegisters {nullptr};
		IDebugSymbols3* m_debugSymbols {nullptr};
		IDebugSystemObjects* m_debugSystemObjects {nullptr};
		bool m_dbgengInitialized {false};
		bool m_activelyDebugging {false};

		virtual bool Start();
		virtual void Reset();

		// Kills the target. Called by EngineLoop() on the thread that created the debug client, never
		// directly from Quit(), because DbgEng clients are thread-affine.
		virtual bool TerminateTargetOnEngineThread();

		std::vector<DebugBreakpoint> m_debug_breakpoints {};
		bool m_lastOperationIsStepInto = false;

		uint64_t m_lastExecutionStatus = DEBUG_STATUS_NO_DEBUGGEE;

		unsigned long m_exitCode {};

		std::vector<ModuleNameAndOffset> m_pendingBreakpoints {};
		std::vector<PendingHardwareBreakpoint> m_pendingHardwareBreakpoints {};
		std::vector<PendingHardwareBreakpoint> m_deferredHardwareBreakpoints {};
		bool m_needsHardwareBreakpointReapplication = false;

		ULONG64 m_server {};
		bool m_connectedToDebugServer = false;
		bool m_dbgSrvLaunchedByAdapter = false;

		bool m_aboutToBeKilled = false;

		// Raised by Quit() so that EngineLoop() performs the terminate on the thread that owns the
		// debug client. See TerminateTargetOnEngineThread(). EngineLoop() clears it when a session
		// starts, since the adapter object outlives a session and an unserviced request would
		// otherwise be latched into the next one.
		std::atomic<bool> m_terminateRequested {false};

        std::string m_pdbFileName {};
        bool m_usePDBFileName = true;

		std::string m_dbgSrvEnginePath;
		bool m_stopAtSystemEntryPoint = false;
		std::optional<uint64_t> m_entryPointOffset;
		bool m_outputStateOnStop = false;
		bool m_runAsAdministrator = false;
		std::vector<std::string> m_environmentVariables;
		uint64_t m_originalImageBase = 0;
		std::function<void(const DbgEngEvent&)> m_eventCallback;
		std::function<std::string()> m_inputFileCallback;

		std::recursive_mutex m_engineLoopMutex;

	public:
		inline static ProcessCallbackInformation ProcessCallbackInfo {};
		static constexpr unsigned long StepoutBreakpointID = 0x5be9c948;

		DbgEngEngine();
		virtual ~DbgEngEngine();

		void SetDbgSrvEnginePath(const std::string& path) { m_dbgSrvEnginePath = path; }
		void SetStopAtSystemEntryPoint(bool enabled) { m_stopAtSystemEntryPoint = enabled; }
		void SetEntryPointOffset(std::optional<uint64_t> offset) { m_entryPointOffset = offset; }
		void SetOutputStateOnStop(bool enabled) { m_outputStateOnStop = enabled; }
		void SetRunAsAdministrator(bool enabled) { m_runAsAdministrator = enabled; }
		void SetEnvironmentVariables(const std::vector<std::string>& variables) { m_environmentVariables = variables; }
		void SetPdbFileName(const std::string& pdbFileName) { m_pdbFileName = pdbFileName; }
		void SetOriginalImageBase(uint64_t imageBase) { m_originalImageBase = imageBase; }
		void SetEventCallback(std::function<void(const DbgEngEvent&)> callback) { m_eventCallback = std::move(callback); }
		void SetInputFileCallback(std::function<std::string()> callback) { m_inputFileCallback = std::move(callback); }

		[[nodiscard]] bool ExecuteWithArgs(const std::string& path, const std::string& args,
			const std::string& workingDir);
		[[nodiscard]] virtual bool ExecuteWithArgsInternal(const std::string& path, const std::string& args,
			const std::string& workingDir);
		[[nodiscard]] bool Attach(std::uint32_t pid);
		[[nodiscard]] bool AttachInternal(std::uint32_t pid);
		[[nodiscard]] bool Connect(const std::string& server, std::uint32_t port);
		bool ConnectToDebugServer(const std::string& ipAddress, std::uint32_t port);
		bool DisconnectDebugServer();

		virtual bool Detach();
		virtual bool Quit();

		bool Wait(std::chrono::milliseconds timeout = std::chrono::milliseconds::max());

		void EngineLoop();

		std::vector<DebugProcess> GetProcessList();

		std::vector<DebugThread> GetThreadList();
		DebugThread GetActiveThread() const;
		std::uint32_t GetActiveThreadId() const;
		bool SetActiveThread(const DebugThread& thread);
		bool SetActiveThreadId(std::uint32_t tid);

		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags = 0);
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0);

		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint);
		bool RemoveBreakpoint(const ModuleNameAndOffset& breakpoint);

		std::vector<DebugBreakpoint> GetBreakpointList() const;

		// Hardware breakpoint and watchpoint support
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1);
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1);
		bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1);
		bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size = 1);

		std::string GetRegisterNameByIndex(std::uint32_t index) const;
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters();
		DebugRegister ReadRegister(const std::string& reg);
		virtual bool WriteRegister(const std::string& reg, intx::uint512 value);
		std::vector<std::string> GetRegisterList() const;

		std::vector<uint8_t> ReadMemory(std::uintptr_t address, std::size_t size);
		virtual bool WriteMemory(std::uintptr_t address, const std::vector<uint8_t>& buffer);

		// bool ReadMemory(std::uintptr_t address, void* out, std::size_t size) override;
		// bool WriteMemory(std::uintptr_t address, const void* out, std::size_t size) override;
		std::vector<DebugModule> GetModuleList();

		std::vector<DebugMemoryRegion> GetMemoryMap();

		std::vector<DebugSymbol> GetSymbolsForModule(const DebugModule& module);

		std::string GetTargetArchitecture();

		DbgEngStopReason GetStopReason();
		void PostEngineEvent(const DbgEngEvent& event);
		unsigned long ExecStatus();
		uint64_t ExitCode();

		bool BreakInto();
		bool Go();
		bool StepInto();
		bool StepOver();
		bool StepReturn();

		std::string InvokeBackendCommand(const std::string& command);
		uint64_t GetInstructionOffset();
		uint64_t GetStackPointer();
		std::uint32_t GetActivePID();

		virtual bool SupportFeature(DebugAdapterCapacity feature);

		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid);

		bool SuspendThread(std::uint32_t tid);
		bool ResumeThread(std::uint32_t tid);

		void ApplyBreakpoints();

		static bool LoadLibraries(const std::string& enginePath, bool strictCheckPath, bool forceUnload);

		std::string GenerateRandomPipeName();

		bool LaunchDbgSrv(const std::string& commandLine);

		bool ConnectToDebugServerInternal(const std::string& connectionString);

	protected:
		std::string GetInputFile() { return m_inputFileCallback ? m_inputFileCallback() : std::string(); }
	};
};  // namespace BinaryNinjaDebugger
