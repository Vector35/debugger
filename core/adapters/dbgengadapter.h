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
#include "../debugadapter.h"
#include "../debugadaptertype.h"

#define NOMINMAX
#include <windows.h>
#include <dbgeng.h>
#include <chrono>

namespace BinaryNinjaDebugger
{
	struct ProcessCallbackInformation
	{
		DebugBreakpoint m_lastBreakpoint{};
		EXCEPTION_RECORD64 m_lastException{};
		unsigned long m_exitCode{};
	};

	#define CALLBACK_METHOD(return_type) return_type __declspec(nothrow) __stdcall
	class DbgEngOutputCallbacks : public IDebugOutputCallbacks
	{
	private:
		DebugAdapter* m_adapter;
	public:
		CALLBACK_METHOD(unsigned long) AddRef() override;
		CALLBACK_METHOD(unsigned long) Release() override;
		CALLBACK_METHOD(HRESULT) QueryInterface(const IID& interface_id, void** _interface) override;
		CALLBACK_METHOD(HRESULT) Output(unsigned long mask, const char* text);
		void SetAdapter(DebugAdapter* adapter);
	};

	class DbgEngAdapter;
	class DbgEngEventCallbacks : public DebugBaseEventCallbacks
	{
	private:
		DbgEngAdapter* m_adapter;
	public:
		void SetAdapter(DbgEngAdapter* adapter) { m_adapter = adapter; }
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
				std::uint64_t start_offset
		) override;
		CALLBACK_METHOD(HRESULT) ExitProcess(unsigned long exit_code) override;
		CALLBACK_METHOD(HRESULT) LoadModule(
				std::uint64_t image_file_handle,
				std::uint64_t base_offset,
				unsigned long module_size,
				const char* module_name,
				const char* image_name,
				unsigned long check_sum,
				unsigned long time_date_stamp
		) override;
		CALLBACK_METHOD(HRESULT) UnloadModule(const char* image_base_name, std::uint64_t base_offset) override;
		CALLBACK_METHOD(HRESULT) SystemError(unsigned long error, unsigned long level) override;
		CALLBACK_METHOD(HRESULT) SessionStatus(unsigned long session_status) override;
		CALLBACK_METHOD(HRESULT) ChangeDebuggeeState(unsigned long flags, std::uint64_t argument) override;
		CALLBACK_METHOD(HRESULT) ChangeEngineState(unsigned long flags, std::uint64_t argument) override;
		CALLBACK_METHOD(HRESULT) ChangeSymbolState(unsigned long flags, std::uint64_t argument) override;
	};
	#undef CALLBACK_METHOD

	class DbgEngAdapter : public DebugAdapter
	{
		DbgEngEventCallbacks m_debugEventCallbacks{};
		DbgEngOutputCallbacks m_outputCallbacks{};
		IDebugClient5* m_debugClient{nullptr};
		IDebugControl5* m_debugControl{nullptr};
		IDebugDataSpaces* m_debugDataSpaces{nullptr};
		IDebugRegisters* m_debugRegisters{nullptr};
		IDebugSymbols* m_debugSymbols{nullptr};
		IDebugSystemObjects* m_debugSystemObjects{nullptr};
		bool m_debugActive{false};

		bool Start();
		void Reset();

		std::vector<DebugBreakpoint> m_debug_breakpoints{};
        bool m_lastOperationIsStepInto = false;

        uint64_t m_lastExecutionStatus = DEBUG_STATUS_BREAK;

		unsigned long m_exitCode{};

        std::vector<ModuleNameAndOffset> m_pendingBreakpoints{};

        ULONG64 m_server{};
        bool m_connectedToDebugServer = false;
        bool m_dbgSrvLaunchedByAdapter = false;

	public:
		inline static ProcessCallbackInformation ProcessCallbackInfo{};
		static constexpr unsigned long StepoutBreakpointID = 0x5be9c948;

		DbgEngAdapter(BinaryView* data);
		~DbgEngAdapter();

		[[nodiscard]] bool Execute(const std::string& path, const LaunchConfigurations& configs = {}) override;
		[[nodiscard]] bool ExecuteWithArgs(const std::string& path, const std::string &args,
										   const std::string& workingDir,
										   const LaunchConfigurations& configs = {}) override;
		[[nodiscard]] bool ExecuteWithArgsInternal(const std::string& path, const std::string &args,
											const std::string& workingDir,
											const LaunchConfigurations& configs = {});
		[[nodiscard]] bool Attach(std::uint32_t pid) override;
		[[nodiscard]] bool AttachInternal(std::uint32_t pid);
		[[nodiscard]] bool Connect(const std::string &server, std::uint32_t port) override;
        bool ConnectToDebugServer(const std::string &server, std::uint32_t port) override;
        bool DisconnectDebugServer() override;

		void Detach() override;
		void Quit() override;

		bool Wait(std::chrono::milliseconds timeout = std::chrono::milliseconds::max());

		void EngineLoop();

		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread &thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;

		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_flags = 0) override;
        DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;

		bool RemoveBreakpoint(const DebugBreakpoint &breakpoint) override;
        bool RemoveBreakpoint(const ModuleNameAndOffset& breakpoint) override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;

		std::string GetRegisterNameByIndex(std::uint32_t index) const;
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string &reg) override;
		bool WriteRegister(const std::string &reg, std::uintptr_t value) override;
		std::vector<std::string> GetRegisterList() const;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;

		//bool ReadMemory(std::uintptr_t address, void* out, std::size_t size) override;
		//bool WriteMemory(std::uintptr_t address, const void* out, std::size_t size) override;
		std::vector<DebugModule> GetModuleList() override;

		std::string GetTargetArchitecture() override;

		DebugStopReason StopReason() override;
		unsigned long ExecStatus();
		uint64_t ExitCode() override;

		bool BreakInto() override;
		DebugStopReason Go() override;
		DebugStopReason StepInto() override;
		DebugStopReason StepOver() override;
		DebugStopReason StepReturn() override;

		std::string InvokeBackendCommand(const std::string& command) override;
		std::uintptr_t GetInstructionOffset() override;

		bool SupportFeature(DebugAdapterCapacity feature) override;

		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;

        void ApplyBreakpoints();

        std::string GetDbgEngPath(const std::string& arch = "x64");

        bool LoadDngEngLibraries();

        std::string GenerateRandomPipeName();

        bool LaunchDbgSrv(const std::string& commandLine);

        bool ConnectToDebugServerInternal(const std::string& connectionString);
	};

	class LocalDbgEngAdapterType: public DebugAdapterType
	{
	public:
		LocalDbgEngAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	void InitDbgEngAdapterType();
};
