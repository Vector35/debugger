/*
Copyright 2020-2025 Vector 35 Inc.

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
#include <memory>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#endif

namespace BinaryNinjaDebugger
{
	class GdbMiAdapter : public DebugAdapter
	{
	private:
		struct GdbProcess
		{
#ifdef _WIN32
			HANDLE process;
			HANDLE stdinPipe;
			HANDLE stdoutPipe;
			HANDLE stderrPipe;
#else
			pid_t pid;
			int stdinFd;
			int stdoutFd;
			int stderrFd;
#endif
			bool valid;
			
			GdbProcess();
			~GdbProcess();
			bool IsRunning();
			void Terminate();
		};

		std::unique_ptr<GdbProcess> m_gdbProcess;
		std::thread m_outputThread;
		std::thread m_errorThread;
		std::mutex m_commandMutex;
		std::condition_variable m_responseCondition;
		std::string m_lastResponse;
		bool m_responseReady;
		bool m_isTargetRunning;
		uint64_t m_exitCode;

		// GDB MI Communication
		std::string SendCommand(const std::string& command);
		void ProcessOutput();
		void ProcessError();
		std::string ParseMiResponse(const std::string& response);
		bool StartGdbProcess();
		void StopGdbProcess();
		std::string GetGdbExecutablePath();

		// Helper methods
		void GenerateDefaultAdapterSettings(BinaryView* data);

	public:
		GdbMiAdapter(BinaryView* data);
		~GdbMiAdapter();

		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
		bool Attach(std::uint32_t pid) override;
		bool Connect(const std::string& server, std::uint32_t port) override;
		bool ConnectToDebugServer(const std::string& server, std::uint32_t port) override;

		bool Detach() override;
		bool Quit() override;

		std::vector<DebugProcess> GetProcessList() override;
		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() const override;
		std::uint32_t GetActiveThreadId() const override;
		bool SetActiveThread(const DebugThread& thread) override;
		bool SetActiveThreadId(std::uint32_t tid) override;

		std::vector<DebugBreakpoint> GetBreakpointList() const override;
		DebugBreakpoint AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type = 0) override;
		DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0) override;
		bool RemoveBreakpoint(const DebugBreakpoint& breakpoint) override;

		std::vector<DebugModule> GetModuleList() override;
		std::vector<DebugRegister> GetRegisters() override;
		bool SetRegisterValue(const std::string& name, std::uintptr_t value) override;

		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;
		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer) override;

		std::string GetTargetArchitecture() override;
		uint64_t GetInstructionOffset() override;
		uint64_t GetStackPointer() override;
		DebugStopReason StopReason() override;
		uint64_t ExitCode() override { return m_exitCode; }

		bool BreakInto() override;
		bool Go() override;
		bool StepInto() override;
		bool StepOver() override;
		bool StepReturn() override;

		bool GoReverse() override;
		bool StepIntoReverse() override;
		bool StepOverReverse() override;
		bool StepReturnReverse() override;

		std::string InvokeBackendCommand(const std::string& command) override;
		bool SupportFeature(DebugAdapterCapacity feature) override;

		Ref<Settings> GetAdapterSettings() override;
	};

	class GdbMiAdapterType : public DebugAdapterType
	{
		static Ref<Settings> RegisterAdapterSettings();

	public:
		GdbMiAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
		static Ref<Settings> GetAdapterSettings();
	};

	void InitGdbMiAdapterType();
};