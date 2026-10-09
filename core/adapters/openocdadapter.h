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
#include "../debugadapter.h"
#include "../debugadaptertype.h"
#include "gdbadapter.h"

#ifdef WIN32
#include <windows.h>
#else
#include <sys/types.h>
#endif
#include <thread>

namespace BinaryNinjaDebugger {

	// OpenOCD's GDB server is roughly the same as normal GDB's RSP, so all handling in GdbAdapter
	// (breakpoints, registers, memory, stepping, ...) works the same here. The changes are to the
	// GDB port (defaults to 3333), and users typically expecting the debugger to start OpenOCD for
	// them rather than having to launch it by hand first. So, when enabled, Connect() spawns a local
	// `openocd` process and then hands off to GdbAdapter::Connect() to do the actual RSP handshake.
	class OpenOCDAdapter : public GdbAdapter
	{
		bool m_spawnedOpenOCD = false;
		bool m_resetOnNextConnect = false;
		std::thread m_executionThread;
#ifdef WIN32
		PROCESS_INFORMATION m_openocdProcess{};
#else
		pid_t m_openocdPid = -1;
#endif

		bool StartOpenOCD();
		void StopOpenOCD();
		void JoinExecutionThread();

	public:
		OpenOCDAdapter(BinaryView* data);
		~OpenOCDAdapter();

		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
		bool Attach(std::uint32_t pid) override;
		std::vector<DebugProcess> GetProcessList() override;
		bool Connect(const std::string& server, std::uint32_t port) override;
		bool Go() override;
		bool StepInto() override;
		bool Detach() override;
		bool Quit() override;
		std::vector<DebugModule> GetModuleList() override;

		Ref<Settings> GetAdapterSettings() override;
	};


	class OpenOCDAdapterType: public DebugAdapterType
	{
		static Ref<Settings> RegisterAdapterSettings();

	public:
		OpenOCDAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
		static Ref<Settings> GetAdapterSettings();
	};

	void InitOpenOCDAdapterType();
}  // namespace BinaryNinjaDebugger
