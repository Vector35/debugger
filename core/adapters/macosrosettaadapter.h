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

#include "gdbadapter.h"
#include "macosnativeadapter.h"
#include <thread>

namespace BinaryNinjaDebugger {
	// Apple's Rosetta service supplies the translated x86 state that Mach APIs cannot expose.
	class MacOSRosettaAdapter : public GdbAdapter
	{
		std::thread m_worker;
		pid_t m_server = 0;
		bool m_owned = false;
		bool m_stepping = false;
		int m_stdin = -1;
		int m_stdout = -1;
		std::thread m_ioWorker;
		std::atomic<bool> m_ioStop {false};
		void StopIO();
		std::string m_ioDirectory;
		uint64_t m_temporaryAddress = 0;
		bool m_temporaryOwned = false;
		struct HardwareBreakpoint
		{
			uint64_t address;
			DebugBreakpointType type;
			size_t size;
		};
		std::vector<HardwareBreakpoint> m_hardware;
		bool m_watchpointStop = false;
		bool RunToTemporary(uint64_t address);
		MacOSNativeAdapter m_inspector;
		bool Start(const std::vector<std::string>& arguments);
		bool Resume(bool step);
		void Join();
		void StopServer();
		bool LoadRegisterInfo() override;
		DebugStopReason SignalToStopReason(std::unordered_map<std::string, uint64_t>& fields) override;

	public:
		MacOSRosettaAdapter(BinaryView* data);
		~MacOSRosettaAdapter() override;
		bool Execute(const std::string& path, const LaunchConfigurations& configs) override;
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& cwd,
			const LaunchConfigurations& configs) override;
		bool Attach(uint32_t pid) override;
		std::vector<DebugProcess> GetProcessList() override { return m_inspector.GetProcessList(); }
		bool Go() override { return Resume(false); }
		bool StepInto() override { return Resume(true); }
		bool StepOver() override;
		bool StepReturn() override;
		bool Detach() override;
		bool Quit() override;
		void WriteStdin(const std::string& text) override;
		bool SuspendThread(uint32_t tid) override { return m_inspector.SuspendThread(tid); }
		bool ResumeThread(uint32_t tid) override { return m_inspector.ResumeThread(tid); }
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		bool WriteRegister(const std::string& name, intx::uint512 value) override;
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size = 1) override;
		std::vector<DebugModule> GetModuleList() override;
		std::vector<DebugMemoryRegion> GetMemoryMap() override;
		std::vector<DebugSymbol> GetSymbolsForModule(const DebugModule& module) override;
		std::vector<DebugFrame> GetFramesOfThread(uint32_t tid) override;
		bool SupportFeature(DebugAdapterCapacity feature) override;
		Ref<Settings> GetAdapterSettings() override { return MacOSNativeAdapterType::GetAdapterSettings(); }
		Ref<Metadata> GetProperty(const std::string& name) override
		{
			m_inspector.SetController(GetController());
			return m_inspector.GetProperty(name);
		}
		bool SetProperty(const std::string& name, const Ref<Metadata>& value) override
		{
			m_inspector.SetController(GetController());
			return m_inspector.SetProperty(name, value);
		}
	};
}  // namespace BinaryNinjaDebugger
