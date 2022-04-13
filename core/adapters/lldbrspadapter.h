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
#include "gdbadapter.h"

namespace BinaryNinjaDebugger
{
	class LldbRspAdapter : public GdbAdapter
	{
		bool LoadRegisterInfo() override;
		DebugStopReason SignalToStopReason(std::unordered_map<std::string, std::uint64_t>& dict) override;

		std::string GetDebugServerPath();

	public:
		LldbRspAdapter(BinaryView* data);
		bool ExecuteWithArgs(const std::string &path, const std::string &args, const std::string &workingDir,
							 const LaunchConfigurations &configs) override;
		bool Attach(uint32_t pid) override;
		DebugStopReason Go() override;
		std::string GetTargetArchitecture() override;
		std::vector<DebugModule> GetModuleList() override;

		// LLDB requires a different way of reading register values, the g packet that works for gdb does not work for lldb
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& reg) override;

		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size) override;
	};


	class LocalLldbRspAdapterType: public DebugAdapterType
	{
	public:
		LocalLldbRspAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	class RemoteLldbRspAdapterType: public DebugAdapterType
	{
	public:
		RemoteLldbRspAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	void InitLldbRspAdapterType();
};
