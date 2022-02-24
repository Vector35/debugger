#pragma once
#include "gdbadapter.h"

namespace BinaryNinjaDebugger
{
	class LldbAdapter : public GdbAdapter
	{
		bool LoadRegisterInfo() override;
		DebugStopReason SignalToStopReason(std::uint64_t signal) override;

	public:
		bool ExecuteWithArgs(const std::string& path, const std::string &args,
							 const LaunchConfigurations& configs) override;
		bool Attach(uint32_t pid) override;
		DebugStopReason Go() override;
		std::string GetTargetArchitecture() override;
		std::vector<DebugModule> GetModuleList() override;

		// LLDB requires a different way of reading register values, the g packet that works for gdb does not work for lldb
		std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override;
		DebugRegister ReadRegister(const std::string& reg) override;
	};


	class LocalLldbAdapterType: public DebugAdapterType
	{
	public:
		LocalLldbAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	class RemoteLldbAdapterType: public DebugAdapterType
	{
	public:
		RemoteLldbAdapterType();
		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data);
		virtual bool IsValidForData(BinaryNinja::BinaryView* data);
		virtual bool CanExecute(BinaryNinja::BinaryView* data);
		virtual bool CanConnect(BinaryNinja::BinaryView* data);
	};


	void InitLldbAdapterType();
};
