#include "../../api/debuggerapi.h"
#include "binaryninjaapi.h"

namespace BinaryNinjaDebuggerAPI
{
	class Win32DebugAdapter: public DebugAdapter
	{
		PROCESS_INFORMATION m_processInfo;
		HANDLE m_debugEvent;
		void DebugLoop();
		void Reset();

	public:
		Win32DebugAdapter(BinaryNinja::BinaryView* data);
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
		bool ExecuteWithArgsInternal(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs);
		std::map<std::string, DebugRegister> ReadAllRegisters() override;
		DataBuffer ReadMemory(uint64_t address, size_t size) override;
	};


	class Win32DebugAdapterType: public DebugAdapterType
	{
	public:
		Win32DebugAdapterType();
		bool IsValidForData(Ref<BinaryView> data) override;
		bool CanExecute(Ref<BinaryView> data) override;
		bool CanConnect(Ref<BinaryView> data) override;
		DbgRef<DebugAdapter> Create(BinaryNinja::BinaryView* data) override;
	};
}