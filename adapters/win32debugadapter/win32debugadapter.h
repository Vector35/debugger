#include "../../api/debuggerapi.h"
#include "binaryninjaapi.h"

namespace BinaryNinjaDebuggerAPI
{
	class Win32DebugAdapter: public DebugAdapter
	{
	public:
		Win32DebugAdapter(BinaryNinja::BinaryView* data);
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
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