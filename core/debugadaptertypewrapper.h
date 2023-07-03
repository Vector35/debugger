#include "binaryninjaapi.h"
#include "debugadaptertype.h"

namespace BinaryNinjaDebugger
{
	class DebugAdapterTypeWrapper: public DebugAdapterType
	{
		BNDebugAdapterTypeWrapper m_type;

	public:
		DebugAdapterTypeWrapper(const std::string& name, BNDebugAdapterTypeWrapper* type);
		DebugAdapter* Create(BinaryNinja::BinaryView* data) override;
		bool IsValidForData(BinaryNinja::BinaryView* data) override;
		bool CanExecute(BinaryNinja::BinaryView* data) override;
		bool CanConnect(BinaryNinja::BinaryView* data) override;
	};
};
