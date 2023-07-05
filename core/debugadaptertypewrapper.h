#include "binaryninjaapi.h"
#include "debugadaptertype.h"

namespace BinaryNinjaDebugger
{
	class DebugAdapterTypeWrapper: public DebugAdapterType
	{
		BNDebuggerCustomDebugAdapterType m_type;

	public:
		DebugAdapterTypeWrapper(const std::string& name, BNDebuggerCustomDebugAdapterType* type);
		DebugAdapter* Create(BinaryNinja::BinaryView* data) override;
		bool IsValidForData(BinaryNinja::BinaryView* data) override;
		bool CanExecute(BinaryNinja::BinaryView* data) override;
		bool CanConnect(BinaryNinja::BinaryView* data) override;
	};
};
