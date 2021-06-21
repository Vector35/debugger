#include "inttypes.h"
#include "debugger.h"
#include "debugview.h"
#include "processview.h"

using namespace BinaryNinja;

extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		Log(BNLogLevel::WarningLog, "Native debugger loaded!" );
		ViewType::registerViewType(new DebugViewType());
        InitDebugMemoryViewType();
        InitDebugMemoryViewType();
        InitDebugProcessViewType();
		return true;
	}

	// BN_DECLARE_CORE_ABI_VERSION

	// BINARYNINJAPLUGIN bool CorePluginInit()
	// {
	// 	Log(BNLogLevel::WarningLog, "Headless debugger loaded!" );
	// 	return true;
	// }
}
