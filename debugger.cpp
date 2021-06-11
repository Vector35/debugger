#include "inttypes.h"
#include "debugger.h"

using namespace BinaryNinja;

extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		Log(BNLogLevel::WarningLog, "Native debugger loaded!" );
		return true;
	}
}
