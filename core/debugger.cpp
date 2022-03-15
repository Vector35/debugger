#include <inttypes.h>
#include "processview.h"
#include "adapters/gdbadapter.h"
#include "adapters/lldbrspadapter.h"
#ifdef WIN32
#include "adapters/dbgengadapter.h"
#endif

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

void InitDebugAdapterTypes()
{
#ifdef WIN32
    InitDbgEngAdapterType();
#endif

    InitGdbAdapterType();
    InitLldbRspAdapterType();
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		SetCurrentPluginLoadOrder(LatePluginLoadOrder);
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Log(BNLogLevel::DebugLog, "Native debugger loaded!" );
        InitDebugAdapterTypes();
        InitDebugProcessViewType();
		return true;
	}
}
