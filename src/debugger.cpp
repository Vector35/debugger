#include <inttypes.h>
#include "debugger.h"
#include "processview.h"
#include "ui/ui.h"
#include "adapters/gdbadapter.h"
#include "adapters/lldbadapter.h"

using namespace BinaryNinja;

void InitDebugAdapterTypes()
{
    InitGdbAdapterType();
    InitLldbAdapterType();
}

extern "C"
{
	BN_DECLARE_UI_ABI_VERSION
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		SetCurrentPluginLoadOrder(LatePluginLoadOrder);
	}

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		if (IsUIEnabled())
        	DebuggerUI::InitializeUI();
		return true;
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		Log(BNLogLevel::DebugLog, "Native debugger loaded!" );
        InitDebugAdapterTypes();
        InitDebugProcessViewType();
		return true;
	}
}
