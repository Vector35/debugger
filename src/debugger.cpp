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

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		Log(BNLogLevel::WarningLog, "Native debugger loaded!" );
        DebuggerUI::InitializeUI();
        InitDebugAdapterTypes();
        InitDebugProcessViewType();
		return true;
	}

	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
        if (!IsUIEnabled())
            Log(BNLogLevel::WarningLog, "Headless debugger loaded!" );

		return true;
	}
}
