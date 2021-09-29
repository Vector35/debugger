#include <inttypes.h>
#include "debugger.h"
#include "ui/debugview.h"
#include "processview.h"
#include "ui/ui.h"
#include "adapters/gdbadapter.h"

using namespace BinaryNinja;

void InitDebugAdapterTypes()
{
    LogWarn("InitDebugAdapterTypes()");
    InitGdbAdapterType();
}

extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		Log(BNLogLevel::WarningLog, "Native debugger loaded!" );
		ViewType::registerViewType(new DebugViewType());
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
