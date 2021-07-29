#include <inttypes.h>
#include "debugger.h"
#include "ui/debugview.h"
#include "processview.h"
#include "ui/ui.h"
#include "dockhandler.h"

using namespace BinaryNinja;

extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		Log(BNLogLevel::WarningLog, "Native debugger loaded!" );
		ViewType::registerViewType(new DebugViewType());
        DebuggerUI::InitializeUI();
		return true;
	}

	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
        if (!IsUIEnabled())
            Log(BNLogLevel::WarningLog, "Headless debugger loaded!" );

        InitDebugMemoryViewType();
        InitDebugProcessViewType();
		return true;
	}
}
