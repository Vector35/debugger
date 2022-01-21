#include <inttypes.h>
#include "debugger.h"
#include "processview.h"
#include "ui/ui.h"
#include "adapters/gdbadapter.h"
#include "adapters/lldbadapter.h"
#include "ui/uinotification.h"

#ifdef WIN32
#include "adapters/dbgengadapter.h"
#endif

using namespace BinaryNinja;

void InitDebugAdapterTypes()
{
#ifdef WIN32
    InitDbgEngAdapterType();
#endif

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
		{
        	DebuggerUI::InitializeUI();
			NotificationListener::init();
		}
		return true;
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		// The current debugger can load in headless macOS, but not Linux and Windows. This causes unit test failures
		// because the available view types on macOS will have one more Debugger view. Here we explicitly not load
		// the debugger in headless mode.
		if (!IsUIEnabled())
			return true;
		Log(BNLogLevel::DebugLog, "Native debugger loaded!" );
        InitDebugAdapterTypes();
        InitDebugProcessViewType();
		return true;
	}
}
