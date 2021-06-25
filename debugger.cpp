#include "inttypes.h"
#include "debugger.h"
#include "debugview.h"
#include "processview.h"
#include "./dockwidgets/registerwidget.h"
#include "dockhandler.h"

using namespace BinaryNinja;

void InitilizeUI()
{
    DockHandler* activeDocks = DockHandler::getActiveDockHandler();
	activeDocks->addDockWidget("Native Debugger Registers", [](const QString& name, ViewFrame* frame, BinaryViewRef data) { return new DebugRegisterWidget(frame, name, data); }, Qt::RightDockWidgetArea, Qt::Horizontal, false);
}


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
        InitilizeUI();
		return true;
	}

	// BN_DECLARE_CORE_ABI_VERSION

	// BINARYNINJAPLUGIN bool CorePluginInit()
	// {
	// 	Log(BNLogLevel::WarningLog, "Headless debugger loaded!" );
	// 	return true;
	// }
}
