#include "ffi.h"
#include "debuggercontroller.h"

using namespace BinaryNinjaDebugger;

BNDebuggerController* BNGetDebuggerController(BinaryNinja::BinaryView* data)
{
	return DebuggerController::GetController(data)->GetAPIObject();
}


Ref<BinaryView> BNDebuggerGetLiveView(BNDebuggerController* controller)
{
	controller->object->GetLiveView();
}


Ref<Architecture> BNDebuggerGetRemoteArchitecture(BNDebuggerController* controller)
{
	controller->object->GetRemoteArchitecture();
}