#include "ffi.h"
#include "debuggercontroller.h"

BNDebuggerController* BNGetDebuggerController(BinaryNinja::BinaryView* data)
{
	return DebuggerController::GetController(data)->GetAPIObject();
}