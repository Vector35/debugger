#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

DebuggerController* DebuggerController::GetController(BinaryNinja::BinaryView* data)
{
	BNDebuggerController* controller = BNGetDebuggerController(data);
	if (!controller)
		return nullptr;

	return new BinaryNinjaDebuggerAPI::DebuggerController(controller);
}


DebuggerController::DebuggerController(BNDebuggerController* controller)
{
	m_object = controller;
}


Ref<BinaryView> DebuggerController::GetLiveView()
{
	return BNDebuggerGetLiveView(m_object);
}


Ref<Architecture> DebuggerController::GetRemoteArchitecture()
{
	return BNDebuggerGetRemoteArchitecture(m_object);
}


