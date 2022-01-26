#include "debuggerapi.h"

using namespace BinaryNinjaDebugger;

BinaryNinjaDebugger::DebuggerController* BinaryNinjaDebugger::DebuggerController::GetController(BinaryNinja::BinaryView* data)
{
	BNDebuggerController* controller = BNGetDebuggerController(data);
	if (!controller)
		return nullptr;

	return new BinaryNinjaDebugger::DebuggerController(controller);
}


BinaryNinjaDebugger::DebuggerController::DebuggerController(BNDebuggerController* controller)
{
	m_object = controller;
}
