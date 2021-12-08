#include "debugadapter.h"
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>


void DebugAdapter::PostDebuggerEvent(const DebuggerEvent &event)
{
	if (m_eventCallback)
		m_eventCallback(event);
}
