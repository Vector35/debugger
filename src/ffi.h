#pragma once
#include "binaryninjaapi.h"

using namespace BinaryNinja;

// Define macros for defining objects exposed by the API
#define DECLARE_DEBUGGER_API_OBJECT(handle, cls) \
	namespace BinaryNinjaDebugger{ class cls; } struct handle { BinaryNinjaDebugger::cls* object; }
#define IMPLEMENT_DEBUGGER_API_OBJECT(handle) \
	private: handle m_apiObject; public: typedef handle* APIHandle; handle* GetAPIObject() { return &m_apiObject; } private:
#define INIT_DEBUGGER_API_OBJECT() \
	m_apiObject.object = this;

DECLARE_DEBUGGER_API_OBJECT(BNDebuggerController, DebuggerController);
DECLARE_DEBUGGER_API_OBJECT(BNDebugAdapterType, DebugAdapterType);
DECLARE_DEBUGGER_API_OBJECT(BNDebugAdapter, DebugAdapter);
DECLARE_DEBUGGER_API_OBJECT(BNDebuggerState, DebuggerState);

BNDebuggerController* BNGetDebuggerController(BinaryNinja::BinaryView* data);
Ref<BinaryView> BNDebuggerGetLiveView(BNDebuggerController* controller);
Ref<Architecture> BNDebuggerGetRemoteArchitecture(BNDebuggerController* controller);
bool