#pragma once

#include "inttypes.h"
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "../debuggerstate.h"
#include "../debuggercontroller.h"

class DebuggerStatusBar: public QLabel
{
	Q_OBJECT;

	DebuggerController* m_controller;
	size_t m_eventCallback;

public:
	DebuggerStatusBar(DebuggerController* controller);
	~DebuggerStatusBar();

	void updateText(QString text);
	void uiEventHandler(const DebuggerEvent& event);
};
