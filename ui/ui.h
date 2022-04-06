#pragma once

#include <QToolBar>
#include <QMenu>
#include <QToolButton>
#include <QIcon>
#include <QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "debuggerwidget.h"
#include "debuggerapi.h"


class DebuggerUI: public QObject
{
    Q_OBJECT

private:
	UIContext* m_context;
    DebuggerController* m_controller;
	QMainWindow* m_window;
	QLabel* m_status;

	size_t m_eventCallback;

public:
    DebuggerUI(UIContext* context, DebuggerController* controller);
	~DebuggerUI();

    static void InitializeUI();

	static DebuggerUI* CreateForViewFrame(ViewFrame* frame);
	static DebuggerUI* GetForViewFrame(ViewFrame* frame);
	static void RemoveForContext(UIContext* context);

	void setStatusText(const QString& text);

	TagTypeRef getPCTagType(BinaryViewRef data);
	TagTypeRef getBreakpointTagType(BinaryViewRef data);

	void navigateDebugger(uint64_t address);

signals:
    void contextChanged();
	void debuggerEvent(const DebuggerEvent& event);

private slots:
	void updateStatusText(const DebuggerEvent& event);
	void updateUI(const DebuggerEvent& event);
};
