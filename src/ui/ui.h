#pragma once

#include <QtWidgets/QToolBar>
#include <QtWidgets/QMenu>
#include <QtWidgets/QToolButton>
#include <QtGui/QIcon>
#include <QtWidgets/QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "../debuggercontroller.h"
#include "debuggerwidget.h"

class DebuggerController;

class DebuggerWidget;
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

signals:
    void contextChanged();
	void debuggerEvent(const DebuggerEvent& event);

private slots:
	void updateStatusText(const DebuggerEvent& event);
	void updateUI(const DebuggerEvent& event);
};
