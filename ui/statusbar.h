#pragma once

#include <QtWidgets/QComboBox>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "debuggerapi.h"


class DebuggerStatusBarWidget: public QWidget
{
Q_OBJECT

	ViewFrame* m_view;
	Ref<BinaryNinjaDebuggerAPI::DebuggerController> m_debugger;
	QLabel* m_status;

	size_t m_debuggerEventCallback;

	void setStatusText(const QString& text);

public:
	DebuggerStatusBarWidget(QWidget* parent, ViewFrame* view, BinaryViewRef debugger);
	~DebuggerStatusBarWidget();

	void notifyFontChanged();

signals:
	void debuggerEvent(const BinaryNinjaDebuggerAPI::DebuggerEvent& event);

private slots:
	void updateStatusText(const BinaryNinjaDebuggerAPI::DebuggerEvent& event);
};

class DebuggerStatusBarContainer : public QWidget
{
	ViewFrame *m_currentFrame;
	std::map<Ref<BinaryNinjaDebuggerAPI::DebuggerController>, DebuggerStatusBarWidget*> m_consoleMap;

	QStackedWidget* m_consoleStack;

	//! Get the current active DebuggerConsole. Returns nullptr in the event of an error
	//! or if there is no active ChatBox.
	DebuggerStatusBarWidget* currentConsole() const;

	//! Delete the DebuggerConsole for the given view.
	void freeDebuggerConsoleForView(QObject*);

public:
	DebuggerStatusBarContainer();

	//! Send text to the actively-focused ChatBox. If there is no active ChatBox,
	//! no action will be taken.
	void sendText(const QString& msg) const;

	void notifyViewChanged(ViewFrame *);
};
