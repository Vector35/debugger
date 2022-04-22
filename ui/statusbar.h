/*
Copyright 2020-2022 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

	QWidget* m_parent;
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
