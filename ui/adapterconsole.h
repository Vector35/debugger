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

#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "globalarea.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "debuggerapi.h"


class AdapterConsole: public QWidget
{
	Q_OBJECT

	ViewFrame* m_view;
	Ref<BinaryNinjaDebuggerAPI::DebuggerController> m_debugger;

	QLineEdit* m_consoleInput;
	QTextEdit* m_consoleLog;
	QString m_prompt;

	size_t m_debuggerEventCallback;

	void addMessage(const QString& msg);
	void sendMessage();

public:
	AdapterConsole(QWidget* parent, ViewFrame* view, BinaryViewRef debugger);
	~AdapterConsole();

	void sendText(const QString& msg);

	void notifyFontChanged();
};

class GlobalAdapterConsoleContainer : public GlobalAreaWidget
{
	ViewFrame *m_currentFrame;
	std::map<Ref<BinaryNinjaDebuggerAPI::DebuggerController>, AdapterConsole*> m_consoleMap;

	QStackedWidget* m_consoleStack;

	//! Get the current active AdapterConsole. Returns nullptr in the event of an error
	//! or if there is no active ChatBox.
	AdapterConsole* currentConsole() const;

	//! Delete the AdapterConsole for the given view.
	void freeDebuggerConsoleForView(QObject*);

public:
	GlobalAdapterConsoleContainer(const QString& title);

	//! Send text to the actively-focused ChatBox. If there is no active ChatBox,
	//! no action will be taken.
	void sendText(const QString& msg) const;

	void notifyViewChanged(ViewFrame *) override;
};
