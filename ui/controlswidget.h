/*
Copyright 2020-2024 Vector 35 Inc.

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

#include <QToolBar>
#include <QMenu>
#include <QToolButton>
#include <QIcon>
#include <QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;


class DebugControlsWidget : public QToolBar
{
	Q_OBJECT

private:
	std::string m_name;
	DbgRef<DebuggerController> m_controller;

	QAction* m_actionRun;
	QAction* m_actionAttachPid;
	QAction* m_actionRestart;
	QAction* m_actionQuit;
	QAction* m_actionDetach;
	QAction* m_actionPause;
	QAction* m_actionResume;
	QAction* m_actionGoBack;
	QAction* m_actionStepInto;
	QAction* m_actionStepIntoBack;
	QAction* m_actionStepOver;
	QAction* m_actionStepOverBack;
	QAction* m_actionStepReturn;

	QAction* m_actionSettings;

	bool canExec();
	bool canConnect();

	QIcon getColoredIcon(const QString& iconPath, const QColor& color);
	QString getToolTip(const QString& name);

public:
	DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data);
	virtual ~DebugControlsWidget();

	void setStartingEnabled(bool enabled);
	void setStoppingEnabled(bool enabled);
	void setSteppingEnabled(bool enabled);
	void setReverseSteppingEnabled(bool enabled);

	void updateButtons();

public Q_SLOTS:
	void performLaunch();
	void performAttachPID();
	void performRestart();
	void performQuit();
	void performDetach();

	void performPause();
	void performResume();
	void performGoReverse();
	void performStepInto();
	void performStepIntoReverse();
	void performStepOver();
	void performStepOverReverse();
	void performStepReturn();

	void performSettings();
};
