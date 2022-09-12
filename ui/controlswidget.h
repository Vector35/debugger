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

#include <QToolBar>
#include <QMenu>
#include <QToolButton>
#include <QIcon>
#include <QLineEdit>
#include "binaryninjaapi.h"
#include "uicontext.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;


class DebugControlsWidget: public QToolBar
{
    Q_OBJECT

private:
    std::string m_name;
    DbgRef<DebuggerController> m_controller;

	QAction* m_actionRun;
	QAction* m_actionAttachPid;
    QAction* m_actionRestart;
    QAction* m_actionQuit;
    QAction* m_actionConnect;
    QAction* m_actionDetach;
	QAction* m_actionPause;
    QAction* m_actionResume;
    QAction* m_actionStepInto;
    QAction* m_actionStepOver;
    QAction* m_actionStepReturn;

    bool canExec();
    bool canConnect();

	QIcon getColoredIcon(const QString& iconPath, const QColor& color);

public:
    DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data);
    virtual ~DebugControlsWidget();

    void setStepIntoEnabled(bool enabled);
    void setStepOverEnabled(bool enabled);
    void setStartingEnabled(bool enabled);
    void setStoppingEnabled(bool enabled);
    void setSteppingEnabled(bool enabled);

	void updateButtons();

public Q_SLOTS:
	void performLaunch();
	void performAttachPID();
    void performRestart();
    void performQuit();
    void performConnect();
    void performDetach();

	void performPause();
    void performResume();
    void performStepInto();
    void performStepOver();
    void performStepReturn();
};
