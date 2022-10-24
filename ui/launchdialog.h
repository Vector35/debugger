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

#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "uitypes.h"
#include "QDialog"
#include "QLabel"

enum DebuggerLaunchOperation
{
	LaunchOperation,
	AttachOperation,
	ConnectOperation,
	ConnectToDebugServerOperation
};


class DebuggerLaunchDialog: public QDialog
{
	Q_OBJECT

private:
	DebuggerControllerRef m_controller;
	size_t m_callbackIndex = -1;
	QLabel* m_text;

public:
	DebuggerLaunchDialog(QWidget* parent, DebuggerControllerRef controller,
						 const enum DebuggerLaunchOperation operation = LaunchOperation);
	~DebuggerLaunchDialog();
};
