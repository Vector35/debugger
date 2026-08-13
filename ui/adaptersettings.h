/*
Copyright 2020-2026 Vector 35 Inc.

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

#include <QDialog>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QFormLayout>
#include <QCheckBox>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "debuggerapi.h"
#include "settingsview.h"

using namespace BinaryNinjaDebuggerAPI;

class AdapterSettingsDialog : public QDialog
{
	Q_OBJECT

private:
	DbgRef<DebuggerController> m_controller;
	QComboBox* m_adapterEntry;
	SettingsView* m_settingsView;
	QStackedWidget* m_stack;
	QMap<QString, QWidget*> m_viewMap;
	QLabel* m_noSettingsLabel;
	QCheckBox* m_useSameSettingsCheckbox = nullptr;
	std::string m_highlightGroup;

	QWidget* getWidgetForAdapter(const QString& adapter);
	bool validateSettings();

public:
	AdapterSettingsDialog(QWidget* parent, DbgRef<DebuggerController> controller, const std::string& highlightGroup = "");

private Q_SLOTS:
	void selectAdapter(const QString& adapter);
	void apply();
};
