/*
Copyright 2020-2025 Vector 35 Inc.

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
#include <QRadioButton>
#include <QButtonGroup>
#include <QGroupBox>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;

// Forward declare the attach process dialog
class AttachProcessDialog;

class TTDRecordDialog : public QDialog
{
	Q_OBJECT

private:
	DbgRef<DebuggerController> m_controller = nullptr;
	QLineEdit* m_pathEntry;
	QLineEdit* m_workingDirectoryEntry;
	QLineEdit* m_argumentsEntry;
	QLineEdit* m_outputDirectory;
	QCheckBox* m_launchWithoutTracing;
	
	// New UI elements for attach mode
	QRadioButton* m_launchModeRadio;
	QRadioButton* m_attachModeRadio;
	QButtonGroup* m_modeButtonGroup;
	QGroupBox* m_launchGroup;
	QGroupBox* m_attachGroup;
	QPushButton* m_selectProcessButton;
	QLineEdit* m_selectedProcessDisplay;
	uint32_t m_selectedPid;

public:
	TTDRecordDialog(QWidget* parent, BinaryView* data);
	void DoTTDTrace();
	std::string GetTTDRecorderPath();

private Q_SLOTS:
	void apply();
	void onModeChanged();
	void selectProcess();
};
