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
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QDialogButtonBox>
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;

class HardwareBreakpointDialog : public QDialog
{
	Q_OBJECT

private:
	DbgRef<DebuggerController> m_controller;
	QLineEdit* m_addressEdit;
	QComboBox* m_typeCombo;
	QComboBox* m_sizeCombo;
	QDialogButtonBox* m_buttonBox;

	uint64_t m_suggestedAddress;

public:
	HardwareBreakpointDialog(QWidget* parent, DbgRef<DebuggerController> controller, uint64_t suggestedAddress = 0);

	uint64_t getAddress() const;
	DebugBreakpointType getType() const;
	size_t getSize() const;

private Q_SLOTS:
	void addBreakpoint();
	void validateInput();
	void typeChanged();
};