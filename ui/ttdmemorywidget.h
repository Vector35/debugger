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

#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

class TTDMemoryWidget : public QWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	
	// Input controls
	QLineEdit* m_startAddressEdit;
	QLineEdit* m_endAddressEdit;
	QCheckBox* m_readAccessCheck;
	QCheckBox* m_writeAccessCheck;
	QCheckBox* m_executeAccessCheck;
	QPushButton* m_queryButton;
	QPushButton* m_clearButton;
	
	// Results table
	QTableWidget* m_resultsTable;
	
	// Status label
	QLabel* m_statusLabel;
	
	void setupUI();
	void setupTable();
	void updateStatus(const QString& message);
	uint64_t parseAddress(const QString& text);
	TTDMemoryAccessType getSelectedAccessTypes();

public:
	TTDMemoryWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDMemoryWidget();

private Q_SLOTS:
	void performQuery();
	void clearResults();
	void onCellDoubleClicked(int row, int column);
};


class TTDMemorySidebarWidget : public SidebarWidget
{
	Q_OBJECT

private:
	TTDMemoryWidget* m_memoryWidget;
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

public:
	TTDMemorySidebarWidget(BinaryViewRef data);
	~TTDMemorySidebarWidget();
};


class TTDMemoryWidgetType : public SidebarWidgetType
{
public:
	TTDMemoryWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
};