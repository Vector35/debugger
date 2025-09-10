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
#include <QTabWidget>
#include <QDialog>
#include <QListWidget>
#include <QDialogButtonBox>
#include <QMenu>
#include <QAction>
#include <QClipboard>
#include <QPoint>
#include <QToolButton>
#include <QPropertyAnimation>
#include <QParallelAnimationGroup>
#include <QShortcut>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"
#include "expandablegroup.h"
#include "debuggeruicommon.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

class ColumnVisibilityDialog : public QDialog
{
	Q_OBJECT

public:
	ColumnVisibilityDialog(QWidget* parent, const QStringList& columnNames, const QList<bool>& visibility);
	QList<bool> getColumnVisibility() const;

private:
	QListWidget* m_columnList;
};

class TTDMemoryQueryWidget : public QWidget
{
	Q_OBJECT

public:
	// Enum for logical column identification
	enum LogicalColumn {
		IndexColumn = 0,
		EventTypeColumn,
		TimeStartColumn,
		TimeEndColumn,
		AccessTypeColumn,
		AddressColumn,
		SizeColumn,
		ValueColumn,
		ThreadIdColumn,
		UniqueThreadIdColumn,
		IPColumn
	};

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
	
	// Column visibility
	QStringList m_columnNames;
	QList<bool> m_columnVisibility;
	
	void setupUI();
	void setupTable();
	void updateStatus(const QString& message);
	uint64_t parseAddress(const QString& text);
	TTDMemoryAccessType getSelectedAccessTypes();
	void setupContextMenu();
	void updateColumnVisibility();
	
public:
	TTDMemoryQueryWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDMemoryQueryWidget();
	
	// Method to set parameters and execute query from context menu
	void setParametersAndQuery(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType);
	
	// Method to check if this tab is unused (no results and default parameters)
	bool isUnused() const;

private Q_SLOTS:
	void performQuery();
	void clearResults();
	void onCellDoubleClicked(int row, int column);
	void showColumnVisibilityDialog();
	void resetColumnsToDefault();
	void showContextMenu(const QPoint& position);
	void copySelectedCell();
	void copySelectedRow();
	void copyEntireTable();
};

class TTDMemoryWidget : public QWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	QTabWidget* m_tabWidget;
	QToolButton* m_newTabButton;
	
	void setupUI();

public:
	TTDMemoryWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDMemoryWidget();
	
	// Method to get current query widget or create new tab
	TTDMemoryQueryWidget* getCurrentOrNewQueryWidget();
	void setParametersAndQuery(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType);
	void setParametersAndQueryInNewTab(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType);

private Q_SLOTS:
	void createNewTab();
	void closeTab(int index);
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
	
	// Method to access the TTD Memory widget for context menu actions
	void setParametersAndQuery(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType);
	void setParametersAndQueryInNewTab(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType);
};


class TTDMemoryWidgetType : public SidebarWidgetType
{
private:
	struct PendingQuery {
		uint64_t startAddr;
		uint64_t endAddr;
		TTDMemoryAccessType accessType;
	};
	static std::map<std::pair<ViewFrame*, BinaryViewRef>, PendingQuery> s_pendingQueries;

public:
	TTDMemoryWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
	
	// Static method to set pending query parameters
	static void SetPendingQuery(ViewFrame* frame, BinaryViewRef data, uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType);
};