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
#include <QContextMenuEvent>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"
#include "expandablegroup.h"
#include "debuggeruicommon.h"
#include "menus.h"
#include "uitypes.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

class TTDHeapQueryWidget : public QWidget
{
	Q_OBJECT

public:
	// Enum for logical column identification
	enum LogicalColumn {
		IndexColumn = 0,
		EventTypeColumn,
		ActionColumn,
		TimeStartColumn,
		TimeEndColumn,
		HeapColumn,
		AddressColumn,
		PreviousAddressColumn,
		SizeColumn,
		BaseAddressColumn,
		FlagsColumn,
		ResultColumn,
		ReserveSizeColumn,
		CommitSizeColumn,
		MakeReadOnlyColumn,
		ThreadIdColumn,
		UniqueThreadIdColumn,
		ParametersColumn
	};

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	
	// Input controls
	QPushButton* m_queryButton;
	QPushButton* m_clearButton;
	
	// Results table
	QTableWidget* m_resultsTable;
	
	// Status label
	QLabel* m_statusLabel;
	
	// Column visibility
	QStringList m_columnNames;
	QList<bool> m_columnVisibility;
	
	// UIAction support
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;
	
	// Event callback
	size_t m_debuggerEventCallback;
	bool m_hasPopulatedData;
	
	void setupUI();
	void setupTable();
	void updateStatus(const QString& message);
	void setupContextMenu();
	void setupUIActions();
	void updateColumnVisibility();
	bool canCopy();
	
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	
public:
	TTDHeapQueryWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDHeapQueryWidget();
	
	// Method to execute query from context menu
	void performQuery();
	
	// Method to check if this tab is unused (no results and default parameters)
	bool isUnused() const;

Q_SIGNALS:
	void debuggerEvent(const DebuggerEvent& event);

private Q_SLOTS:
	void clearResults();
	void onCellDoubleClicked(int row, int column);
	void showColumnVisibilityDialog();
	void resetColumnsToDefault();
	void showContextMenu(const QPoint& position);
	void copy();
	void copySelectedCell();
	void copySelectedRow();
	void copyEntireTable();
	void onDebuggerEvent(const DebuggerEvent& event);
};

class TTDHeapWidget : public QWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	QTabWidget* m_tabWidget;
	QToolButton* m_newTabButton;
	
	void setupUI();

public:
	TTDHeapWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDHeapWidget();
	
	// Method to get current query widget or create new tab
	TTDHeapQueryWidget* getCurrentOrNewQueryWidget();
	void performQuery();
	void performQueryInNewTab();

private Q_SLOTS:
	void createNewTab();
	void closeTab(int index);
};


class TTDHeapSidebarWidget : public SidebarWidget
{
	Q_OBJECT

private:
	TTDHeapWidget* m_heapWidget;
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

public:
	TTDHeapSidebarWidget(BinaryViewRef data);
	~TTDHeapSidebarWidget();
	
	// Method to access the TTD Heap widget for context menu actions
	void performQuery();
	void performQueryInNewTab();
};


class TTDHeapWidgetType : public SidebarWidgetType
{
public:
	TTDHeapWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
};