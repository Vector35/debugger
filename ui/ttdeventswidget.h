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
#include <QContextMenuEvent>
#include <QComboBox>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"
#include "expandablegroup.h"
#include "debuggeruicommon.h"
#include "menus.h"
#include "uitypes.h"
#include <vector>

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

class TTDEventsColumnVisibilityDialog : public QDialog
{
	Q_OBJECT

public:
	TTDEventsColumnVisibilityDialog(QWidget* parent, const QStringList& columnNames, const QList<bool>& visibility);
	QList<bool> getColumnVisibility() const;

private:
	QListWidget* m_columnList;
};

class TTDEventsQueryWidget : public QWidget
{
	Q_OBJECT

public:
	// Enum for widget specialization
	enum WidgetType {
		AllEvents,     // Shows all events with filtering checkboxes
		ModuleEvents,  // Shows only module events with relevant columns
		ThreadEvents,  // Shows only thread events with relevant columns  
		ExceptionEvents // Shows only exception events with relevant columns
	};

	// Enum for logical column identification
	enum LogicalColumn {
		IndexColumn = 0,
		EventTypeColumn,
		PositionColumn,
		ThreadIdColumn,
		ThreadUniqueIdColumn,
		ModuleNameColumn,
		ModuleAddressColumn,
		ModuleSizeColumn,
		ExceptionTypeColumn,
		ExceptionCodeColumn,
		ExceptionPCColumn
	};

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	WidgetType m_widgetType;  // Determines specialization mode
	
	// Input controls - checkboxes for filtering
	QCheckBox* m_threadCreatedCheck;
	QCheckBox* m_threadTerminatedCheck;
	QCheckBox* m_moduleLoadedCheck;
	QCheckBox* m_moduleUnloadedCheck;
	QCheckBox* m_exceptionCheck;
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
	
	// All events cache
	std::vector<TTDEvent> m_allEvents;
	
	void setupUI();
	void setupTable();
	void updateStatus(const QString& message);
	void setupContextMenu();
	void setupUIActions();
	void updateColumnVisibility();
	bool canCopy();
	void filterAndDisplayEvents();
	void filterAndDisplaySpecializedEvents(); // For specialized widget types
	
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	
public:
	TTDEventsQueryWidget(QWidget* parent, BinaryViewRef data, WidgetType type = AllEvents);
	virtual ~TTDEventsQueryWidget();
	
	// Method to execute query and show all events
	void performInitialQuery();
	
	// Method to check if this tab is unused (no results)
	bool isUnused() const;

public Q_SLOTS:
	void clearResults();

private Q_SLOTS:
	void performQuery();
	void onCellDoubleClicked(int row, int column);
	void showColumnVisibilityDialog();
	void resetColumnsToDefault();
	void showContextMenu(const QPoint& position);
	void copy();
	void copySelectedCell();
	void copySelectedRow();
	void copyEntireTable();
	void onFilterChanged();
	void refreshEvents();  // Clear and re-query events from backend
};

class TTDEventsWidget : public QWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	QTabWidget* m_tabWidget;
	QToolButton* m_newTabButton;
	TTDEventsQueryWidget *m_moduleEventsWidget, *m_threadEventsWidget, *m_exceptionEventsWidget;
	bool m_isPopulated;
	
	void setupUI();
	void loadAllEvents();

public:
	TTDEventsWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDEventsWidget();
	
	// Method to get current query widget or create new tab
	TTDEventsQueryWidget* getCurrentOrNewQueryWidget();
	
	// Methods for event handling
	void refreshAllTabs();
	void clearAllTabs();

private slots:
	void createNewTab();
	void closeTab(int index);
};


class TTDEventsSidebarWidget : public SidebarWidget
{
	Q_OBJECT

private:
	TTDEventsWidget* m_eventsWidget;
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	size_t m_debuggerEventCallback;

public:
	TTDEventsSidebarWidget(BinaryViewRef data);
	~TTDEventsSidebarWidget();

signals:
	void debuggerEvent(const DebuggerEvent& event);

private slots:
	void onDebuggerEvent(const DebuggerEvent& event);
};


class TTDEventsWidgetType : public SidebarWidgetType
{
public:
	TTDEventsWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
};