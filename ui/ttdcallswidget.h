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
#include <QTextEdit>
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
#include <QFrame>
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


class TTDCallsQueryWidget : public QWidget
{
	Q_OBJECT

public:
	// Enum for logical column identification
	enum LogicalColumn
	{
		IndexColumn = 0,
		EventTypeColumn,
		TimeStartColumn,
		TimeEndColumn,
		FunctionColumn,
		FunctionAddressColumn,
		ReturnAddressColumn,
		ReturnValueColumn,
		ThreadIdColumn,
		UniqueThreadIdColumn,
		ParametersColumn
	};

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	// Input controls
	QLineEdit* m_symbolsEdit;
	QLineEdit* m_startAddressEdit;
	QLineEdit* m_endAddressEdit;
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

	void setupUI();
	void setupTable();
	void updateStatus(const QString& message);
	uint64_t parseAddress(const QString& text);
	void setupContextMenu();
	void setupUIActions();
	void updateColumnVisibility();
	bool canCopy();

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

public:
	TTDCallsQueryWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDCallsQueryWidget();

	// Method to set parameters and execute query from context menu
	void setParametersAndQuery(const std::string& symbols, uint64_t startAddr = 0, uint64_t endAddr = 0);

	// Method to set parameters without executing query (for duplicating tabs)
	void setParameters(const std::string& symbols, uint64_t startAddr = 0, uint64_t endAddr = 0);
	void setParameters(const QString& symbols, const QString& startAddr, const QString& endAddr);

	// Method to check if this tab is unused (no results and default parameters)
	bool isUnused() const;

	// Methods to get current query parameters for duplication
	QString getSymbols() const { return m_symbolsEdit->text(); }
	QString getStartAddress() const { return m_startAddressEdit->text(); }
	QString getEndAddress() const { return m_endAddressEdit->text(); }

private Q_SLOTS:
	void performQuery();
	void clearResults();
	void onCellDoubleClicked(int row, int column);
	void showColumnVisibilityDialog();
	void resetColumnsToDefault();
	void showContextMenu(const QPoint& position);
	void copy();
	void copySelectedCell();
	void copySelectedRow();
	void copyEntireTable();
};

class TTDCallsWidget : public QWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	QTabWidget* m_tabWidget;
	QToolButton* m_newTabButton;

	void setupUI();

public:
	TTDCallsWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDCallsWidget();

	// Method to get current query widget or create new tab
	TTDCallsQueryWidget* getCurrentOrNewQueryWidget();
	void setParametersAndQuery(const std::string& symbols, uint64_t startAddr = 0, uint64_t endAddr = 0);
	void setParametersAndQueryInNewTab(const std::string& symbols, uint64_t startAddr = 0, uint64_t endAddr = 0);

private Q_SLOTS:
	void createNewTab();
	void closeTab(int index);
};


class TTDCallsSidebarWidget : public SidebarWidget
{
	Q_OBJECT

private:
	TTDCallsWidget* m_callsWidget;
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

public:
	TTDCallsSidebarWidget(BinaryViewRef data);
	~TTDCallsSidebarWidget();

	// Method to access the TTD Calls widget for context menu actions
	void setParametersAndQuery(const std::string& symbols, uint64_t startAddr = 0, uint64_t endAddr = 0);
	void setParametersAndQueryInNewTab(const std::string& symbols, uint64_t startAddr = 0, uint64_t endAddr = 0);
};


class TTDCallsWidgetType : public SidebarWidgetType
{
private:
	struct PendingQuery
	{
		std::string symbols;
		uint64_t startAddr;
		uint64_t endAddr;
	};
	static std::map<std::pair<ViewFrame*, BinaryViewRef>, PendingQuery> s_pendingQueries;

public:
	TTDCallsWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;

	// Static method to set pending query parameters
	static void SetPendingQuery(
		ViewFrame* frame, BinaryViewRef data, const std::string& symbols, uint64_t startAddr = 0, uint64_t endAddr = 0);
};