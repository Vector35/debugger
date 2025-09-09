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
#include <QGroupBox>
#include <QSplitter>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

class TTDCallsSidebarWidget : public SidebarWidget
{
	Q_OBJECT

public:
	TTDCallsSidebarWidget(QWidget* parent, BinaryViewRef data);

private:
	TTDCallsWidget* m_widget;
	BinaryViewRef m_data;
};

class TTDCallsWidget : public QWidget
{
	Q_OBJECT

public:
	TTDCallsWidget(QWidget* parent, BinaryViewRef data);

private slots:
	void onQueryButtonClicked();
	void onClearButtonClicked();
	void onExportButtonClicked();
	void onResultsTableContextMenu(const QPoint& pos);
	void onResultsTableItemDoubleClicked(int row, int column);
	void onAddressRangeToggled(bool enabled);

private:
	void setupUI();
	void populateResults(const std::vector<TTDCallEvent>& events);
	void clearResults();
	void exportResults();
	void copySelectedToClipboard();
	void navigateToAddress(uint64_t address);
	std::vector<std::string> parseSymbolsInput(const QString& input);
	bool parseAddressRange(const QString& input, uint64_t& minAddr, uint64_t& maxAddr);

	BinaryViewRef m_data;
	QVBoxLayout* m_layout;
	
	// Query controls
	QGroupBox* m_queryGroup;
	QLineEdit* m_symbolsEdit;
	QCheckBox* m_addressRangeCheck;
	QLineEdit* m_addressRangeEdit;
	QPushButton* m_queryButton;
	QPushButton* m_clearButton;
	QPushButton* m_exportButton;
	
	// Results table
	QTableWidget* m_resultsTable;
	QLabel* m_statusLabel;
	
	// Context menu actions
	QAction* m_copyAction;
	QAction* m_goToFunctionAction;
	QAction* m_goToReturnAction;
	QAction* m_setPositionAction;

	enum ColumnIndex {
		IndexColumn = 0,
		ThreadIdColumn = 1,
		UniqueThreadIdColumn = 2,
		FunctionColumn = 3,
		FunctionAddressColumn = 4,
		ReturnAddressColumn = 5,
		ReturnValueColumn = 6,
		TimeStartColumn = 7,
		TimeEndColumn = 8,
		ParametersColumn = 9
	};
};

class TTDCallsWidgetType : public SidebarWidgetType
{
public:
	TTDCallsWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
};