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

#include <QWidget>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QThread>
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"
#include "menus.h"
#include "uitypes.h"
#include "ttdbehavior.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

// Worker thread for running analysis
class TTDBehaviorAnalysisWorker : public QThread
{
	Q_OBJECT

public:
	TTDBehaviorAnalysisWorker(DbgRef<DebuggerController> controller, const TTDBehaviorAnalysisSet& analysisSet, QObject* parent = nullptr);

protected:
	void run() override;

signals:
	void analysisProgress(int percentage, const QString& message);
	void analysisCompleted(bool success, const QString& message, const TTDBehaviorAnalysisResult& result);

private:
	DbgRef<DebuggerController> m_controller;
	TTDBehaviorAnalysisSet m_analysisSet;
};


class TTDBehaviorResultWidget : public QWidget
{
	Q_OBJECT

public:
	TTDBehaviorResultWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDBehaviorResultWidget();

	void setResults(const TTDBehaviorAnalysisResult& result);
	void clearResults();

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	QTableWidget* m_resultsTable;
	QLabel* m_statusLabel;

	// Column definitions for each category
	struct ColumnDef
	{
		QString name;
		int width;
	};
	std::vector<ColumnDef> m_columns;

	TTDBehaviorAnalysisResult m_currentResult;

	void setupUI();
	void setupTable();
	void setupContextMenu();
	void updateColumnHeaders();

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

private Q_SLOTS:
	void onCellDoubleClicked(int row, int column);
	void copySelectedCell();
	void copySelectedRow();
	void copyEntireTable();
};


class TTDBehaviorWidget : public QWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	// Controls
	QComboBox* m_analysisSetCombo;
	QPushButton* m_analyzeButton;
	QProgressBar* m_progressBar;
	QLabel* m_statusLabel;

	// Results
	TTDBehaviorResultWidget* m_resultWidget;

	// Analysis sets
	std::vector<TTDBehaviorAnalysisSet> m_analysisSets;

	// Worker thread
	TTDBehaviorAnalysisWorker* m_worker;

	void setupUI();
	void loadAnalysisSets();

public:
	TTDBehaviorWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDBehaviorWidget();

private Q_SLOTS:
	void runAnalysis();
	void onAnalysisProgress(int percentage, const QString& message);
	void onAnalysisCompleted(bool success, const QString& message, const TTDBehaviorAnalysisResult& result);
};


class TTDBehaviorSidebarWidget : public SidebarWidget
{
	Q_OBJECT

private:
	TTDBehaviorWidget* m_behaviorWidget;
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

public:
	TTDBehaviorSidebarWidget(BinaryViewRef data);
	~TTDBehaviorSidebarWidget();
};


class TTDBehaviorWidgetType : public SidebarWidgetType
{
public:
	TTDBehaviorWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
};
