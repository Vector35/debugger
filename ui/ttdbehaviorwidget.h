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

#include <QAbstractTableModel>
#include <QElapsedTimer>
#include <QFile>
#include <functional>
#include <memory>
#include <QProgressBar>
#include <QTabWidget>
#include <QTableView>
#include <QToolButton>
#include <QTimer>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QMenu>
#include <QPoint>
#include <QProcess>
#include <vector>
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"
#include "debuggeruicommon.h"
#include "uitypes.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;


// The report reader and its query engine live in core (core/ttdbehavior.h), reachable
// here through the debugger API. That is what lets the same queries run from Python;
// this widget is now just a view over them.
//
// Rows are decoded from the mapped file on demand rather than held as objects, so the
// model asks the report for a row when it needs to paint one.
using TTDApiCall = BinaryNinjaDebuggerAPI::TTDApiCall;
using TTDApiCallParam = BinaryNinjaDebuggerAPI::TTDApiCallParam;
using TTDBehaviorReport = BinaryNinjaDebuggerAPI::TTDBehaviorReport;


class TTDBehaviorCallModel : public QAbstractTableModel
{
	Q_OBJECT

public:
	enum Column
	{
		SeqColumn = 0,
		PositionColumn,
		ThreadColumn,
		ModuleColumn,
		ApiColumn,
		ParametersColumn,
		ReturnColumn,
		ReturnAddressColumn,
		ColumnCount
	};

	TTDBehaviorCallModel(QObject* parent);

	void setReport(std::shared_ptr<TTDBehaviorReport> report);

	// Runs `text` as a query against the report and keeps the rows it matched.
	//
	// Deliberately not a QSortFilterProxyModel: that class maintains a bidirectional
	// source/proxy row mapping, and any call to its rowCount() materialises the whole
	// thing, which on a multi-million-call report made every keystroke look like a
	// freeze. The core returns the matching indices in one call instead.
	void setFilter(const QString& text);

	// Row of the table -> the call it shows, or nullptr when out of range. Decoded into a
	// single-row cache, so asking for the same row repeatedly (as data() does, once per
	// column) costs one decode. `withParams` is only needed by the detail pane.
	const TTDApiCall* callAt(int row, bool withParams = false) const;

	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
	void rebuildVisible();

	std::shared_ptr<TTDBehaviorReport> m_report;
	QString m_filterText;             // as typed, so a repeat of the same text is a no-op
	std::vector<uint64_t> m_visible;  // source indices; empty when unfiltered
	bool m_filtered = false;          // whether m_visible is in use

	mutable TTDApiCall m_cached;
	mutable size_t m_cachedIndex = static_cast<size_t>(-1);
	mutable bool m_cachedHasParams = false;
};


// One query over the loaded report: a filter, the rows it matches, and the detail pane
// for whichever of them is selected. Tabs of these share a single report, since the
// point of having several is to ask different questions of the same trace without
// paying to load it again.
class TTDBehaviorQueryWidget : public QWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	QLineEdit* m_filterEdit;
	QLabel* m_statusLabel;
	QTableView* m_table;
	QTextEdit* m_detail;

	TTDBehaviorCallModel* m_model;
	std::shared_ptr<TTDBehaviorReport> m_report;
	QString m_reportPath;  // the core report holds no display name of its own

	// Set by the container, which is what knows them; shown in this tab's status line.
	double m_writeSeconds = 0.0;
	double m_loadSeconds = -1.0;

	// Filtering waits for a pause in typing rather than running on every keystroke:
	// on a large trace each pass is real work, and eight of them while typing
	// "kernel32" is eight times the work for seven results nobody looks at.
	QTimer* m_filterTimer;

	void setupUI();
	void showDetail(const TTDApiCall* call);

public:
	TTDBehaviorQueryWidget(QWidget* parent, BinaryViewRef data);

	// Point this tab at a report. Cheap: the model only takes a reference to it.
	void setReport(std::shared_ptr<TTDBehaviorReport> report, const QString& path);

	QString filterText() const;
	void setFilterText(const QString& text);

	// Appended to the status line by the container, which is what knows them.
	void setTimings(double writeSeconds, double loadSeconds);
	void updateStatus();

Q_SIGNALS:
	// So the container can label the tab after whatever the tab is asking.
	void filterApplied(const QString& text);

private Q_SLOTS:
	void applyFilter();
	void onFilterTextEdited();
	void onSelectionChanged();
	void onDoubleClicked(const QModelIndex& index);
	void onContextMenu(const QPoint& pos);
	void copySelectedRows();
};


// Holds the report and the things that act on it as a whole -- loading, extracting,
// progress -- above a tab bar of queries.
class TTDBehaviorWidget : public SidebarWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	QPushButton* m_loadButton;
	QPushButton* m_extractButton;
	QTabWidget* m_tabWidget;
	QToolButton* m_newTabButton;

	// Shown only while an extraction or a report load is in flight.
	QWidget* m_progressRow;
	QProgressBar* m_progressBar;
	QLabel* m_progressLabel;
	QPushButton* m_cancelButton;
	QElapsedTimer m_operationTimer;
	QByteArray m_stderrTail;  // partial line left over between readyRead signals

	// Reported in each tab's status line: serialising and loading a report are the two
	// costs most worth seeing, since they dominated the wall clock before the binary
	// format.
	double m_lastWriteSeconds = 0.0;
	double m_lastLoadSeconds = -1.0;

	std::shared_ptr<TTDBehaviorReport> m_report;
	QString m_reportPath;
	QProcess* m_extractProcess = nullptr;

	void setupUI();
	QString extractorPath(bool prompt);

	void beginOperation(const QString& what, bool cancellable);
	void endOperation();
	void setProgress(double percent, const QString& detail);
	void consumeExtractorStderr();

	TTDBehaviorQueryWidget* currentQuery() const;

public:
	TTDBehaviorWidget(BinaryViewRef data);
	~TTDBehaviorWidget();

	// Parses `path` on a worker thread -- a multi-hundred-MB report takes long enough
	// that doing it inline freezes the UI -- and installs it when finished.
	void loadReport(const QString& path);

	// Swap in a parsed report and hand it to every tab. Must run on the UI thread.
	void installReport(std::shared_ptr<TTDBehaviorReport> report, const QString& path);

private Q_SLOTS:
	void onLoadClicked();
	void onExtractClicked();
	void onCancelClicked();
	void createNewTab();
	void closeTab(int index);
};


class TTDBehaviorWidgetType : public SidebarWidgetType
{
public:
	TTDBehaviorWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return AlwaysShowSidebarIcon; }
};
