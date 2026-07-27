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
#include <QTableView>
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


// One decoded parameter of an API call. Only `name`/`type`/`kind`/`value` are always
// present; the rest depend on what the Win32 API metadata said about the parameter.
struct TTDApiCallParam
{
	QString name;
	QString type;
	QString kind;
	uint64_t value = 0;
	QString str;           // resolved ANSI/UTF-16 string, if the parameter is one
	QStringList flags;     // symbolic names for enum/flag parameters
	QByteArray bytes;      // captured buffer contents
	uint64_t deref = 0;    // pointed-to value for `int*`-like parameters
	bool hasDeref = false;
	bool out = false;      // [Out] parameter
	bool atReturn = false; // value was re-read at the call's return position
};


// A single Windows API call observed during the trace.
struct TTDApiCall
{
	uint64_t seq = 0;
	uint64_t tid = 0;
	QString position;
	QString module;
	QString api;
	uint64_t ret = 0;
	std::vector<TTDApiCallParam> params;
	bool decoded = false;  // true when a real signature was available for this call
	QString paramSummary;  // precomputed single-line rendering for the table

	// Lowercased "module!api params" that the filter scans. Deliberately a byte
	// string rather than a QString: a trace can hold millions of calls, so this
	// halves the per-call footprint versus UTF-16, and searching 8-bit data is
	// several times faster than a case-insensitive QString comparison.
	std::string searchText;
};


// The set of API calls extracted from one trace, as parsed from an extractor report.
struct TTDBehaviorReport
{
	QString reportPath;
	QString tracePath;
	QString arch;
	QString sampleName;
	uint64_t pid = 0;
	std::vector<TTDApiCall> calls;
	size_t decodedCount = 0;  // counted once at load, not per status update

	bool load(const QString& path, QString& error);
	void clear();
};


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
		ColumnCount
	};

	TTDBehaviorCallModel(QObject* parent);

	void setReport(std::shared_ptr<TTDBehaviorReport> report);

	// Substring filter over the precomputed per-call haystack, applied by rebuilding
	// the visible-row list in one linear pass.
	//
	// This is deliberately not a QSortFilterProxyModel. That class maintains a full
	// bidirectional source/proxy row mapping, and any call to its rowCount() forces
	// the whole mapping to be materialised -- which on a multi-million-call trace
	// costs far more than scanning the haystacks, and made every keystroke look like
	// a freeze.
	void setFilter(const QString& text);

	// Row of the table -> the call it shows, or nullptr when out of range.
	const TTDApiCall* callAt(int row) const;

	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
	void rebuildVisible();

	std::shared_ptr<TTDBehaviorReport> m_report;
	std::string m_filter;             // lowercased, empty means show everything
	std::vector<uint32_t> m_visible;  // indices into m_report->calls; empty when unfiltered
	bool m_filtered = false;          // whether m_visible is in use
};


class TTDBehaviorWidget : public SidebarWidget
{
	Q_OBJECT

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	QLineEdit* m_filterEdit;
	QPushButton* m_loadButton;
	QPushButton* m_extractButton;
	QLabel* m_statusLabel;
	QTableView* m_table;
	QTextEdit* m_detail;

	TTDBehaviorCallModel* m_model;
	std::shared_ptr<TTDBehaviorReport> m_report;
	QProcess* m_extractProcess = nullptr;

	// Filtering waits for a pause in typing rather than running on every keystroke:
	// on a large trace each pass is real work, and eight of them while typing
	// "kernel32" is eight times the work for seven results nobody looks at.
	QTimer* m_filterTimer;

	void setupUI();
	void applyFilter();
	void updateStatus();
	void showDetail(const TTDApiCall* call);
	QString extractorPath(bool prompt);

public:
	TTDBehaviorWidget(BinaryViewRef data);
	~TTDBehaviorWidget();

	void loadReport(const QString& path);

private Q_SLOTS:
	void onLoadClicked();
	void onExtractClicked();
	void onFilterTextEdited();
	void onSelectionChanged();
	void onDoubleClicked(const QModelIndex& index);
	void onContextMenu(const QPoint& pos);
	void copySelectedRows();
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
