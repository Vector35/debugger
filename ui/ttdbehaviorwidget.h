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
	QByteArray bytes;      // captured buffer contents, possibly only a prefix
	uint64_t bytesTotal = 0;  // the buffer's real length when `bytes` was capped, else 0
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
	// Where the call returns to: the instruction after the CALL, so it names the call
	// site and therefore which module made the call.
	uint64_t returnAddress = 0;
	std::vector<TTDApiCallParam> params;
	bool decoded = false;  // true when a real signature was available for this call
	QString paramSummary;  // single-line rendering for the table

	// Lowercased "module!api params" that the filter scans. Deliberately a byte
	// string rather than a QString: a trace can hold millions of calls, so this
	// halves the per-call footprint versus UTF-16, and searching 8-bit data is
	// several times faster than a case-insensitive QString comparison.
	//
	// Only populated by the JSON backend. The binary one keeps the equivalent text in
	// the mapped file and matches against it there, so nothing is built per call.
	std::string searchText;
};


// A parsed filter expression.
//
// Whitespace-separated terms, ANDed together. A bare word (or "quoted phrase") is a
// substring match over everything searchable about a call; `field:value` narrows to one
// field. That keeps what people already type working, while giving them a way to say
// which WriteFile they meant.
//
//   module:kernel32 api:WriteFile        only kernel32's, not ntdll's
//   api:Reg* ret:!0                      registry calls that failed
//   retaddr:0x400000-0x500000            calls made from the sample itself
//   password                             anything mentioning it, buffers included
//
// module/api resolve against the report's deduplicated string table once per query, so
// evaluating them per row is an integer compare rather than a string search.
class TTDBehaviorQuery
{
public:
	// Comparison against one of the call's numeric fields.
	struct Numeric
	{
		enum Op { Equal, NotEqual, Greater, GreaterEqual, Less, LessEqual, Range };
		Op op = Equal;
		uint64_t a = 0;
		uint64_t b = 0;
		bool test(uint64_t value) const;
	};

	enum class Field { Text, Module, Api, Tid, Ret, RetAddr };

	struct Term
	{
		Field field = Field::Text;
		std::string text;      // lowercased, for Text/Module/Api
		bool prefix = false;   // the term ended in '*'
		Numeric numeric;       // for Tid/Ret/RetAddr
		std::vector<uint32_t> stringOffsets;  // resolved module/api matches
		bool resolved = false;
	};

	// Never fails: anything that does not look like a field term is treated as text, so
	// a half-typed query still does something sensible rather than erroring.
	void parse(const QString& text);
	bool isEmpty() const { return m_terms.empty(); }
	bool hasFieldTerms() const;

	// Bind module/api terms to the report's string table. Call once per report per query.
	void resolve(const class TTDBehaviorReport& report);

	const std::vector<Term>& terms() const { return m_terms; }

private:
	std::vector<Term> m_terms;
};


// The set of API calls extracted from one trace.
//
// Two backends. The binary one memory-maps the extractor's compact format and decodes
// records straight out of the mapping when a row is asked for -- there is no per-call
// object, so opening a 3.4M-call report costs a header validation instead of the ~17s
// (and ~1.4GB) that parsing the JSON equivalent did. The JSON one is kept because
// reports already on disk are in that format, and because it is what capa consumes.
class TTDBehaviorReport
{
public:
	QString reportPath;
	QString tracePath;
	QString arch;
	QString sampleName;
	uint64_t pid = 0;
	size_t decodedCount = 0;  // counted once at load, not per status update

	// Widest content in the two narrow columns, so they can be sized to fit exactly.
	// QTableView::resizeColumnsToContents() only samples the first 1000 rows, which on a
	// multi-million-call trace sizes "#" for three digits and Position for its shortest
	// early values, then clips everything after.
	uint64_t maxSeq = 0;
	int maxPositionChars = 0;

	// Dispatches on the file's magic, so the caller does not care which format it has.
	bool load(const QString& path, QString& error);
	void clear();

	size_t callCount() const;

	// Decode one call. `withParams` is the expensive half, so the table omits it and only
	// the detail pane asks for it.
	void fillCall(size_t index, TTDApiCall& out, bool withParams) const;

	// Does this call satisfy every term of `query`?
	bool matches(size_t index, const TTDBehaviorQuery& query) const;

	// Every distinct string in the table, for a query to resolve module/api terms
	// against. Empty for the JSON backend, which compares per row instead.
	void forEachString(const std::function<void(uint32_t, const char*, size_t)>& fn) const;
	bool isMapped() const { return m_map != nullptr; }

private:
	bool loadJson(const QString& path, QString& error);
	bool loadBinary(const QString& path, QString& error);
	const uint8_t* callRecord(size_t index) const;
	QString mappedString(uint32_t offset) const;

	// JSON backend: everything materialised up front.
	std::vector<TTDApiCall> m_calls;

	// Binary backend: the mapping plus the header's region offsets.
	std::unique_ptr<QFile> m_file;
	const uint8_t* m_map = nullptr;
	qint64 m_mapSize = 0;
	uint64_t m_callCount = 0;
	uint64_t m_callsOff = 0;
	uint64_t m_paramsOff = 0;
	uint64_t m_stringsOff = 0;
	uint64_t m_stringsSize = 0;
	uint64_t m_blobOff = 0;
	uint64_t m_blobSize = 0;
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
		ReturnAddressColumn,
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
	const TTDBehaviorQuery& query() const { return m_query; }

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
	TTDBehaviorQuery m_query;
	std::vector<uint32_t> m_visible;  // source indices; empty when unfiltered
	bool m_filtered = false;          // whether m_visible is in use

	mutable TTDApiCall m_cached;
	mutable size_t m_cachedIndex = static_cast<size_t>(-1);
	mutable bool m_cachedHasParams = false;
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

	// Shown only while an extraction or a report load is in flight.
	QWidget* m_progressRow;
	QProgressBar* m_progressBar;
	QLabel* m_progressLabel;
	QPushButton* m_cancelButton;
	QElapsedTimer m_operationTimer;
	QByteArray m_stderrTail;  // partial line left over between readyRead signals

	// Reported in the status line: serialising and loading a report are the two costs
	// most worth seeing, since they dominated the wall clock before the binary format.
	double m_lastWriteSeconds = 0.0;
	double m_lastLoadSeconds = -1.0;

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

	void beginOperation(const QString& what, bool cancellable);
	void endOperation();
	void setProgress(double percent, const QString& detail);
	void consumeExtractorStderr();

public:
	TTDBehaviorWidget(BinaryViewRef data);
	~TTDBehaviorWidget();

	// Parses `path` on a worker thread -- a multi-hundred-MB report takes long enough
	// that doing it inline freezes the UI -- and installs it when finished.
	void loadReport(const QString& path);

	// Swap in a parsed report and refresh the view. Must run on the UI thread.
	void installReport(std::shared_ptr<TTDBehaviorReport> report);

private Q_SLOTS:
	void onLoadClicked();
	void onExtractClicked();
	void onCancelClicked();
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
