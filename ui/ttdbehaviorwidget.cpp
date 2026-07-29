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

// Shows the Windows API calls a TTD trace made, with their parameters decoded against
// Microsoft's Win32 API metadata: real arity, resolved strings, symbolic flag names,
// captured buffers, and [Out] parameters re-read at the call's return position.
//
// The sweep itself is done out-of-process by an extractor built on the TTD replay SDK
// (https://github.com/HullaBrian/ttd-capa), which writes a JSON report this widget
// parses. Extraction takes seconds even on large traces, so it is not on the critical
// path of a debug session.

#include "ttdbehaviorwidget.h"

#include <QApplication>
#include <QClipboard>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCoreApplication>
#include <QMessageBox>
#include <QPointer>
#include <algorithm>
#include <cmath>
#include <thread>
#include "fontsettings.h"
#include "theme.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

// Settings key holding the path of the extractor executable. Registered by
// GlobalDebuggerUI::InitializeUI().
static const char* kExtractorSetting = "debugger.ttdBehaviorExtractorPath";

// Values wider than a table cell can usefully show get elided here rather than in the
// view, so the copied text matches what is on screen.
static const int kMaxStringDisplay = 96;
static const int kMaxBytesDisplay = 32;

// The extractor captures up to 64 KiB per buffer, which is 4096 lines of hex dump --
// more than the detail pane can usefully show or lay out quickly. Clip the rendering,
// not the data: the full bytes stay in the report.
static const int kMaxHexDumpBytes = 4096;


namespace {
	// QJsonValue stores anything that does not fit in a qint64 as a double, so pointer-sized
	// sentinels such as 0xFFFFFFFFFFFFFFFE arrive rounded. Clamp instead of letting the
	// conversion be undefined.
	uint64_t jsonToUInt64(const QJsonValue& value)
	{
		if (value.isDouble())
		{
			double d = value.toDouble();
			qint64 i = value.toInteger(0);
			if (static_cast<double>(i) == d)
				return static_cast<uint64_t>(i);
			if (!std::isfinite(d) || d <= 0.0)
				return 0;
			if (d >= 18446744073709551616.0)
				return UINT64_MAX;
			return static_cast<uint64_t>(d);
		}
		return 0;
	}


	QString formatHex(uint64_t value)
	{
		return QString("0x%1").arg(value, 0, 16);
	}


	QString escapeString(const QString& str)
	{
		QString out;
		out.reserve(str.size());
		for (QChar c : str)
		{
			if (c == '\\')
				out += "\\\\";
			else if (c == '"')
				out += "\\\"";
			else if (c == '\n')
				out += "\\n";
			else if (c == '\r')
				out += "\\r";
			else if (c == '\t')
				out += "\\t";
			else if (c.unicode() < 0x20)
				out += QString("\\x%1").arg(static_cast<int>(c.unicode()), 2, 16, QChar('0'));
			else
				out += c;
		}
		return out;
	}


	QString elide(const QString& str, int limit)
	{
		if (str.size() <= limit)
			return str;
		return str.left(limit) + QString::fromUtf8("\xe2\x80\xa6");
	}


	QString bytesPreview(const QByteArray& bytes)
	{
		QByteArray head = bytes.left(kMaxBytesDisplay);
		QString hex = QString::fromLatin1(head.toHex(' '));
		if (bytes.size() > head.size())
			hex += QString::fromUtf8(" \xe2\x80\xa6");
		return hex;
	}


	// One parameter, rendered the way it reads best given what the decoder recovered:
	// a resolved string beats symbolic flags, which beat a raw value.
	QString formatPosition(const TTDApiCall& call)
	{
		return QString("%1:%2").arg(call.positionSequence, 0, 16).arg(call.positionSteps, 0, 16).toUpper();
	}


	QByteArray toByteArray(const std::vector<uint8_t>& bytes)
	{
		return QByteArray(reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()));
	}


	QString formatParamValue(const TTDApiCallParam& param)
	{
		if (!param.str.empty())
			return QString("\"%1\"").arg(
				elide(escapeString(QString::fromStdString(param.str)), kMaxStringDisplay));
		if (!param.flags.empty())
		{
			QStringList names;
			for (const std::string& flag : param.flags)
				names.append(QString::fromStdString(flag));
			return names.join('|');
		}
		if (!param.bytes.empty())
			return QString("%1 -> [%2]").arg(formatHex(param.value), bytesPreview(toByteArray(param.bytes)));
		if (param.hasDeref)
			return QString("%1 -> %2").arg(formatHex(param.value), formatHex(param.deref));
		return formatHex(param.value);
	}


	QString hexDump(const QByteArray& bytes)
	{
		QString out;
		for (int offset = 0; offset < bytes.size(); offset += 16)
		{
			QByteArray line = bytes.mid(offset, 16);
			QString ascii;
			for (char c : line)
				ascii += (c >= 0x20 && c < 0x7f) ? QChar(c) : QChar('.');
			out += QString("    %1  %2  %3\n")
					   .arg(offset, 4, 16, QChar('0'))
					   .arg(QString::fromLatin1(line.toHex(' ')), -47)
					   .arg(ascii);
		}
		return out;
	}
}  // namespace


TTDBehaviorCallModel::TTDBehaviorCallModel(QObject* parent) : QAbstractTableModel(parent) {}


void TTDBehaviorCallModel::setReport(std::shared_ptr<TTDBehaviorReport> report)
{
	beginResetModel();
	m_report = std::move(report);
	rebuildVisible();
	endResetModel();
}


void TTDBehaviorCallModel::setFilter(const QString& text)
{
	if (text.trimmed() == m_filterText)
		return;

	beginResetModel();
	m_filterText = text.trimmed();
	rebuildVisible();
	endResetModel();
}


void TTDBehaviorCallModel::rebuildVisible()
{
	m_cachedIndex = static_cast<size_t>(-1);
	m_visible.clear();
	m_visible.shrink_to_fit();
	m_filtered = !m_filterText.isEmpty();
	if (!m_filtered || !m_report || !m_report->IsOpen())
		return;

	// One call filters the whole report on the core side and returns the matching rows.
	// Measured at 8-70ms over 3.4M calls depending on the query, against 30-50% more if
	// the boundary were crossed per row.
	m_visible = m_report->RunQuery(m_filterText.toStdString());
}


const TTDApiCall* TTDBehaviorCallModel::callAt(int row, bool withParams) const
{
	if (!m_report || !m_report->IsOpen() || row < 0)
		return nullptr;
	size_t index = static_cast<size_t>(row);
	if (m_filtered)
	{
		if (index >= m_visible.size())
			return nullptr;
		index = static_cast<size_t>(m_visible[index]);
	}
	if (index >= m_report->GetCallCount())
		return nullptr;

	// No stored objects to point at, so decode into a one-row cache. data() is called
	// once per column, so without this a row would be decoded seven times per repaint.
	if (m_cachedIndex != index || (withParams && !m_cachedHasParams))
	{
		m_cached = TTDApiCall();
		if (!m_report->GetCall(index, m_cached, withParams))
			return nullptr;
		m_cachedIndex = index;
		m_cachedHasParams = withParams;
	}
	return &m_cached;
}


int TTDBehaviorCallModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid() || !m_report)
		return 0;
	return static_cast<int>(m_filtered ? m_visible.size() : m_report->GetCallCount());
}


int TTDBehaviorCallModel::columnCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return ColumnCount;
}


QVariant TTDBehaviorCallModel::data(const QModelIndex& index, int role) const
{
	const TTDApiCall* call = callAt(index.row());
	if (!call)
		return QVariant();

	if (role == Qt::ToolTipRole)
		return QString("%1!%2(%3)").arg(call->module, call->api, call->paramSummary);

	if (role != Qt::DisplayRole)
		return QVariant();

	switch (index.column())
	{
	case SeqColumn:
		return QString::number(call->seq);
	case PositionColumn:
		return QString("%1:%2").arg(call->positionSequence, 0, 16).arg(call->positionSteps, 0, 16).toUpper();
	case ThreadColumn:
		return QString::number(call->tid);
	case ModuleColumn:
		return QString::fromStdString(call->module);
	case ApiColumn:
		return QString::fromStdString(call->api);
	case ParametersColumn:
		return QString::fromStdString(call->paramSummary);
	case ReturnColumn:
		return formatHex(call->ret);
	case ReturnAddressColumn:
		return formatHex(call->returnAddress);
	default:
		return QVariant();
	}
}


QVariant TTDBehaviorCallModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
		return QVariant();

	switch (section)
	{
	case SeqColumn:
		return "#";
	case PositionColumn:
		return "Position";
	case ThreadColumn:
		return "TID";
	case ModuleColumn:
		return "Module";
	case ApiColumn:
		return "Function";
	case ParametersColumn:
		return "Parameters";
	case ReturnColumn:
		return "Return";
	case ReturnAddressColumn:
		return "Return Address";
	default:
		return QVariant();
	}
}


TTDBehaviorQueryWidget::TTDBehaviorQueryWidget(QWidget* parent, BinaryViewRef data) :
	QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	m_report = std::make_shared<TTDBehaviorReport>();
	setupUI();
	updateStatus();
}


void TTDBehaviorQueryWidget::setupUI()
{
	auto* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(4);

	m_filterEdit = new QLineEdit();
	m_filterEdit->setPlaceholderText("Filter, e.g.  module:kernel32 api:WriteFile ret:!0");
	// The syntax is the only part of this that is not self-evident, so spell it out
	// where someone hovering the box will find it.
	m_filterEdit->setToolTip(QStringList {
		"Terms are combined with AND. A bare word matches anywhere, including buffer contents.",
		"",
		"  module:kernel32             exact module, so ntdll!WriteFile is excluded",
		"  api:WriteFile               exact function name",
		"  api:Reg*                    trailing * matches a prefix",
		"  tid:4                       thread id",
		"  ret:!0    ret:>0x1000       return value; also >= <= < and 10-20 ranges",
		"  retaddr:0x400000-0x500000   call site, e.g. calls the sample made itself",
		"  \"c:\\windows\"               quoted phrase",
		"",
		"Values may be decimal or 0x hex. An unrecognised prefix is treated as text.",
	}.join('\n'));
	m_filterEdit->setClearButtonEnabled(true);
	m_filterEdit->setContentsMargins(4, 4, 4, 0);
	layout->addWidget(m_filterEdit);

	m_model = new TTDBehaviorCallModel(this);

	// A full scan of a 3.4M-call report measures 60-190ms, so filtering can run
	// synchronously and appear immediate. The short debounce is only there to coalesce
	// a burst of keystrokes into one pass; it is below the threshold where waiting is
	// perceptible, so it costs nothing on smaller reports.
	m_filterTimer = new QTimer(this);
	m_filterTimer->setSingleShot(true);
	m_filterTimer->setInterval(150);

	m_table = new QTableView();
	m_table->setModel(m_model);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_table->setAlternatingRowColors(true);
	m_table->setSortingEnabled(false);
	m_table->setWordWrap(false);
	m_table->setContextMenuPolicy(Qt::CustomContextMenu);
	m_table->verticalHeader()->setVisible(false);
	m_table->verticalHeader()->setDefaultSectionSize(QFontMetrics(getMonospaceFont(this)).height() + 4);
	m_table->horizontalHeader()->setStretchLastSection(false);
	m_table->setFont(getMonospaceFont(this));

	m_detail = new QTextEdit();
	m_detail->setReadOnly(true);
	m_detail->setLineWrapMode(QTextEdit::NoWrap);
	m_detail->setFont(getMonospaceFont(this));
	m_detail->setPlaceholderText("Select a call to see its decoded parameters");

	auto* splitter = new QSplitter(Qt::Vertical);
	splitter->addWidget(m_table);
	splitter->addWidget(m_detail);
	splitter->setStretchFactor(0, 3);
	splitter->setStretchFactor(1, 1);
	layout->addWidget(splitter, 1);

	m_statusLabel = new QLabel();
	m_statusLabel->setContentsMargins(4, 0, 4, 4);
	layout->addWidget(m_statusLabel);

	setLayout(layout);

	connect(m_filterEdit, &QLineEdit::textChanged, this, &TTDBehaviorQueryWidget::onFilterTextEdited);
	// Enter applies immediately rather than waiting out the debounce.
	connect(m_filterEdit, &QLineEdit::returnPressed, this, &TTDBehaviorQueryWidget::applyFilter);
	connect(m_filterTimer, &QTimer::timeout, this, &TTDBehaviorQueryWidget::applyFilter);
	connect(m_table, &QTableView::doubleClicked, this, &TTDBehaviorQueryWidget::onDoubleClicked);
	connect(m_table, &QTableView::customContextMenuRequested, this, &TTDBehaviorQueryWidget::onContextMenu);
	connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged, this,
		&TTDBehaviorQueryWidget::onSelectionChanged);
}


QString TTDBehaviorQueryWidget::filterText() const
{
	return m_filterEdit->text();
}


void TTDBehaviorQueryWidget::setFilterText(const QString& text)
{
	m_filterEdit->setText(text);
	applyFilter();
}


void TTDBehaviorQueryWidget::setTimings(double writeSeconds, double loadSeconds)
{
	m_writeSeconds = writeSeconds;
	m_loadSeconds = loadSeconds;
	updateStatus();
}


void TTDBehaviorQueryWidget::setReport(std::shared_ptr<TTDBehaviorReport> report, const QString& path)
{
	m_report = std::move(report);
	m_reportPath = path;
	m_model->setReport(m_report);
	m_detail->clear();
	m_table->resizeColumnsToContents();
	// The parameter rendering is long enough that fitting it would push every other
	// column off screen; cap it and let the detail pane carry the full value.
	if (m_table->columnWidth(TTDBehaviorCallModel::ParametersColumn) > 600)
		m_table->setColumnWidth(TTDBehaviorCallModel::ParametersColumn, 600);

	// resizeColumnsToContents() samples only the leading rows, which is fine for the
	// columns whose content is uniform but clips these two: the last call's index has
	// far more digits than the first thousand, and positions grow as the trace advances.
	// Size them from the widest value actually present.
	QFontMetrics metrics(m_table->font());
	const int padding = 16;
	int seqWidth = metrics.horizontalAdvance(QString::number(m_report->GetMaxSequence())) + padding;
	int positionWidth = metrics.horizontalAdvance(QString(m_report->GetMaxPositionChars(), 'M')) + padding;
	if (seqWidth > m_table->columnWidth(TTDBehaviorCallModel::SeqColumn))
		m_table->setColumnWidth(TTDBehaviorCallModel::SeqColumn, seqWidth);
	if (positionWidth > m_table->columnWidth(TTDBehaviorCallModel::PositionColumn))
		m_table->setColumnWidth(TTDBehaviorCallModel::PositionColumn, positionWidth);

	updateStatus();
}


TTDBehaviorWidget::TTDBehaviorWidget(BinaryViewRef data) : SidebarWidget("TTD Behavior"), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	m_report = std::make_shared<TTDBehaviorReport>();
	setupUI();
}


TTDBehaviorWidget::~TTDBehaviorWidget()
{
	if (m_extractProcess && m_extractProcess->state() != QProcess::NotRunning)
	{
		m_extractProcess->kill();
		m_extractProcess->waitForFinished(1000);
	}
}


void TTDBehaviorWidget::setupUI()
{
	auto* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(4);

	// Loading and extracting act on the report as a whole, so they live above the tabs
	// rather than being repeated in each one.
	auto* toolbar = new QHBoxLayout();
	toolbar->setContentsMargins(4, 4, 4, 0);

	m_loadButton = new QPushButton("Load Report...");
	m_loadButton->setToolTip("Load a report of API calls extracted from a TTD trace");
	toolbar->addWidget(m_loadButton);

	m_extractButton = new QPushButton("Extract...");
	m_extractButton->setToolTip("Run the extractor over a TTD trace and load the result");
	toolbar->addWidget(m_extractButton);
	toolbar->addStretch(1);

	layout->addLayout(toolbar);

	m_tabWidget = new QTabWidget();
	m_tabWidget->setTabsClosable(true);

	m_newTabButton = new QToolButton();
	m_newTabButton->setText("+");
	m_newTabButton->setAutoRaise(true);
	m_newTabButton->setToolTip("New query tab");
	m_tabWidget->setCornerWidget(m_newTabButton, Qt::TopRightCorner);

	layout->addWidget(m_tabWidget, 1);

	// Progress row: hidden until something long-running starts. Shared, because a load
	// or an extraction affects every tab.
	m_progressRow = new QWidget();
	auto* progressLayout = new QHBoxLayout(m_progressRow);
	progressLayout->setContentsMargins(4, 0, 4, 0);
	m_progressBar = new QProgressBar();
	m_progressBar->setRange(0, 100);
	m_progressBar->setTextVisible(false);
	progressLayout->addWidget(m_progressBar, 1);
	m_progressLabel = new QLabel();
	progressLayout->addWidget(m_progressLabel);
	m_cancelButton = new QPushButton("Cancel");
	m_cancelButton->setToolTip("Stop the extraction and keep the calls recorded so far");
	progressLayout->addWidget(m_cancelButton);
	m_progressRow->setVisible(false);
	layout->addWidget(m_progressRow);

	setLayout(layout);

	connect(m_loadButton, &QPushButton::clicked, this, &TTDBehaviorWidget::onLoadClicked);
	connect(m_extractButton, &QPushButton::clicked, this, &TTDBehaviorWidget::onExtractClicked);
	connect(m_cancelButton, &QPushButton::clicked, this, &TTDBehaviorWidget::onCancelClicked);
	connect(m_newTabButton, &QToolButton::clicked, this, &TTDBehaviorWidget::createNewTab);
	connect(m_tabWidget, &QTabWidget::tabCloseRequested, this, &TTDBehaviorWidget::closeTab);

	createNewTab();
}


TTDBehaviorQueryWidget* TTDBehaviorWidget::currentQuery() const
{
	return qobject_cast<TTDBehaviorQueryWidget*>(m_tabWidget->currentWidget());
}


void TTDBehaviorWidget::createNewTab()
{
	// Seed from the current tab, so refining a query is a matter of opening a tab and
	// editing rather than retyping it.
	QString seed;
	if (TTDBehaviorQueryWidget* current = currentQuery())
		seed = current->filterText();

	auto* query = new TTDBehaviorQueryWidget(this, m_data);
	int index = m_tabWidget->addTab(query, QString("Query %1").arg(m_tabWidget->count() + 1));

	query->setReport(m_report, m_reportPath);
	query->setTimings(m_lastWriteSeconds, m_lastLoadSeconds);
	if (!seed.isEmpty())
		query->setFilterText(seed);

	// Label the tab with what it is asking, which is far more use than "Query 3" once
	// there are several.
	connect(query, &TTDBehaviorQueryWidget::filterApplied, this, [this, query](const QString& text) {
		int at = m_tabWidget->indexOf(query);
		if (at < 0)
			return;
		QString label = text.trimmed();
		if (label.isEmpty())
			label = QString("Query %1").arg(at + 1);
		else if (label.size() > 24)
			label = label.left(24) + QString::fromUtf8("\xe2\x80\xa6");
		m_tabWidget->setTabText(at, label);
		m_tabWidget->setTabToolTip(at, text.trimmed());
	});

	m_tabWidget->setCurrentIndex(index);
}


void TTDBehaviorWidget::closeTab(int index)
{
	// Keep at least one, so the widget is never an empty frame.
	if (m_tabWidget->count() <= 1)
		return;
	QWidget* widget = m_tabWidget->widget(index);
	m_tabWidget->removeTab(index);
	widget->deleteLater();
}


void TTDBehaviorQueryWidget::updateStatus()
{
	if (m_report->GetCallCount() == 0)
	{
		m_statusLabel->setText("No report loaded");
		return;
	}

	int shown = m_model->rowCount();
	QString name = QFileInfo(m_reportPath).fileName();
	QString text = QString("%1: %2 of %3 calls shown, %4 with decoded parameters")
					   .arg(name)
					   .arg(shown)
					   .arg(m_report->GetCallCount())
					   .arg(m_report->GetDecodedCount());
	// Where the time actually went, since that is the thing worth knowing about a format.
	if (m_writeSeconds > 0.0)
		text += QString("  |  saved in %1s").arg(m_writeSeconds, 0, 'f', 1);
	if (m_loadSeconds >= 0.0)
		text += QString("%1loaded in %2s")
					.arg(m_writeSeconds > 0.0 ? ", " : "  |  ")
					.arg(m_loadSeconds, 0, 'f', 2);
	m_statusLabel->setText(text);
}


namespace {
	// "1m 24s" / "12s" -- short enough to sit in a status row.
	QString formatDuration(qint64 milliseconds)
	{
		qint64 seconds = milliseconds / 1000;
		if (seconds < 60)
			return QString("%1s").arg(seconds);
		return QString("%1m %2s").arg(seconds / 60).arg(seconds % 60);
	}
}  // namespace


void TTDBehaviorWidget::beginOperation(const QString& what, bool cancellable)
{
	m_operationTimer.start();
	m_progressBar->setRange(0, 100);
	m_progressBar->setValue(0);
	m_progressLabel->setText(what);
	m_cancelButton->setVisible(cancellable);
	m_cancelButton->setEnabled(cancellable);
	m_progressRow->setVisible(true);
	m_loadButton->setEnabled(false);
	m_extractButton->setEnabled(false);
}


void TTDBehaviorWidget::endOperation()
{
	m_progressRow->setVisible(false);
	m_loadButton->setEnabled(true);
	m_extractButton->setEnabled(true);
}


void TTDBehaviorWidget::setProgress(double percent, const QString& detail)
{
	qint64 elapsed = m_operationTimer.elapsed();
	QString text = detail;
	text += QString("  %1 elapsed").arg(formatDuration(elapsed));

	if (percent > 0.0)
	{
		m_progressBar->setRange(0, 100);
		m_progressBar->setValue(static_cast<int>(percent));
		// Linear extrapolation from the work done so far. Crude, but the sweep rate is
		// steady enough for it to be useful, and anything cleverer would still be a
		// guess.
		if (percent >= 1.0 && percent < 100.0)
		{
			qint64 remaining = static_cast<qint64>(elapsed * (100.0 - percent) / percent);
			text += QString(", ~%1 left").arg(formatDuration(remaining));
		}
	}
	else
	{
		// No measurable progress to report: a busy indicator beats a bar stuck at zero.
		m_progressBar->setRange(0, 0);
	}

	m_progressLabel->setText(text);
}


void TTDBehaviorWidget::consumeExtractorStderr()
{
	if (!m_extractProcess)
		return;

	m_stderrTail += m_extractProcess->readAllStandardError();
	int newline = -1;
	while ((newline = m_stderrTail.indexOf('\n')) >= 0)
	{
		QString line = QString::fromLocal8Bit(m_stderrTail.left(newline)).trimmed();
		m_stderrTail.remove(0, newline + 1);

		if (line.startsWith("[progress]"))
		{
			QStringList parts = line.split(' ', Qt::SkipEmptyParts);
			if (parts.size() >= 3)
			{
				bool ok = false;
				double percent = parts[1].toDouble(&ok);
				if (ok)
					setProgress(percent, QString("Sweeping trace: %1 calls").arg(parts[2]));
			}
		}
		else if (line.startsWith("[timing] write"))
		{
			QStringList parts = line.split(' ', Qt::SkipEmptyParts);
			if (parts.size() >= 3)
				m_lastWriteSeconds = parts[2].toDouble();
		}
		else if (line == "[phase] strings")
		{
			setProgress(0.0, "Recovering strings the sweep could not read");
			m_cancelButton->setEnabled(false);
		}
		else if (line == "[phase] write")
		{
			// The report can be hundreds of MB; serialising it takes comparable time to
			// the sweep, and there is no progress to be had from it.
			setProgress(0.0, "Writing report");
			m_cancelButton->setEnabled(false);
		}
	}
}


void TTDBehaviorWidget::loadReport(const QString& path)
{
	beginOperation(QString("Loading %1").arg(QFileInfo(path).fileName()), false);
	setProgress(0.0, "Parsing report");

	// Parsing a 650MB report takes tens of seconds; on the UI thread that is a freeze.
	// The report is self-contained, so build it on a worker and hand the finished object
	// back. QPointer guards the widget being destroyed while the worker runs.
	QPointer<TTDBehaviorWidget> self(this);
	std::thread([self, path]() {
		QElapsedTimer timer;
		timer.start();
		auto report = std::make_shared<TTDBehaviorReport>();
		std::string loadError;
		bool ok = report->Open(path.toStdString(), loadError);
		QString error = QString::fromStdString(loadError);
		double loadSeconds = timer.elapsed() / 1000.0;

		// Back to the UI thread to install it.
		QMetaObject::invokeMethod(
			QCoreApplication::instance(),
			[self, report, error, ok, loadSeconds, path]() {
				if (!self)
					return;
				self->endOperation();
				if (!ok)
				{
					QMessageBox::warning(self, "TTD Behavior", error);
					return;
				}
				self->m_lastLoadSeconds = loadSeconds;
				self->installReport(report, path);
			},
			Qt::QueuedConnection);
	}).detach();
}


void TTDBehaviorWidget::installReport(std::shared_ptr<TTDBehaviorReport> report, const QString& path)
{
	m_report = std::move(report);
	m_reportPath = path;
	// Every tab points at the same report -- that is the reason to have tabs at all --
	// but each keeps its own query, so each re-resolves and re-filters against it.
	for (int i = 0; i < m_tabWidget->count(); ++i)
	{
		if (auto* query = qobject_cast<TTDBehaviorQueryWidget*>(m_tabWidget->widget(i)))
		{
			query->setReport(m_report, m_reportPath);
			query->setTimings(m_lastWriteSeconds, m_lastLoadSeconds);
		}
	}
}


void TTDBehaviorWidget::onLoadClicked()
{
	QString path = QFileDialog::getOpenFileName(
		this, "Load TTD API Call Report", QString(), "TTD behavior reports (*.ttdb *.json);;All files (*)");
	if (!path.isEmpty())
		loadReport(path);
}


QString TTDBehaviorWidget::extractorPath(bool prompt)
{
	auto settings = Settings::Instance();
	QString path = QString::fromStdString(settings->Get<std::string>(kExtractorSetting));
	if (!path.isEmpty() && QFileInfo(path).isExecutable())
		return path;

	if (!prompt)
		return QString();

	path = QFileDialog::getOpenFileName(this, "Locate the TTD API call extractor", QString(),
#ifdef WIN32
		"Executables (*.exe);;All files (*)");
#else
		"All files (*)");
#endif
	if (!path.isEmpty())
		settings->Set(kExtractorSetting, path.toStdString());
	return path;
}


void TTDBehaviorWidget::onExtractClicked()
{
	if (m_extractProcess && m_extractProcess->state() != QProcess::NotRunning)
	{
		QMessageBox::information(this, "TTD Behavior", "An extraction is already running.");
		return;
	}

	QString extractor = extractorPath(true);
	if (extractor.isEmpty())
		return;

	// Prefer the trace the current session is replaying; fall back to asking.
	QString trace;
	if (m_controller && m_controller->IsTTD())
	{
		auto adapterSettings = m_controller->GetAdapterSettings();
		if (adapterSettings)
		{
			BNSettingsScope scope = SettingsResourceScope;
			trace = QString::fromStdString(adapterSettings->Get<std::string>("launch.trace_path", m_data, &scope));
		}
	}
	if (trace.isEmpty() || !QFileInfo::exists(trace))
	{
		trace = QFileDialog::getOpenFileName(
			this, "Select TTD Trace", QString(), "TTD traces (*.run);;All files (*)");
	}
	if (trace.isEmpty())
		return;

	// Next to the trace, not in a temp directory: extraction takes minutes on a large
	// trace, the report is the useful artifact, and it belongs with the trace it came
	// from rather than somewhere the OS will eventually clean up.
	QFileInfo traceInfo(trace);
	QDir traceDir = traceInfo.absoluteDir();
	QString output = traceDir.filePath(traceInfo.completeBaseName() + ".ttdb");

	// A trace can sit somewhere unwritable -- a read-only share, or a mounted image.
	// Ask rather than silently falling back to a temp file, which is the thing we are
	// deliberately not doing.
	if (!QFileInfo(traceDir.absolutePath()).isWritable())
	{
		output = QFileDialog::getSaveFileName(this, "Save Extracted Report As", output,
			"TTD behavior reports (*.ttdb);;All files (*)");
		if (output.isEmpty())
			return;
	}
	else if (QFileInfo::exists(output))
	{
		// Re-extracting is deterministic, so the existing report is as good as a fresh
		// one -- offer to just load it instead of spending the minutes again.
		QMessageBox box(this);
		box.setWindowTitle("TTD Behavior");
		box.setText(QString("%1 already exists.").arg(QFileInfo(output).fileName()));
		box.setInformativeText("Load the existing report, or extract again and replace it?");
		QPushButton* loadButton = box.addButton("Load Existing", QMessageBox::AcceptRole);
		QPushButton* replaceButton = box.addButton("Extract Again", QMessageBox::DestructiveRole);
		box.addButton(QMessageBox::Cancel);
		box.setDefaultButton(loadButton);
		box.exec();

		if (box.clickedButton() == loadButton)
		{
			loadReport(output);
			return;
		}
		if (box.clickedButton() != replaceButton)
			return;
	}

	m_extractProcess = new QProcess(this);
	// The extractor loads its API metadata index and the TTD replay DLLs from its own
	// directory, so it has to run from there.
	m_extractProcess->setWorkingDirectory(QFileInfo(extractor).absolutePath());
	m_stderrTail.clear();

	connect(m_extractProcess, &QProcess::readyReadStandardError, this,
		&TTDBehaviorWidget::consumeExtractorStderr);
	connect(m_extractProcess, &QProcess::finished, this,
		[this, output](int exitCode, QProcess::ExitStatus status) {
			consumeExtractorStderr();
			QString stderrText = QString::fromLocal8Bit(m_extractProcess->readAllStandardError());
			m_extractProcess->deleteLater();
			m_extractProcess = nullptr;
			endOperation();

			if (status != QProcess::NormalExit || exitCode != 0)
			{
				QMessageBox::warning(this, "TTD Behavior",
					QString("Extraction failed (exit %1):\n\n%2").arg(exitCode).arg(stderrText));
				return;
			}
			// A cancelled sweep still writes what it collected, so this path is the same
			// whether the run completed or was stopped early.
			loadReport(output);
		});

	// --progress drives the bar below; --cancel-on-stdin lets Cancel stop the sweep and
	// still keep everything recorded up to that point.
	QStringList arguments {trace, "-b", output, "--progress", "--cancel-on-stdin"};
	int64_t maxBuffer = Settings::Instance()->Get<int64_t>("debugger.ttdBehaviorMaxBuffer");
	if (maxBuffer > 0)
		arguments << "--max-buffer" << QString::number(maxBuffer);
	// Without this a quarter of string parameters come back empty, because the sweep
	// reads memory through an interface the SDK restricts to a fast, incomplete lookup.
	if (Settings::Instance()->Get<bool>("debugger.ttdBehaviorRecoverStrings"))
		arguments << "--recover-strings";

	beginOperation(QString("Extracting from %1").arg(QFileInfo(trace).fileName()), true);
	setProgress(0.0, "Starting extractor");
	m_extractProcess->start(extractor, arguments);
}


void TTDBehaviorWidget::onCancelClicked()
{
	if (!m_extractProcess || m_extractProcess->state() == QProcess::NotRunning)
		return;

	// The extractor watches stdin for this and interrupts the replay, then writes out
	// everything it recorded. Killing the process instead would throw that away.
	m_extractProcess->write("cancel\n");
	m_cancelButton->setEnabled(false);
	setProgress(0.0, "Finishing up the calls recorded so far");
}


void TTDBehaviorQueryWidget::onFilterTextEdited()
{
	m_filterTimer->start();
	// Only worth saying on a report big enough for the pass to be visible; below that
	// the label would flicker for no reason.
	if (m_report->GetCallCount() > 250000)
		m_statusLabel->setText("Filtering...");
}


void TTDBehaviorQueryWidget::applyFilter()
{
	m_filterTimer->stop();
	m_model->setFilter(m_filterEdit->text());
	updateStatus();
	emit filterApplied(m_filterEdit->text());
}


void TTDBehaviorQueryWidget::showDetail(const TTDApiCall* call)
{
	if (!call)
	{
		m_detail->clear();
		return;
	}

	QString text;
	text += QString("%1!%2  @ %3  tid %4  (#%5)\n")
				.arg(QString::fromStdString(call->module), QString::fromStdString(call->api), formatPosition(*call))
				.arg(call->tid)
				.arg(call->seq);
	text += QString("returned %1, to %2\n\n").arg(formatHex(call->ret), formatHex(call->returnAddress));

	if (!call->decoded)
	{
		text += "No signature was available for this function; the values below are the\n";
		text += "raw argument registers captured heuristically.\n\n";
		text += QString("  %1\n").arg(call->paramSummary);
		m_detail->setPlainText(text);
		return;
	}

	for (const TTDApiCallParam& param : call->params)
	{
		QString annotations;
		if (param.out)
			annotations += " [out]";
		if (param.atReturn)
			annotations += " [read at return]";

		text += QString("%1 : %2%3\n")
					.arg(QString::fromStdString(param.name), QString::fromStdString(param.type), annotations);
		text += QString("    value   %1\n").arg(formatHex(param.value));
		if (!param.str.empty())
			text += QString("    string  \"%1\"\n").arg(escapeString(QString::fromStdString(param.str)));
		if (!param.flags.empty())
		{
			QStringList names;
			for (const std::string& flag : param.flags)
				names.append(QString::fromStdString(flag));
			text += QString("    flags   %1\n").arg(names.join(" | "));
		}
		if (param.hasDeref)
			text += QString("    deref   %1 (%2)\n").arg(formatHex(param.deref)).arg(param.deref);
		if (!param.bytes.empty())
		{
			// Say so when this is only the head of a larger buffer: reporting the
			// captured size alone reads as the buffer's real size.
			if (param.bytesTotal > static_cast<uint64_t>(param.bytes.size()))
			{
				text += QString("    buffer  first %1 of %2 bytes (raise the extractor's --max-buffer for more)\n")
							.arg(param.bytes.size())
							.arg(param.bytesTotal);
			}
			else
			{
				text += QString("    buffer  %1 bytes\n").arg(param.bytes.size());
			}

			QByteArray shown = toByteArray(param.bytes).left(kMaxHexDumpBytes);
			text += hexDump(shown);
			if (shown.size() < param.bytes.size())
			{
				text += QString("    ... %1 more captured bytes not shown\n")
							.arg(param.bytes.size() - shown.size());
			}
		}
		text += "\n";
	}

	m_detail->setPlainText(text);
}


void TTDBehaviorQueryWidget::onSelectionChanged()
{
	QModelIndexList selected = m_table->selectionModel()->selectedRows();
	if (selected.isEmpty())
	{
		showDetail(nullptr);
		return;
	}
	showDetail(m_model->callAt(selected.first().row(), true));
}


void TTDBehaviorQueryWidget::onDoubleClicked(const QModelIndex& index)
{
	const TTDApiCall* call = m_model->callAt(index.row());
	if (!call || !m_controller || !m_controller->IsTTD())
		return;

	QStringList parts = formatPosition(*call).split(':');
	if (parts.size() != 2)
		return;

	bool sequenceOk = false, stepOk = false;
	uint64_t sequence = parts[0].toULongLong(&sequenceOk, 16);
	uint64_t step = parts[1].toULongLong(&stepOk, 16);
	if (!sequenceOk || !stepOk)
		return;

	if (!m_controller->SetTTDPosition(TTDPosition(sequence, step)))
	{
		m_statusLabel->setText(QString("Failed to travel to %1").arg(formatPosition(*call)));
		return;
	}

	// SetTTDPosition drives the backend's !tt directly and posts no stop event, so
	// nothing else moves the view. Read the instruction pointer back from the adapter --
	// it is queried live, so it reflects the position we just landed on -- and navigate
	// there ourselves.
	uint64_t ip = m_controller->IP();
	BinaryViewRef liveView = m_controller->GetData();
	ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
	if (frame && liveView)
	{
		// The position of a call is the callee's entry, which for a system DLL is
		// usually somewhere analysis has not defined a function yet.
		if (liveView->GetAnalysisFunctionsContainingAddress(ip).empty()
			&& !m_controller->FunctionExistsInOldView(ip))
		{
			auto id = liveView->BeginUndoActions();
			liveView->CreateUserFunction(liveView->GetDefaultPlatform(), ip);
			liveView->ForgetUndoActions(id);
		}
		frame->navigate(liveView, ip, true, true);
	}

	m_statusLabel->setText(QString("Traveled to %1, IP 0x%2").arg(formatPosition(*call)).arg(ip, 0, 16));
}


void TTDBehaviorQueryWidget::copySelectedRows()
{
	QModelIndexList selected = m_table->selectionModel()->selectedRows();
	QStringList lines;
	for (const QModelIndex& index : selected)
	{
		const TTDApiCall* call = m_model->callAt(index.row());
		if (!call)
			continue;
		lines.append(QString("%1  %2!%3(%4) -> %5")
						 .arg(formatPosition(*call), QString::fromStdString(call->module), QString::fromStdString(call->api),
						 QString::fromStdString(call->paramSummary), formatHex(call->ret)));
	}
	if (!lines.isEmpty())
		QApplication::clipboard()->setText(lines.join('\n'));
}


void TTDBehaviorQueryWidget::onContextMenu(const QPoint& pos)
{
	if (m_table->selectionModel()->selectedRows().isEmpty())
		return;

	QMenu menu(this);
	QAction* copyAction = menu.addAction("Copy");
	QAction* navigateAction = nullptr;
	if (m_controller && m_controller->IsTTD())
		navigateAction = menu.addAction("Time Travel Here");

	QAction* chosen = menu.exec(m_table->viewport()->mapToGlobal(pos));
	if (!chosen)
		return;
	if (chosen == copyAction)
		copySelectedRows();
	else if (chosen == navigateAction)
		onDoubleClicked(m_table->selectionModel()->selectedRows().first());
}


TTDBehaviorWidgetType::TTDBehaviorWidgetType() :
	SidebarWidgetType(QImage(":/debugger/ttd-analysis"), "TTD Behavior")
{}


SidebarWidget* TTDBehaviorWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new TTDBehaviorWidget(data);
}
