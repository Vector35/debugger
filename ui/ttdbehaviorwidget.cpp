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
#include <QMessageBox>
#include <cmath>
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
	QString formatParamValue(const TTDApiCallParam& param)
	{
		if (!param.str.isEmpty())
			return QString("\"%1\"").arg(elide(escapeString(param.str), kMaxStringDisplay));
		if (!param.flags.isEmpty())
			return param.flags.join('|');
		if (!param.bytes.isEmpty())
			return QString("%1 -> [%2]").arg(formatHex(param.value), bytesPreview(param.bytes));
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


void TTDBehaviorReport::clear()
{
	reportPath.clear();
	tracePath.clear();
	arch.clear();
	sampleName.clear();
	pid = 0;
	decodedCount = 0;
	calls.clear();
}


bool TTDBehaviorReport::load(const QString& path, QString& error)
{
	clear();

	QFile file(path);
	if (!file.open(QIODevice::ReadOnly))
	{
		error = QString("Cannot open %1: %2").arg(path, file.errorString());
		return false;
	}

	QByteArray contents = file.readAll();
	file.close();

	QJsonParseError parseError {};
	QJsonDocument doc = QJsonDocument::fromJson(contents, &parseError);
	if (doc.isNull())
	{
		error = QString("Not a valid JSON report: %1").arg(parseError.errorString());
		return false;
	}
	if (!doc.isObject())
	{
		error = "Report root is not a JSON object";
		return false;
	}

	QJsonObject root = doc.object();
	if (!root.contains("processes"))
	{
		error = "Report has no \"processes\" array; is this a TTD API call report?";
		return false;
	}

	reportPath = path;
	QJsonObject trace = root.value("trace").toObject();
	tracePath = trace.value("path").toString();
	arch = trace.value("arch").toString();
	sampleName = root.value("sample").toObject().value("name").toString();

	for (const QJsonValue& processValue : root.value("processes").toArray())
	{
		QJsonObject process = processValue.toObject();
		if (pid == 0)
			pid = jsonToUInt64(process.value("pid"));
		if (sampleName.isEmpty())
			sampleName = process.value("name").toString();

		for (const QJsonValue& callValue : process.value("calls").toArray())
		{
			QJsonObject callObject = callValue.toObject();
			TTDApiCall call;
			call.seq = jsonToUInt64(callObject.value("seq"));
			call.tid = jsonToUInt64(callObject.value("tid"));
			call.position = callObject.value("position").toString();
			call.module = callObject.value("module").toString();
			call.api = callObject.value("api").toString();
			call.ret = jsonToUInt64(callObject.value("ret"));

			QStringList rendered;
			if (callObject.contains("params"))
			{
				call.decoded = true;
				for (const QJsonValue& paramValue : callObject.value("params").toArray())
				{
					QJsonObject paramObject = paramValue.toObject();
					TTDApiCallParam param;
					param.name = paramObject.value("name").toString();
					param.type = paramObject.value("type").toString();
					param.kind = paramObject.value("kind").toString();
					param.value = jsonToUInt64(paramObject.value("value"));
					param.str = paramObject.value("str").toString();
					param.out = paramObject.value("out").toBool();
					param.atReturn = paramObject.value("at_return").toBool();
					if (paramObject.contains("deref"))
					{
						param.hasDeref = true;
						param.deref = jsonToUInt64(paramObject.value("deref"));
					}
					for (const QJsonValue& flag : paramObject.value("flags").toArray())
						param.flags.append(flag.toString());
					if (paramObject.contains("bytes"))
						param.bytes = QByteArray::fromHex(paramObject.value("bytes").toString().toLatin1());
					// Present only when the extractor's --max-buffer cut the capture short.
					param.bytesTotal = jsonToUInt64(paramObject.value("bytes_total"));

					rendered.append(QString("%1=%2").arg(param.name, formatParamValue(param)));
					call.params.push_back(std::move(param));
				}
			}
			else
			{
				// No signature was available for this function, so the extractor fell
				// back to capturing the four argument registers. Show them positionally.
				for (const QJsonValue& argValue : callObject.value("args").toArray())
				{
					if (argValue.isString())
						rendered.append(
							QString("\"%1\"").arg(elide(escapeString(argValue.toString()), kMaxStringDisplay)));
					else
						rendered.append(formatHex(jsonToUInt64(argValue)));
				}
			}

			call.paramSummary = rendered.join(", ");
			call.searchText =
				QString("%1!%2 %3").arg(call.module, call.api, call.paramSummary).toLower().toUtf8().toStdString();
			if (call.decoded)
				++decodedCount;
			calls.push_back(std::move(call));
		}
	}

	return true;
}


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
	std::string filter = text.trimmed().toLower().toUtf8().toStdString();
	if (filter == m_filter)
		return;

	beginResetModel();
	m_filter = std::move(filter);
	rebuildVisible();
	endResetModel();
}


void TTDBehaviorCallModel::rebuildVisible()
{
	m_visible.clear();
	m_visible.shrink_to_fit();
	m_filtered = !m_filter.empty();
	if (!m_filtered || !m_report)
		return;

	// One linear pass of substring searches over 8-bit haystacks. No reserve() up
	// front: a selective filter is the common case, and reserving for every call
	// would dwarf the result.
	const size_t count = m_report->calls.size();
	for (size_t i = 0; i < count; ++i)
	{
		if (m_report->calls[i].searchText.find(m_filter) != std::string::npos)
			m_visible.push_back(static_cast<uint32_t>(i));
	}
}


const TTDApiCall* TTDBehaviorCallModel::callAt(int row) const
{
	if (!m_report || row < 0)
		return nullptr;
	size_t index = static_cast<size_t>(row);
	if (m_filtered)
	{
		if (index >= m_visible.size())
			return nullptr;
		index = m_visible[index];
	}
	if (index >= m_report->calls.size())
		return nullptr;
	return &m_report->calls[index];
}


int TTDBehaviorCallModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid() || !m_report)
		return 0;
	return static_cast<int>(m_filtered ? m_visible.size() : m_report->calls.size());
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
		return call->position;
	case ThreadColumn:
		return QString::number(call->tid);
	case ModuleColumn:
		return call->module;
	case ApiColumn:
		return call->api;
	case ParametersColumn:
		return call->paramSummary;
	case ReturnColumn:
		return formatHex(call->ret);
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
	default:
		return QVariant();
	}
}


TTDBehaviorWidget::TTDBehaviorWidget(BinaryViewRef data) : SidebarWidget("TTD Behavior"), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	m_report = std::make_shared<TTDBehaviorReport>();
	setupUI();
	updateStatus();
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

	auto* toolbar = new QHBoxLayout();
	toolbar->setContentsMargins(4, 4, 4, 0);

	m_loadButton = new QPushButton("Load Report...");
	m_loadButton->setToolTip("Load a JSON report of API calls extracted from a TTD trace");
	toolbar->addWidget(m_loadButton);

	m_extractButton = new QPushButton("Extract...");
	m_extractButton->setToolTip("Run the extractor over a TTD trace and load the result");
	toolbar->addWidget(m_extractButton);

	m_filterEdit = new QLineEdit();
	m_filterEdit->setPlaceholderText("Filter by module, function, or parameter");
	m_filterEdit->setClearButtonEnabled(true);
	toolbar->addWidget(m_filterEdit, 1);

	layout->addLayout(toolbar);

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

	connect(m_loadButton, &QPushButton::clicked, this, &TTDBehaviorWidget::onLoadClicked);
	connect(m_extractButton, &QPushButton::clicked, this, &TTDBehaviorWidget::onExtractClicked);
	connect(m_filterEdit, &QLineEdit::textChanged, this, &TTDBehaviorWidget::onFilterTextEdited);
	// Enter applies immediately rather than waiting out the debounce.
	connect(m_filterEdit, &QLineEdit::returnPressed, this, &TTDBehaviorWidget::applyFilter);
	connect(m_filterTimer, &QTimer::timeout, this, &TTDBehaviorWidget::applyFilter);
	connect(m_table, &QTableView::doubleClicked, this, &TTDBehaviorWidget::onDoubleClicked);
	connect(m_table, &QTableView::customContextMenuRequested, this, &TTDBehaviorWidget::onContextMenu);
	connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged, this,
		&TTDBehaviorWidget::onSelectionChanged);
}


void TTDBehaviorWidget::updateStatus()
{
	if (m_report->calls.empty())
	{
		m_statusLabel->setText("No report loaded");
		return;
	}

	int shown = m_model->rowCount();
	QString name = QFileInfo(m_report->reportPath).fileName();
	m_statusLabel->setText(QString("%1: %2 of %3 calls shown, %4 with decoded parameters")
							   .arg(name)
							   .arg(shown)
							   .arg(m_report->calls.size())
							   .arg(m_report->decodedCount));
}


void TTDBehaviorWidget::loadReport(const QString& path)
{
	auto report = std::make_shared<TTDBehaviorReport>();
	QString error;
	if (!report->load(path, error))
	{
		QMessageBox::warning(this, "TTD Behavior", error);
		return;
	}

	m_report = report;
	m_model->setReport(m_report);
	m_detail->clear();
	m_table->resizeColumnsToContents();
	// The parameter rendering is long enough that fitting it would push every other
	// column off screen; cap it and let the detail pane carry the full value.
	if (m_table->columnWidth(TTDBehaviorCallModel::ParametersColumn) > 600)
		m_table->setColumnWidth(TTDBehaviorCallModel::ParametersColumn, 600);
	updateStatus();
}


void TTDBehaviorWidget::onLoadClicked()
{
	QString path = QFileDialog::getOpenFileName(
		this, "Load TTD API Call Report", QString(), "JSON reports (*.json);;All files (*)");
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
	QString output = traceDir.filePath(traceInfo.completeBaseName() + ".ttd.json");

	// A trace can sit somewhere unwritable -- a read-only share, or a mounted image.
	// Ask rather than silently falling back to a temp file, which is the thing we are
	// deliberately not doing.
	if (!QFileInfo(traceDir.absolutePath()).isWritable())
	{
		output = QFileDialog::getSaveFileName(this, "Save Extracted Report As", output,
			"JSON reports (*.json);;All files (*)");
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
	connect(m_extractProcess, &QProcess::finished, this,
		[this, output](int exitCode, QProcess::ExitStatus status) {
			m_extractButton->setEnabled(true);
			QString stderrText = QString::fromLocal8Bit(m_extractProcess->readAllStandardError());
			m_extractProcess->deleteLater();
			m_extractProcess = nullptr;

			if (status != QProcess::NormalExit || exitCode != 0)
			{
				QMessageBox::warning(this, "TTD Behavior",
					QString("Extraction failed (exit %1):\n\n%2").arg(exitCode).arg(stderrText));
				updateStatus();
				return;
			}
			loadReport(output);
		});

	QStringList arguments {trace, "-o", output};
	int64_t maxBuffer = Settings::Instance()->Get<int64_t>("debugger.ttdBehaviorMaxBuffer");
	if (maxBuffer > 0)
		arguments << "--max-buffer" << QString::number(maxBuffer);

	m_extractButton->setEnabled(false);
	m_statusLabel->setText(QString("Extracting from %1...").arg(QFileInfo(trace).fileName()));
	m_extractProcess->start(extractor, arguments);
}


void TTDBehaviorWidget::onFilterTextEdited()
{
	m_filterTimer->start();
	// Only worth saying on a report big enough for the pass to be visible; below that
	// the label would flicker for no reason.
	if (m_report->calls.size() > 250000)
		m_statusLabel->setText("Filtering...");
}


void TTDBehaviorWidget::applyFilter()
{
	m_filterTimer->stop();
	m_model->setFilter(m_filterEdit->text());
	updateStatus();
}


void TTDBehaviorWidget::showDetail(const TTDApiCall* call)
{
	if (!call)
	{
		m_detail->clear();
		return;
	}

	QString text;
	text += QString("%1!%2  @ %3  tid %4  (#%5)\n")
				.arg(call->module, call->api, call->position)
				.arg(call->tid)
				.arg(call->seq);
	text += QString("returned %1\n\n").arg(formatHex(call->ret));

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

		text += QString("%1 : %2%3\n").arg(param.name, param.type, annotations);
		text += QString("    value   %1\n").arg(formatHex(param.value));
		if (!param.str.isEmpty())
			text += QString("    string  \"%1\"\n").arg(escapeString(param.str));
		if (!param.flags.isEmpty())
			text += QString("    flags   %1\n").arg(param.flags.join(" | "));
		if (param.hasDeref)
			text += QString("    deref   %1 (%2)\n").arg(formatHex(param.deref)).arg(param.deref);
		if (!param.bytes.isEmpty())
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

			QByteArray shown = param.bytes.left(kMaxHexDumpBytes);
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


void TTDBehaviorWidget::onSelectionChanged()
{
	QModelIndexList selected = m_table->selectionModel()->selectedRows();
	if (selected.isEmpty())
	{
		showDetail(nullptr);
		return;
	}
	showDetail(m_model->callAt(selected.first().row()));
}


void TTDBehaviorWidget::onDoubleClicked(const QModelIndex& index)
{
	const TTDApiCall* call = m_model->callAt(index.row());
	if (!call || !m_controller || !m_controller->IsTTD())
		return;

	QStringList parts = call->position.split(':');
	if (parts.size() != 2)
		return;

	bool sequenceOk = false, stepOk = false;
	uint64_t sequence = parts[0].toULongLong(&sequenceOk, 16);
	uint64_t step = parts[1].toULongLong(&stepOk, 16);
	if (!sequenceOk || !stepOk)
		return;

	if (!m_controller->SetTTDPosition(TTDPosition(sequence, step)))
	{
		m_statusLabel->setText(QString("Failed to travel to %1").arg(call->position));
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

	m_statusLabel->setText(QString("Traveled to %1, IP 0x%2").arg(call->position).arg(ip, 0, 16));
}


void TTDBehaviorWidget::copySelectedRows()
{
	QModelIndexList selected = m_table->selectionModel()->selectedRows();
	QStringList lines;
	for (const QModelIndex& index : selected)
	{
		const TTDApiCall* call = m_model->callAt(index.row());
		if (!call)
			continue;
		lines.append(QString("%1  %2!%3(%4) -> %5")
						 .arg(call->position, call->module, call->api, call->paramSummary, formatHex(call->ret)));
	}
	if (!lines.isEmpty())
		QApplication::clipboard()->setText(lines.join('\n'));
}


void TTDBehaviorWidget::onContextMenu(const QPoint& pos)
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
