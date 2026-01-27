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

#include "ttdbehaviorwidget.h"
#include "debuggeruicommon.h"
#include <QMessageBox>
#include <QApplication>
#include <QContextMenuEvent>

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

// Worker thread implementation
TTDBehaviorAnalysisWorker::TTDBehaviorAnalysisWorker(
	DbgRef<DebuggerController> controller, const TTDBehaviorAnalysisSet& analysisSet, QObject* parent)
	: QThread(parent), m_controller(controller), m_analysisSet(analysisSet)
{
}

void TTDBehaviorAnalysisWorker::run()
{
	if (!m_controller)
	{
		TTDBehaviorAnalysisResult result;
		result.success = false;
		result.errorMessage = "No debugger controller available";
		emit analysisCompleted(false, QString::fromStdString(result.errorMessage), result);
		return;
	}

	emit analysisProgress(10, "Starting analysis...");

	TTDBehaviorAnalysisResult result = m_controller->AnalyzeTTDBehavior(m_analysisSet);

	emit analysisProgress(100, result.success ? "Analysis completed" : "Analysis failed");
	emit analysisCompleted(result.success, QString::fromStdString(result.success ? "" : result.errorMessage), result);
}


// Result widget implementation
TTDBehaviorResultWidget::TTDBehaviorResultWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	setupUI();
}

TTDBehaviorResultWidget::~TTDBehaviorResultWidget()
{
}

void TTDBehaviorResultWidget::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(4);

	// Results table
	m_resultsTable = new QTableWidget(this);
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
	m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_resultsTable->setAlternatingRowColors(true);
	m_resultsTable->setSortingEnabled(true);
	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	m_resultsTable->verticalHeader()->setVisible(false);

	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, this, &TTDBehaviorResultWidget::onCellDoubleClicked);

	layout->addWidget(m_resultsTable);

	// Status label
	m_statusLabel = new QLabel(this);
	m_statusLabel->setAlignment(Qt::AlignCenter);
	layout->addWidget(m_statusLabel);
}

void TTDBehaviorResultWidget::setupTable()
{
	m_resultsTable->clear();
	m_resultsTable->setColumnCount(static_cast<int>(m_columns.size()));

	QStringList headers;
	for (const auto& col : m_columns)
	{
		headers << col.name;
	}
	m_resultsTable->setHorizontalHeaderLabels(headers);

	// Set column widths
	for (size_t i = 0; i < m_columns.size(); i++)
	{
		m_resultsTable->setColumnWidth(static_cast<int>(i), m_columns[i].width);
	}

	QHeaderView* header = m_resultsTable->horizontalHeader();
	header->setStretchLastSection(true);
}

void TTDBehaviorResultWidget::setResults(const TTDBehaviorAnalysisResult& result)
{
	m_currentResult = result;

	// Determine columns based on the result data
	m_columns.clear();

	// Fixed columns
	m_columns.push_back({"#", 50});
	m_columns.push_back({"Action", 80});
	m_columns.push_back({"Time", 100});
	m_columns.push_back({"Thread", 60});

	// Dynamic columns based on values present in events
	std::set<std::string> valueKeys;
	for (const auto& event : result.events)
	{
		for (const auto& [key, val] : event.values)
		{
			valueKeys.insert(key);
		}
	}

	for (const auto& key : valueKeys)
	{
		int width = 100;
		// Adjust width based on key name
		if (key == "FileName" || key == "SourceFileName" || key == "DestFileName")
			width = 200;
		else if (key == "Size" || key == "Flags")
			width = 80;

		m_columns.push_back({QString::fromStdString(key), width});
	}

	setupTable();

	// Populate rows
	m_resultsTable->setRowCount(static_cast<int>(result.events.size()));

	for (size_t i = 0; i < result.events.size(); i++)
	{
		const auto& event = result.events[i];
		int row = static_cast<int>(i);
		int col = 0;

		// Index
		m_resultsTable->setItem(row, col++, new NumericalTableWidgetItem(QString::number(i), i));

		// Action
		m_resultsTable->setItem(row, col++, new QTableWidgetItem(QString::fromStdString(event.action)));

		// Time
		QString timeStr = QString("%1:%2")
			.arg(event.timeStart.sequence, 0, 16)
			.arg(event.timeStart.step, 0, 16);
		uint64_t timeSortValue = (event.timeStart.sequence << 32) | (event.timeStart.step & 0xFFFFFFFF);
		m_resultsTable->setItem(row, col++, new NumericalTableWidgetItem(timeStr, timeSortValue));

		// Thread
		m_resultsTable->setItem(row, col++, new NumericalTableWidgetItem(QString::number(event.threadId), event.threadId));

		// Dynamic value columns
		for (const auto& key : valueKeys)
		{
			auto it = event.values.find(key);
			QString value = (it != event.values.end()) ? QString::fromStdString(it->second) : "";

			// Try to parse as number for proper sorting
			bool ok = false;
			uint64_t numValue = 0;
			if (value.startsWith("0x"))
			{
				numValue = value.mid(2).toULongLong(&ok, 16);
			}
			else
			{
				numValue = value.toULongLong(&ok);
			}

			if (ok)
			{
				m_resultsTable->setItem(row, col++, new NumericalTableWidgetItem(value, numValue));
			}
			else
			{
				m_resultsTable->setItem(row, col++, new QTableWidgetItem(value));
			}
		}
	}

	m_statusLabel->setText(QString("Found %1 events").arg(result.events.size()));
}

void TTDBehaviorResultWidget::clearResults()
{
	m_resultsTable->clear();
	m_resultsTable->setRowCount(0);
	m_resultsTable->setColumnCount(0);
	m_currentResult = TTDBehaviorAnalysisResult{};
	m_statusLabel->setText("");
}

void TTDBehaviorResultWidget::onCellDoubleClicked(int row, int column)
{
	if (row < 0 || static_cast<size_t>(row) >= m_currentResult.events.size())
		return;

	const auto& event = m_currentResult.events[row];

	// Check if Time column was clicked (column 2)
	if (column == 2)
	{
		// Navigate to this position in the TTD trace
		if (m_controller && m_controller->IsTTD())
		{
			m_controller->SetTTDPosition(event.timeStart);
		}
	}
}

void TTDBehaviorResultWidget::contextMenuEvent(QContextMenuEvent* event)
{
	QMenu menu(this);

	QAction* copyCell = menu.addAction("Copy Cell");
	QAction* copyRow = menu.addAction("Copy Row");
	QAction* copyTable = menu.addAction("Copy Table");

	connect(copyCell, &QAction::triggered, this, &TTDBehaviorResultWidget::copySelectedCell);
	connect(copyRow, &QAction::triggered, this, &TTDBehaviorResultWidget::copySelectedRow);
	connect(copyTable, &QAction::triggered, this, &TTDBehaviorResultWidget::copyEntireTable);

	menu.exec(event->globalPos());
}

void TTDBehaviorResultWidget::copySelectedCell()
{
	QTableWidgetItem* item = m_resultsTable->currentItem();
	if (item)
	{
		QApplication::clipboard()->setText(item->text());
	}
}

void TTDBehaviorResultWidget::copySelectedRow()
{
	QList<QTableWidgetItem*> items = m_resultsTable->selectedItems();
	if (items.isEmpty())
		return;

	int row = items.first()->row();
	QStringList values;
	for (int col = 0; col < m_resultsTable->columnCount(); col++)
	{
		QTableWidgetItem* item = m_resultsTable->item(row, col);
		values << (item ? item->text() : "");
	}
	QApplication::clipboard()->setText(values.join("\t"));
}

void TTDBehaviorResultWidget::copyEntireTable()
{
	QStringList lines;

	// Header
	QStringList headers;
	for (int col = 0; col < m_resultsTable->columnCount(); col++)
	{
		QTableWidgetItem* header = m_resultsTable->horizontalHeaderItem(col);
		headers << (header ? header->text() : "");
	}
	lines << headers.join("\t");

	// Data
	for (int row = 0; row < m_resultsTable->rowCount(); row++)
	{
		QStringList values;
		for (int col = 0; col < m_resultsTable->columnCount(); col++)
		{
			QTableWidgetItem* item = m_resultsTable->item(row, col);
			values << (item ? item->text() : "");
		}
		lines << values.join("\t");
	}

	QApplication::clipboard()->setText(lines.join("\n"));
}


// Main behavior widget implementation
TTDBehaviorWidget::TTDBehaviorWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data), m_worker(nullptr)
{
	m_controller = DebuggerController::GetController(data);
	loadAnalysisSets();
	setupUI();
}

TTDBehaviorWidget::~TTDBehaviorWidget()
{
	if (m_worker)
	{
		m_worker->terminate();
		m_worker->wait(3000);
		delete m_worker;
	}
}

void TTDBehaviorWidget::loadAnalysisSets()
{
	m_analysisSets = TTDBehaviorAnalysisSetManager::GetBuiltinSets();
}

void TTDBehaviorWidget::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(8, 8, 8, 8);
	mainLayout->setSpacing(8);

	// Controls group
	QHBoxLayout* controlsLayout = new QHBoxLayout();

	// Analysis set selector
	m_analysisSetCombo = new QComboBox(this);
	for (const auto& set : m_analysisSets)
	{
		m_analysisSetCombo->addItem(QString::fromStdString(set.name));
	}
	m_analysisSetCombo->setToolTip("Select which API behavior to analyze");
	controlsLayout->addWidget(m_analysisSetCombo, 1);

	// Analyze button
	m_analyzeButton = new QPushButton("Analyze", this);
	m_analyzeButton->setToolTip("Run the selected behavior analysis");
	connect(m_analyzeButton, &QPushButton::clicked, this, &TTDBehaviorWidget::runAnalysis);
	controlsLayout->addWidget(m_analyzeButton);

	mainLayout->addLayout(controlsLayout);

	// Progress bar
	m_progressBar = new QProgressBar(this);
	m_progressBar->setRange(0, 100);
	m_progressBar->setValue(0);
	m_progressBar->setVisible(false);
	mainLayout->addWidget(m_progressBar);

	// Status label
	m_statusLabel = new QLabel(this);
	m_statusLabel->setAlignment(Qt::AlignCenter);
	mainLayout->addWidget(m_statusLabel);

	// Results widget
	m_resultWidget = new TTDBehaviorResultWidget(this, m_data);
	mainLayout->addWidget(m_resultWidget, 1);
}

void TTDBehaviorWidget::runAnalysis()
{
	if (!m_controller || !m_controller->IsTTD())
	{
		QMessageBox::warning(this, "TTD Not Active", "TTD debugging is not active. Please load a TTD trace first.");
		return;
	}

	int selectedIndex = m_analysisSetCombo->currentIndex();
	if (selectedIndex < 0 || static_cast<size_t>(selectedIndex) >= m_analysisSets.size())
	{
		QMessageBox::warning(this, "No Analysis Selected", "Please select an analysis type.");
		return;
	}

	const TTDBehaviorAnalysisSet& analysisSet = m_analysisSets[selectedIndex];

	// Disable controls during analysis
	m_analyzeButton->setEnabled(false);
	m_analysisSetCombo->setEnabled(false);
	m_progressBar->setVisible(true);
	m_progressBar->setValue(0);
	m_statusLabel->setText("Running analysis...");

	// Clear previous results
	m_resultWidget->clearResults();

	// Create and start worker thread
	if (m_worker)
	{
		m_worker->terminate();
		m_worker->wait(1000);
		delete m_worker;
	}

	m_worker = new TTDBehaviorAnalysisWorker(m_controller, analysisSet, this);
	connect(m_worker, &TTDBehaviorAnalysisWorker::analysisProgress, this, &TTDBehaviorWidget::onAnalysisProgress);
	connect(m_worker, &TTDBehaviorAnalysisWorker::analysisCompleted, this, &TTDBehaviorWidget::onAnalysisCompleted);
	m_worker->start();
}

void TTDBehaviorWidget::onAnalysisProgress(int percentage, const QString& message)
{
	m_progressBar->setValue(percentage);
	m_statusLabel->setText(message);
}

void TTDBehaviorWidget::onAnalysisCompleted(bool success, const QString& message, const TTDBehaviorAnalysisResult& result)
{
	// Re-enable controls
	m_analyzeButton->setEnabled(true);
	m_analysisSetCombo->setEnabled(true);
	m_progressBar->setVisible(false);

	if (success)
	{
		m_resultWidget->setResults(result);
		m_statusLabel->setText(QString("Analysis complete: %1 events found").arg(result.events.size()));
	}
	else
	{
		m_statusLabel->setText(QString("Analysis failed: %1").arg(message));
	}
}


// Sidebar widget implementation
TTDBehaviorSidebarWidget::TTDBehaviorSidebarWidget(BinaryViewRef data)
	: SidebarWidget("TTD Behavior"), m_data(data)
{
	m_controller = DebuggerController::GetController(data);

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	m_behaviorWidget = new TTDBehaviorWidget(this, data);
	layout->addWidget(m_behaviorWidget);
}

TTDBehaviorSidebarWidget::~TTDBehaviorSidebarWidget()
{
}


// Sidebar widget type implementation
TTDBehaviorWidgetType::TTDBehaviorWidgetType()
	: SidebarWidgetType(QImage(":/debugger/ttd-events"), "TTD Behavior")  // TODO: Add dedicated icon
{
}

SidebarWidget* TTDBehaviorWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new TTDBehaviorSidebarWidget(data);
}

class TTDBehaviorContentClassifier : public SidebarContentClassifier
{
public:
	bool hasContent(ViewFrame*, BinaryViewRef data) override
	{
		auto controller = DebuggerController::GetController(data);
		if (!controller)
			return false;
		return controller->IsTTD();
	}
};

SidebarContentClassifier* TTDBehaviorWidgetType::contentClassifier(ViewFrame*, BinaryViewRef)
{
	return new TTDBehaviorContentClassifier();
}
