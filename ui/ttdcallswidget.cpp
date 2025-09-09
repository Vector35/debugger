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

#include "ttdcallswidget.h"
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QTextStream>
#include <QHeaderView>
#include <QSplitter>
#include <QGroupBox>
#include <QGridLayout>
#include <QDateTime>
#include <QProgressDialog>
#include <QThread>
#include <QRegularExpression>

TTDCallsSidebarWidget::TTDCallsSidebarWidget(QWidget* parent, BinaryViewRef data) :
	SidebarWidget(parent), m_data(data)
{
	auto layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	
	m_widget = new TTDCallsWidget(this, data);
	layout->addWidget(m_widget);
}

TTDCallsWidgetType::TTDCallsWidgetType() : SidebarWidgetType(QImage(":/debugger/ttd-calls"), "TTD Calls")
{
}

SidebarWidget* TTDCallsWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new TTDCallsSidebarWidget(frame, data);
}

TTDCallsWidget::TTDCallsWidget(QWidget* parent, BinaryViewRef data) :
	QWidget(parent), m_data(data)
{
	setupUI();
}

void TTDCallsWidget::setupUI()
{
	m_layout = new QVBoxLayout(this);
	m_layout->setContentsMargins(10, 10, 10, 10);
	m_layout->setSpacing(10);

	// Query controls group
	m_queryGroup = new QGroupBox("TTD.Calls Query", this);
	auto queryLayout = new QGridLayout(m_queryGroup);

	// Symbol input
	queryLayout->addWidget(new QLabel("Symbol(s):"), 0, 0);
	m_symbolsEdit = new QLineEdit(this);
	m_symbolsEdit->setPlaceholderText("e.g., \"kernel32!*\", \"module!symbol1\", \"module!symbol2\"");
	m_symbolsEdit->setMinimumWidth(400);
	queryLayout->addWidget(m_symbolsEdit, 0, 1, 1, 2);

	// Address range filter
	m_addressRangeCheck = new QCheckBox("Filter by Return Address Range:", this);
	queryLayout->addWidget(m_addressRangeCheck, 1, 0);
	m_addressRangeEdit = new QLineEdit(this);
	m_addressRangeEdit->setPlaceholderText("0x7ff7967a0000-0x7ff7967a7000");
	m_addressRangeEdit->setEnabled(false);
	queryLayout->addWidget(m_addressRangeEdit, 1, 1);

	// Buttons
	auto buttonLayout = new QHBoxLayout();
	m_queryButton = new QPushButton("Execute Query", this);
	m_queryButton->setDefault(true);
	m_clearButton = new QPushButton("Clear Results", this);
	m_exportButton = new QPushButton("Export...", this);
	m_exportButton->setEnabled(false);
	
	buttonLayout->addWidget(m_queryButton);
	buttonLayout->addWidget(m_clearButton);
	buttonLayout->addWidget(m_exportButton);
	buttonLayout->addStretch();
	
	queryLayout->addLayout(buttonLayout, 2, 0, 1, 3);

	m_layout->addWidget(m_queryGroup);

	// Results table
	m_resultsTable = new QTableWidget(this);
	m_resultsTable->setColumnCount(10);
	
	QStringList headers;
	headers << "Index" << "Thread ID" << "Unique Thread ID" << "Function"
			<< "Function Address" << "Return Address" << "Return Value"
			<< "Time Start" << "Time End" << "Parameters";
	m_resultsTable->setHorizontalHeaderLabels(headers);
	
	// Configure table
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setAlternatingRowColors(true);
	m_resultsTable->setSortingEnabled(true);
	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	
	// Auto-resize columns
	auto header = m_resultsTable->horizontalHeader();
	header->setStretchLastSection(true);
	header->setSectionResizeMode(QHeaderView::Interactive);
	
	m_layout->addWidget(m_resultsTable);

	// Status label
	m_statusLabel = new QLabel("Ready to execute TTD.Calls queries", this);
	m_statusLabel->setStyleSheet("color: #666; font-style: italic;");
	m_layout->addWidget(m_statusLabel);

	// Context menu actions
	m_copyAction = new QAction("Copy", this);
	m_goToFunctionAction = new QAction("Go to Function", this);
	m_goToReturnAction = new QAction("Go to Return Address", this);
	m_setPositionAction = new QAction("Set TTD Position to Start", this);

	// Connect signals
	connect(m_queryButton, &QPushButton::clicked, this, &TTDCallsWidget::onQueryButtonClicked);
	connect(m_clearButton, &QPushButton::clicked, this, &TTDCallsWidget::onClearButtonClicked);
	connect(m_exportButton, &QPushButton::clicked, this, &TTDCallsWidget::onExportButtonClicked);
	connect(m_resultsTable, &QTableWidget::customContextMenuRequested, this, &TTDCallsWidget::onResultsTableContextMenu);
	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, this, &TTDCallsWidget::onResultsTableItemDoubleClicked);
	connect(m_addressRangeCheck, &QCheckBox::toggled, this, &TTDCallsWidget::onAddressRangeToggled);
	connect(m_symbolsEdit, &QLineEdit::returnPressed, this, &TTDCallsWidget::onQueryButtonClicked);
	
	connect(m_copyAction, &QAction::triggered, this, &TTDCallsWidget::copySelectedToClipboard);
	connect(m_goToFunctionAction, &QAction::triggered, [this]() {
		int row = m_resultsTable->currentRow();
		if (row >= 0) {
			auto item = m_resultsTable->item(row, FunctionAddressColumn);
			if (item) {
				bool ok;
				uint64_t addr = item->text().toULongLong(&ok, 16);
				if (ok) navigateToAddress(addr);
			}
		}
	});
	connect(m_goToReturnAction, &QAction::triggered, [this]() {
		int row = m_resultsTable->currentRow();
		if (row >= 0) {
			auto item = m_resultsTable->item(row, ReturnAddressColumn);
			if (item) {
				bool ok;
				uint64_t addr = item->text().toULongLong(&ok, 16);
				if (ok) navigateToAddress(addr);
			}
		}
	});
	connect(m_setPositionAction, &QAction::triggered, [this]() {
		int row = m_resultsTable->currentRow();
		if (row >= 0) {
			auto timeStartItem = m_resultsTable->item(row, TimeStartColumn);
			if (timeStartItem && !timeStartItem->text().isEmpty()) {
				// Parse time position and set TTD position
				QString timeText = timeStartItem->text();
				QRegularExpression re("([0-9A-Fa-f]+):([0-9A-Fa-f]+)");
				auto match = re.match(timeText);
				if (match.hasMatch()) {
					bool ok1, ok2;
					uint64_t sequence = match.captured(1).toULongLong(&ok1, 16);
					uint64_t step = match.captured(2).toULongLong(&ok2, 16);
					if (ok1 && ok2) {
						auto controller = DebuggerController::GetController(m_data);
						if (controller) {
							TTDPosition pos;
							pos.sequence = sequence;
							pos.step = step;
							controller->SetTTDPosition(pos);
							m_statusLabel->setText(QString("Set TTD position to %1:%2").arg(sequence, 0, 16).arg(step, 0, 16));
						}
					}
				}
			}
		}
	});
}

void TTDCallsWidget::onQueryButtonClicked()
{
	// Get symbols input
	QString symbolsText = m_symbolsEdit->text().trimmed();
	if (symbolsText.isEmpty()) {
		QMessageBox::warning(this, "Invalid Input", "Please enter at least one symbol pattern.");
		return;
	}

	auto symbols = parseSymbolsInput(symbolsText);
	if (symbols.empty()) {
		QMessageBox::warning(this, "Invalid Input", "Failed to parse symbol patterns.");
		return;
	}

	// Check if we have a debugger controller
	auto controller = DebuggerController::GetController(m_data);
	if (!controller) {
		QMessageBox::warning(this, "Debugger Error", "No debugger controller available.");
		return;
	}

	// Check if TTD is supported
	if (!controller->IsTTD()) {
		QMessageBox::warning(this, "TTD Not Available", "TTD features are not available with the current debug adapter.");
		return;
	}

	m_statusLabel->setText("Executing TTD.Calls query...");
	m_queryButton->setEnabled(false);
	QApplication::processEvents();

	std::vector<TTDCallEvent> events;
	
	try {
		// Check if address range filter is enabled
		if (m_addressRangeCheck->isChecked()) {
			QString rangeText = m_addressRangeEdit->text().trimmed();
			uint64_t minAddr, maxAddr;
			if (parseAddressRange(rangeText, minAddr, maxAddr)) {
				events = controller->GetTTDCallsWithAddressFilter(symbols, minAddr, maxAddr);
			} else {
				QMessageBox::warning(this, "Invalid Address Range", "Please enter a valid address range (e.g., 0x7ff7967a0000-0x7ff7967a7000).");
				m_queryButton->setEnabled(true);
				m_statusLabel->setText("Ready");
				return;
			}
		} else {
			events = controller->GetTTDCalls(symbols);
		}

		populateResults(events);
		m_statusLabel->setText(QString("Found %1 call events").arg(events.size()));
		m_exportButton->setEnabled(!events.empty());
		
	} catch (const std::exception& e) {
		QMessageBox::critical(this, "Query Error", QString("Failed to execute TTD.Calls query: %1").arg(e.what()));
		m_statusLabel->setText("Query failed");
	}

	m_queryButton->setEnabled(true);
}

void TTDCallsWidget::onClearButtonClicked()
{
	clearResults();
}

void TTDCallsWidget::onExportButtonClicked()
{
	exportResults();
}

void TTDCallsWidget::onResultsTableContextMenu(const QPoint& pos)
{
	int row = m_resultsTable->rowAt(pos.y());
	if (row < 0) return;

	QMenu menu(this);
	menu.addAction(m_copyAction);
	menu.addSeparator();
	menu.addAction(m_goToFunctionAction);
	menu.addAction(m_goToReturnAction);
	menu.addSeparator();
	menu.addAction(m_setPositionAction);

	menu.exec(m_resultsTable->mapToGlobal(pos));
}

void TTDCallsWidget::onResultsTableItemDoubleClicked(int row, int column)
{
	if (row < 0) return;

	// Double-click on function address or return address columns to navigate
	if (column == FunctionAddressColumn || column == ReturnAddressColumn) {
		auto item = m_resultsTable->item(row, column);
		if (item) {
			bool ok;
			uint64_t addr = item->text().toULongLong(&ok, 16);
			if (ok) navigateToAddress(addr);
		}
	}
}

void TTDCallsWidget::onAddressRangeToggled(bool enabled)
{
	m_addressRangeEdit->setEnabled(enabled);
}

void TTDCallsWidget::populateResults(const std::vector<TTDCallEvent>& events)
{
	clearResults();
	
	m_resultsTable->setRowCount(events.size());
	
	for (size_t i = 0; i < events.size(); i++) {
		const auto& event = events[i];
		
		// Index
		m_resultsTable->setItem(i, IndexColumn, new QTableWidgetItem(QString("0x%1").arg(i, 0, 16)));
		
		// Thread ID
		m_resultsTable->setItem(i, ThreadIdColumn, new QTableWidgetItem(QString("0x%1").arg(event.threadId, 0, 16)));
		
		// Unique Thread ID
		m_resultsTable->setItem(i, UniqueThreadIdColumn, new QTableWidgetItem(QString("0x%1").arg(event.uniqueThreadId, 0, 16)));
		
		// Function name
		m_resultsTable->setItem(i, FunctionColumn, new QTableWidgetItem(QString::fromStdString(event.function)));
		
		// Function address
		m_resultsTable->setItem(i, FunctionAddressColumn, new QTableWidgetItem(QString("0x%1").arg(event.functionAddress, 0, 16)));
		
		// Return address
		m_resultsTable->setItem(i, ReturnAddressColumn, new QTableWidgetItem(QString("0x%1").arg(event.returnAddress, 0, 16)));
		
		// Return value
		if (event.hasReturnValue) {
			m_resultsTable->setItem(i, ReturnValueColumn, new QTableWidgetItem(QString("0x%1").arg(event.returnValue, 0, 16)));
		} else {
			m_resultsTable->setItem(i, ReturnValueColumn, new QTableWidgetItem("N/A"));
		}
		
		// Time start
		m_resultsTable->setItem(i, TimeStartColumn, new QTableWidgetItem(QString("%1:%2").arg(event.timeStart.sequence, 0, 16).arg(event.timeStart.step, 0, 16)));
		
		// Time end
		m_resultsTable->setItem(i, TimeEndColumn, new QTableWidgetItem(QString("%1:%2").arg(event.timeEnd.sequence, 0, 16).arg(event.timeEnd.step, 0, 16)));
		
		// Parameters
		QStringList paramStrs;
		for (uint64_t param : event.parameters) {
			paramStrs << QString("0x%1").arg(param, 0, 16);
		}
		QString paramText = paramStrs.isEmpty() ? "N/A" : QString("{%1}").arg(paramStrs.join(", "));
		m_resultsTable->setItem(i, ParametersColumn, new QTableWidgetItem(paramText));
	}
	
	m_resultsTable->resizeColumnsToContents();
}

void TTDCallsWidget::clearResults()
{
	m_resultsTable->setRowCount(0);
	m_statusLabel->setText("Ready to execute TTD.Calls queries");
	m_exportButton->setEnabled(false);
}

void TTDCallsWidget::exportResults()
{
	if (m_resultsTable->rowCount() == 0) {
		QMessageBox::information(this, "No Data", "No results to export.");
		return;
	}

	QString fileName = QFileDialog::getSaveFileName(this, "Export TTD.Calls Results", 
		QString("ttd_calls_%1.csv").arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")), 
		"CSV Files (*.csv)");
	
	if (fileName.isEmpty()) return;

	QFile file(fileName);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
		QMessageBox::critical(this, "Export Error", QString("Failed to open file: %1").arg(file.errorString()));
		return;
	}

	QTextStream out(&file);
	
	// Write headers
	QStringList headers;
	for (int col = 0; col < m_resultsTable->columnCount(); col++) {
		headers << m_resultsTable->horizontalHeaderItem(col)->text();
	}
	out << headers.join(",") << "\n";
	
	// Write data
	for (int row = 0; row < m_resultsTable->rowCount(); row++) {
		QStringList rowData;
		for (int col = 0; col < m_resultsTable->columnCount(); col++) {
			auto item = m_resultsTable->item(row, col);
			QString value = item ? item->text() : "";
			// Escape commas and quotes in CSV
			if (value.contains(",") || value.contains("\"")) {
				value = "\"" + value.replace("\"", "\"\"") + "\"";
			}
			rowData << value;
		}
		out << rowData.join(",") << "\n";
	}

	QMessageBox::information(this, "Export Complete", QString("Results exported to: %1").arg(fileName));
}

void TTDCallsWidget::copySelectedToClipboard()
{
	auto selection = m_resultsTable->selectionModel()->selectedRows();
	if (selection.isEmpty()) return;

	QStringList lines;
	
	// Add header
	QStringList headers;
	for (int col = 0; col < m_resultsTable->columnCount(); col++) {
		headers << m_resultsTable->horizontalHeaderItem(col)->text();
	}
	lines << headers.join("\t");
	
	// Add selected rows
	for (const auto& index : selection) {
		QStringList rowData;
		for (int col = 0; col < m_resultsTable->columnCount(); col++) {
			auto item = m_resultsTable->item(index.row(), col);
			rowData << (item ? item->text() : "");
		}
		lines << rowData.join("\t");
	}

	QApplication::clipboard()->setText(lines.join("\n"));
}

void TTDCallsWidget::navigateToAddress(uint64_t address)
{
	if (!m_data) return;
	
	// Navigate to the address in the binary view
	if (auto frame = ViewFrame::viewFrameForWidget(this)) {
		frame->navigate(m_data, address);
	}
}

std::vector<std::string> TTDCallsWidget::parseSymbolsInput(const QString& input)
{
	std::vector<std::string> symbols;
	
	// Parse comma-separated quoted strings or simple symbols
	QRegularExpression re(R"("([^"]+)"|([^,\s]+))");
	auto matches = re.globalMatch(input);
	
	while (matches.hasNext()) {
		auto match = matches.next();
		QString symbol = match.captured(1); // Quoted string
		if (symbol.isEmpty()) {
			symbol = match.captured(2); // Unquoted string
		}
		if (!symbol.isEmpty()) {
			symbols.push_back(symbol.toStdString());
		}
	}
	
	return symbols;
}

bool TTDCallsWidget::parseAddressRange(const QString& input, uint64_t& minAddr, uint64_t& maxAddr)
{
	QRegularExpression re(R"(0x([0-9A-Fa-f]+)\s*-\s*0x([0-9A-Fa-f]+))");
	auto match = re.match(input.trimmed());
	
	if (!match.hasMatch()) return false;
	
	bool ok1, ok2;
	minAddr = match.captured(1).toULongLong(&ok1, 16);
	maxAddr = match.captured(2).toULongLong(&ok2, 16);
	
	return ok1 && ok2 && minAddr < maxAddr;
}

#include "ttdcallswidget.moc"