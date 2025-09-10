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
#include "ui.h"
#include <QGroupBox>
#include <QScrollArea>
#include <QSplitter>
#include <QMessageBox>
#include <QApplication>
#include <QPropertyAnimation>
#include <QEasingCurve>
#include <QGridLayout>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QFrame>
#include <QTimer>
#include <map>

#include "moc_ttdcallswidget.cpp"

TTDCallsQueryWidget::TTDCallsQueryWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	
	// Initialize column names and default visibility
	m_columnNames = {
		"Index", "Event Type", "Time Start", "Time End", "Function",
		"Function Address", "Return Address", "Return Value", "Thread ID",
		"Unique Thread ID", "Parameters"
	};
	
	// Default visibility - show most important columns by default
	m_columnVisibility = {
		true,  // Index
		false, // Event Type (always "Call", less useful to show)
		true,  // Time Start
		true,  // Time End  
		true,  // Function
		true,  // Function Address
		true,  // Return Address
		true,  // Return Value
		false, // Thread ID
		false, // Unique Thread ID
		true   // Parameters
	};
	
	setupUI();
	setupTable();
	setupContextMenu();
	updateColumnVisibility();
}

TTDCallsQueryWidget::~TTDCallsQueryWidget()
{
}

void TTDCallsQueryWidget::setupUI()
{
	auto layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	
	// Create expandable input controls group
	// Create expandable group with content widget
	auto contentWidget = new QWidget();
	auto inputLayout = new QFormLayout(contentWidget);
	
	// Symbols input (single line for comma-separated symbols)
	m_symbolsEdit = new QLineEdit();
	m_symbolsEdit->setPlaceholderText("Enter symbols separated by commas, e.g.: kernel32!*, ntdll!NtCreateFile, module!symbol");
	inputLayout->addRow("Symbols:", m_symbolsEdit);
	
	// Address range filter (optional) - temporarily disabled due to crashes
	auto addressLayout = new QHBoxLayout();
	m_startAddressEdit = new QLineEdit();
	m_startAddressEdit->setPlaceholderText("Start address (hex, optional)");
	m_startAddressEdit->setEnabled(false); // Temporarily disabled due to crashes
	m_endAddressEdit = new QLineEdit();
	m_endAddressEdit->setPlaceholderText("End address (hex, optional)");
	m_endAddressEdit->setEnabled(false); // Temporarily disabled due to crashes
	addressLayout->addWidget(new QLabel("Return Address Range:"));
	addressLayout->addWidget(m_startAddressEdit);
	addressLayout->addWidget(new QLabel("to"));
	addressLayout->addWidget(m_endAddressEdit);
	addressLayout->addStretch();
	inputLayout->addRow(addressLayout);
	
	// Button layout
	auto buttonLayout = new QHBoxLayout();
	m_queryButton = new QPushButton("Query TTD Calls");
	m_queryButton->setToolTip("Execute TTD calls query with the specified symbols and address range");
	m_clearButton = new QPushButton("Clear Results");
	buttonLayout->addWidget(m_queryButton);
	buttonLayout->addWidget(m_clearButton);
	buttonLayout->addStretch();
	inputLayout->addRow(buttonLayout);
	
	// Set the content widget to the expandable group
	auto expandableGroup = new ExpandableGroup(inputLayout, "Query Parameters", this, true);
	layout->addWidget(expandableGroup, 0); // Give minimal space to expandable group
	
	// Results table
	m_resultsTable = new QTableWidget(0, static_cast<int>(m_columnNames.size()));
	m_resultsTable->setHorizontalHeaderLabels(m_columnNames);
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setAlternatingRowColors(true);
	m_resultsTable->setSortingEnabled(true);
	m_resultsTable->verticalHeader()->setVisible(false);
	m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers); // Make cells non-editable

	layout->addWidget(m_resultsTable, 1); // Give most space to the table
	
	// Connect signals
	connect(m_queryButton, &QPushButton::clicked, this, &TTDCallsQueryWidget::performQuery);
	connect(m_clearButton, &QPushButton::clicked, this, &TTDCallsQueryWidget::clearResults);
	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, this, &TTDCallsQueryWidget::onCellDoubleClicked);
	
	// Add Ctrl+C shortcut for copying current cell
	QShortcut* copyShortcut = new QShortcut(QKeySequence::Copy, m_resultsTable);
	connect(copyShortcut, &QShortcut::activated, this, &TTDCallsQueryWidget::copySelectedCell);
}

void TTDCallsQueryWidget::setupTable()
{
	// Set column widths
	QHeaderView* header = m_resultsTable->horizontalHeader();
	header->setStretchLastSection(true);
	
	// Set reasonable default column widths
	m_resultsTable->setColumnWidth(static_cast<int>(IndexColumn), 60);
	m_resultsTable->setColumnWidth(static_cast<int>(EventTypeColumn), 80);
	m_resultsTable->setColumnWidth(static_cast<int>(TimeStartColumn), 100);
	m_resultsTable->setColumnWidth(static_cast<int>(TimeEndColumn), 100);
	m_resultsTable->setColumnWidth(static_cast<int>(FunctionColumn), 200);
	m_resultsTable->setColumnWidth(static_cast<int>(FunctionAddressColumn), 120);
	m_resultsTable->setColumnWidth(static_cast<int>(ReturnAddressColumn), 120);
	m_resultsTable->setColumnWidth(static_cast<int>(ReturnValueColumn), 120);
	m_resultsTable->setColumnWidth(static_cast<int>(ThreadIdColumn), 80);
	m_resultsTable->setColumnWidth(static_cast<int>(UniqueThreadIdColumn), 100);
	// Parameters column will stretch
}

void TTDCallsQueryWidget::setupContextMenu()
{
	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_resultsTable, &QTableWidget::customContextMenuRequested, this, &TTDCallsQueryWidget::showContextMenu);
}



uint64_t TTDCallsQueryWidget::parseAddress(const QString& text)
{
	if (text.isEmpty())
		return 0;
		
	QString cleanText = text.trimmed();
	if (cleanText.startsWith("0x") || cleanText.startsWith("0X"))
		cleanText = cleanText.mid(2);
		
	bool ok;
	uint64_t address = cleanText.toULongLong(&ok, 16);
	return ok ? address : 0;
}

void TTDCallsQueryWidget::performQuery()
{
	if (!m_controller)
	{
		return;
	}
	
	if (!m_controller->IsConnected())
	{
		return;
	}
	
	// Get symbols string  
	QString symbolsText = m_symbolsEdit->text().trimmed();
	if (symbolsText.isEmpty())
	{
		return;
	}
	
	// Parse address range
	uint64_t startAddr = parseAddress(m_startAddressEdit->text());
	uint64_t endAddr = parseAddress(m_endAddressEdit->text());
	
	// Execute query
	auto events = m_controller->GetTTDCallsForSymbols(symbolsText.toStdString(), startAddr, endAddr);
	
	// Clear previous results
	m_resultsTable->setRowCount(0);
	
	if (events.empty())
	{
		return;
	}
	
	// Disable sorting while populating to avoid issues
	bool sortingEnabled = m_resultsTable->isSortingEnabled();
	m_resultsTable->setSortingEnabled(false);
	
	// Populate table
	m_resultsTable->setRowCount(static_cast<int>(events.size()));
	
	for (size_t i = 0; i < events.size(); ++i)
	{
		const auto& event = events[i];
		int row = static_cast<int>(i);
		
		// Index
		m_resultsTable->setItem(row, static_cast<int>(IndexColumn), 
			new NumericalTableWidgetItem(QString::number(i), i));
		
		// Event Type
		m_resultsTable->setItem(row, static_cast<int>(EventTypeColumn), 
			new QTableWidgetItem(QString::fromStdString(event.eventType)));
		
		// Time Start
		QString timeStartStr = QString("%1:%2").arg(event.timeStart.sequence, 0, 16).arg(event.timeStart.step, 0, 16);
		// For time sorting, use the sequence as primary sort key and step as secondary
		uint64_t timeStartSortValue = (event.timeStart.sequence << 32) | (event.timeStart.step & 0xFFFFFFFF);
		m_resultsTable->setItem(row, static_cast<int>(TimeStartColumn), 
			new NumericalTableWidgetItem(timeStartStr, timeStartSortValue));
		
		// Time End
		QString timeEndStr;
		uint64_t timeEndSortValue;
		// Check for max position values - both 0xffffffffffffffff and 0xfffffffffffffffe are considered max position
		// 0xffffffffffffffff is the traditional max value, 0xfffffffffffffffe is also used in some TTD scenarios
		if ((event.timeEnd.sequence == UINT64_MAX && event.timeEnd.step == UINT64_MAX) ||
		    (event.timeEnd.sequence == 0xfffffffffffffffeULL && event.timeEnd.step == 0xfffffffffffffffeULL))
		{
			timeEndStr = "Max Position";
			timeEndSortValue = UINT64_MAX; // Sort max position at the end
		}
		else
		{
			timeEndStr = QString("%1:%2").arg(event.timeEnd.sequence, 0, 16).arg(event.timeEnd.step, 0, 16);
			timeEndSortValue = (event.timeEnd.sequence << 32) | (event.timeEnd.step & 0xFFFFFFFF);
		}
		m_resultsTable->setItem(row, static_cast<int>(TimeEndColumn), 
			new NumericalTableWidgetItem(timeEndStr, timeEndSortValue));
		
		// Function
		m_resultsTable->setItem(row, static_cast<int>(FunctionColumn), 
			new QTableWidgetItem(QString::fromStdString(event.function)));
		
		// Function Address
		m_resultsTable->setItem(row, static_cast<int>(FunctionAddressColumn), 
			new NumericalTableWidgetItem(QString("0x%1").arg(event.functionAddress, 0, 16), event.functionAddress));
		
		// Return Address
		m_resultsTable->setItem(row, static_cast<int>(ReturnAddressColumn), 
			new NumericalTableWidgetItem(QString("0x%1").arg(event.returnAddress, 0, 16), event.returnAddress));
		
		// Return Value
		QString returnValueStr = event.hasReturnValue ? 
			QString("0x%1").arg(event.returnValue, 0, 16) : QString("N/A");
		uint64_t returnValueSortValue = event.hasReturnValue ? event.returnValue : 0;
		m_resultsTable->setItem(row, static_cast<int>(ReturnValueColumn), 
			new NumericalTableWidgetItem(returnValueStr, returnValueSortValue));
		
		// Thread ID
		m_resultsTable->setItem(row, static_cast<int>(ThreadIdColumn), 
			new NumericalTableWidgetItem(QString("0x%1").arg(event.threadId, 0, 16), event.threadId));
		
		// Unique Thread ID
		m_resultsTable->setItem(row, static_cast<int>(UniqueThreadIdColumn), 
			new NumericalTableWidgetItem(QString("0x%1").arg(event.uniqueThreadId, 0, 16), event.uniqueThreadId));
		
		// Parameters
		QString parametersStr;
		if (!event.parameters.empty())
		{
			QStringList paramList;
			for (const auto& param : event.parameters)
				paramList.append(QString::fromStdString(param));
			parametersStr = "{" + paramList.join(", ") + "}";
		}
		else
		{
			parametersStr = "{}";
		}
		m_resultsTable->setItem(row, static_cast<int>(ParametersColumn), 
			new QTableWidgetItem(parametersStr));
	}
	
	// Re-enable sorting if it was enabled
	m_resultsTable->setSortingEnabled(sortingEnabled);
	
	// Set default sort order: sort by index column (0) in ascending order
	m_resultsTable->sortByColumn(0, Qt::AscendingOrder);
	
	// Force table update
	m_resultsTable->update();
	m_resultsTable->repaint();
}

void TTDCallsQueryWidget::clearResults()
{
	m_resultsTable->setRowCount(0);
}

void TTDCallsQueryWidget::onCellDoubleClicked(int row, int column)
{
	// Handle double-click events - navigate to addresses or time travel
	if (row < 0 || row >= m_resultsTable->rowCount())
		return;

	if (column == TimeStartColumn || column == TimeEndColumn)
	{
		// Handle time travel for both time start and time end columns
		QTableWidgetItem* timeItem = m_resultsTable->item(row, column);
		if (timeItem && m_controller)
		{
			QString timeStr = timeItem->text();
			
			// Skip if this is "Max Position"
			if (timeStr == "Max Position")
				return;
			
			QStringList parts = timeStr.split(':');
			if (parts.size() == 2)
			{
				bool ok1, ok2;
				uint64_t sequence = parts[0].toULongLong(&ok1, 16);
				uint64_t step = parts[1].toULongLong(&ok2, 16);
				
				if (ok1 && ok2)
				{
					TTDPosition pos(sequence, step);
					if (m_controller->SetTTDPosition(pos))
					{
						QTableWidgetItem* funcAddrItem = m_resultsTable->item(row, FunctionAddressColumn);
						if (funcAddrItem && m_data)
						{
							QString funcAddrStr = funcAddrItem->text();
							if (funcAddrStr.startsWith("0x", Qt::CaseInsensitive))
							{
								bool ok;
								uint64_t funcAddress = funcAddrStr.mid(2).toULongLong(&ok, 16);
								if (ok)
								{
									ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
									if (frame)
									{
										frame->navigate(m_data, funcAddress);
									}
								}
							}
						}
					}
				}
			}
		}
	}
	else if (column == FunctionAddressColumn || column == ReturnAddressColumn)
	{
		// Navigate to address in Binary Ninja
		QTableWidgetItem* item = m_resultsTable->item(row, column);
		if (item)
		{
			QString addressText = item->text();
			if (addressText.startsWith("0x", Qt::CaseInsensitive))
			{
				bool ok;
				uint64_t address = addressText.mid(2).toULongLong(&ok, 16);
				
				if (ok && address != 0)
				{
					// Navigate to address in Binary Ninja
					ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
					if (frame)
					{
						frame->navigate(m_data, address);
					}
				}
			}
		}
	}
}

void TTDCallsQueryWidget::updateColumnVisibility()
{
	// Apply column visibility settings
	for (int i = 0; i < m_columnNames.size(); ++i)
	{
		m_resultsTable->setColumnHidden(i, !m_columnVisibility[i]);
	}
}

void TTDCallsQueryWidget::showColumnVisibilityDialog()
{
	// This would be implemented similar to TTDMemoryWidget's column visibility dialog
	// For now, just a placeholder
	QMessageBox::information(this, "Column Visibility", "Column visibility dialog not yet implemented");
}

void TTDCallsQueryWidget::resetColumnsToDefault()
{
	// Reset to default visibility
	m_columnVisibility = {
		true,  // Index
		false, // Event Type
		true,  // Time Start
		true,  // Time End  
		true,  // Function
		true,  // Function Address
		true,  // Return Address
		true,  // Return Value
		false, // Thread ID
		false, // Unique Thread ID
		true   // Parameters
	};
	updateColumnVisibility();
}

void TTDCallsQueryWidget::showContextMenu(const QPoint& position)
{
	QMenu contextMenu(this);
	
	contextMenu.addAction("Copy Cell", this, &TTDCallsQueryWidget::copySelectedCell);
	contextMenu.addAction("Copy Row", this, &TTDCallsQueryWidget::copySelectedRow);
	contextMenu.addAction("Copy All", this, &TTDCallsQueryWidget::copyEntireTable);
	contextMenu.addSeparator();
	contextMenu.addAction("Column Visibility...", this, &TTDCallsQueryWidget::showColumnVisibilityDialog);
	contextMenu.addAction("Reset Columns", this, &TTDCallsQueryWidget::resetColumnsToDefault);
	
	contextMenu.exec(m_resultsTable->mapToGlobal(position));
}

void TTDCallsQueryWidget::copySelectedCell()
{
	QTableWidgetItem* item = m_resultsTable->currentItem();
	if (item)
	{
		QApplication::clipboard()->setText(item->text());
	}
}

void TTDCallsQueryWidget::copySelectedRow()
{
	int row = m_resultsTable->currentRow();
	if (row >= 0)
	{
		QStringList rowData;
		for (int col = 0; col < m_resultsTable->columnCount(); ++col)
		{
			if (!m_resultsTable->isColumnHidden(col))
			{
				QTableWidgetItem* item = m_resultsTable->item(row, col);
				rowData.append(item ? item->text() : "");
			}
		}
		QApplication::clipboard()->setText(rowData.join("\t"));
	}
}

void TTDCallsQueryWidget::copyEntireTable()
{
	QStringList tableData;
	
	// Header
	QStringList headerData;
	for (int col = 0; col < m_resultsTable->columnCount(); ++col)
	{
		if (!m_resultsTable->isColumnHidden(col))
		{
			headerData.append(m_columnNames[col]);
		}
	}
	tableData.append(headerData.join("\t"));
	
	// Data rows
	for (int row = 0; row < m_resultsTable->rowCount(); ++row)
	{
		QStringList rowData;
		for (int col = 0; col < m_resultsTable->columnCount(); ++col)
		{
			if (!m_resultsTable->isColumnHidden(col))
			{
				QTableWidgetItem* item = m_resultsTable->item(row, col);
				rowData.append(item ? item->text() : "");
			}
		}
		tableData.append(rowData.join("\t"));
	}
	
	QApplication::clipboard()->setText(tableData.join("\n"));
}

void TTDCallsQueryWidget::setParametersAndQuery(const std::string& symbols, uint64_t startAddr, uint64_t endAddr)
{
	// Set symbol parameters
	m_symbolsEdit->setText(QString::fromStdString(symbols));
	
	// Set address range
	if (startAddr != 0)
		m_startAddressEdit->setText(QString("0x%1").arg(startAddr, 0, 16));
	if (endAddr != 0)
		m_endAddressEdit->setText(QString("0x%1").arg(endAddr, 0, 16));
	
	// Execute query
	performQuery();
}

bool TTDCallsQueryWidget::isUnused() const
{
	// Consider a tab unused if it has no results
	return m_resultsTable->rowCount() == 0;
}

// TTDCallsWidget implementation

TTDCallsWidget::TTDCallsWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	setupUI();
}

TTDCallsWidget::~TTDCallsWidget()
{
}

void TTDCallsWidget::setupUI()
{
	auto layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	
	// Tab widget setup
	m_tabWidget = new QTabWidget();
	m_tabWidget->setTabsClosable(true);
	
	// Create "+" button as corner widget (matches TTD Memory widget)
	m_newTabButton = new QToolButton();
	m_newTabButton->setText("+");
	m_newTabButton->setAutoRaise(true);
	m_newTabButton->setToolTip("New TTD Calls Query Tab");
	
	// Set the button as corner widget
	m_tabWidget->setCornerWidget(m_newTabButton, Qt::TopRightCorner);
	
	layout->addWidget(m_tabWidget);
	
	// Create initial tab
	createNewTab();
	
	// Connect signals
	connect(m_newTabButton, &QToolButton::clicked, this, &TTDCallsWidget::createNewTab);
	connect(m_tabWidget, &QTabWidget::tabCloseRequested, this, &TTDCallsWidget::closeTab);
}

void TTDCallsWidget::createNewTab()
{
	auto queryWidget = new TTDCallsQueryWidget(this, m_data);
	int index = m_tabWidget->addTab(queryWidget, QString("Query %1").arg(m_tabWidget->count() + 1));
	m_tabWidget->setCurrentIndex(index);
}

void TTDCallsWidget::closeTab(int index)
{
	if (m_tabWidget->count() > 1)
	{
		QWidget* widget = m_tabWidget->widget(index);
		m_tabWidget->removeTab(index);
		delete widget;
	}
}

TTDCallsQueryWidget* TTDCallsWidget::getCurrentOrNewQueryWidget()
{
	// Get current tab widget
	TTDCallsQueryWidget* currentWidget = qobject_cast<TTDCallsQueryWidget*>(m_tabWidget->currentWidget());
	if (currentWidget)
		return currentWidget;
	
	// If no current widget or cast failed, create a new tab
	createNewTab();
	return qobject_cast<TTDCallsQueryWidget*>(m_tabWidget->currentWidget());
}

void TTDCallsWidget::setParametersAndQuery(const std::string& symbols, uint64_t startAddr, uint64_t endAddr)
{
	auto queryWidget = getCurrentOrNewQueryWidget();
	if (queryWidget)
		queryWidget->setParametersAndQuery(symbols, startAddr, endAddr);
}

void TTDCallsWidget::setParametersAndQueryInNewTab(const std::string& symbols, uint64_t startAddr, uint64_t endAddr)
{
	// Check if the current tab is unused - if so, reuse it instead of creating a new tab
	TTDCallsQueryWidget* currentWidget = qobject_cast<TTDCallsQueryWidget*>(m_tabWidget->currentWidget());
	if (currentWidget && currentWidget->isUnused())
	{
		// Reuse the current unused tab
		currentWidget->setParametersAndQuery(symbols, startAddr, endAddr);
	}
	else
	{
		// Create a new tab since the current one is already in use
		createNewTab();
		TTDCallsQueryWidget* queryWidget = qobject_cast<TTDCallsQueryWidget*>(m_tabWidget->currentWidget());
		if (queryWidget)
		{
			queryWidget->setParametersAndQuery(symbols, startAddr, endAddr);
		}
	}
}

// TTDCallsSidebarWidget implementation

TTDCallsSidebarWidget::TTDCallsSidebarWidget(BinaryViewRef data) : SidebarWidget("TTD Calls"), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	
	auto layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	
	m_callsWidget = new TTDCallsWidget(this, data);
	layout->addWidget(m_callsWidget);
}

TTDCallsSidebarWidget::~TTDCallsSidebarWidget()
{
}

void TTDCallsSidebarWidget::setParametersAndQuery(const std::string& symbols, uint64_t startAddr, uint64_t endAddr)
{
	if (m_callsWidget)
		m_callsWidget->setParametersAndQuery(symbols, startAddr, endAddr);
}

void TTDCallsSidebarWidget::setParametersAndQueryInNewTab(const std::string& symbols, uint64_t startAddr, uint64_t endAddr)
{
	if (m_callsWidget)
		m_callsWidget->setParametersAndQueryInNewTab(symbols, startAddr, endAddr);
}

// TTDCallsWidgetType implementation

std::map<std::pair<ViewFrame*, BinaryViewRef>, TTDCallsWidgetType::PendingQuery> TTDCallsWidgetType::s_pendingQueries;

TTDCallsWidgetType::TTDCallsWidgetType() : SidebarWidgetType(QImage(":/debugger/ttd-calls"), "TTD Calls")
{
}

SidebarWidget* TTDCallsWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	auto widget = new TTDCallsSidebarWidget(data);
	
	// Check for pending query
	auto key = std::make_pair(frame, data);
	auto it = s_pendingQueries.find(key);
	if (it != s_pendingQueries.end())
	{
		widget->setParametersAndQuery(it->second.symbols, it->second.startAddr, it->second.endAddr);
		s_pendingQueries.erase(it);
	}
	
	return widget;
}

SidebarContentClassifier* TTDCallsWidgetType::contentClassifier(ViewFrame*, BinaryViewRef)
{
	return nullptr; // No content classification needed
}

void TTDCallsWidgetType::SetPendingQuery(ViewFrame* frame, BinaryViewRef data, const std::string& symbols, uint64_t startAddr, uint64_t endAddr)
{
	auto key = std::make_pair(frame, data);
	PendingQuery query;
	query.symbols = symbols;
	query.startAddr = startAddr;
	query.endAddr = endAddr;
	s_pendingQueries[key] = query;
}