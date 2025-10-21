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

#include "ttdmemorywidget.h"
#include "ui.h"
#include <QGridLayout>
#include <QGroupBox>
#include <QMessageBox>
#include <QApplication>
#include <QHeaderView>
#include <QMenu>
#include <QClipboard>
#include <QCheckBox>
#include <QToolButton>
#include <QPropertyAnimation>
#include <QFrame>
#include <map>

// ColumnVisibilityDialog implementation
ColumnVisibilityDialog::ColumnVisibilityDialog(QWidget* parent, const QStringList& columnNames, const QList<bool>& visibility)
	: QDialog(parent)
{
	setWindowTitle("Column Visibility");
	setModal(true);
	resize(300, 400);
	
	QVBoxLayout* layout = new QVBoxLayout(this);
	
	QLabel* label = new QLabel("Select columns to display:");
	layout->addWidget(label);
	
	m_columnList = new QListWidget();
	
	for (int i = 0; i < columnNames.size(); ++i)
	{
		QListWidgetItem* item = new QListWidgetItem(columnNames[i]);
		item->setCheckState(visibility[i] ? Qt::Checked : Qt::Unchecked);
		item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
		m_columnList->addItem(item);
	}
	
	layout->addWidget(m_columnList);
	
	QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults);
	connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	
	// Handle restore defaults
	connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, [this]() {
		// Reset to default visibility (hide Event Type, Time End, Unique Thread ID)
		QList<bool> defaultVisibility;
		defaultVisibility << true  // Index
		              << false // Event Type (hidden by default)
		              << true  // Time Start
		              << false // Time End (hidden by default)
		              << true  // Access Type
		              << true  // Address
		              << true  // Size
		              << true  // Value
		              << true  // Thread ID
		              << false // Unique Thread ID (hidden by default)
		              << true; // IP
		              
		for (int i = 0; i < m_columnList->count() && i < defaultVisibility.size(); ++i)
		{
			QListWidgetItem* item = m_columnList->item(i);
			item->setCheckState(defaultVisibility[i] ? Qt::Checked : Qt::Unchecked);
		}
	});
	
	layout->addWidget(buttons);
}

QList<bool> ColumnVisibilityDialog::getColumnVisibility() const
{
	QList<bool> visibility;
	for (int i = 0; i < m_columnList->count(); ++i)
	{
		QListWidgetItem* item = m_columnList->item(i);
		visibility.append(item->checkState() == Qt::Checked);
	}
	return visibility;
}

// TTDMemoryQueryWidget implementation
TTDMemoryQueryWidget::TTDMemoryQueryWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(m_data);
	
	// Initialize column names and visibility
	m_columnNames << "Index" << "Event Type" << "Time Start" << "Time End" << "Access Type" 
	              << "Address" << "Size" << "Value" << "Thread ID" << "Unique Thread ID" << "IP";
	
	// Set default visibility (hide Event Type, Time End, Unique Thread ID)
	m_columnVisibility << true  // Index
	                   << false // Event Type (hidden by default)
	                   << true  // Time Start
	                   << false // Time End (hidden by default)
	                   << true  // Access Type
	                   << true  // Address
	                   << true  // Size
	                   << true  // Value
	                   << true  // Thread ID
	                   << false // Unique Thread ID (hidden by default)
	                   << true; // IP
	
	setupUI();
	setupUIActions();
}

TTDMemoryQueryWidget::~TTDMemoryQueryWidget()
{
}

void TTDMemoryQueryWidget::setupUI()
{
	// Set size policy to allow widget to adapt to sidebar space and prevent scroll bar clipping
	setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	
	// Create expandable group for query parameters
	// Create content widget for the expandable group
	QWidget* inputWidget = new QWidget();
	QFormLayout* inputLayout = new QFormLayout(inputWidget);
	
	// Address range inputs
	m_startAddressEdit = new QLineEdit();
	m_startAddressEdit->setToolTip("Start address in hexadecimal format");
	
	m_endAddressEdit = new QLineEdit();
	m_endAddressEdit->setToolTip("End address in hexadecimal format");
	
	// Set default values based on binary view address range
	if (m_data)
	{
		uint64_t startAddr = m_data->GetStart();
		uint64_t endAddr = m_data->GetEnd();
		m_startAddressEdit->setText(QString::asprintf("0x%llx", startAddr));
		m_endAddressEdit->setText(QString::asprintf("0x%llx", endAddr));
	}
	else
	{
		m_startAddressEdit->setPlaceholderText("0x00000000");
		m_endAddressEdit->setPlaceholderText("0xFFFFFFFF");
	}
	
	inputLayout->addRow("Start Address:", m_startAddressEdit);
	inputLayout->addRow("End Address:", m_endAddressEdit);
	
	// Memory access type checkboxes
	QHBoxLayout* accessLayout = new QHBoxLayout();
	m_readAccessCheck = new QCheckBox("Read");
	m_readAccessCheck->setChecked(true);
	m_readAccessCheck->setToolTip("Include memory read operations");
	
	m_writeAccessCheck = new QCheckBox("Write");
	m_writeAccessCheck->setChecked(true);
	m_writeAccessCheck->setToolTip("Include memory write operations");
	
	m_executeAccessCheck = new QCheckBox("Execute");
	m_executeAccessCheck->setChecked(false);
	m_executeAccessCheck->setToolTip("Include memory execute operations");
	
	accessLayout->addWidget(m_readAccessCheck);
	accessLayout->addWidget(m_writeAccessCheck);
	accessLayout->addWidget(m_executeAccessCheck);
	accessLayout->addStretch();
	
	inputLayout->addRow("Access Types:", accessLayout);
	
	// Control buttons
	QHBoxLayout* buttonLayout = new QHBoxLayout();
	m_queryButton = new QPushButton("Query Memory Events");
	m_queryButton->setToolTip("Execute TTD memory analysis query");
	connect(m_queryButton, &QPushButton::clicked, this, &TTDMemoryQueryWidget::performQuery);
	
	m_clearButton = new QPushButton("Clear Results");
	m_clearButton->setToolTip("Clear the results table");
	connect(m_clearButton, &QPushButton::clicked, this, &TTDMemoryQueryWidget::clearResults);
	
	buttonLayout->addWidget(m_queryButton);
	buttonLayout->addWidget(m_clearButton);
	buttonLayout->addStretch();
	
	inputLayout->addRow("", buttonLayout);
	
	// Connect Enter key press in line edits to perform query
	connect(m_startAddressEdit, &QLineEdit::returnPressed, this, &TTDMemoryQueryWidget::performQuery);
	connect(m_endAddressEdit, &QLineEdit::returnPressed, this, &TTDMemoryQueryWidget::performQuery);
	
	// Set the input widget as the content of the expandable group
	ExpandableGroup* expandableGroup = new ExpandableGroup(inputLayout, "Query Parameters", this, true);
	
	mainLayout->addWidget(expandableGroup, 0); // Give minimal space to expandable group
	
	// Results table
	setupTable();
	mainLayout->addWidget(m_resultsTable, 1); // Give most space to the table
	
	// Status label
	m_statusLabel = new QLabel("Ready");
	m_statusLabel->setStyleSheet("QLabel { font-size: 12px; }");
	mainLayout->addWidget(m_statusLabel);
	
	setLayout(mainLayout);
	
	// Button is always enabled - errors are shown in performQuery() if needed
	m_queryButton->setEnabled(true);
	m_queryButton->setToolTip("Execute TTD memory analysis query");
	updateStatus("Ready");
}

void TTDMemoryQueryWidget::setupTable()
{
	m_resultsTable = new QTableWidget();
	m_resultsTable->setColumnCount(m_columnNames.size());
	m_resultsTable->setHorizontalHeaderLabels(m_columnNames);
	
	// Set size policy to ensure table scrollbar works correctly within sidebar constraints
	m_resultsTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	
	// Configure table appearance
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setAlternatingRowColors(true);
	m_resultsTable->setSortingEnabled(true);
	m_resultsTable->verticalHeader()->setVisible(false);
	m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers); // Make cells non-editable
	
	// Set column widths
	QHeaderView* header = m_resultsTable->horizontalHeader();
	header->setStretchLastSection(true);
	m_resultsTable->setColumnWidth(0, 80);  // Index
	m_resultsTable->setColumnWidth(1, 100); // Event Type
	m_resultsTable->setColumnWidth(2, 120); // Time Start
	m_resultsTable->setColumnWidth(3, 120); // Time End
	m_resultsTable->setColumnWidth(4, 100); // Access Type
	m_resultsTable->setColumnWidth(5, 120); // Address
	m_resultsTable->setColumnWidth(6, 80);  // Size
	m_resultsTable->setColumnWidth(7, 120); // Value
	m_resultsTable->setColumnWidth(8, 80);  // Thread ID
	m_resultsTable->setColumnWidth(9, 100); // Unique Thread ID
	// IP column will stretch
	
	// Apply initial column visibility
	updateColumnVisibility();
	
	// Connect double-click handler
	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, 
			this, &TTDMemoryQueryWidget::onCellDoubleClicked);
	
	// Setup context menu
	setupContextMenu();
}

void TTDMemoryQueryWidget::setupContextMenu()
{
	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_resultsTable, &QTableWidget::customContextMenuRequested,
			this, &TTDMemoryQueryWidget::showContextMenu);
}

void TTDMemoryQueryWidget::setupUIActions()
{
	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();

	// Add Copy action with Ctrl+C support
	m_menu->addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&]() { copy(); }, [&]() { return canCopy(); }));
	
	m_menu->addAction("Copy Row", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy Row", UIAction([&]() { copySelectedRow(); }, [&]() { return canCopy(); }));
	
	m_menu->addAction("Copy Table", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy Table", UIAction([&]() { copyEntireTable(); }, [&]() { return m_resultsTable->rowCount() > 0; }));

	m_menu->addAction("Column Visibility...", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Column Visibility...", UIAction([&]() { showColumnVisibilityDialog(); }));
	
	m_menu->addAction("Reset Columns to Default", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Reset Columns to Default", UIAction([&]() { resetColumnsToDefault(); }));
}

void TTDMemoryQueryWidget::updateColumnVisibility()
{
	for (int i = 0; i < m_columnVisibility.size(); ++i)
	{
		m_resultsTable->setColumnHidden(i, !m_columnVisibility[i]);
	}
}

void TTDMemoryQueryWidget::performQuery()
{
	if (!m_controller || !m_controller->IsTTD())
	{
		QMessageBox::warning(this, "TTD Not Available", 
			"Time Travel Debugging is not available with the current target.");
		return;
	}
	
	// Parse input parameters
	uint64_t startAddress = parseAddress(m_startAddressEdit->text());
	uint64_t endAddress = parseAddress(m_endAddressEdit->text());
	
	if (endAddress <= startAddress)
	{
		QMessageBox::warning(this, "Invalid Address Range", 
			"End address must be greater than start address.");
		return;
	}
	
	TTDMemoryAccessType accessType = getSelectedAccessTypes();
	if (accessType == 0)
	{
		QMessageBox::warning(this, "No Access Type Selected", 
			"Please select at least one memory access type (Read, Write, or Execute).");
		return;
	}
	
	// Clear previous results
	clearResults();
	updateStatus("Executing TTD memory query...");
	
	// Disable query button during execution
	m_queryButton->setEnabled(false);
	QApplication::processEvents();
	
	try
	{
		// Execute the TTD memory query
		auto events = m_controller->GetTTDMemoryAccessForAddress(startAddress, endAddress, accessType);
		
		// Populate the results table
		m_resultsTable->setRowCount(events.size());
		
		for (size_t i = 0; i < events.size(); ++i)
		{
			const auto& event = events[i];
			
			// Index
			m_resultsTable->setItem(i, 0, new NumericalTableWidgetItem(QString("0x%1").arg(i, 0, 16), i));
			
			// Event Type
			m_resultsTable->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(event.eventType)));
			
			// Time Start
			QString timeStartStr = QString("%1:%2")
				.arg(event.timeStart.sequence, 0, 16)
				.arg(event.timeStart.step, 0, 16);
			uint64_t timeStartSortValue = (event.timeStart.sequence << 32) | (event.timeStart.step & 0xFFFFFFFF);
			m_resultsTable->setItem(i, 2, new NumericalTableWidgetItem(timeStartStr, timeStartSortValue));
			
			// Time End
			QString timeEndStr = QString("%1:%2")
				.arg(event.timeEnd.sequence, 0, 16)
				.arg(event.timeEnd.step, 0, 16);
			uint64_t timeEndSortValue = (event.timeEnd.sequence << 32) | (event.timeEnd.step & 0xFFFFFFFF);
			m_resultsTable->setItem(i, 3, new NumericalTableWidgetItem(timeEndStr, timeEndSortValue));
			
			// Access Type
			QString accessTypeStr;
			if (event.accessType & TTDMemoryRead) accessTypeStr += "R";
			if (event.accessType & TTDMemoryWrite) accessTypeStr += "W";
			if (event.accessType & TTDMemoryExecute) accessTypeStr += "E";
			m_resultsTable->setItem(i, 4, new QTableWidgetItem(accessTypeStr));
			
			// Address
			QString addressStr = QString("0x%1").arg(event.address, 0, 16);
			m_resultsTable->setItem(i, 5, new NumericalTableWidgetItem(addressStr, event.address));
			
			// Size
			m_resultsTable->setItem(i, 6, new NumericalTableWidgetItem(QString::number(event.size), event.size));
			
			// Value
			QString valueStr = QString("0x%1").arg(event.value, 0, 16);
			m_resultsTable->setItem(i, 7, new NumericalTableWidgetItem(valueStr, event.value));
			
			// Thread ID
			m_resultsTable->setItem(i, 8, new NumericalTableWidgetItem(QString::number(event.threadId), event.threadId));
			
			// Unique Thread ID
			m_resultsTable->setItem(i, 9, new NumericalTableWidgetItem(QString::number(event.uniqueThreadId), event.uniqueThreadId));
			
			// IP (Instruction Address)
			QString instrAddrStr = QString("0x%1").arg(event.instructionAddress, 0, 16);
			m_resultsTable->setItem(i, 10, new NumericalTableWidgetItem(instrAddrStr, event.instructionAddress));
		}
		
		updateStatus(QString("Found %1 memory access events").arg(events.size()));
	}
	catch (const std::exception& e)
	{
		QMessageBox::critical(this, "Query Error", 
			QString("Failed to execute TTD memory query: %1").arg(e.what()));
		updateStatus("Query failed");
	}
	
	// Re-enable query button
	m_queryButton->setEnabled(true);
}

void TTDMemoryQueryWidget::clearResults()
{
	m_resultsTable->setRowCount(0);
	updateStatus("Results cleared");
}

void TTDMemoryQueryWidget::onCellDoubleClicked(int row, int column)
{
	// Handle double-click events - navigate to address or position
	if (row < 0 || row >= m_resultsTable->rowCount())
		return;

	if (column == TimeStartColumn || column == TimeEndColumn)
	{
		// Parse position and navigate to it
		QTableWidgetItem* posItem = m_resultsTable->item(row, column);
		if (posItem && m_controller)
		{
			QString posStr = posItem->text();
			QStringList parts = posStr.split(':');
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
						QTableWidgetItem* ipItem = m_resultsTable->item(row, IPColumn);
						if (ipItem && m_data)
						{
							QString ipStr = ipItem->text();
							if (ipStr.startsWith("0x", Qt::CaseInsensitive))
							{
								bool ok;
								uint64_t ipAddress = ipStr.mid(2).toULongLong(&ok, 16);
								if (ok)
								{
									ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
									if (frame)
									{
										frame->navigate(m_data, ipAddress);
									}
								}
							}
						}
						updateStatus(QString("Time traveled to position %1 and navigated to instruction").arg(posStr));
					}
					else
					{
						updateStatus("Failed to navigate to position");
					}
				}
			}
		}
	}
	else if (column == AddressColumn || column == IPColumn)
	{
		// Navigate to address in disassembly view
		QTableWidgetItem* addrItem = m_resultsTable->item(row, column);
		if (addrItem && m_data)
		{
			QString addrStr = addrItem->text();
			if (addrStr.startsWith("0x", Qt::CaseInsensitive))
			{
				bool ok;
				uint64_t address = addrStr.mid(2).toULongLong(&ok, 16);
				if (ok)
				{
					// Navigate to the address in the disassembly view
					ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
					if (frame)
					{
						frame->navigate(m_data, address);
						updateStatus(QString("Navigated to address %1").arg(addrStr));
					}
					else
					{
						updateStatus(QString("Address: %1 (no view frame available)").arg(addrStr));
					}
				}
			}
		}
	}
}

void TTDMemoryQueryWidget::showColumnVisibilityDialog()
{
	ColumnVisibilityDialog dialog(this, m_columnNames, m_columnVisibility);
	if (dialog.exec() == QDialog::Accepted)
	{
		m_columnVisibility = dialog.getColumnVisibility();
		updateColumnVisibility();
	}
}

void TTDMemoryQueryWidget::contextMenuEvent(QContextMenuEvent* event)
{
	showContextMenu(event->pos());
}

void TTDMemoryQueryWidget::showContextMenu(const QPoint& position)
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}

bool TTDMemoryQueryWidget::canCopy()
{
	return m_resultsTable->currentItem() != nullptr;
}

void TTDMemoryQueryWidget::copy()
{
	copySelectedCell();
}

void TTDMemoryQueryWidget::copySelectedCell()
{
	QTableWidgetItem* item = m_resultsTable->currentItem();
	if (item)
	{
		QClipboard* clipboard = QApplication::clipboard();
		clipboard->setText(item->text());
	}
}

void TTDMemoryQueryWidget::copySelectedRow()
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
				rowData << (item ? item->text() : "");
			}
		}
		
		QClipboard* clipboard = QApplication::clipboard();
		clipboard->setText(rowData.join("\t"));
	}
}

void TTDMemoryQueryWidget::copyEntireTable()
{
	QStringList tableData;
	
	// Add headers
	QStringList headers;
	for (int col = 0; col < m_resultsTable->columnCount(); ++col)
	{
		if (!m_resultsTable->isColumnHidden(col))
		{
			headers << m_columnNames[col];
		}
	}
	tableData << headers.join("\t");
	
	// Add data rows
	for (int row = 0; row < m_resultsTable->rowCount(); ++row)
	{
		QStringList rowData;
		for (int col = 0; col < m_resultsTable->columnCount(); ++col)
		{
			if (!m_resultsTable->isColumnHidden(col))
			{
				QTableWidgetItem* item = m_resultsTable->item(row, col);
				rowData << (item ? item->text() : "");
			}
		}
		tableData << rowData.join("\t");
	}
	
	QClipboard* clipboard = QApplication::clipboard();
	clipboard->setText(tableData.join("\n"));
}

void TTDMemoryQueryWidget::resetColumnsToDefault()
{
	// Reset to default visibility (hide Event Type, Time End, Unique Thread ID)
	m_columnVisibility.clear();
	m_columnVisibility << true  // Index
	                   << false // Event Type (hidden by default)
	                   << true  // Time Start
	                   << false // Time End (hidden by default)
	                   << true  // Access Type
	                   << true  // Address
	                   << true  // Size
	                   << true  // Value
	                   << true  // Thread ID
	                   << false // Unique Thread ID (hidden by default)
	                   << true; // IP
	
	updateColumnVisibility();
}

void TTDMemoryQueryWidget::updateStatus(const QString& message)
{
	m_statusLabel->setText(message);
}

uint64_t TTDMemoryQueryWidget::parseAddress(const QString& text)
{
	QString cleanText = text.trimmed();
	if (cleanText.isEmpty())
		return 0;
		
	// Remove 0x prefix if present
	if (cleanText.startsWith("0x", Qt::CaseInsensitive))
		cleanText = cleanText.mid(2);
		
	bool ok;
	uint64_t address = cleanText.toULongLong(&ok, 16);
	return ok ? address : 0;
}

TTDMemoryAccessType TTDMemoryQueryWidget::getSelectedAccessTypes()
{
	TTDMemoryAccessType accessType = static_cast<TTDMemoryAccessType>(0);
	
	if (m_readAccessCheck->isChecked())
		accessType = static_cast<TTDMemoryAccessType>(accessType | TTDMemoryRead);
	if (m_writeAccessCheck->isChecked())
		accessType = static_cast<TTDMemoryAccessType>(accessType | TTDMemoryWrite);
	if (m_executeAccessCheck->isChecked())
		accessType = static_cast<TTDMemoryAccessType>(accessType | TTDMemoryExecute);
		
	return accessType;
}

void TTDMemoryQueryWidget::setParametersAndQuery(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType)
{
	// Set address fields
	m_startAddressEdit->setText(QString("0x%1").arg(startAddr, 0, 16));
	m_endAddressEdit->setText(QString("0x%1").arg(endAddr, 0, 16));
	
	// Set access type checkboxes
	m_readAccessCheck->setChecked(accessType & TTDMemoryRead);
	m_writeAccessCheck->setChecked(accessType & TTDMemoryWrite);
	m_executeAccessCheck->setChecked(accessType & TTDMemoryExecute);
	
	// Trigger the query
	performQuery();
}

void TTDMemoryQueryWidget::setParameters(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType)
{
	// Set address fields
	m_startAddressEdit->setText(QString("0x%1").arg(startAddr, 0, 16));
	m_endAddressEdit->setText(QString("0x%1").arg(endAddr, 0, 16));
	
	// Set access type checkboxes
	m_readAccessCheck->setChecked(accessType & TTDMemoryRead);
	m_writeAccessCheck->setChecked(accessType & TTDMemoryWrite);
	m_executeAccessCheck->setChecked(accessType & TTDMemoryExecute);
	
	// Don't trigger the query
}

void TTDMemoryQueryWidget::setParameters(const QString& startAddr, const QString& endAddr, TTDMemoryAccessType accessType)
{
	// Set address fields as strings
	if (!startAddr.isEmpty())
		m_startAddressEdit->setText(startAddr);
	if (!endAddr.isEmpty())
		m_endAddressEdit->setText(endAddr);
	
	// Set access type checkboxes
	m_readAccessCheck->setChecked(accessType & TTDMemoryRead);
	m_writeAccessCheck->setChecked(accessType & TTDMemoryWrite);
	m_executeAccessCheck->setChecked(accessType & TTDMemoryExecute);
	
	// Don't trigger the query
}

bool TTDMemoryQueryWidget::isUnused() const
{
	// Consider a tab unused if it has no results
	return m_resultsTable->rowCount() == 0;
}

// TTDMemoryWidget implementation (tab container)
TTDMemoryWidget::TTDMemoryWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(m_data);
	setupUI();
}

TTDMemoryWidget::~TTDMemoryWidget()
{
}

void TTDMemoryWidget::setupUI()
{
	setWindowTitle("TTD Memory Analysis");
	// Set size policy to allow widget to adapt to sidebar space and prevent scroll bar clipping
	setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	
	// Tab widget setup
	m_tabWidget = new QTabWidget(this);
	m_tabWidget->setTabsClosable(true);
	connect(m_tabWidget, &QTabWidget::tabCloseRequested, this, &TTDMemoryWidget::closeTab);
	
	// Create "+" button as corner widget
	m_newTabButton = new QToolButton(m_tabWidget);
	m_newTabButton->setText("+");
	m_newTabButton->setAutoRaise(true);
	m_newTabButton->setToolTip("New tab");
	connect(m_newTabButton, &QToolButton::clicked, this, &TTDMemoryWidget::createNewTab);
	
	// Set the button as corner widget
	m_tabWidget->setCornerWidget(m_newTabButton, Qt::TopRightCorner);
	
	mainLayout->addWidget(m_tabWidget);
	
	// Create initial tab
	createNewTab();
}

void TTDMemoryWidget::createNewTab()
{
	// Get parameters from current tab if exists
	TTDMemoryQueryWidget* currentWidget = qobject_cast<TTDMemoryQueryWidget*>(m_tabWidget->currentWidget());
	QString startAddr, endAddr;
	TTDMemoryAccessType accessType = static_cast<TTDMemoryAccessType>(0);
	
	if (currentWidget)
	{
		startAddr = currentWidget->getStartAddress();
		endAddr = currentWidget->getEndAddress();
		accessType = currentWidget->getCurrentAccessType();
	}
	
	// Create new tab
	TTDMemoryQueryWidget* queryWidget = new TTDMemoryQueryWidget(this, m_data);
	int tabIndex = m_tabWidget->addTab(queryWidget, QString("Query %1").arg(m_tabWidget->count() + 1));
	m_tabWidget->setCurrentIndex(tabIndex);
	
	// Set parameters from previous tab if any existed
	if (currentWidget && (!startAddr.isEmpty() || !endAddr.isEmpty() || accessType != 0))
	{
		queryWidget->setParameters(startAddr, endAddr, accessType);
	}
}

void TTDMemoryWidget::closeTab(int index)
{
	if (m_tabWidget->count() > 1)
	{
		QWidget* widget = m_tabWidget->widget(index);
		m_tabWidget->removeTab(index);
		widget->deleteLater();
	}
}

TTDMemoryQueryWidget* TTDMemoryWidget::getCurrentOrNewQueryWidget()
{
	// Get current tab widget
	TTDMemoryQueryWidget* currentWidget = qobject_cast<TTDMemoryQueryWidget*>(m_tabWidget->currentWidget());
	if (currentWidget)
		return currentWidget;
	
	// If no current widget or cast failed, create a new tab
	createNewTab();
	return qobject_cast<TTDMemoryQueryWidget*>(m_tabWidget->currentWidget());
}

void TTDMemoryWidget::setParametersAndQuery(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType)
{
	TTDMemoryQueryWidget* queryWidget = getCurrentOrNewQueryWidget();
	if (queryWidget)
	{
		queryWidget->setParametersAndQuery(startAddr, endAddr, accessType);
	}
}

void TTDMemoryWidget::setParametersAndQueryInNewTab(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType)
{
	// Check if the current tab is unused - if so, reuse it instead of creating a new tab
	TTDMemoryQueryWidget* currentWidget = qobject_cast<TTDMemoryQueryWidget*>(m_tabWidget->currentWidget());
	if (currentWidget && currentWidget->isUnused())
	{
		// Reuse the current unused tab
		currentWidget->setParametersAndQuery(startAddr, endAddr, accessType);
	}
	else
	{
		// Create a new tab since the current one is already in use
		createNewTab();
		TTDMemoryQueryWidget* queryWidget = qobject_cast<TTDMemoryQueryWidget*>(m_tabWidget->currentWidget());
		if (queryWidget)
		{
			queryWidget->setParametersAndQuery(startAddr, endAddr, accessType);
		}
	}
}



// TTDMemorySidebarWidget implementation
TTDMemorySidebarWidget::TTDMemorySidebarWidget(BinaryViewRef data) 
	: SidebarWidget("TTD Memory"), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	
	auto* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	
	m_memoryWidget = new TTDMemoryWidget(this, data);
	layout->addWidget(m_memoryWidget);
	
	setLayout(layout);
}

TTDMemorySidebarWidget::~TTDMemorySidebarWidget()
{
}

void TTDMemorySidebarWidget::setParametersAndQuery(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType)
{
	if (m_memoryWidget)
	{
		m_memoryWidget->setParametersAndQuery(startAddr, endAddr, accessType);
	}
}

void TTDMemorySidebarWidget::setParametersAndQueryInNewTab(uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType)
{
	if (m_memoryWidget)
	{
		m_memoryWidget->setParametersAndQueryInNewTab(startAddr, endAddr, accessType);
	}
}


// TTDMemoryWidgetType implementation
std::map<std::pair<ViewFrame*, BinaryViewRef>, TTDMemoryWidgetType::PendingQuery> TTDMemoryWidgetType::s_pendingQueries;

TTDMemoryWidgetType::TTDMemoryWidgetType()
	: SidebarWidgetType(QIcon(":/debugger/ttd-memory").pixmap(QSize(64, 64)).toImage(), "TTD Memory")
{
}

SidebarWidget* TTDMemoryWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	TTDMemorySidebarWidget* widget = new TTDMemorySidebarWidget(data);
	
	// Check if there's a pending query for this frame/data combination
	auto key = std::make_pair(frame, data);
	auto it = s_pendingQueries.find(key);
	if (it != s_pendingQueries.end())
	{
		const PendingQuery& query = it->second;
		widget->setParametersAndQuery(query.startAddr, query.endAddr, query.accessType);
		s_pendingQueries.erase(it);
	}
	
	return widget;
}

SidebarContentClassifier* TTDMemoryWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}

void TTDMemoryWidgetType::SetPendingQuery(ViewFrame* frame, BinaryViewRef data, uint64_t startAddr, uint64_t endAddr, TTDMemoryAccessType accessType)
{
	auto key = std::make_pair(frame, data);
	PendingQuery query;
	query.startAddr = startAddr;
	query.endAddr = endAddr;
	query.accessType = accessType;
	s_pendingQueries[key] = query;
	
	// Try to find if the widget is already active and apply the query immediately
	// This is a best-effort approach - the widget might apply the query when it becomes active
}

#include "ttdmemorywidget.moc"