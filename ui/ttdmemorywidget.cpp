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
	setMinimumSize(800, 600);
	
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	
	// Input controls group
	QGroupBox* inputGroup = new QGroupBox("Query Parameters");
	QFormLayout* inputLayout = new QFormLayout(inputGroup);
	
	// Address range inputs
	m_startAddressEdit = new QLineEdit();
	m_startAddressEdit->setPlaceholderText("0x00000000");
	m_startAddressEdit->setToolTip("Start address in hexadecimal format");
	inputLayout->addRow("Start Address:", m_startAddressEdit);
	
	m_endAddressEdit = new QLineEdit();
	m_endAddressEdit->setPlaceholderText("0xFFFFFFFF");
	m_endAddressEdit->setToolTip("End address in hexadecimal format");
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
	connect(m_queryButton, &QPushButton::clicked, this, &TTDMemoryWidget::performQuery);
	
	m_clearButton = new QPushButton("Clear Results");
	m_clearButton->setToolTip("Clear the results table");
	connect(m_clearButton, &QPushButton::clicked, this, &TTDMemoryWidget::clearResults);
	
	buttonLayout->addWidget(m_queryButton);
	buttonLayout->addWidget(m_clearButton);
	buttonLayout->addStretch();
	
	inputLayout->addRow("", buttonLayout);
	
	mainLayout->addWidget(inputGroup);
	
	// Results table
	setupTable();
	mainLayout->addWidget(m_resultsTable);
	
	// Status label
	m_statusLabel = new QLabel("Ready");
	m_statusLabel->setStyleSheet("QLabel { color: #666; font-size: 12px; }");
	mainLayout->addWidget(m_statusLabel);
	
	setLayout(mainLayout);
	
	// Update UI state based on controller
	bool canQuery = false;
	if (m_controller)
	{
		canQuery = m_controller->IsTTD();
	}
	
	m_queryButton->setEnabled(canQuery);
	
	if (!canQuery)
	{
		if (!m_controller)
		{
			updateStatus("No debugger controller available");
		}
		else if (!m_controller->IsTTD())
		{
			updateStatus("TTD (Time Travel Debugging) not available with current target");
		}
	}
	else
	{
		updateStatus("Ready - TTD memory analysis available");
	}
}

void TTDMemoryWidget::setupTable()
{
	m_resultsTable = new QTableWidget();
	m_resultsTable->setColumnCount(9);
	
	QStringList headers;
	headers << "Event Type" << "Time Start" << "Time End" << "Access Type" << "Address" << "Size" << "Thread ID" << "Unique Thread ID" << "Instruction Address";
	m_resultsTable->setHorizontalHeaderLabels(headers);
	
	// Configure table appearance
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setAlternatingRowColors(true);
	m_resultsTable->setSortingEnabled(true);
	m_resultsTable->verticalHeader()->setVisible(false);
	
	// Set column widths
	QHeaderView* header = m_resultsTable->horizontalHeader();
	header->setStretchLastSection(true);
	m_resultsTable->setColumnWidth(0, 100); // Event Type
	m_resultsTable->setColumnWidth(1, 120); // Time Start
	m_resultsTable->setColumnWidth(2, 120); // Time End
	m_resultsTable->setColumnWidth(3, 100); // Access Type
	m_resultsTable->setColumnWidth(4, 120); // Address
	m_resultsTable->setColumnWidth(5, 80);  // Size
	m_resultsTable->setColumnWidth(6, 80);  // Thread ID
	m_resultsTable->setColumnWidth(7, 100); // Unique Thread ID
	// Instruction Address column will stretch
	
	// Connect double-click handler
	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, 
			this, &TTDMemoryWidget::onCellDoubleClicked);
}

void TTDMemoryWidget::performQuery()
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
			
			// Event Type
			m_resultsTable->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(event.eventType)));
			
			// Time Start
			QString timeStartStr = QString("%1:%2")
				.arg(event.timeStart.sequence, 0, 16)
				.arg(event.timeStart.step, 0, 16);
			m_resultsTable->setItem(i, 1, new QTableWidgetItem(timeStartStr));
			
			// Time End
			QString timeEndStr = QString("%1:%2")
				.arg(event.timeEnd.sequence, 0, 16)
				.arg(event.timeEnd.step, 0, 16);
			m_resultsTable->setItem(i, 2, new QTableWidgetItem(timeEndStr));
			
			// Access Type
			QString accessTypeStr;
			if (event.accessType & TTDMemoryRead) accessTypeStr += "R";
			if (event.accessType & TTDMemoryWrite) accessTypeStr += "W";
			if (event.accessType & TTDMemoryExecute) accessTypeStr += "E";
			m_resultsTable->setItem(i, 3, new QTableWidgetItem(accessTypeStr));
			
			// Address
			QString addressStr = QString("0x%1").arg(event.address, 0, 16);
			m_resultsTable->setItem(i, 4, new QTableWidgetItem(addressStr));
			
			// Size
			m_resultsTable->setItem(i, 5, new QTableWidgetItem(QString::number(event.size)));
			
			// Thread ID
			m_resultsTable->setItem(i, 6, new QTableWidgetItem(QString::number(event.threadId)));
			
			// Unique Thread ID
			m_resultsTable->setItem(i, 7, new QTableWidgetItem(QString::number(event.uniqueThreadId)));
			
			// Instruction Address
			QString instrAddrStr = QString("0x%1").arg(event.instructionAddress, 0, 16);
			m_resultsTable->setItem(i, 8, new QTableWidgetItem(instrAddrStr));
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

void TTDMemoryWidget::clearResults()
{
	m_resultsTable->setRowCount(0);
	updateStatus("Results cleared");
}

void TTDMemoryWidget::onCellDoubleClicked(int row, int column)
{
	// Handle double-click events - could navigate to address or position
	if (row < 0 || row >= m_resultsTable->rowCount())
		return;
		
	if (column == 1) // Time Start column
	{
		// Parse position and navigate to it
		QTableWidgetItem* posItem = m_resultsTable->item(row, 1);
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
						updateStatus(QString("Navigated to position %1").arg(posStr));
					}
					else
					{
						updateStatus("Failed to navigate to position");
					}
				}
			}
		}
	}
	else if (column == 4 || column == 8) // Address or Instruction Address columns
	{
		// Could implement navigation to address in disassembly view
		QTableWidgetItem* addrItem = m_resultsTable->item(row, column);
		if (addrItem)
		{
			QString addrStr = addrItem->text();
			updateStatus(QString("Address: %1 (navigation could be implemented)").arg(addrStr));
		}
	}
}

void TTDMemoryWidget::updateStatus(const QString& message)
{
	m_statusLabel->setText(message);
}

uint64_t TTDMemoryWidget::parseAddress(const QString& text)
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

TTDMemoryAccessType TTDMemoryWidget::getSelectedAccessTypes()
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


// TTDMemoryWidgetType implementation
TTDMemoryWidgetType::TTDMemoryWidgetType()
	: SidebarWidgetType(QIcon(":/debugger/cctv-camera").pixmap(QSize(64, 64)).toImage(), "TTD Memory")
{
}

SidebarWidget* TTDMemoryWidgetType::createWidget(ViewFrame*, BinaryViewRef data)
{
	return new TTDMemorySidebarWidget(data);
}

SidebarContentClassifier* TTDMemoryWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}

#include "ttdmemorywidget.moc"