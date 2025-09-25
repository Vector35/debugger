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

#include "ttdheapwidget.h"
#include "fmt/format.h"
#include <QApplication>
#include <QMessageBox>
#include <QCheckBox>

using namespace BinaryNinjaDebuggerAPI;

// Helper class for numerical sorting
class NumericalTableWidgetItem : public QTableWidgetItem
{
public:
	NumericalTableWidgetItem(const QString &text, uint64_t numValue) : QTableWidgetItem(text), m_numValue(numValue) {}
	
	bool operator<(const QTableWidgetItem &other) const override
	{
		const NumericalTableWidgetItem* numOther = dynamic_cast<const NumericalTableWidgetItem*>(&other);
		if (numOther)
			return m_numValue < numOther->m_numValue;
		return QTableWidgetItem::operator<(other);
	}

private:
	uint64_t m_numValue;
};

// TTDHeapQueryWidget implementation
TTDHeapQueryWidget::TTDHeapQueryWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(m_data);
	if (!m_controller)
	{
		LogError("Failed to get debugger controller");
		return;
	}
	
	// Initialize column names and visibility
	m_columnNames << "Index" << "Event Type" << "Action" << "Time Start" << "Time End" 
	              << "Heap" << "Address" << "Previous Address" << "Size" << "Base Address"
	              << "Flags" << "Result" << "Reserve Size" << "Commit Size" << "Make Read Only"
	              << "Thread ID" << "Unique Thread ID" << "Parameters";
	
	// Default visibility - show most important columns by default
	m_columnVisibility << true << true << true << true << true  // Index, Event Type, Action, Time Start, Time End
	                   << true << true << false << true << false  // Heap, Address, Previous Address, Size, Base Address
	                   << false << true << false << false << false  // Flags, Result, Reserve Size, Commit Size, Make Read Only
	                   << false << false << false;  // Thread ID, Unique Thread ID, Parameters
	
	setupUI();
	setupUIActions();
}

TTDHeapQueryWidget::~TTDHeapQueryWidget()
{
	if (m_contextMenuManager)
		delete m_contextMenuManager;
}

void TTDHeapQueryWidget::setupUI()
{
	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Controls section
	auto* controlsWidget = new QWidget();
	auto* controlsLayout = new QHBoxLayout(controlsWidget);
	controlsLayout->setContentsMargins(8, 8, 8, 8);

	m_queryButton = new QPushButton("Query Heap Objects");
	m_clearButton = new QPushButton("Clear Results");
	
	controlsLayout->addWidget(m_queryButton);
	controlsLayout->addWidget(m_clearButton);
	controlsLayout->addStretch();

	// Status label
	m_statusLabel = new QLabel("Ready to query TTD heap objects");
	m_statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
	controlsLayout->addWidget(m_statusLabel);

	layout->addWidget(controlsWidget);

	// Results table
	m_resultsTable = new QTableWidget();
	setupTable();
	layout->addWidget(m_resultsTable);

	// Connect signals
	connect(m_queryButton, &QPushButton::clicked, this, &TTDHeapQueryWidget::performQuery);
	connect(m_clearButton, &QPushButton::clicked, this, &TTDHeapQueryWidget::clearResults);
	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, this, &TTDHeapQueryWidget::onCellDoubleClicked);
}

void TTDHeapQueryWidget::setupTable()
{
	m_resultsTable->setColumnCount(m_columnNames.size());
	m_resultsTable->setHorizontalHeaderLabels(m_columnNames);
	m_resultsTable->horizontalHeader()->setStretchLastSection(true);
	m_resultsTable->setAlternatingRowColors(true);
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setSortingEnabled(true);
	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	
	// Set column widths
	m_resultsTable->setColumnWidth(IndexColumn, 80);
	m_resultsTable->setColumnWidth(EventTypeColumn, 100);
	m_resultsTable->setColumnWidth(ActionColumn, 100);
	m_resultsTable->setColumnWidth(TimeStartColumn, 120);
	m_resultsTable->setColumnWidth(TimeEndColumn, 120);
	m_resultsTable->setColumnWidth(HeapColumn, 120);
	m_resultsTable->setColumnWidth(AddressColumn, 120);
	m_resultsTable->setColumnWidth(PreviousAddressColumn, 120);
	m_resultsTable->setColumnWidth(SizeColumn, 100);
	m_resultsTable->setColumnWidth(BaseAddressColumn, 120);
	m_resultsTable->setColumnWidth(FlagsColumn, 100);
	m_resultsTable->setColumnWidth(ResultColumn, 100);
	m_resultsTable->setColumnWidth(ReserveSizeColumn, 100);
	m_resultsTable->setColumnWidth(CommitSizeColumn, 100);
	m_resultsTable->setColumnWidth(MakeReadOnlyColumn, 100);
	m_resultsTable->setColumnWidth(ThreadIdColumn, 100);
	m_resultsTable->setColumnWidth(UniqueThreadIdColumn, 120);

	updateColumnVisibility();
	
	connect(m_resultsTable, &QTableWidget::customContextMenuRequested, this, &TTDHeapQueryWidget::showContextMenu);
}

void TTDHeapQueryWidget::updateStatus(const QString& message)
{
	m_statusLabel->setText(message);
	QApplication::processEvents();
}

void TTDHeapQueryWidget::performQuery()
{
	if (!m_controller)
	{
		updateStatus("No debugger controller available");
		return;
	}

	updateStatus("Querying TTD heap objects...");
	m_queryButton->setEnabled(false);
	QApplication::processEvents();
	
	try
	{
		// Execute the TTD heap query
		auto events = m_controller->GetTTDHeapObjects();
		
		// Populate the results table
		m_resultsTable->setRowCount(events.size());
		
		for (size_t i = 0; i < events.size(); ++i)
		{
			const auto& event = events[i];
			
			// Index
			m_resultsTable->setItem(i, IndexColumn, new NumericalTableWidgetItem(QString("0x%1").arg(i, 0, 16), i));
			
			// Event Type
			m_resultsTable->setItem(i, EventTypeColumn, new QTableWidgetItem(QString::fromStdString(event.eventType)));
			
			// Action
			m_resultsTable->setItem(i, ActionColumn, new QTableWidgetItem(QString::fromStdString(event.action)));
			
			// Time Start
			QString timeStartStr = QString("%1:%2")
				.arg(event.timeStart.sequence, 0, 16)
				.arg(event.timeStart.step, 0, 16);
			m_resultsTable->setItem(i, TimeStartColumn, new QTableWidgetItem(timeStartStr));
			
			// Time End
			QString timeEndStr = QString("%1:%2")
				.arg(event.timeEnd.sequence, 0, 16)
				.arg(event.timeEnd.step, 0, 16);
			m_resultsTable->setItem(i, TimeEndColumn, new QTableWidgetItem(timeEndStr));
			
			// Heap
			m_resultsTable->setItem(i, HeapColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.heap, 0, 16), event.heap));
			
			// Address
			if (event.address != 0)
				m_resultsTable->setItem(i, AddressColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.address, 0, 16), event.address));
			else
				m_resultsTable->setItem(i, AddressColumn, new QTableWidgetItem(""));
			
			// Previous Address
			if (event.previousAddress != 0)
				m_resultsTable->setItem(i, PreviousAddressColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.previousAddress, 0, 16), event.previousAddress));
			else
				m_resultsTable->setItem(i, PreviousAddressColumn, new QTableWidgetItem(""));
			
			// Size
			if (event.size != 0)
				m_resultsTable->setItem(i, SizeColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.size, 0, 16), event.size));
			else
				m_resultsTable->setItem(i, SizeColumn, new QTableWidgetItem(""));
			
			// Base Address
			if (event.baseAddress != 0)
				m_resultsTable->setItem(i, BaseAddressColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.baseAddress, 0, 16), event.baseAddress));
			else
				m_resultsTable->setItem(i, BaseAddressColumn, new QTableWidgetItem(""));
			
			// Flags
			if (event.flags != 0)
				m_resultsTable->setItem(i, FlagsColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.flags, 0, 16), event.flags));
			else
				m_resultsTable->setItem(i, FlagsColumn, new QTableWidgetItem(""));
			
			// Result
			m_resultsTable->setItem(i, ResultColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.result, 0, 16), event.result));
			
			// Reserve Size
			if (event.reserveSize != 0)
				m_resultsTable->setItem(i, ReserveSizeColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.reserveSize, 0, 16), event.reserveSize));
			else
				m_resultsTable->setItem(i, ReserveSizeColumn, new QTableWidgetItem(""));
			
			// Commit Size
			if (event.commitSize != 0)
				m_resultsTable->setItem(i, CommitSizeColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.commitSize, 0, 16), event.commitSize));
			else
				m_resultsTable->setItem(i, CommitSizeColumn, new QTableWidgetItem(""));
			
			// Make Read Only
			if (event.makeReadOnly != 0)
				m_resultsTable->setItem(i, MakeReadOnlyColumn, new NumericalTableWidgetItem(QString("0x%1").arg(event.makeReadOnly, 0, 16), event.makeReadOnly));
			else
				m_resultsTable->setItem(i, MakeReadOnlyColumn, new QTableWidgetItem(""));
			
			// Thread ID
			m_resultsTable->setItem(i, ThreadIdColumn, new NumericalTableWidgetItem(QString::number(event.threadId), event.threadId));
			
			// Unique Thread ID
			m_resultsTable->setItem(i, UniqueThreadIdColumn, new NumericalTableWidgetItem(QString::number(event.uniqueThreadId), event.uniqueThreadId));
			
			// Parameters
			QStringList paramStrings;
			for (const auto& param : event.parameters)
			{
				paramStrings << QString::fromStdString(param);
			}
			m_resultsTable->setItem(i, ParametersColumn, new QTableWidgetItem(paramStrings.join(", ")));
		}
		
		updateStatus(QString("Found %1 heap objects").arg(events.size()));
	}
	catch (const std::exception& e)
	{
		updateStatus(QString("Error querying heap objects: %1").arg(e.what()));
		LogError("Exception in TTD heap query: %s", e.what());
	}
	
	m_queryButton->setEnabled(true);
}

void TTDHeapQueryWidget::clearResults()
{
	m_resultsTable->setRowCount(0);
	updateStatus("Results cleared");
}

void TTDHeapQueryWidget::onCellDoubleClicked(int row, int column)
{
	if (!m_controller)
		return;

	// Navigate to TimeStart for the selected heap event
	if (column == TimeStartColumn)
	{
		auto* item = m_resultsTable->item(row, TimeStartColumn);
		if (!item)
			return;

		QString timeStr = item->text();
		QStringList parts = timeStr.split(':');
		if (parts.size() != 2)
			return;

		bool ok1, ok2;
		uint64_t sequence = parts[0].toULongLong(&ok1, 16);
		uint64_t step = parts[1].toULongLong(&ok2, 16);

		if (ok1 && ok2)
		{
			TTDPosition position(sequence, step);
			if (m_controller->SetTTDPosition(position))
			{
				updateStatus(QString("Navigated to position %1:%2").arg(sequence, 0, 16).arg(step, 0, 16));
			}
			else
			{
				updateStatus("Failed to navigate to position");
			}
		}
	}
	// Navigate to TimeEnd for the selected heap event
	else if (column == TimeEndColumn)
	{
		auto* item = m_resultsTable->item(row, TimeEndColumn);
		if (!item)
			return;

		QString timeStr = item->text();
		QStringList parts = timeStr.split(':');
		if (parts.size() != 2)
			return;

		bool ok1, ok2;
		uint64_t sequence = parts[0].toULongLong(&ok1, 16);
		uint64_t step = parts[1].toULongLong(&ok2, 16);

		if (ok1 && ok2)
		{
			TTDPosition position(sequence, step);
			if (m_controller->SetTTDPosition(position))
			{
				updateStatus(QString("Navigated to position %1:%2").arg(sequence, 0, 16).arg(step, 0, 16));
			}
			else
			{
				updateStatus("Failed to navigate to position");
			}
		}
	}
}

bool TTDHeapQueryWidget::isUnused() const
{
	return m_resultsTable->rowCount() == 0;
}

void TTDHeapQueryWidget::setupContextMenu()
{
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();
	
	m_menu->addAction(new MenuAction("Column Visibility...", [=]() { showColumnVisibilityDialog(); }));
	m_menu->addAction(new MenuAction("Reset Columns to Default", [=]() { resetColumnsToDefault(); }));
	
	m_contextMenuManager->setMenus(QList<Menu*>{m_menu});
}

void TTDHeapQueryWidget::setupUIActions()
{
	setupContextMenu();
	
	m_actionHandler.setupActionHandler(this);
	m_actionHandler.setActionDisplayName("Copy", "Copy");
	m_actionHandler.bindAction("Copy", UIAction([=]() { copy(); }, [=]() { return canCopy(); }));
}

void TTDHeapQueryWidget::updateColumnVisibility()
{
	for (int i = 0; i < m_columnVisibility.size() && i < m_resultsTable->columnCount(); ++i)
	{
		m_resultsTable->setColumnHidden(i, !m_columnVisibility[i]);
	}
}

bool TTDHeapQueryWidget::canCopy()
{
	return m_resultsTable->selectedItems().size() > 0;
}

void TTDHeapQueryWidget::contextMenuEvent(QContextMenuEvent* event)
{
	if (m_contextMenuManager)
		m_contextMenuManager->show(m_menu, &m_actionHandler);
}

void TTDHeapQueryWidget::showColumnVisibilityDialog()
{
	// Create a simple dialog to toggle column visibility
	QDialog dialog(this);
	dialog.setWindowTitle("Column Visibility");
	dialog.setModal(true);
	
	auto* layout = new QVBoxLayout(&dialog);
	
	QList<QCheckBox*> checkboxes;
	for (int i = 0; i < m_columnNames.size(); ++i)
	{
		auto* checkbox = new QCheckBox(m_columnNames[i]);
		checkbox->setChecked(m_columnVisibility[i]);
		checkboxes.append(checkbox);
		layout->addWidget(checkbox);
	}
	
	auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	layout->addWidget(buttonBox);
	
	connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
	connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
	
	if (dialog.exec() == QDialog::Accepted)
	{
		for (int i = 0; i < checkboxes.size() && i < m_columnVisibility.size(); ++i)
		{
			m_columnVisibility[i] = checkboxes[i]->isChecked();
		}
		updateColumnVisibility();
	}
}

void TTDHeapQueryWidget::resetColumnsToDefault()
{
	// Reset to default visibility
	m_columnVisibility.clear();
	m_columnVisibility << true << true << true << true << true  // Index, Event Type, Action, Time Start, Time End
	                   << true << true << false << true << false  // Heap, Address, Previous Address, Size, Base Address
	                   << false << true << false << false << false  // Flags, Result, Reserve Size, Commit Size, Make Read Only
	                   << false << false << false;  // Thread ID, Unique Thread ID, Parameters
	updateColumnVisibility();
}

void TTDHeapQueryWidget::showContextMenu(const QPoint& position)
{
	if (m_contextMenuManager)
		m_contextMenuManager->show(m_menu, &m_actionHandler);
}

void TTDHeapQueryWidget::copy()
{
	copySelectedRow();
}

void TTDHeapQueryWidget::copySelectedCell()
{
	auto selectedItems = m_resultsTable->selectedItems();
	if (selectedItems.isEmpty())
		return;
	
	QApplication::clipboard()->setText(selectedItems.first()->text());
}

void TTDHeapQueryWidget::copySelectedRow()
{
	auto selectedItems = m_resultsTable->selectedItems();
	if (selectedItems.isEmpty())
		return;
	
	int row = selectedItems.first()->row();
	QStringList rowData;
	
	for (int col = 0; col < m_resultsTable->columnCount(); ++col)
	{
		auto* item = m_resultsTable->item(row, col);
		rowData << (item ? item->text() : "");
	}
	
	QApplication::clipboard()->setText(rowData.join("\t"));
}

void TTDHeapQueryWidget::copyEntireTable()
{
	QStringList tableData;
	
	// Add header
	QStringList headers;
	for (int col = 0; col < m_resultsTable->columnCount(); ++col)
	{
		headers << m_resultsTable->horizontalHeaderItem(col)->text();
	}
	tableData << headers.join("\t");
	
	// Add rows
	for (int row = 0; row < m_resultsTable->rowCount(); ++row)
	{
		QStringList rowData;
		for (int col = 0; col < m_resultsTable->columnCount(); ++col)
		{
			auto* item = m_resultsTable->item(row, col);
			rowData << (item ? item->text() : "");
		}
		tableData << rowData.join("\t");
	}
	
	QApplication::clipboard()->setText(tableData.join("\n"));
}

// TTDHeapWidget implementation (tab container)
TTDHeapWidget::TTDHeapWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(m_data);
	setupUI();
}

TTDHeapWidget::~TTDHeapWidget()
{
}

void TTDHeapWidget::setupUI()
{
	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);

	// Tab widget with new tab button
	auto* headerWidget = new QWidget();
	auto* headerLayout = new QHBoxLayout(headerWidget);
	headerLayout->setContentsMargins(0, 0, 0, 0);

	m_tabWidget = new QTabWidget();
	m_tabWidget->setTabsClosable(true);
	m_tabWidget->setMovable(true);

	m_newTabButton = new QToolButton();
	m_newTabButton->setText("+");
	m_newTabButton->setToolTip("New Tab");
	m_newTabButton->setAutoRaise(true);

	headerLayout->addWidget(m_tabWidget, 1);
	headerLayout->addWidget(m_newTabButton);

	layout->addWidget(headerWidget);

	// Create initial tab
	createNewTab();

	// Connect signals
	connect(m_newTabButton, &QToolButton::clicked, this, &TTDHeapWidget::createNewTab);
	connect(m_tabWidget, &QTabWidget::tabCloseRequested, this, &TTDHeapWidget::closeTab);
}

void TTDHeapWidget::createNewTab()
{
	auto* queryWidget = new TTDHeapQueryWidget(this, m_data);
	int index = m_tabWidget->addTab(queryWidget, "Heap Query");
	m_tabWidget->setCurrentIndex(index);
}

void TTDHeapWidget::closeTab(int index)
{
	if (m_tabWidget->count() <= 1)
		return; // Keep at least one tab

	QWidget* widget = m_tabWidget->widget(index);
	m_tabWidget->removeTab(index);
	delete widget;
}

TTDHeapQueryWidget* TTDHeapWidget::getCurrentOrNewQueryWidget()
{
	auto* currentWidget = qobject_cast<TTDHeapQueryWidget*>(m_tabWidget->currentWidget());
	if (!currentWidget || !currentWidget->isUnused())
	{
		createNewTab();
		currentWidget = qobject_cast<TTDHeapQueryWidget*>(m_tabWidget->currentWidget());
	}
	return currentWidget;
}

void TTDHeapWidget::performQuery()
{
	auto* queryWidget = getCurrentOrNewQueryWidget();
	if (queryWidget)
		queryWidget->performQuery();
}

void TTDHeapWidget::performQueryInNewTab()
{
	createNewTab();
	auto* queryWidget = qobject_cast<TTDHeapQueryWidget*>(m_tabWidget->currentWidget());
	if (queryWidget)
		queryWidget->performQuery();
}

// TTDHeapSidebarWidget implementation
TTDHeapSidebarWidget::TTDHeapSidebarWidget(BinaryViewRef data)
	: SidebarWidget("TTD Heap"), m_data(data)
{
	m_controller = DebuggerController::GetController(m_data);
	m_heapWidget = new TTDHeapWidget(this, m_data);
	
	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_heapWidget);
}

TTDHeapSidebarWidget::~TTDHeapSidebarWidget()
{
}

void TTDHeapSidebarWidget::performQuery()
{
	if (m_heapWidget)
		m_heapWidget->performQuery();
}

void TTDHeapSidebarWidget::performQueryInNewTab()
{
	if (m_heapWidget)
		m_heapWidget->performQueryInNewTab();
}

// TTDHeapWidgetType implementation
TTDHeapWidgetType::TTDHeapWidgetType()
	: SidebarWidgetType(QIcon(":/debugger/ttd-heap").pixmap(QSize(64, 64)).toImage(), "TTD Heap")
{
}

SidebarWidget* TTDHeapWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new TTDHeapSidebarWidget(data);
}

SidebarContentClassifier* TTDHeapWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}

#include "ttdheapwidget.moc"