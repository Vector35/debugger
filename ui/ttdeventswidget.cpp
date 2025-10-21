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

#include "ttdeventswidget.h"
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
#include <QFileInfo>
#include <map>

// TTDEventsColumnVisibilityDialog implementation
TTDEventsColumnVisibilityDialog::TTDEventsColumnVisibilityDialog(QWidget* parent, const QStringList& columnNames, const QList<bool>& visibility)
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
		// Reset to default visibility (show main columns, hide some detailed ones)
		QList<bool> defaultVisibility;
		defaultVisibility << true  // Index
		              << true  // Event Type
		              << true  // Position
		              << true  // Thread ID
		              << false // Thread Unique ID (hidden by default)
		              << true  // Module Name
		              << true  // Module Address
		              << false // Module Size (hidden by default)
		              << true  // Exception Type
		              << true  // Exception Code
		              << true; // Exception PC
		              
		for (int i = 0; i < m_columnList->count() && i < defaultVisibility.size(); ++i)
		{
			QListWidgetItem* item = m_columnList->item(i);
			item->setCheckState(defaultVisibility[i] ? Qt::Checked : Qt::Unchecked);
		}
	});
	
	layout->addWidget(buttons);
}

QList<bool> TTDEventsColumnVisibilityDialog::getColumnVisibility() const
{
	QList<bool> visibility;
	for (int i = 0; i < m_columnList->count(); ++i)
	{
		QListWidgetItem* item = m_columnList->item(i);
		visibility.append(item->checkState() == Qt::Checked);
	}
	return visibility;
}

// TTDEventsQueryWidget implementation
TTDEventsQueryWidget::TTDEventsQueryWidget(QWidget* parent, BinaryViewRef data, WidgetType type)
	: QWidget(parent), m_data(data), m_widgetType(type),
	  m_threadCreatedCheck(nullptr), m_threadTerminatedCheck(nullptr), 
	  m_moduleLoadedCheck(nullptr), m_moduleUnloadedCheck(nullptr), 
	  m_exceptionCheck(nullptr), m_queryButton(nullptr), m_clearButton(nullptr),
	  m_resultsTable(nullptr), m_statusLabel(nullptr), m_contextMenuManager(nullptr)
{
	m_controller = DebuggerController::GetController(data);
	if (!m_controller)
	{
		// Create a placeholder widget showing no controller available
		QVBoxLayout* layout = new QVBoxLayout(this);
		QLabel* label = new QLabel("No debugger controller available for TTD Events analysis.");
		label->setAlignment(Qt::AlignCenter);
		layout->addWidget(label);
		return;
	}

	setupUI();
	setupTable();
	setupUIActions();
	setupContextMenu();
}

TTDEventsQueryWidget::~TTDEventsQueryWidget()
{
	if (m_contextMenuManager)
	{
		delete m_contextMenuManager;
	}
}

void TTDEventsQueryWidget::setupUI()
{
	QVBoxLayout* mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);  // Add padding like TTD memory/calls widget

	// Only show input controls for AllEvents widget type
	if (m_widgetType == AllEvents)
	{
		// Input controls
		QGroupBox* inputGroup = new QGroupBox("Event Type Filters");
		QVBoxLayout* inputLayout = new QVBoxLayout(inputGroup);

		// Event type checkboxes
		m_threadCreatedCheck = new QCheckBox("Thread Created");
		m_threadCreatedCheck->setChecked(true);
		connect(m_threadCreatedCheck, &QCheckBox::toggled, this, &TTDEventsQueryWidget::onFilterChanged);
		inputLayout->addWidget(m_threadCreatedCheck);
		
		m_threadTerminatedCheck = new QCheckBox("Thread Terminated");
		m_threadTerminatedCheck->setChecked(true);
		connect(m_threadTerminatedCheck, &QCheckBox::toggled, this, &TTDEventsQueryWidget::onFilterChanged);
		inputLayout->addWidget(m_threadTerminatedCheck);
		
		m_moduleLoadedCheck = new QCheckBox("Module Loaded");
		m_moduleLoadedCheck->setChecked(true);
		connect(m_moduleLoadedCheck, &QCheckBox::toggled, this, &TTDEventsQueryWidget::onFilterChanged);
		inputLayout->addWidget(m_moduleLoadedCheck);
		
		m_moduleUnloadedCheck = new QCheckBox("Module Unloaded");
		m_moduleUnloadedCheck->setChecked(true);
		connect(m_moduleUnloadedCheck, &QCheckBox::toggled, this, &TTDEventsQueryWidget::onFilterChanged);
		inputLayout->addWidget(m_moduleUnloadedCheck);
		
		m_exceptionCheck = new QCheckBox("Exception");
		m_exceptionCheck->setChecked(true);
		connect(m_exceptionCheck, &QCheckBox::toggled, this, &TTDEventsQueryWidget::onFilterChanged);
		inputLayout->addWidget(m_exceptionCheck);

		// Query buttons
		QHBoxLayout* buttonLayout = new QHBoxLayout();
		
		m_queryButton = new QPushButton("Query All TTD Events");
		m_queryButton->setDefault(true);
		connect(m_queryButton, &QPushButton::clicked, this, &TTDEventsQueryWidget::performQuery);
		buttonLayout->addWidget(m_queryButton);
		
		m_clearButton = new QPushButton("Clear Results");
		connect(m_clearButton, &QPushButton::clicked, this, &TTDEventsQueryWidget::clearResults);
		buttonLayout->addWidget(m_clearButton);
		
		buttonLayout->addStretch();
		inputLayout->addLayout(buttonLayout);

		mainLayout->addWidget(inputGroup);
	}
	else
	{
		// For specialized widgets, initialize checkboxes as null pointers
		m_threadCreatedCheck = nullptr;
		m_threadTerminatedCheck = nullptr;
		m_moduleLoadedCheck = nullptr;
		m_moduleUnloadedCheck = nullptr;
		m_exceptionCheck = nullptr;
		m_queryButton = nullptr;
		m_clearButton = nullptr;
	}

	// Results table
	m_resultsTable = new QTableWidget();
	mainLayout->addWidget(m_resultsTable, 1);  // Give table most of the space

	// Status label
	m_statusLabel = new QLabel("Ready to query TTD events.");
	m_statusLabel->setContentsMargins(5, 5, 5, 5);  // Add padding around status text
	mainLayout->addWidget(m_statusLabel);

	// Connect double-click on table
	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, this, &TTDEventsQueryWidget::onCellDoubleClicked);
}

void TTDEventsQueryWidget::setupTable()
{
	// Configure columns and visibility based on widget type
	switch (m_widgetType)
	{
		case ModuleEvents:
			m_columnNames << "Index" << "Position" << "Event Type" << "Name" 
			              << "Module Address" << "Module Size" << "Module Checksum" << "Module Timestamp" << "Path";
			m_columnVisibility << true  // Index
			                   << true  // Position
			                   << true  // Event Type
			                   << true  // Name
			                   << true  // Module Address
			                   << true  // Module Size
			                   << false // Module Checksum (hidden by default)
			                   << false // Module Timestamp (hidden by default)
			                   << true; // Path (moved to last column)
			break;
			
		case ThreadEvents:
			m_columnNames << "Index" << "Position" << "Event Type" << "Thread ID" << "Thread UniqueID"
			              << "Lifetime Start" << "Lifetime End" << "Active Start" << "Active End";
			m_columnVisibility << true  // Index
			                   << true  // Position
			                   << true  // Event Type
			                   << true  // Thread ID
			                   << true  // Thread UniqueID
			                   << true  // Lifetime Start
			                   << true  // Lifetime End
			                   << true  // Active Start
			                   << true; // Active End
			break;
			
		case ExceptionEvents:
			m_columnNames << "Index" << "Position" << "Exception Type" << "Program Counter" 
			              << "Exception Code" << "Exception Flags" << "Record Address";
			m_columnVisibility << true  // Index
			                   << true  // Position
			                   << true  // Exception Type
			                   << true  // Program Counter
			                   << true  // Exception Code
			                   << true  // Exception Flags
			                   << true; // Record Address
			break;
			
		default: // AllEvents
			m_columnNames << "Index" << "Event Type" << "Position" << "Thread ID" << "Thread UniqueID" 
			              << "Module Name" << "Module Address" << "Module Size" << "Exception Type" 
			              << "Exception Code" << "Exception PC";
			// Default column visibility (show main columns, hide some detailed ones)
			m_columnVisibility << true  // Index
			                   << true  // Event Type
			                   << true  // Position
			                   << true  // Thread ID
			                   << false // Thread Unique ID (hidden by default)
			                   << true  // Module Name
			                   << true  // Module Address
			                   << false // Module Size (hidden by default)
			                   << true  // Exception Type
			                   << true  // Exception Code
			                   << true; // Exception PC
			break;
	}

	m_resultsTable->setColumnCount(m_columnNames.size());
	m_resultsTable->setHorizontalHeaderLabels(m_columnNames);
	
	// Make cells non-editable
	m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	
	// Hide the row numbers (vertical header) but keep the Index column
	m_resultsTable->verticalHeader()->setVisible(false);
	
	// Enable sorting
	m_resultsTable->setSortingEnabled(true);
	
	// Set selection behavior
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setAlternatingRowColors(true);
	
	// Adjust column widths
	QHeaderView* header = m_resultsTable->horizontalHeader();
	header->setStretchLastSection(true);
	header->setSectionResizeMode(QHeaderView::Interactive);
	
	// Set context menu policy
	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_resultsTable, &QTableWidget::customContextMenuRequested, this, &TTDEventsQueryWidget::showContextMenu);
	
	// Apply initial column visibility
	updateColumnVisibility();
}

void TTDEventsQueryWidget::updateColumnVisibility()
{
	for (int i = 0; i < m_columnNames.size() && i < m_columnVisibility.size(); ++i)
	{
		m_resultsTable->setColumnHidden(i, !m_columnVisibility[i]);
	}
}

void TTDEventsQueryWidget::updateStatus(const QString& message)
{
	if (m_statusLabel)
	{
		m_statusLabel->setText(message);
	}
}

void TTDEventsQueryWidget::setupUIActions()
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

	// Refresh action to clear and re-query from backend
	m_menu->addAction("Refresh", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Refresh", UIAction([&]() { refreshEvents(); }));
}

void TTDEventsQueryWidget::setupContextMenu()
{
	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_resultsTable, &QTableWidget::customContextMenuRequested,
			this, &TTDEventsQueryWidget::showContextMenu);
}

void TTDEventsQueryWidget::performQuery()
{
	if (!m_controller)
	{
		updateStatus("No debugger controller available.");
		return;
	}

	if (!m_controller->IsConnected())
	{
		updateStatus("No active debugging session.");
		return;
	}

	if (!m_controller->IsTTD())
	{
		updateStatus("No a TTD debugging session.");
		return;
	}

	updateStatus("Querying all TTD events...");
	
	// Only disable button if it exists (AllEvents widgets have buttons, specialized don't)
	if (m_queryButton)
		m_queryButton->setEnabled(false);
	
	try
	{
		// Get all events and cache them
		m_allEvents = m_controller->GetAllTTDEvents();
		
		updateStatus(QString("Query completed. Loaded %1 total events.").arg(m_allEvents.size()));
		
		// Filter and display events based on widget type
		if (m_widgetType == AllEvents)
		{
			filterAndDisplayEvents();
		}
		else
		{
			filterAndDisplaySpecializedEvents();
		}
	}
	catch (const std::exception& e)
	{
		updateStatus(QString("Query failed: %1").arg(e.what()));
		QMessageBox::warning(this, "TTD Events Query Error", QString("Failed to query TTD events:\n%1").arg(e.what()));
	}
	
	// Only re-enable button if it exists
	if (m_queryButton)
		m_queryButton->setEnabled(true);
}

void TTDEventsQueryWidget::filterAndDisplayEvents()
{
	if (m_allEvents.empty())
	{
		m_resultsTable->setRowCount(0);
		updateStatus("No events to display.");
		return;
	}
	
	// Filter events based on checkbox states
	std::vector<TTDEvent> filteredEvents;
	
	for (const auto& event : m_allEvents)
	{
		bool shouldInclude = false;
		
		switch (event.type)
		{
			case TTDEventThreadCreated:
				shouldInclude = m_threadCreatedCheck ? m_threadCreatedCheck->isChecked() : false;
				break;
			case TTDEventThreadTerminated:
				shouldInclude = m_threadTerminatedCheck ? m_threadTerminatedCheck->isChecked() : false;
				break;
			case TTDEventModuleLoaded:
				shouldInclude = m_moduleLoadedCheck ? m_moduleLoadedCheck->isChecked() : false;
				break;
			case TTDEventModuleUnloaded:
				shouldInclude = m_moduleUnloadedCheck ? m_moduleUnloadedCheck->isChecked() : false;
				break;
			case TTDEventException:
				shouldInclude = m_exceptionCheck ? m_exceptionCheck->isChecked() : false;
				break;
		}
		
		if (shouldInclude)
		{
			filteredEvents.push_back(event);
		}
	}
	
	// Populate table with filtered results
	m_resultsTable->setRowCount(filteredEvents.size());
	
	for (size_t i = 0; i < filteredEvents.size(); ++i)
	{
		const TTDEvent& event = filteredEvents[i];
		
		// Index
		m_resultsTable->setItem(i, IndexColumn, new QTableWidgetItem(QString::number(i + 1)));
		
		// Event Type
		QString eventTypeStr;
		switch (event.type)
		{
			case TTDEventThreadCreated:
				eventTypeStr = "ThreadCreated";
				break;
			case TTDEventThreadTerminated:
				eventTypeStr = "ThreadTerminated";
				break;
			case TTDEventModuleLoaded:
				eventTypeStr = "ModuleLoaded";
				break;
			case TTDEventModuleUnloaded:
				eventTypeStr = "ModuleUnloaded";
				break;
			case TTDEventException:
				eventTypeStr = "Exception";
				break;
			default:
				eventTypeStr = "Unknown";
				break;
		}
		m_resultsTable->setItem(i, EventTypeColumn, new QTableWidgetItem(eventTypeStr));
		
		// Position
		QString positionStr = QString("%1:%2").arg(event.position.sequence, 0, 16).arg(event.position.step, 0, 16);
		m_resultsTable->setItem(i, PositionColumn, new QTableWidgetItem(positionStr));
		
		// Thread details (if available)
		if (event.thread.has_value())
		{
			m_resultsTable->setItem(i, ThreadIdColumn, new QTableWidgetItem(QString::number(event.thread->id)));
			m_resultsTable->setItem(i, ThreadUniqueIdColumn, new QTableWidgetItem(QString::number(event.thread->uniqueId)));
		}
		else
		{
			m_resultsTable->setItem(i, ThreadIdColumn, new QTableWidgetItem(""));
			m_resultsTable->setItem(i, ThreadUniqueIdColumn, new QTableWidgetItem(""));
		}
		
		// Module details (if available)
		if (event.module.has_value())
		{
			m_resultsTable->setItem(i, ModuleNameColumn, new QTableWidgetItem(QString::fromStdString(event.module->name)));
			m_resultsTable->setItem(i, ModuleAddressColumn, new QTableWidgetItem(QString("0x%1").arg(event.module->address, 0, 16)));
			m_resultsTable->setItem(i, ModuleSizeColumn, new QTableWidgetItem(QString::number(event.module->size)));
		}
		else
		{
			m_resultsTable->setItem(i, ModuleNameColumn, new QTableWidgetItem(""));
			m_resultsTable->setItem(i, ModuleAddressColumn, new QTableWidgetItem(""));
			m_resultsTable->setItem(i, ModuleSizeColumn, new QTableWidgetItem(""));
		}
		
		// Exception details (if available)
		if (event.exception.has_value())
		{
			QString exceptionTypeStr = (event.exception->type == TTDExceptionHardware) ? "Hardware" : "Software";
			m_resultsTable->setItem(i, ExceptionTypeColumn, new QTableWidgetItem(exceptionTypeStr));
			m_resultsTable->setItem(i, ExceptionCodeColumn, new QTableWidgetItem(QString("0x%1").arg(event.exception->code, 0, 16)));
			m_resultsTable->setItem(i, ExceptionPCColumn, new QTableWidgetItem(QString("0x%1").arg(event.exception->programCounter, 0, 16)));
		}
		else
		{
			m_resultsTable->setItem(i, ExceptionTypeColumn, new QTableWidgetItem(""));
			m_resultsTable->setItem(i, ExceptionCodeColumn, new QTableWidgetItem(""));
			m_resultsTable->setItem(i, ExceptionPCColumn, new QTableWidgetItem(""));
		}
	}

	m_resultsTable->resizeColumnsToContents();
	updateStatus(QString("Displaying %1 of %2 events.").arg(filteredEvents.size()).arg(m_allEvents.size()));
}

void TTDEventsQueryWidget::filterAndDisplaySpecializedEvents()
{
	if (m_allEvents.empty())
	{
		m_resultsTable->setRowCount(0);
		updateStatus("No events to display.");
		return;
	}
	
	// Filter events based on widget type
	std::vector<TTDEvent> filteredEvents;
	
	for (const auto& event : m_allEvents)
	{
		bool shouldInclude = false;
		
		switch (m_widgetType)
		{
			case ModuleEvents:
				shouldInclude = (event.type == TTDEventModuleLoaded || event.type == TTDEventModuleUnloaded);
				break;
			case ThreadEvents:
				shouldInclude = (event.type == TTDEventThreadCreated || event.type == TTDEventThreadTerminated);
				break;
			case ExceptionEvents:
				shouldInclude = (event.type == TTDEventException);
				break;
			default:
				shouldInclude = true; // AllEvents
				break;
		}
		
		if (shouldInclude)
		{
			filteredEvents.push_back(event);
		}
	}
	
	// Populate table with filtered results using specialized columns
	m_resultsTable->setRowCount(filteredEvents.size());
	
	for (size_t i = 0; i < filteredEvents.size(); ++i)
	{
		const TTDEvent& event = filteredEvents[i];
		int col = 0;
		
		// Index (always first column)
		m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString::number(i + 1)));
		
		switch (m_widgetType)
		{
			case ModuleEvents:
				// Position, Event Type, Name (base name), Module Address, Module Size, Module Checksum, Module Timestamp, Path (full path)
				{
					QString positionStr = QString("%1:%2").arg(event.position.sequence, 0, 16).arg(event.position.step, 0, 16);
					m_resultsTable->setItem(i, col++, new QTableWidgetItem(positionStr));
					
					QString eventTypeStr = (event.type == TTDEventModuleLoaded) ? "Loaded" : "Unloaded";
					m_resultsTable->setItem(i, col++, new QTableWidgetItem(eventTypeStr));
					
					if (event.module.has_value())
					{
						// Extract base name from full path
						QString fullPath = QString::fromStdString(event.module->name);
						QString baseName = QFileInfo(fullPath).fileName();
						if (baseName.isEmpty())
							baseName = fullPath;  // fallback to full path if no filename
						
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(baseName));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString("0x%1").arg(event.module->address, 0, 16)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString::number(event.module->size)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString("0x%1").arg(event.module->checksum, 0, 16)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString("0x%1").arg(event.module->timestamp, 0, 16)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(fullPath));  // Full path in last column
					}
					else
					{
						// Fill empty cells for all module columns
						for (int j = 0; j < 6; j++)
							m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
					}
				}
				break;
				
			case ThreadEvents:
				// Position, Event Type, Thread ID, Thread UniqueID, Lifetime Start, Lifetime End, Active Start, Active End
				{
					QString positionStr = QString("%1:%2").arg(event.position.sequence, 0, 16).arg(event.position.step, 0, 16);
					m_resultsTable->setItem(i, col++, new QTableWidgetItem(positionStr));
					
					QString eventTypeStr = (event.type == TTDEventThreadCreated) ? "Created" : "Terminated";
					m_resultsTable->setItem(i, col++, new QTableWidgetItem(eventTypeStr));
					
					if (event.thread.has_value())
					{
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString::number(event.thread->id)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString::number(event.thread->uniqueId)));
						
						// Lifetime range
						QString lifetimeStart = QString("%1:%2").arg(event.thread->lifetimeStart.sequence, 0, 16).arg(event.thread->lifetimeStart.step, 0, 16);
						QString lifetimeEnd = QString("%1:%2").arg(event.thread->lifetimeEnd.sequence, 0, 16).arg(event.thread->lifetimeEnd.step, 0, 16);
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(lifetimeStart));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(lifetimeEnd));
						
						// Active time range
						QString activeStart = QString("%1:%2").arg(event.thread->activeTimeStart.sequence, 0, 16).arg(event.thread->activeTimeStart.step, 0, 16);
						QString activeEnd = QString("%1:%2").arg(event.thread->activeTimeEnd.sequence, 0, 16).arg(event.thread->activeTimeEnd.step, 0, 16);
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(activeStart));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(activeEnd));
					}
					else
					{
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
					}
				}
				break;
				
			case ExceptionEvents:
				// Position, Exception Type, Program Counter, Exception Code, Exception Flags, Record Address
				{
					QString positionStr = QString("%1:%2").arg(event.position.sequence, 0, 16).arg(event.position.step, 0, 16);
					m_resultsTable->setItem(i, col++, new QTableWidgetItem(positionStr));
					
					if (event.exception.has_value())
					{
						QString exceptionTypeStr = (event.exception->type == TTDExceptionHardware) ? "Hardware" : "Software";
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(exceptionTypeStr));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString("0x%1").arg(event.exception->programCounter, 0, 16)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString("0x%1").arg(event.exception->code, 0, 16)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString("0x%1").arg(event.exception->flags, 0, 16)));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(QString("0x%1").arg(event.exception->recordAddress, 0, 16)));
					}
					else
					{
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
						m_resultsTable->setItem(i, col++, new QTableWidgetItem(""));
					}
				}
				break;
				
			default:
				// This shouldn't happen for specialized widgets
				break;
		}
	}

	m_resultsTable->resizeColumnsToContents();
	updateStatus(QString("Displaying %1 events.").arg(filteredEvents.size()));
}

void TTDEventsQueryWidget::onFilterChanged()
{
	// Re-filter and display events when checkbox states change
	// Only applies to AllEvents widget type (specialized widgets don't have checkboxes)
	if (m_widgetType == AllEvents && !m_allEvents.empty())
	{
		filterAndDisplayEvents();
	}
}

void TTDEventsQueryWidget::clearResults()
{
	m_resultsTable->setRowCount(0);
	m_allEvents.clear();
	updateStatus("Results cleared.");
}

void TTDEventsQueryWidget::refreshEvents()
{
	// Clear current contents and re-query from backend
	clearResults();
	performQuery();
}

void TTDEventsQueryWidget::onCellDoubleClicked(int row, int column)
{
	if (!m_controller)
		return;
	
	QTableWidgetItem* item = m_resultsTable->item(row, column);
	if (!item)
		return;
	
	QString cellText = item->text();
	
	// Check if this is a position column - navigate to TTD position
	QString columnName = m_resultsTable->horizontalHeaderItem(column) ? 
	                      m_resultsTable->horizontalHeaderItem(column)->text() : "";
	
	if (columnName.contains("Position", Qt::CaseInsensitive) || column == PositionColumn)
	{
		QStringList parts = cellText.split(':');
		if (parts.size() == 2)
		{
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
	// Check if this is an address column - jump to address
	else if (columnName.contains("Address", Qt::CaseInsensitive) || 
	         columnName.contains("PC", Qt::CaseInsensitive) ||
	         column == ModuleAddressColumn || 
	         column == ExceptionPCColumn)
	{
		if (cellText.startsWith("0x"))
		{
			bool ok;
			uint64_t address = cellText.mid(2).toULongLong(&ok, 16);
			if (ok)
			{
				// Jump to address in disassembly view
				// Navigate to the address in the disassembly view
				ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
				if (frame)
				{
					frame->navigate(m_data, address);
					updateStatus(QString("Navigated to address %1").arg(cellText));
				}
				else
				{
					updateStatus(QString("Address: %1 (no view frame available)").arg(cellText));
				}
			}
		}
	}
}

void TTDEventsQueryWidget::contextMenuEvent(QContextMenuEvent* event)
{
	if (m_contextMenuManager)
	{
		m_contextMenuManager->show(m_menu, &m_actionHandler);
	}
}

void TTDEventsQueryWidget::showContextMenu(const QPoint& position)
{
	QPoint globalPos = m_resultsTable->mapToGlobal(position);
	if (m_contextMenuManager)
	{
		m_contextMenuManager->show(m_menu, &m_actionHandler);
	}
}

void TTDEventsQueryWidget::showColumnVisibilityDialog()
{
	TTDEventsColumnVisibilityDialog dialog(this, m_columnNames, m_columnVisibility);
	if (dialog.exec() == QDialog::Accepted)
	{
		m_columnVisibility = dialog.getColumnVisibility();
		updateColumnVisibility();
	}
}

void TTDEventsQueryWidget::resetColumnsToDefault()
{
	// Reset to default visibility
	m_columnVisibility.clear();
	m_columnVisibility << true  // Index
	                   << true  // Event Type
	                   << true  // Position
	                   << true  // Thread ID
	                   << false // Thread Unique ID (hidden by default)
	                   << true  // Module Name
	                   << true  // Module Address
	                   << false // Module Size (hidden by default)
	                   << true  // Exception Type
	                   << true  // Exception Code
	                   << true; // Exception PC
	
	updateColumnVisibility();
}

bool TTDEventsQueryWidget::canCopy()
{
	return m_resultsTable->selectionModel()->hasSelection();
}

void TTDEventsQueryWidget::copy()
{
	copySelectedRow();
}

void TTDEventsQueryWidget::copySelectedCell()
{
	QItemSelectionModel* selectionModel = m_resultsTable->selectionModel();
	if (!selectionModel->hasSelection())
		return;
		
	QModelIndexList selected = selectionModel->selectedIndexes();
	if (selected.isEmpty())
		return;
		
	QTableWidgetItem* item = m_resultsTable->item(selected.first().row(), selected.first().column());
	if (item)
	{
		QClipboard* clipboard = QApplication::clipboard();
		clipboard->setText(item->text());
	}
}

void TTDEventsQueryWidget::copySelectedRow()
{
	QItemSelectionModel* selectionModel = m_resultsTable->selectionModel();
	if (!selectionModel->hasSelection())
		return;
		
	QModelIndexList selected = selectionModel->selectedRows();
	if (selected.isEmpty())
		return;
		
	QStringList rowData;
	int row = selected.first().row();
	
	for (int col = 0; col < m_resultsTable->columnCount(); ++col)
	{
		if (!m_resultsTable->isColumnHidden(col))
		{
			QTableWidgetItem* item = m_resultsTable->item(row, col);
			rowData << (item ? item->text() : "");
		}
	}
	
	QClipboard* clipboard = QApplication::clipboard();
	clipboard->setText(rowData.join('\t'));
}

void TTDEventsQueryWidget::copyEntireTable()
{
	QStringList tableData;
	
	// Header row
	QStringList headers;
	for (int col = 0; col < m_resultsTable->columnCount(); ++col)
	{
		if (!m_resultsTable->isColumnHidden(col))
		{
			headers << m_columnNames[col];
		}
	}
	tableData << headers.join('\t');
	
	// Data rows
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
		tableData << rowData.join('\t');
	}
	
	QClipboard* clipboard = QApplication::clipboard();
	clipboard->setText(tableData.join('\n'));
}

void TTDEventsQueryWidget::performInitialQuery()
{
	// For specialized widgets, automatically load and filter events
	if (m_widgetType != AllEvents)
	{
		// First perform the query to get all events
		performQuery();
		
		// Then filter based on widget type
		filterAndDisplaySpecializedEvents();
	}
	else
	{
		// For AllEvents widget, just perform the query
		performQuery();
	}
}

bool TTDEventsQueryWidget::isUnused() const
{
	return m_allEvents.empty();
}

// TTDEventsWidget implementation
TTDEventsWidget::TTDEventsWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data), m_isPopulated(false)
{
	m_controller = DebuggerController::GetController(data);
	setupUI();
	
	// Only automatically load events if the debugger is connected and running TTD
	if (m_controller && m_controller->IsConnected() && m_controller->IsTTD())
	{
		loadAllEvents();
		m_isPopulated = true;
	}
}

TTDEventsWidget::~TTDEventsWidget()
{
}

void TTDEventsWidget::setupUI()
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	// Create tab widget
	m_tabWidget = new QTabWidget();
	m_tabWidget->setTabsClosable(true);
	connect(m_tabWidget, &QTabWidget::tabCloseRequested, this, &TTDEventsWidget::closeTab);
	layout->addWidget(m_tabWidget);

	// Create "+" button as corner widget
	m_newTabButton = new QToolButton(m_tabWidget);
	m_newTabButton->setText("+");
	m_newTabButton->setAutoRaise(true);
	m_newTabButton->setToolTip("New tab");
	connect(m_newTabButton, &QToolButton::clicked, this, &TTDEventsWidget::createNewTab);
	
	// Set the button as corner widget
	m_tabWidget->setCornerWidget(m_newTabButton, Qt::TopRightCorner);

	// Create the 3 specialized tabs
	m_moduleEventsWidget = new TTDEventsQueryWidget(this, m_data, TTDEventsQueryWidget::ModuleEvents);
	m_threadEventsWidget = new TTDEventsQueryWidget(this, m_data, TTDEventsQueryWidget::ThreadEvents);
	m_exceptionEventsWidget = new TTDEventsQueryWidget(this, m_data, TTDEventsQueryWidget::ExceptionEvents);

	// Add tabs to the widget
	m_tabWidget->addTab(m_moduleEventsWidget, "Module Events");
	m_tabWidget->addTab(m_threadEventsWidget, "Thread Events");
	m_tabWidget->addTab(m_exceptionEventsWidget, "Exception Events");
}

void TTDEventsWidget::loadAllEvents()
{
	if (m_moduleEventsWidget)
		m_moduleEventsWidget->performInitialQuery();
	if (m_threadEventsWidget)
		m_threadEventsWidget->performInitialQuery();
	if (m_exceptionEventsWidget)
		m_exceptionEventsWidget->performInitialQuery();
}

void TTDEventsWidget::refreshAllTabs()
{
	// Only refresh if debugger is connected and data is available and we haven't already populated
	if (m_controller && m_controller->IsConnected() && m_controller->IsTTD() && !m_isPopulated)
	{
		loadAllEvents();
		m_isPopulated = true;
	}
}

void TTDEventsWidget::clearAllTabs()
{
	if (m_moduleEventsWidget)
		m_moduleEventsWidget->clearResults();
	if (m_threadEventsWidget)
		m_threadEventsWidget->clearResults();
	if (m_exceptionEventsWidget)
		m_exceptionEventsWidget->clearResults();
	
	// Clear all custom tabs as well
	for (int i = 3; i < m_tabWidget->count(); i++)
	{
		TTDEventsQueryWidget* widget = qobject_cast<TTDEventsQueryWidget*>(m_tabWidget->widget(i));
		if (widget)
			widget->clearResults();
	}
	
	m_isPopulated = false;
}

TTDEventsQueryWidget* TTDEventsWidget::getCurrentOrNewQueryWidget()
{
	// Get current tab widget
	TTDEventsQueryWidget* currentWidget = qobject_cast<TTDEventsQueryWidget*>(m_tabWidget->currentWidget());
	if (currentWidget)
		return currentWidget;
	
	// If no current widget or cast failed, create a new tab
	createNewTab();
	return qobject_cast<TTDEventsQueryWidget*>(m_tabWidget->currentWidget());
}

void TTDEventsWidget::createNewTab()
{
	// Create new tab with AllEvents type (has filtering controls)
	TTDEventsQueryWidget* queryWidget = new TTDEventsQueryWidget(this, m_data, TTDEventsQueryWidget::AllEvents);
	int tabIndex = m_tabWidget->addTab(queryWidget, QString("Query %1").arg(m_tabWidget->count() - 2)); // -2 because we have 3 fixed tabs
	m_tabWidget->setCurrentIndex(tabIndex);
	
	// If we've already populated the specialized tabs, also populate this new tab
	if (m_isPopulated)
	{
		queryWidget->performInitialQuery();
	}
}

void TTDEventsWidget::closeTab(int index)
{
	// Don't allow closing the first 3 specialized tabs
	if (index >= 3 && m_tabWidget->count() > 3)
	{
		QWidget* widget = m_tabWidget->widget(index);
		m_tabWidget->removeTab(index);
		widget->deleteLater();
	}
}

// TTDEventsSidebarWidget implementation
TTDEventsSidebarWidget::TTDEventsSidebarWidget(BinaryViewRef data)
	: SidebarWidget("TTD Events"), m_data(data)
{
	m_controller = DebuggerController::GetController(data);
	
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	
	m_eventsWidget = new TTDEventsWidget(this, data);
	layout->addWidget(m_eventsWidget);
	
	setLayout(layout);

	// Register for debugger events
	if (m_controller)
	{
		connect(this, &TTDEventsSidebarWidget::debuggerEvent, this, &TTDEventsSidebarWidget::onDebuggerEvent);
		
		m_debuggerEventCallback = m_controller->RegisterEventCallback(
			[&](const DebuggerEvent& event) {
				emit debuggerEvent(event);
			},
			"TTD Events Widget");
	}
}

TTDEventsSidebarWidget::~TTDEventsSidebarWidget()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_debuggerEventCallback);
}

void TTDEventsSidebarWidget::onDebuggerEvent(const DebuggerEvent& event)
{
	switch (event.type)
	{
		case TargetStoppedEventType:
			// When target stops, refresh all tabs if not already populated
			if (m_eventsWidget)
				m_eventsWidget->refreshAllTabs();
			break;
		case TargetExitedEventType:
		case DetachedEventType:
			// When target exits or is detached, clear all contents
			if (m_eventsWidget)
				m_eventsWidget->clearAllTabs();
			break;
		default:
			break;
	}
}

// TTDEventsWidgetType implementation
TTDEventsWidgetType::TTDEventsWidgetType()
	: SidebarWidgetType(QImage(":/debugger/ttd-events"), "TTD Events")
{
}

SidebarWidget* TTDEventsWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	TTDEventsSidebarWidget* result = new TTDEventsSidebarWidget(data);
	return result;
}

SidebarContentClassifier* TTDEventsWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}

#include "ttdeventswidget.moc"