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

#include "ttdbookmarkwidget.h"
#include "ui.h"
#include <QApplication>
#include <QMessageBox>

#include "moc_ttdbookmarkwidget.cpp"

static uint64_t PositionSortValue(const TTDPosition& position)
{
	return (position.sequence << 32) | (position.step & 0xFFFFFFFF);
}


// TTDBookmarkEditDialog implementation

TTDBookmarkEditDialog::TTDBookmarkEditDialog(QWidget* parent, const QString& position, const QString& note,
	const QString& viewAddress)
	: QDialog(parent)
{
	setWindowTitle(position.isEmpty() ? "Add TTD Bookmark" : "Edit TTD Bookmark");
	setModal(true);
	setMinimumWidth(500);

	auto layout = new QFormLayout(this);
	layout->setContentsMargins(10, 10, 10, 10);
	layout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

	m_positionEdit = new QLineEdit(position);
	m_positionEdit->setPlaceholderText("sequence:step (hex), e.g. 1a0:12f");
	layout->addRow("Position:", m_positionEdit);

	m_viewAddressEdit = new QLineEdit(viewAddress);
	m_viewAddressEdit->setPlaceholderText("View address (hex, optional)");
	layout->addRow("View Address:", m_viewAddressEdit);

	m_noteEdit = new QLineEdit(note);
	m_noteEdit->setPlaceholderText("Optional note for this bookmark");
	m_noteEdit->setMinimumWidth(400);
	layout->addRow("Note:", m_noteEdit);

	auto buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
	connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	layout->addRow(buttons);

	// Focus the note field by default
	m_noteEdit->setFocus();
	m_noteEdit->selectAll();
}

QString TTDBookmarkEditDialog::getPosition() const { return m_positionEdit->text().trimmed(); }
QString TTDBookmarkEditDialog::getNote() const { return m_noteEdit->text().trimmed(); }
QString TTDBookmarkEditDialog::getViewAddress() const { return m_viewAddressEdit->text().trimmed(); }


// TTDBookmarkWidget implementation

TTDBookmarkWidget::TTDBookmarkWidget(QWidget* parent, BinaryViewRef data)
	: QWidget(parent), m_data(data), m_resultsTable(nullptr), m_statusLabel(nullptr),
	  m_addButton(nullptr), m_contextMenuManager(nullptr)
{
	m_controller = DebuggerController::GetController(data);

	setupUI();
	setupTable();
	setupUIActions();
	setupContextMenu();
	loadBookmarksFromMetadata();
	refreshTable();
}

TTDBookmarkWidget::~TTDBookmarkWidget()
{
	if (m_contextMenuManager)
		delete m_contextMenuManager;
}

void TTDBookmarkWidget::setupUI()
{
	auto mainLayout = new QVBoxLayout(this);
	mainLayout->setContentsMargins(0, 0, 0, 0);

	// Button bar
	auto buttonLayout = new QHBoxLayout();
	m_addButton = new QPushButton("Add TTD Bookmark");
	connect(m_addButton, &QPushButton::clicked, this, &TTDBookmarkWidget::addBookmarkFromDialog);
	buttonLayout->addWidget(m_addButton);

	auto addCurrentButton = new QPushButton("Bookmark Current Position");
	connect(addCurrentButton, &QPushButton::clicked, this, &TTDBookmarkWidget::addBookmarkFromCurrentPosition);
	buttonLayout->addWidget(addCurrentButton);

	buttonLayout->addStretch();
	mainLayout->addLayout(buttonLayout);

	// Results table
	m_resultsTable = new QTableWidget();
	mainLayout->addWidget(m_resultsTable, 1);

	// Status label
	m_statusLabel = new QLabel("No bookmarks.");
	m_statusLabel->setContentsMargins(5, 5, 5, 5);
	mainLayout->addWidget(m_statusLabel);

	// Connect double-click
	connect(m_resultsTable, &QTableWidget::cellDoubleClicked, this, &TTDBookmarkWidget::onCellDoubleClicked);
}

void TTDBookmarkWidget::setupTable()
{
	QStringList columns;
	columns << "Index" << "Position" << "View Address" << "Note";

	m_resultsTable->setColumnCount(columns.size());
	m_resultsTable->setHorizontalHeaderLabels(columns);
	m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_resultsTable->verticalHeader()->setVisible(false);
	m_resultsTable->setSortingEnabled(true);
	m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_resultsTable->setAlternatingRowColors(true);

	QHeaderView* header = m_resultsTable->horizontalHeader();
	header->setStretchLastSection(true);
	header->setSectionResizeMode(QHeaderView::Interactive);

	m_resultsTable->setContextMenuPolicy(Qt::CustomContextMenu);
	connect(m_resultsTable, &QTableWidget::customContextMenuRequested, this, &TTDBookmarkWidget::showContextMenu);
}

void TTDBookmarkWidget::setupUIActions()
{
	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();

	m_menu->addAction("Add TTD Bookmark...", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Add TTD Bookmark...", UIAction([&]() { addBookmarkFromDialog(); }));

	m_menu->addAction("Bookmark Current Position", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Bookmark Current Position", UIAction([&]() { addBookmarkFromCurrentPosition(); }));

	m_menu->addAction("Edit Bookmark...", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Edit Bookmark...", UIAction([&]() { editSelectedBookmark(); },
		[&]() { return m_resultsTable->selectionModel()->hasSelection(); }));

	m_menu->addAction("Remove Bookmark", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Remove Bookmark", UIAction([&]() { removeSelectedBookmark(); },
		[&]() { return m_resultsTable->selectionModel()->hasSelection(); }));

	m_menu->addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&]() { copy(); }, [&]() { return canCopy(); }));

	m_menu->addAction("Copy Row", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy Row", UIAction([&]() { copySelectedRow(); }, [&]() { return canCopy(); }));

	m_menu->addAction("Copy Table", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy Table", UIAction([&]() { copyEntireTable(); },
		[&]() { return m_resultsTable->rowCount() > 0; }));
}

void TTDBookmarkWidget::setupContextMenu()
{
	// Already connected in setupTable
}

void TTDBookmarkWidget::updateStatus(const QString& message)
{
	if (m_statusLabel)
		m_statusLabel->setText(message);
}

bool TTDBookmarkWidget::canCopy()
{
	return m_resultsTable->selectionModel()->hasSelection();
}

void TTDBookmarkWidget::loadBookmarksFromMetadata()
{
	m_bookmarks.clear();

	if (!m_controller)
		return;

	m_bookmarks = m_controller->GetTTDBookmarks();
}

void TTDBookmarkWidget::refreshTable()
{
	bool sortingEnabled = m_resultsTable->isSortingEnabled();
	m_resultsTable->setSortingEnabled(false);

	m_resultsTable->setRowCount(static_cast<int>(m_bookmarks.size()));

	for (int i = 0; i < static_cast<int>(m_bookmarks.size()); ++i)
	{
		const auto& bookmark = m_bookmarks[i];

		m_resultsTable->setItem(i, IndexColumn, new NumericalTableWidgetItem(QString::number(i + 1), i + 1));

		QString posStr = QString("%1:%2").arg(bookmark.position.sequence, 0, 16).arg(bookmark.position.step, 0, 16);
		m_resultsTable->setItem(i, PositionColumn, new NumericalTableWidgetItem(posStr, PositionSortValue(bookmark.position)));

		if (bookmark.viewAddress != 0)
		{
			m_resultsTable->setItem(i, ViewAddressColumn,
				new NumericalTableWidgetItem(QString("0x%1").arg(bookmark.viewAddress, 0, 16), bookmark.viewAddress));
		}
		else
		{
			m_resultsTable->setItem(i, ViewAddressColumn, new NumericalTableWidgetItem("", 0));
		}

		m_resultsTable->setItem(i, NoteColumn, new QTableWidgetItem(QString::fromStdString(bookmark.note)));
	}

	m_resultsTable->setSortingEnabled(sortingEnabled);
	m_resultsTable->resizeColumnsToContents();

	if (m_bookmarks.empty())
		updateStatus("No bookmarks.");
	else
		updateStatus(QString("%1 bookmark(s).").arg(m_bookmarks.size()));
}

void TTDBookmarkWidget::addBookmark(const TTDPosition& position, const std::string& note, uint64_t viewAddress)
{
	if (!m_controller)
		return;

	m_controller->AddTTDBookmark(position, note, viewAddress);
	loadBookmarksFromMetadata();
	refreshTable();
}

void TTDBookmarkWidget::removeBookmark(int index)
{
	if (!m_controller || index < 0 || index >= static_cast<int>(m_bookmarks.size()))
		return;

	m_controller->RemoveTTDBookmark(m_bookmarks[index].position);
	loadBookmarksFromMetadata();
	refreshTable();
}

void TTDBookmarkWidget::updateBookmark(int index, const TTDPosition& position, const std::string& note,
	uint64_t viewAddress)
{
	if (!m_controller || index < 0 || index >= static_cast<int>(m_bookmarks.size()))
		return;

	// If position changed, remove old and add new
	if (!(m_bookmarks[index].position == position))
	{
		m_controller->RemoveTTDBookmark(m_bookmarks[index].position);
		m_controller->AddTTDBookmark(position, note, viewAddress);
	}
	else
	{
		m_controller->UpdateTTDBookmark(position, note, viewAddress);
	}
	loadBookmarksFromMetadata();
	refreshTable();
}

void TTDBookmarkWidget::onCellDoubleClicked(int row, int column)
{
	if (!m_controller || row < 0 || row >= static_cast<int>(m_bookmarks.size()))
		return;

	// Get the original bookmark index from the Index column (1-based display)
	QTableWidgetItem* indexItem = m_resultsTable->item(row, IndexColumn);
	if (!indexItem)
		return;
	int bookmarkIndex = static_cast<int>(indexItem->data(Qt::UserRole).toULongLong()) - 1;
	if (bookmarkIndex < 0 || bookmarkIndex >= static_cast<int>(m_bookmarks.size()))
		return;

	const auto& bookmark = m_bookmarks[bookmarkIndex];

	// Store pending view address so we can navigate after the TargetStoppedEvent
	// handler has finished (it calls navigateToCurrentIP, which would override us).
	m_pendingViewAddress = bookmark.viewAddress;

	if (m_controller->SetTTDPosition(bookmark.position))
	{
		updateStatus(QString("Navigated to bookmark %1").arg(bookmarkIndex + 1));
	}
	else
	{
		m_pendingViewAddress = 0;
		updateStatus("Failed to navigate to bookmark position");
	}
}

void TTDBookmarkWidget::navigateToPendingViewAddress()
{
	if (m_pendingViewAddress == 0)
		return;

	uint64_t addr = m_pendingViewAddress;
	m_pendingViewAddress = 0;

	ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
	if (frame)
		frame->navigate(m_data, addr);
}

void TTDBookmarkWidget::contextMenuEvent(QContextMenuEvent* event)
{
	if (m_contextMenuManager)
		m_contextMenuManager->show(m_menu, &m_actionHandler);
}

void TTDBookmarkWidget::showContextMenu(const QPoint& position)
{
	if (m_contextMenuManager)
		m_contextMenuManager->show(m_menu, &m_actionHandler);
}

void TTDBookmarkWidget::addBookmarkFromDialog()
{
	TTDBookmarkEditDialog dialog(this);
	if (dialog.exec() != QDialog::Accepted)
		return;

	QString posStr = dialog.getPosition();
	QStringList parts = posStr.split(':');
	if (parts.size() != 2)
	{
		QMessageBox::warning(this, "Invalid Position", "Position must be in format sequence:step (hex).");
		return;
	}

	bool ok1, ok2;
	uint64_t sequence = parts[0].toULongLong(&ok1, 16);
	uint64_t step = parts[1].toULongLong(&ok2, 16);

	if (!ok1 || !ok2)
	{
		QMessageBox::warning(this, "Invalid Position", "Could not parse position as hex values.");
		return;
	}

	uint64_t viewAddress = 0;
	QString viewAddrStr = dialog.getViewAddress();
	if (!viewAddrStr.isEmpty())
	{
		QString cleanText = viewAddrStr.trimmed();
		if (cleanText.startsWith("0x") || cleanText.startsWith("0X"))
			cleanText = cleanText.mid(2);
		bool ok;
		viewAddress = cleanText.toULongLong(&ok, 16);
		if (!ok)
			viewAddress = 0;
	}

	addBookmark(TTDPosition(sequence, step), dialog.getNote().toStdString(), viewAddress);
}

void TTDBookmarkWidget::addBookmarkFromCurrentPosition()
{
	if (!m_controller)
	{
		QMessageBox::warning(this, "No Controller", "No debugger controller available.");
		return;
	}

	if (!m_controller->IsConnected() || !m_controller->IsTTD())
	{
		QMessageBox::warning(this, "Not Available", "TTD session is not active.");
		return;
	}

	TTDPosition currentPos = m_controller->GetCurrentTTDPosition();

	// Get current view address
	uint64_t viewAddress = 0;
	ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
	if (frame)
		viewAddress = frame->getCurrentOffset();

	// Show dialog pre-filled with current position
	QString posStr = QString("%1:%2").arg(currentPos.sequence, 0, 16).arg(currentPos.step, 0, 16);
	QString viewAddrStr = viewAddress != 0 ? QString("0x%1").arg(viewAddress, 0, 16) : "";

	TTDBookmarkEditDialog dialog(this, posStr, "", viewAddrStr);
	if (dialog.exec() == QDialog::Accepted)
	{
		// Re-parse in case user edited the position
		QString editedPosStr = dialog.getPosition();
		QStringList parts = editedPosStr.split(':');
		if (parts.size() == 2)
		{
			bool ok1, ok2;
			uint64_t seq = parts[0].toULongLong(&ok1, 16);
			uint64_t stp = parts[1].toULongLong(&ok2, 16);
			if (ok1 && ok2)
			{
				uint64_t addr = 0;
				QString addrStr = dialog.getViewAddress();
				if (!addrStr.isEmpty())
				{
					QString clean = addrStr.trimmed();
					if (clean.startsWith("0x") || clean.startsWith("0X"))
						clean = clean.mid(2);
					bool ok;
					addr = clean.toULongLong(&ok, 16);
					if (!ok)
						addr = 0;
				}
				addBookmark(TTDPosition(seq, stp), dialog.getNote().toStdString(), addr);
			}
		}
	}
}

void TTDBookmarkWidget::editSelectedBookmark()
{
	QItemSelectionModel* sel = m_resultsTable->selectionModel();
	if (!sel->hasSelection())
		return;

	int row = sel->selectedRows().first().row();
	QTableWidgetItem* indexItem = m_resultsTable->item(row, IndexColumn);
	if (!indexItem)
		return;

	int bookmarkIndex = static_cast<int>(indexItem->data(Qt::UserRole).toULongLong()) - 1;
	if (bookmarkIndex < 0 || bookmarkIndex >= static_cast<int>(m_bookmarks.size()))
		return;

	const auto& bookmark = m_bookmarks[bookmarkIndex];
	QString posStr = QString("%1:%2").arg(bookmark.position.sequence, 0, 16).arg(bookmark.position.step, 0, 16);
	QString viewAddrStr = bookmark.viewAddress != 0 ? QString("0x%1").arg(bookmark.viewAddress, 0, 16) : "";

	TTDBookmarkEditDialog dialog(this, posStr, QString::fromStdString(bookmark.note), viewAddrStr);
	if (dialog.exec() != QDialog::Accepted)
		return;

	QString editedPosStr = dialog.getPosition();
	QStringList parts = editedPosStr.split(':');
	if (parts.size() != 2)
		return;

	bool ok1, ok2;
	uint64_t seq = parts[0].toULongLong(&ok1, 16);
	uint64_t stp = parts[1].toULongLong(&ok2, 16);
	if (!ok1 || !ok2)
		return;

	uint64_t addr = 0;
	QString addrStr = dialog.getViewAddress();
	if (!addrStr.isEmpty())
	{
		QString clean = addrStr.trimmed();
		if (clean.startsWith("0x") || clean.startsWith("0X"))
			clean = clean.mid(2);
		bool ok;
		addr = clean.toULongLong(&ok, 16);
		if (!ok)
			addr = 0;
	}

	updateBookmark(bookmarkIndex, TTDPosition(seq, stp), dialog.getNote().toStdString(), addr);
}

void TTDBookmarkWidget::removeSelectedBookmark()
{
	QItemSelectionModel* sel = m_resultsTable->selectionModel();
	if (!sel->hasSelection())
		return;

	int row = sel->selectedRows().first().row();
	QTableWidgetItem* indexItem = m_resultsTable->item(row, IndexColumn);
	if (!indexItem)
		return;

	int bookmarkIndex = static_cast<int>(indexItem->data(Qt::UserRole).toULongLong()) - 1;
	removeBookmark(bookmarkIndex);
}

void TTDBookmarkWidget::copy()
{
	copySelectedRow();
}

void TTDBookmarkWidget::copySelectedRow()
{
	QItemSelectionModel* sel = m_resultsTable->selectionModel();
	if (!sel->hasSelection())
		return;

	int row = sel->selectedRows().first().row();
	QStringList rowData;
	for (int col = 0; col < m_resultsTable->columnCount(); ++col)
	{
		QTableWidgetItem* item = m_resultsTable->item(row, col);
		rowData << (item ? item->text() : "");
	}
	QApplication::clipboard()->setText(rowData.join('\t'));
}

void TTDBookmarkWidget::copyEntireTable()
{
	QStringList tableData;

	QStringList headers;
	headers << "Index" << "Position" << "View Address" << "Note";
	tableData << headers.join('\t');

	for (int row = 0; row < m_resultsTable->rowCount(); ++row)
	{
		QStringList rowData;
		for (int col = 0; col < m_resultsTable->columnCount(); ++col)
		{
			QTableWidgetItem* item = m_resultsTable->item(row, col);
			rowData << (item ? item->text() : "");
		}
		tableData << rowData.join('\t');
	}

	QApplication::clipboard()->setText(tableData.join('\n'));
}


// TTDBookmarkSidebarWidget implementation

TTDBookmarkSidebarWidget::TTDBookmarkSidebarWidget(BinaryViewRef data)
	: SidebarWidget("TTD Bookmarks"), m_data(data)
{
	m_controller = DebuggerController::GetController(data);

	auto layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	m_bookmarkWidget = new TTDBookmarkWidget(this, data);
	layout->addWidget(m_bookmarkWidget);

	// Register for debugger events
	if (m_controller)
	{
		connect(this, &TTDBookmarkSidebarWidget::debuggerEvent, this, &TTDBookmarkSidebarWidget::onDebuggerEvent);

		m_debuggerEventCallback = m_controller->RegisterEventCallback(
			[&](const DebuggerEvent& event) {
				emit debuggerEvent(event);
			},
			"TTD Bookmarks Widget");
	}
}

TTDBookmarkSidebarWidget::~TTDBookmarkSidebarWidget()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_debuggerEventCallback);
}

void TTDBookmarkSidebarWidget::onDebuggerEvent(const DebuggerEvent& event)
{
	switch (event.type)
	{
		case TargetStoppedEventType:
			if (m_bookmarkWidget)
				m_bookmarkWidget->navigateToPendingViewAddress();
			break;
		case TTDBookmarkChangedEvent:
			if (m_bookmarkWidget)
			{
				m_bookmarkWidget->loadBookmarksFromMetadata();
				m_bookmarkWidget->refreshTable();
			}
			break;
		default:
			break;
	}
}


// TTDBookmarkWidgetType implementation

TTDBookmarkWidgetType::TTDBookmarkWidgetType()
	: SidebarWidgetType(QImage(":/debugger/ttd-timestamp"), "TTD Bookmarks")
{
}

SidebarWidget* TTDBookmarkWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new TTDBookmarkSidebarWidget(data);
}

SidebarContentClassifier* TTDBookmarkWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}
