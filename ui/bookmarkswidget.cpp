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

#include <QPainter>
#include <QHeaderView>
#include <QInputDialog>
#include <QMessageBox>
#include <QShowEvent>
#include "bookmarkswidget.h"
#include "ui.h"
#include "menus.h"
#include "fmt/format.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

BookmarkItem::BookmarkItem(const std::string& description, const std::string& ttdPosition, uint64_t address, const QDateTime& timestamp) :
	m_description(description), m_ttdPosition(ttdPosition), m_address(address), m_timestamp(timestamp)
{}


bool BookmarkItem::operator==(const BookmarkItem& other) const
{
	return (m_description == other.description()) && (m_ttdPosition == other.ttdPosition()) && 
		   (m_address == other.address()) && (m_timestamp == other.timestamp());
}


bool BookmarkItem::operator!=(const BookmarkItem& other) const
{
	return !(*this == other);
}


bool BookmarkItem::operator<(const BookmarkItem& other) const
{
	if (m_timestamp < other.timestamp())
		return true;
	else if (m_timestamp > other.timestamp())
		return false;
	return m_description < other.description();
}


DebugBookmarksListModel::DebugBookmarksListModel(QWidget* parent, ViewFrame* view) :
	QAbstractTableModel(parent), m_view(view)
{}


DebugBookmarksListModel::~DebugBookmarksListModel() {}


BookmarkItem DebugBookmarksListModel::getRow(int row) const
{
	if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

	return m_items[row];
}


QModelIndex DebugBookmarksListModel::index(int row, int column, const QModelIndex&) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugBookmarksListModel::data(const QModelIndex& index, int role) const
{
	if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	BookmarkItem* item = static_cast<BookmarkItem*>(index.internalPointer());
	if (!item)
		return QVariant();

	if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole))
		return QVariant();

	switch (index.column())
	{
	case DescriptionColumn:
		return QString::fromStdString(item->description());
	case PositionColumn:
		return QString::fromStdString(item->ttdPosition());
	case AddressColumn:
		return QString::asprintf("0x%" PRIx64, item->address());
	case TimestampColumn:
		return item->timestamp().toString("yyyy-MM-dd hh:mm:ss");
	default:
		return QVariant();
	}
}


QVariant DebugBookmarksListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Vertical)
		return QVariant();
	if (role != Qt::DisplayRole)
		return QVariant();

	switch (column)
	{
	case DescriptionColumn:
		return "Description";
	case PositionColumn:
		return "TTD Position";
	case AddressColumn:
		return "Address";
	case TimestampColumn:
		return "Timestamp";
	default:
		return QVariant();
	}
}


void DebugBookmarksListModel::updateRows(std::vector<BookmarkItem> newRows)
{
	beginResetModel();
	m_items = newRows;
	endResetModel();
}


void DebugBookmarksListModel::addBookmark(const BookmarkItem& bookmark)
{
	beginInsertRows(QModelIndex(), m_items.size(), m_items.size());
	m_items.push_back(bookmark);
	endInsertRows();
}


void DebugBookmarksListModel::removeBookmark(int row)
{
	if (row >= 0 && (size_t)row < m_items.size())
	{
		beginRemoveRows(QModelIndex(), row, row);
		m_items.erase(m_items.begin() + row);
		endRemoveRows();
	}
}


DebugBookmarksItemDelegate::DebugBookmarksItemDelegate(QWidget* parent) : QStyledItemDelegate(parent)
{
	updateFonts();
}


void DebugBookmarksItemDelegate::updateFonts()
{
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	QFontMetrics metrics(m_font);
	m_baseline = metrics.ascent();
	m_charWidth = metrics.boundingRect('X').width();
	m_charHeight = metrics.height();
	m_charOffset = metrics.descent();
}


void DebugBookmarksItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	painter->setFont(m_font);
	QStyledItemDelegate::paint(painter, option, idx);
}


QSize DebugBookmarksItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	return QSize(0, m_charHeight + 2);
}


DebugBookmarksWidget::DebugBookmarksWidget(ViewFrame* view, BinaryViewRef data, Menu* menu) :
	QTableView(view), m_view(view)
{
	m_controller = DebuggerController::GetController(data);
	if (!m_controller)
		return;

	m_model = new DebugBookmarksListModel(this, view);
	setModel(m_model);
	setSelectionBehavior(QAbstractItemView::SelectItems);
	setSelectionMode(QAbstractItemView::ExtendedSelection);

	m_delegate = new DebugBookmarksItemDelegate(this);
	setItemDelegate(m_delegate);

	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::ExtendedSelection);

	verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	verticalHeader()->setVisible(false);

	setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

	resizeColumnsToContents();
	resizeRowsToContents();
	horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);

	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = menu;
	if (m_menu == nullptr)
		m_menu = new Menu();

	QString removeBookmarkActionName = QString::fromStdString("Remove Bookmark");
	UIAction::registerAction(removeBookmarkActionName, QKeySequence::Delete);
	m_menu->addAction(removeBookmarkActionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		removeBookmarkActionName, UIAction([&]() { remove(); }, [&]() { return selectionNotEmpty(); }));

	QString jumpToBookmarkActionName = QString::fromStdString("Jump To Bookmark");
	UIAction::registerAction(jumpToBookmarkActionName);
	m_menu->addAction(jumpToBookmarkActionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		jumpToBookmarkActionName, UIAction([&]() { jump(); }, [&]() { return selectionNotEmpty(); }));

	QString addBookmarkActionName = QString::fromStdString("Add Bookmark...");
	UIAction::registerAction(addBookmarkActionName);
	m_menu->addAction(addBookmarkActionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		addBookmarkActionName, UIAction([&]() { add(); }));

	connect(this, &QTableView::doubleClicked, this, &DebugBookmarksWidget::onDoubleClicked);

	updateContent();
}


DebugBookmarksWidget::~DebugBookmarksWidget() {}


void DebugBookmarksWidget::updateFonts()
{
	m_delegate->updateFonts();
}


bool DebugBookmarksWidget::selectionNotEmpty()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	return !sel.empty();
}


std::string DebugBookmarksWidget::getCurrentTTDPosition()
{
	if (!m_controller || !m_controller->IsConnectedToDebugServer())
		return "";

	// For TTD adapters, we can use InvokeBackendCommand to get the current position
	// TTD position commands typically return position in format like "12A:B4"
	// For now, we'll use a basic approach to get position info
	try 
	{
		// Check if this is a TTD adapter by checking adapter capabilities
		// This is a simplified approach - in a full implementation we'd check the adapter type
		auto adapterResult = m_controller->InvokeBackendCommand(".echo TTD_Position_Check");
		if (!adapterResult.empty())
		{
			// Try to get TTD position using a TTD-specific command
			// Different TTD engines might use different commands:
			// WinDbg TTD: "!tt" or "!position"  
			// Other TTD systems might use different commands
			auto posResult = m_controller->InvokeBackendCommand("!tt");
			if (!posResult.empty() && posResult.find("Position") != std::string::npos)
			{
				// Extract position from result - this is a simplified parser
				size_t pos = posResult.find("Position");
				if (pos != std::string::npos)
				{
					size_t start = posResult.find(":", pos);
					if (start != std::string::npos)
					{
						size_t end = posResult.find_first_of(" \n\r\t", start);
						if (end != std::string::npos)
							return posResult.substr(start - 2, end - start + 2);
					}
				}
			}
		}
	}
	catch (...)
	{
		// Fallback if commands fail
	}

	// Fallback: create a pseudo-position based on current IP and timestamp
	uint64_t currentIP = m_controller->GetCurrentIP();
	auto now = QDateTime::currentDateTime();
	return fmt::format("{}:{}", currentIP, now.toSecsSinceEpoch() % 10000);
}


void DebugBookmarksWidget::contextMenuEvent(QContextMenuEvent* event)
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}


void DebugBookmarksWidget::showEvent(QShowEvent* event)
{
	QTableView::showEvent(event);
	// Refresh bookmarks when the widget becomes visible
	// This ensures we pick up any bookmarks added via global actions
	updateContent();
}


void DebugBookmarksWidget::jump()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto row = sel[0].row();
	auto bookmark = m_model->getRow(row);

	// Navigate to the bookmarked position
	if (m_controller && m_controller->IsConnectedToDebugServer())
	{
		bool ttdSuccess = false;
		
		try 
		{
			// First, try to navigate to the TTD position if we have a valid one
			if (!bookmark.ttdPosition().empty() && bookmark.ttdPosition() != "0:0")
			{
				// Try TTD-specific position navigation
				// Different TTD systems use different commands:
				// WinDbg TTD: "!tt <position>" 
				// Other systems might use "!goto <position>" or similar
				std::string posCmd = fmt::format("!tt {}", bookmark.ttdPosition());
				auto result = m_controller->InvokeBackendCommand(posCmd);
				
				// Check if command was successful (basic heuristic)
				if (!result.empty() && result.find("Error") == std::string::npos && 
					result.find("Invalid") == std::string::npos)
				{
					ttdSuccess = true;
				}
				else
				{
					// Try alternate TTD position command
					posCmd = fmt::format("!position {}", bookmark.ttdPosition());
					result = m_controller->InvokeBackendCommand(posCmd);
					if (!result.empty() && result.find("Error") == std::string::npos && 
						result.find("Invalid") == std::string::npos)
					{
						ttdSuccess = true;
					}
				}
			}
		}
		catch (...)
		{
			// If TTD positioning fails, we'll fall back to address navigation
		}

		// Always navigate to the address as well for visual feedback
		UIContext* context = UIContext::contextForWidget(this);
		if (context)
		{
			ViewFrame* frame = context->getCurrentViewFrame();
			if (frame && m_controller->GetData())
			{
				bool navSuccess = frame->navigate(m_controller->GetData(), bookmark.address(), true, true);
				
				// Show feedback to user about navigation result
				if (ttdSuccess && navSuccess)
				{
					// Success - no message needed, but could add status update
				}
				else if (!ttdSuccess && navSuccess)
				{
					// TTD positioning failed but address navigation worked
					LogDebug("Bookmark: TTD position '%s' navigation failed, used address navigation", bookmark.ttdPosition().c_str());
				}
				else
				{
					// Both failed - show warning
					QMessageBox::warning(this, "Navigate to Bookmark", 
						QString("Failed to navigate to bookmark '%1'").arg(QString::fromStdString(bookmark.description())));
				}
			}
		}
	}
	else
	{
		QMessageBox::warning(this, "Navigate to Bookmark", "Cannot navigate: not connected to debugger");
	}
}


void DebugBookmarksWidget::remove()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	// Remove selected bookmarks (in reverse order to maintain indices)
	std::vector<int> rows;
	for (const auto& index : sel)
	{
		rows.push_back(index.row());
	}
	std::sort(rows.rbegin(), rows.rend()); // Sort in descending order

	for (int row : rows)
	{
		m_model->removeBookmark(row);
	}
	
	saveBookmarks();
}


void DebugBookmarksWidget::onDoubleClicked()
{
	jump();
}


void DebugBookmarksWidget::add()
{
	if (!m_controller)
	{
		QMessageBox::warning(this, "Add Bookmark", "Cannot add bookmark: no debugger controller available");
		return;
	}
	
	if (!m_controller->IsConnectedToDebugServer())
	{
		QMessageBox::warning(this, "Add Bookmark", "Cannot add bookmark: not connected to debugger");
		return;
	}

	bool ok;
	QString description = QInputDialog::getText(this, "Add Bookmark", 
		"Enter a description for this bookmark:", QLineEdit::Normal, "", &ok);
	if (!ok || description.trimmed().isEmpty())
		return;

	try 
	{
		// Get current position info
		std::string ttdPosition = getCurrentTTDPosition();
		uint64_t currentAddress = m_controller->GetCurrentIP();

		// Create bookmark with trimmed description
		BookmarkItem bookmark(description.trimmed().toStdString(), ttdPosition, currentAddress);
		m_model->addBookmark(bookmark);
		saveBookmarks();
		
		// Show success feedback
		LogDebug("Added bookmark '%s' at address 0x%llx with TTD position '%s'", 
			bookmark.description().c_str(), bookmark.address(), bookmark.ttdPosition().c_str());
	}
	catch (...)
	{
		QMessageBox::critical(this, "Add Bookmark", "Failed to create bookmark due to an error");
	}
}


void DebugBookmarksWidget::updateContent()
{
	loadBookmarks();
}


void DebugBookmarksWidget::saveBookmarks()
{
	if (!m_controller || !m_controller->GetData())
		return;

	try 
	{
		// Serialize bookmarks to metadata following the breakpoints pattern
		std::vector<Ref<Metadata>> bookmarks;
		for (const auto& bookmark : m_model->getItems())
		{
			std::map<std::string, Ref<Metadata>> info;
			info["description"] = new Metadata(bookmark.description());
			info["ttdPosition"] = new Metadata(bookmark.ttdPosition());
			info["address"] = new Metadata(bookmark.address());
			info["timestamp"] = new Metadata(bookmark.timestamp().toString().toStdString());
			bookmarks.push_back(new Metadata(info));
		}
		m_controller->GetData()->StoreMetadata("debugger.bookmarks", new Metadata(bookmarks));
	}
	catch (...)
	{
		// Ignore serialization errors for now
	}
}


void DebugBookmarksWidget::loadBookmarks()
{
	if (!m_controller || !m_controller->GetData())
		return;

	try 
	{
		Ref<Metadata> metadata = m_controller->GetData()->QueryMetadata("debugger.bookmarks");
		if (!metadata || !metadata->IsArray())
			return;

		vector<Ref<Metadata>> array = metadata->GetArray();
		std::vector<BookmarkItem> newBookmarks;

		for (auto& element : array)
		{
			if (!element || !element->IsKeyValueStore())
				continue;

			std::map<std::string, Ref<Metadata>> info = element->GetKeyValueStore();
			
			if (!(info["description"] && info["description"]->IsString()) ||
				!(info["ttdPosition"] && info["ttdPosition"]->IsString()) ||
				!(info["address"] && info["address"]->IsUnsignedInteger()) ||
				!(info["timestamp"] && info["timestamp"]->IsString()))
				continue;

			std::string description = info["description"]->GetString();
			std::string ttdPosition = info["ttdPosition"]->GetString();
			uint64_t address = info["address"]->GetUnsignedInteger();
			QDateTime timestamp = QDateTime::fromString(QString::fromStdString(info["timestamp"]->GetString()));

			BookmarkItem bookmark(description, ttdPosition, address, timestamp);
			newBookmarks.push_back(bookmark);
		}

		m_model->updateRows(newBookmarks);
	}
	catch (...)
	{
		// Ignore deserialization errors for now
	}
}


void DebugBookmarksWidget::uiEventHandler(const DebuggerEvent& event)
{
	// Update content when relevant events occur
	switch (event.type)
	{
	case TargetStoppedEventType:
	case DetachedEventType:
		updateContent();
		break;
	case LaunchedEventType:
	case ConnectedEventType:
		// Reload bookmarks when we connect/launch as metadata may have changed
		updateContent();
		break;
	default:
		break;
	}
}