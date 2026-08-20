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

#include "../../../ui/shared/internalaction.h"
#include <QPainter>
#include <QHeaderView>
#include <QGuiApplication>
#include <QMimeData>
#include <QClipboard>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>
#include <algorithm>
#include "ui.h"
#include "memorymapwidget.h"
#include "clickablelabel.h"

using namespace BinaryNinja;
using namespace std;

constexpr int SortFilterRole = Qt::UserRole + 1;

MemoryRegionItem::MemoryRegionItem(
	uint64_t start, size_t size, std::string name, bool read, bool write, bool execute, bool shared) :
	m_start(start), m_size(size), m_name(name), m_read(read), m_write(write), m_execute(execute), m_shared(shared)
{}


std::string MemoryRegionItem::permissions() const
{
	std::string result;
	result += m_read ? 'r' : '-';
	result += m_write ? 'w' : '-';
	result += m_execute ? 'x' : '-';
	result += m_shared ? 's' : 'p';
	return result;
}


bool MemoryRegionItem::operator==(const MemoryRegionItem& other) const
{
	return (m_start == other.start()) && (m_size == other.size()) && (m_name == other.name())
		&& (m_read == other.read()) && (m_write == other.write()) && (m_execute == other.execute())
		&& (m_shared == other.shared());
}


bool MemoryRegionItem::operator!=(const MemoryRegionItem& other) const
{
	return !(*this == other);
}


bool MemoryRegionItem::operator<(const MemoryRegionItem& other) const
{
	if (m_start < other.start())
		return true;
	else if (m_start > other.start())
		return false;
	return m_size < other.size();
}


DebugMemoryMapListModel::DebugMemoryMapListModel(QWidget* parent, ViewFrame* view) :
	QAbstractTableModel(parent), m_view(view)
{}


DebugMemoryMapListModel::~DebugMemoryMapListModel() {}


MemoryRegionItem DebugMemoryMapListModel::getRow(int row) const
{
	if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

	return m_items[row];
}


QModelIndex DebugMemoryMapListModel::index(int row, int column, const QModelIndex&) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugMemoryMapListModel::data(const QModelIndex& index, int role) const
{
	if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	MemoryRegionItem* item = static_cast<MemoryRegionItem*>(index.internalPointer());
	if (!item)
		return QVariant();

	if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole) && (role != SortFilterRole))
		return QVariant();

	switch (index.column())
	{
	case DebugMemoryMapListModel::StartColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->start());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugMemoryMapListModel::EndColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->endAddress());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugMemoryMapListModel::SizeColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, (uint64_t)item->size());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugMemoryMapListModel::PermissionsColumn:
	{
		QString text = QString::fromStdString(item->permissions());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugMemoryMapListModel::NameColumn:
	{
		QString text = QString::fromStdString(item->name());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	}
	return QVariant();
}


QVariant DebugMemoryMapListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
	case DebugMemoryMapListModel::StartColumn:
		return "Start";
	case DebugMemoryMapListModel::EndColumn:
		return "End";
	case DebugMemoryMapListModel::SizeColumn:
		return "Size";
	case DebugMemoryMapListModel::PermissionsColumn:
		return "Permissions";
	case DebugMemoryMapListModel::NameColumn:
		return "Name";
	}
	return QVariant();
}


void DebugMemoryMapListModel::updateRows(std::vector<DebugMemoryRegion> newRegions)
{
	beginResetModel();
	std::vector<MemoryRegionItem> newRows;
	for (const DebugMemoryRegion& region : newRegions)
	{
		newRows.emplace_back(region.m_start, region.m_size, region.m_name, region.m_read, region.m_write,
			region.m_execute, region.m_shared);
	}

	std::sort(newRows.begin(), newRows.end(), [=](const MemoryRegionItem& a, const MemoryRegionItem& b) {
		return a.start() < b.start();
	});

	m_items = newRows;
	endResetModel();
}


DebugMemoryMapItemDelegate::DebugMemoryMapItemDelegate(QWidget* parent) : QStyledItemDelegate(parent)
{
	updateFonts();
}


void DebugMemoryMapItemDelegate::paint(
	QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	painter->setFont(m_font);

	bool selected = (option.state & QStyle::State_Selected) != 0;
	if (selected)
		painter->setBrush(getThemeColor(SelectionColor));
	else
		painter->setBrush(option.backgroundBrush);

	painter->setPen(Qt::NoPen);
	painter->setFont(m_font);

	QRect textRect = option.rect;
	textRect.setBottom(textRect.top() + m_charHeight + 2);
	painter->drawRect(textRect);

	auto data = idx.data(Qt::DisplayRole);
	switch (idx.column())
	{
	case DebugMemoryMapListModel::StartColumn:
	case DebugMemoryMapListModel::EndColumn:
		painter->setPen(getThemeColor(AddressColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case DebugMemoryMapListModel::SizeColumn:
		painter->setPen(getThemeColor(NumberColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case DebugMemoryMapListModel::PermissionsColumn:
	case DebugMemoryMapListModel::NameColumn:
	{
		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	default:
		break;
	}
}


void DebugMemoryMapItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebugMemoryMapItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
	return QSize(totalWidth, m_charHeight + 2);
}


DebugMemoryMapWidget::DebugMemoryMapWidget(ViewFrame* view, BinaryViewRef data) : QTableView(view), m_view(view)
{
	setProperty("bn.uiTestId", "debugger.memoryMap.table");
	setProperty("bn.uiTestScope", "debugger.memoryMap.table");
	setAccessibleName("Debugger memory regions");
	m_controller = DebuggerController::GetController(data);
	if (!m_controller)
		return;

	m_model = new DebugMemoryMapListModel(this, view);
	m_filter = new DebugMemoryMapFilterProxyModel(this);
	m_filter->setSourceModel(m_model);
	setModel(m_filter);
	setShowGrid(false);

	m_delegate = new DebugMemoryMapItemDelegate(this);
	setItemDelegate(m_delegate);

	setSelectionBehavior(QAbstractItemView::SelectItems);

	verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	verticalHeader()->setVisible(false);

	horizontalHeader()->setStretchLastSection(true);
	horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

	setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

	resizeColumnsToContents();
	resizeRowsToContents();

	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);

	QString actionName = QString::fromStdString("Jump To Start");
	UIIdentity::registerBuiltInAction(actionName);
	m_menu.addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([this]() { jumpToStart(); }));

	actionName = QString::fromStdString("Jump To End");
	UIIdentity::registerBuiltInAction(actionName);
	m_menu.addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([this]() { jumpToEnd(); }));

	m_menu.addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&]() { copy(); }, [&]() { return canCopy(); }));
	m_actionHandler.setActionDisplayName("Copy", [&]() {
		QModelIndexList sel = selectionModel()->selectedIndexes();
		if (sel.empty())
			return "Copy";

		switch (sel[0].column())
		{
		case DebugMemoryMapListModel::StartColumn:
			return "Copy Start";
		case DebugMemoryMapListModel::EndColumn:
			return "Copy End";
		case DebugMemoryMapListModel::SizeColumn:
			return "Copy Size";
		case DebugMemoryMapListModel::PermissionsColumn:
			return "Copy Permissions";
		case DebugMemoryMapListModel::NameColumn:
			return "Copy Name";
		default:
			return "Copy";
		}
	});

	UIAction::registerAction("Copy All");
	m_menu.addAction("Copy All", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy All", UIAction([&]() { copyAll(); }, [&]() { return canCopyAll(); }));

	actionName = QString::fromStdString("Select In Binary View");
	UIIdentity::registerBuiltInAction(actionName);
	m_menu.addAction(actionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		actionName, UIAction([this]() { selectInView(); }, [this]() { return canSelectRegion(); }));

	actionName = QString::fromStdString("Save Region To Disk...");
	UIIdentity::registerBuiltInAction(actionName);
	m_menu.addAction(actionName, "Options", MENU_ORDER_LAST);
	m_actionHandler.bindAction(
		actionName, UIAction([this]() { saveToDisk(); }, [this]() { return canSaveRegion(); }));

	connect(this, &QTableView::doubleClicked, this, &DebugMemoryMapWidget::onDoubleClicked);
	connect(this, &DebugMemoryMapWidget::debuggerEvent, this, &DebugMemoryMapWidget::onDebuggerEvent);

	m_debuggerEventCallback = m_controller->RegisterEventCallback(
		[&](const DebuggerEvent& event) { emit debuggerEvent(event); }, "Memory Map Widget");

	updateContent();
}


DebugMemoryMapWidget::~DebugMemoryMapWidget()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_debuggerEventCallback);
}


void DebugMemoryMapWidget::updateColumnWidths()
{
	resizeColumnToContents(DebugMemoryMapListModel::StartColumn);
	resizeColumnToContents(DebugMemoryMapListModel::EndColumn);
	resizeColumnToContents(DebugMemoryMapListModel::SizeColumn);
	resizeColumnToContents(DebugMemoryMapListModel::PermissionsColumn);
	resizeColumnToContents(DebugMemoryMapListModel::NameColumn);
}


void DebugMemoryMapWidget::notifyRegionsChanged(std::vector<DebugMemoryRegion> regions)
{
	m_model->updateRows(regions);
	updateColumnWidths();
}


void DebugMemoryMapWidget::onDebuggerEvent(const DebuggerEvent& event)
{
	switch (event.type)
	{
	case TargetStoppedEventType:
	case TargetExitedEventType:
		// These updates ensure the widgets become empty after the target stops
	case DetachedEventType:
		updateContent();
		break;
	default:
		break;
	}
}


void DebugMemoryMapWidget::updateContent()
{
	if (!m_controller->IsConnected())
		return;

	std::vector<DebugMemoryRegion> regions = m_controller->GetMemoryMap();
	notifyRegionsChanged(regions);
}


void DebugMemoryMapWidget::contextMenuEvent(QContextMenuEvent* event)
{
	showContextMenu();
}


void DebugMemoryMapWidget::showContextMenu()
{
	m_contextMenuManager->show(&m_menu, &m_actionHandler);
}


void DebugMemoryMapWidget::jumpToStart()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto region = m_model->getRow(sourceIndex.row());
	uint64_t address = region.start();

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_controller->GetData())
		frame->navigate(m_controller->GetData(), address, true, true);
}


void DebugMemoryMapWidget::jumpToEnd()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto region = m_model->getRow(sourceIndex.row());
	uint64_t address = region.endAddress();

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_controller->GetData())
		frame->navigate(m_controller->GetData(), address, true, true);
}


bool DebugMemoryMapWidget::canCopy()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	return !sel.empty();
}


bool DebugMemoryMapWidget::canCopyAll()
{
	return m_model->rowCount() > 0;
}


void DebugMemoryMapWidget::copy()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	// Sort into visual order (top-to-bottom, then left-to-right) so a multi-cell selection is
	// copied the way it is laid out on screen.
	std::sort(sel.begin(), sel.end(), [](const QModelIndex& a, const QModelIndex& b) {
		if (a.row() != b.row())
			return a.row() < b.row();
		return a.column() < b.column();
	});

	auto cellText = [this](const QModelIndex& proxyIndex) -> QString {
		auto sourceIndex = m_filter->mapToSource(proxyIndex);
		if (!sourceIndex.isValid())
			return QString();

		auto region = m_model->getRow(sourceIndex.row());
		switch (proxyIndex.column())
		{
		case DebugMemoryMapListModel::StartColumn:
			return QString::asprintf("0x%" PRIx64, region.start());
		case DebugMemoryMapListModel::EndColumn:
			return QString::asprintf("0x%" PRIx64, region.endAddress());
		case DebugMemoryMapListModel::SizeColumn:
			return QString::asprintf("0x%" PRIx64, (uint64_t)region.size());
		case DebugMemoryMapListModel::PermissionsColumn:
			return QString::fromStdString(region.permissions());
		case DebugMemoryMapListModel::NameColumn:
			return QString::fromStdString(region.name());
		default:
			return QString();
		}
	};

	// Group the selected cells by row: tab-separate columns within a row, newline between rows.
	QStringList lines;
	QStringList currentRow;
	int lastRow = sel[0].row();
	for (const auto& index : sel)
	{
		if (index.row() != lastRow)
		{
			lines.append(currentRow.join('\t'));
			currentRow.clear();
			lastRow = index.row();
		}
		currentRow.append(cellText(index));
	}
	lines.append(currentRow.join('\t'));

	QString text = lines.join('\n');

	auto* clipboard = QGuiApplication::clipboard();
	clipboard->clear();
	auto* mime = new QMimeData();
	mime->setText(text);
	clipboard->setMimeData(mime);
}


void DebugMemoryMapWidget::copyAll()
{
	int rowCount = m_model->rowCount();
	if (rowCount == 0)
		return;

	QStringList lines;

	// Add header
	lines.append("Start\tEnd\tSize\tPermissions\tName");

	// Add all region rows
	for (int row = 0; row < rowCount; row++)
	{
		auto region = m_model->getRow(row);
		QString line = QString::asprintf("0x%" PRIx64 "\t0x%" PRIx64 "\t0x%" PRIx64 "\t%s\t%s", region.start(),
			region.endAddress(), (uint64_t)region.size(), region.permissions().c_str(), region.name().c_str());
		lines.append(line);
	}

	QString text = lines.join("\n");

	auto* clipboard = QGuiApplication::clipboard();
	clipboard->clear();
	auto* mime = new QMimeData();
	mime->setText(text);
	clipboard->setMimeData(mime);
}


bool DebugMemoryMapWidget::canSelectRegion()
{
	return m_controller->IsConnected() && !selectionModel()->selectedIndexes().empty();
}


bool DebugMemoryMapWidget::canSaveRegion()
{
	return m_controller->IsConnected() && !selectionModel()->selectedIndexes().empty();
}


void DebugMemoryMapWidget::selectInView()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto region = m_model->getRow(sourceIndex.row());

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	BinaryViewRef data = m_controller->GetData();
	if (!data)
		return;

	// Navigate to the start of the region first, then select the whole range in the resulting view.
	frame->navigate(data, region.start(), true, true);

	View* view = frame->getCurrentViewInterface();
	if (view)
		view->setSelectionOffsets({region.start(), region.endAddress()});
}


void DebugMemoryMapWidget::saveToDisk()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto region = m_model->getRow(sourceIndex.row());

	if (!m_controller->IsConnected())
		return;

	DataBuffer buffer = m_controller->ReadMemory(region.start(), region.size());
	if (buffer.GetLength() == 0)
	{
		QMessageBox::critical(this, "Save Failed",
			QString::asprintf("Could not read any memory from the region at 0x%" PRIx64 ".", region.start()));
		return;
	}

	QString defaultName = QString::asprintf("region_0x%" PRIx64 "-0x%" PRIx64 ".bin", region.start(), region.endAddress());
	QString savePath = QFileDialog::getSaveFileName(this, "Save Memory Region", defaultName, "All Files (*)");
	if (savePath.isEmpty())
		return;

	QFile file(savePath);
	if (!file.open(QIODevice::WriteOnly))
	{
		QMessageBox::critical(this, "Save Failed", "Could not open the destination file for writing.");
		return;
	}

	qint64 written = file.write((const char*)buffer.GetData(), buffer.GetLength());
	file.close();

	if (written != (qint64)buffer.GetLength())
	{
		QMessageBox::critical(this, "Save Failed", "Failed to write the full memory region to disk.");
		return;
	}

	// The region may be only partially readable; if so we saved fewer bytes than the region's nominal size.
	if (buffer.GetLength() < region.size())
	{
		QMessageBox::warning(this, "Partial Save",
			QString::asprintf("Only 0x%" PRIx64 " of 0x%" PRIx64 " bytes were readable and saved.",
				(uint64_t)buffer.GetLength(), (uint64_t)region.size()));
	}
}


void DebugMemoryMapWidget::onDoubleClicked()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	if (sel[0].column() != DebugMemoryMapListModel::StartColumn
		&& sel[0].column() != DebugMemoryMapListModel::EndColumn)
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto region = m_model->getRow(sourceIndex.row());
	uint64_t address;

	if (sourceIndex.column() == DebugMemoryMapListModel::StartColumn)
		address = region.start();
	else
		address = region.endAddress();

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_controller->GetData())
		frame->navigate(m_controller->GetData(), address, true, true);
};


void DebugMemoryMapWidget::setFilter(const string& filter, FilterOptions options)
{
	if (options.testFlag(UseRegexOption))
		m_filter->setFilterRegularExpression(QString::fromStdString(filter));
	else
		m_filter->setFilterFixedString(QString::fromStdString(filter));
	m_filter->setFilterCaseSensitivity(
		options.testFlag(CaseSensitiveOption) ? Qt::CaseSensitive : Qt::CaseInsensitive);
	updateColumnWidths();
}


void DebugMemoryMapWidget::updateFonts()
{
	m_delegate->updateFonts();
}


void DebugMemoryMapWidget::scrollToFirstItem() {}


void DebugMemoryMapWidget::scrollToCurrentItem() {}


void DebugMemoryMapWidget::ensureSelection() {}


void DebugMemoryMapWidget::activateSelection() {}


DebugMemoryMapWithFilter::DebugMemoryMapWithFilter(ViewFrame* view, BinaryViewRef data) : m_view(view)
{
	setProperty("bn.uiTestId", "debugger.memoryMap");
	setProperty("bn.uiTestScope", "debugger.memoryMap");
	setAccessibleName("Debugger Memory Map");
	m_memoryMap = new DebugMemoryMapWidget(view, data);
	m_separateEdit = new FilterEdit(m_memoryMap);
	m_separateEdit->setProperty("bn.uiTestId", "debugger.memoryMap.filter");
	m_separateEdit->setAccessibleName("Search debugger memory regions");
	m_separateEdit->showRegexToggle(true);
	m_filter = new FilteredView(this, m_memoryMap, m_memoryMap, m_separateEdit);
	m_filter->setFilterPlaceholderText("Search memory regions");

	auto headerLayout = new QHBoxLayout;
	headerLayout->addWidget(m_separateEdit, 1);

	// Vertically-align the hamburger icon with the text field and give the
	// layout just a bit more breathing room since it's really close to
	// the surrounding elements.
	headerLayout->setContentsMargins(1, 1, 6, 0);
	headerLayout->setAlignment(Qt::AlignBaseline);

	auto* icon = new ClickableIcon(QImage(":/debugger/menu"), QSize(16, 16));
	icon->setProperty("bn.uiTestId", "debugger.memoryMap.menu");
	icon->setAccessibleName("Debugger memory map menu");
	connect(icon, &ClickableIcon::clicked, m_memoryMap, &DebugMemoryMapWidget::showContextMenu);
	headerLayout->addWidget(icon);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addLayout(headerLayout);
	layout->addWidget(m_filter, 1);
}


void DebugMemoryMapWithFilter::updateFonts()
{
	m_memoryMap->updateFonts();
}


DebugMemoryMapContainer::DebugMemoryMapContainer(ViewFrame* frame, BinaryViewRef data) :
	SidebarWidget("Debugger Memory Map")
{
	setProperty("bn.uiTestId", "sidebar.debuggerMemoryMap");
	setProperty("bn.uiTestScope", "sidebar.debuggerMemoryMap");
	setAccessibleName("Debugger Memory Map");
	m_widget = new DebugMemoryMapWithFilter(frame, data);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_widget);
}


void DebugMemoryMapContainer::notifyFontChanged()
{
	m_widget->updateFonts();
}


DebugMemoryMapFilterProxyModel::DebugMemoryMapFilterProxyModel(QObject* parent) : QSortFilterProxyModel(parent)
{
	setFilterCaseSensitivity(Qt::CaseInsensitive);
}


bool DebugMemoryMapFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
{
	QRegularExpression regExp = filterRegularExpression();
	if (!regExp.isValid())
		return true;

	for (int column = 0; column < sourceModel()->columnCount(sourceParent); column++)
	{
		QModelIndex index = sourceModel()->index(sourceRow, column, sourceParent);
		QString data = index.data(SortFilterRole).toString();
		if (data.indexOf(regExp) != -1)
			return true;
	}
	return false;
}


DebugMemoryMapSidebarWidgetType::DebugMemoryMapSidebarWidgetType() :
	SidebarWidgetType(QImage(":/icons/images/squares-bug.png"), "Debugger Memory Map")
{}


SidebarWidget* DebugMemoryMapSidebarWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new DebugMemoryMapContainer(frame, data);
}


SidebarContentClassifier* DebugMemoryMapSidebarWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}
