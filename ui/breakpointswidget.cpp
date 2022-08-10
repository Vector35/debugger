/*
Copyright 2020-2022 Vector 35 Inc.

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
#include <QFileInfo>
#include "breakpointswidget.h"
#include "ui.h"
#include "menus.h"
#include "fmt/format.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

BreakpointItem::BreakpointItem(bool enabled, const ModuleNameAndOffset location, uint64_t address):
    m_enabled(enabled), m_location(location), m_address(address)
{
}


bool BreakpointItem::operator==(const BreakpointItem& other) const
{
    return (m_enabled == other.enabled()) && (m_location == other.location()) && (m_address == other.address());
}


bool BreakpointItem::operator!=(const BreakpointItem& other) const
{
    return !(*this == other);
}


bool BreakpointItem::operator<(const BreakpointItem& other) const
{
    if (m_enabled < other.enabled())
        return true;
    else if (m_enabled > other.enabled())
        return false;
    else if (m_location < other.location())
        return true;
    else if (m_location > other.location())
        return false;
    return m_address < other.address();
}


DebugBreakpointsListModel::DebugBreakpointsListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view):
    QAbstractTableModel(parent), m_data(data), m_view(view)
{
}


DebugBreakpointsListModel::~DebugBreakpointsListModel()
{
}


BreakpointItem DebugBreakpointsListModel::getRow(int row) const
{
    if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

    return m_items[row];
}


QModelIndex DebugBreakpointsListModel::index(int row, int column, const QModelIndex &) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugBreakpointsListModel::data(const QModelIndex& index, int role) const
{
    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	BreakpointItem *item = static_cast<BreakpointItem*>(index.internalPointer());
	if (!item)
		return QVariant();

    if (role != Qt::DisplayRole)
        return QVariant();

    switch (index.column())
    {
//    case DebugBreakpointsListModel::EnabledColumn:
//    {
//        QString text = item->enabled() ? "true" : "false";
//        return QVariant(text);
//    }
    case DebugBreakpointsListModel::LocationColumn:
    {
		QString text;
		if (item->location().module == "")
		{
			text = QString::fromStdString(
					fmt::format("0x{:x}", item->location().offset));
		}
		else
		{
			// TODO: This should probably be done at the API level, e.g., also returning a short name of the module
			QFileInfo fileInfo(QString::fromStdString(item->location().module));
			auto fileName = fileInfo.fileName();
			text = QString::fromStdString(
					fmt::format("{} + 0x{:x}", fileName.toStdString(), item->location().offset));
		}
        return QVariant(text);
    }
    case DebugBreakpointsListModel::AddressColumn:
    {
        QString text = QString::fromStdString(
                fmt::format("0x{:x}", item->address()));
        return QVariant(text);
    }
    }
    return QVariant();
}


QVariant DebugBreakpointsListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
//		case DebugBreakpointsListModel::EnabledColumn:
//			return "Enabled";
		case DebugBreakpointsListModel::LocationColumn:
			return "Location";
		case DebugBreakpointsListModel::AddressColumn:
			return "Remote Address";
	}
	return QVariant();
}


void DebugBreakpointsListModel::updateRows(std::vector<BreakpointItem> newRows)
{
    beginResetModel();
    m_items = newRows;
    endResetModel();
}


DebugBreakpointsItemDelegate::DebugBreakpointsItemDelegate(QWidget* parent):
    QStyledItemDelegate(parent)
{
    updateFonts();
}


void DebugBreakpointsItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
	const QModelIndex& idx) const
{
	painter->setFont(m_font);

	bool selected = (option.state & QStyle::State_Selected) != 0;
	if (selected)
		painter->setBrush(getThemeColor(SelectionColor));
	else
		painter->setBrush(option.backgroundBrush);

	painter->setPen(Qt::NoPen);

	QRect textRect = option.rect;
	textRect.setBottom(textRect.top() + m_charHeight + 2);
	painter->drawRect(textRect);

	auto data = idx.data(Qt::DisplayRole);
	switch (idx.column())
	{
//	case DebugBreakpointsListModel::EnabledColumn:
	case DebugBreakpointsListModel::LocationColumn:
	case DebugBreakpointsListModel::AddressColumn:
	{
        painter->setFont(m_font);
        painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	default:
		break;
	}
}


void DebugBreakpointsItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


DebugBreakpointsWidget::DebugBreakpointsWidget(const QString& name, ViewFrame* view, BinaryViewRef data, Menu* menu):
    m_view(view)
{
    m_controller = DebuggerController::GetController(data);

    m_table = new QTableView(this);
    m_model = new DebugBreakpointsListModel(m_table, data, view);
    m_table->setModel(m_model);
    m_table->setSelectionBehavior(QAbstractItemView::SelectItems);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);

    m_delegate = new DebugBreakpointsItemDelegate(this);
    m_table->setItemDelegate(m_delegate);

    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);

    m_table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->verticalHeader()->setVisible(false);

    m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

    m_table->resizeColumnsToContents();
    m_table->resizeRowsToContents();
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(m_table);
    setLayout(layout);

    m_actionHandler.setupActionHandler(this);
    m_contextMenuManager = new ContextMenuManager(this);
    m_handler = UIActionHandler::actionHandlerFromWidget(this);
    m_menu = menu;
    if (m_menu == nullptr)
        m_menu = new Menu();

    QString removeBreakpointActionName = QString::fromStdString("Remove Breakpoint");
    UIAction::registerAction(removeBreakpointActionName, QKeySequence::Delete);
    m_menu->addAction(removeBreakpointActionName, "Options", MENU_ORDER_NORMAL);
    m_handler->bindAction(removeBreakpointActionName, UIAction([&](){ remove(); }));

    QString jumpToBreakpointActionName = QString::fromStdString("Jump To Breakpoint");
    UIAction::registerAction(jumpToBreakpointActionName);
    m_menu->addAction(jumpToBreakpointActionName, "Options", MENU_ORDER_NORMAL);
    m_actionHandler.bindAction(jumpToBreakpointActionName, UIAction([&](){ jump(); }));

    updateContent();
}


DebugBreakpointsWidget::~DebugBreakpointsWidget()
{
}


//void DebugBreakpointsWidget::notifyFontChanged()
//{
//    m_delegate->updateFonts();
//}


void DebugBreakpointsWidget::contextMenuEvent(QContextMenuEvent* event)
{
    m_contextMenuManager->show(m_menu, m_handler);
}


void DebugBreakpointsWidget::jump()
{
	QModelIndexList sel = m_table->selectionModel()->selectedRows();
	if (sel.empty())
		return;

	BreakpointItem bp = m_model->getRow(sel[0].row());

	auto address_or_offset = bp.address();
	Ref<BinaryView> view = m_controller->GetData();
    const auto is_absolute = m_controller->IsConnected();
    if (!is_absolute)
        address_or_offset += view->GetStart();

    UIContext* context = UIContext::contextForWidget(this);
    ViewFrame* frame = context->getCurrentViewFrame();
	if (m_controller->GetLiveView())
    	frame->navigate(m_controller->GetLiveView(), address_or_offset, true, true);
	else
		frame->navigate(m_controller->GetData(), address_or_offset, true, true);
}


void DebugBreakpointsWidget::remove()
{
    QModelIndexList sel = m_table->selectionModel()->selectedRows();
    for (const QModelIndex& index: sel)
    {
        // Process the selection one by one
        BreakpointItem bp = m_model->getRow(index.row());
//        We need better handling here
//        state->DeleteBreakpoint(bp.address());
        m_controller->DeleteBreakpoint(bp.location());
    }
}


void DebugBreakpointsWidget::updateContent()
{
	std::vector<DebugBreakpoint> breakpoints = m_controller->GetBreakpoints();

    std::vector<BreakpointItem> bps;
    for (const DebugBreakpoint& bp: breakpoints)
    {
		ModuleNameAndOffset info;
		info.module = bp.module;
		info.offset = bp.offset;
        bps.emplace_back(bp.enabled, info, bp.address);
    }

    m_model->updateRows(bps);
}


BreakpointSideBarWidget::BreakpointSideBarWidget(const QString& name, ViewFrame* view, BinaryViewRef data):
    SidebarWidget(name), m_view(view), m_data(data)
{
    m_controller = DebuggerController::GetController(m_data);

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->setAlignment(Qt::AlignTop);

    m_breakpointsWidget = new DebugBreakpointsWidget("Debugger Breakpoints", m_view, m_data, m_menu);

    layout->addWidget(m_breakpointsWidget);
    setLayout(layout);

	m_ui = DebuggerUI::GetForViewFrame(view);
	connect(m_ui, &DebuggerUI::debuggerEvent, this, &BreakpointSideBarWidget::uiEventHandler);
}


BreakpointSideBarWidget::~BreakpointSideBarWidget()
{
}



void BreakpointSideBarWidget::uiEventHandler(const DebuggerEvent &event)
{
    switch (event.type)
    {
    case TargetStoppedEventType:
    case DetachedEventType:
    case QuitDebuggingEventType:
    case BackEndDisconnectedEventType:
    case RelativeBreakpointAddedEvent:
    case AbsoluteBreakpointAddedEvent:
    case RelativeBreakpointRemovedEvent:
    case AbsoluteBreakpointRemovedEvent:
		updateContent();
    default:
        break;
    }
}


void BreakpointSideBarWidget::updateContent()
{
	m_breakpointsWidget->updateContent();
}


void BreakpointSideBarWidget::notifyFontChanged()
{

}
