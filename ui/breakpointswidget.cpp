/*
Copyright 2020-2023 Vector 35 Inc.

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

BreakpointItem::BreakpointItem(bool enabled, const ModuleNameAndOffset location, uint64_t address) :
	m_enabled(enabled), m_location(location), m_address(address)
{}


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


DebugBreakpointsListModel::DebugBreakpointsListModel(QWidget* parent, ViewFrame* view) :
	QAbstractTableModel(parent), m_view(view)
{}


DebugBreakpointsListModel::~DebugBreakpointsListModel() {}


BreakpointItem DebugBreakpointsListModel::getRow(int row) const
{
	if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

	return m_items[row];
}


QModelIndex DebugBreakpointsListModel::index(int row, int column, const QModelIndex&) const
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

	BreakpointItem* item = static_cast<BreakpointItem*>(index.internalPointer());
	if (!item)
		return QVariant();

	if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole))
		return QVariant();

	switch (index.column())
	{
//	case DebugBreakpointsListModel::EnabledColumn:
//	{
//		QString text = item->enabled() ? "true" : "false";
//		return QVariant(text);
//	}
	case DebugBreakpointsListModel::LocationColumn:
	{
		QString text;
		if (item->location().module == "")
		{
			text = QString::fromStdString(fmt::format("0x{:x}", item->location().offset));
		}
		else
		{
			// TODO: This should probably be done at the API level, e.g., also returning a short name of the module
			QFileInfo fileInfo(QString::fromStdString(item->location().module));
			auto fileName = fileInfo.fileName();
			text = QString::fromStdString(fmt::format("{} + 0x{:x}", fileName.toStdString(), item->location().offset));
		}

		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugBreakpointsListModel::AddressColumn:
	{
		QString text = QString::fromStdString(fmt::format("0x{:x}", item->address()));
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

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
//	case DebugBreakpointsListModel::EnabledColumn:
//		return "Enabled";
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


DebugBreakpointsItemDelegate::DebugBreakpointsItemDelegate(QWidget* parent) : QStyledItemDelegate(parent)
{
	updateFonts();
}


void DebugBreakpointsItemDelegate::paint(
	QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const
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


QSize DebugBreakpointsItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
	return QSize(totalWidth, m_charHeight + 2);
}


DebugBreakpointsWidget::DebugBreakpointsWidget(ViewFrame* view, BinaryViewRef data, Menu* menu):
	QTableView(view), m_view(view)
{
	m_controller = DebuggerController::GetController(data);
	if (!m_controller)
		return;

	m_model = new DebugBreakpointsListModel(this, view);
	setModel(m_model);
	setSelectionBehavior(QAbstractItemView::SelectItems);
	setSelectionMode(QAbstractItemView::ExtendedSelection);

	m_delegate = new DebugBreakpointsItemDelegate(this);
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

	QString removeBreakpointActionName = QString::fromStdString("Remove Breakpoint");
	UIAction::registerAction(removeBreakpointActionName, QKeySequence::Delete);
	m_menu->addAction(removeBreakpointActionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		removeBreakpointActionName, UIAction([&]() { remove(); }, [&]() { return selectionNotEmpty(); }));

	QString jumpToBreakpointActionName = QString::fromStdString("Jump To Breakpoint");
	UIAction::registerAction(jumpToBreakpointActionName);
	m_menu->addAction(jumpToBreakpointActionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		jumpToBreakpointActionName, UIAction([&]() { jump(); }, [&]() { return selectionNotEmpty(); }));

	QString addBreakpointActionName = QString::fromStdString("Add Breakpoint...");
	UIAction::registerAction(addBreakpointActionName);
	m_menu->addAction(addBreakpointActionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		addBreakpointActionName, UIAction([&]() { add(); }));

	connect(this, &QTableView::doubleClicked, this, &DebugBreakpointsWidget::onDoubleClicked);

	updateContent();
}


DebugBreakpointsWidget::~DebugBreakpointsWidget() {}


void DebugBreakpointsWidget::onDoubleClicked()
{
	jump();
}


void DebugBreakpointsWidget::updateFonts()
{
	m_delegate->updateFonts();
}


void DebugBreakpointsWidget::contextMenuEvent(QContextMenuEvent* event)
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}


bool DebugBreakpointsWidget::selectionNotEmpty()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	return (!sel.empty()) && sel[0].isValid();
}


void DebugBreakpointsWidget::jump()
{
	QModelIndexList sel = selectionModel()->selectedRows();
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


void DebugBreakpointsWidget::add()
{
	UIContext* ctxt = UIContext::contextForWidget(this);
	if (!ctxt)
		return;

	ViewFrame* frame = ctxt->getCurrentViewFrame();
	if (!frame)
		return;

	auto view = frame->getCurrentBinaryView();
	if (!view)
		return;

	uint64_t address = 0;
	if (!ViewFrame::getAddressFromInput(frame, view, address,
			frame->getCurrentOffset(), "Add Breakpoint", "The address of the breakpoint:", true))
		return;

	bool isAbsoluteAddress = false;
	if (view->GetTypeName() == "Debugger")
		isAbsoluteAddress = true;

	if (isAbsoluteAddress)
	{
		m_controller->AddBreakpoint(address);
	}
	else
	{
		std::string filename = m_controller->GetInputFile();
		uint64_t offset = address - view->GetStart();
		ModuleNameAndOffset info = {filename, offset};
		m_controller->AddBreakpoint(info);
	}
}


void DebugBreakpointsWidget::remove()
{
	QModelIndexList sel = selectionModel()->selectedRows();
	std::vector<ModuleNameAndOffset> breakpointsToRemove;

	for (const QModelIndex& index : sel)
	{
		// We cannot delete the breakpoint inside this loop because deleting a breakpoint will cause this widget to
		// remove the breakpoint from the list, which will invalidate the index of the remaining breakpoints.
		BreakpointItem bp = m_model->getRow(index.row());
		breakpointsToRemove.push_back(bp.location());
	}

	for (const auto& bp : breakpointsToRemove)
		m_controller->DeleteBreakpoint(bp);
}


void DebugBreakpointsWidget::updateContent()
{
	std::vector<DebugBreakpoint> breakpoints = m_controller->GetBreakpoints();

	std::vector<BreakpointItem> bps;
	for (const DebugBreakpoint& bp : breakpoints)
	{
		ModuleNameAndOffset info;
		info.module = bp.module;
		info.offset = bp.offset;
		bps.emplace_back(bp.enabled, info, bp.address);
	}

	m_model->updateRows(bps);
}
