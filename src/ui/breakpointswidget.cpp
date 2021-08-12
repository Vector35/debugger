#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include "breakpointswidget.h"
#include "../ui/ui.h"

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
    case DebugBreakpointsListModel::EnabledColumn:
    {
        QString text = item->enabled() ? "true" : "false";
        return QVariant(text);
    }
    case DebugBreakpointsListModel::LocationColumn:
    {
        QString text = QString::fromStdString(
                fmt::format("{} + 0x{:x}", item->location().module, item->location().offset));
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
		case DebugBreakpointsListModel::EnabledColumn:
			return "Enabled";
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
	case DebugBreakpointsListModel::EnabledColumn:
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


DebugBreakpointsWidget::DebugBreakpointsWidget(const QString& name, ViewFrame* view, BinaryViewRef data):
    SidebarWidget(name), m_view(view), m_data(data)
{
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
    m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(m_table);
    setLayout(layout);

    QString removeBreakpointActionName = QString::fromStdString("Remove Breakpoint");
    UIAction::registerAction(removeBreakpointActionName, QKeySequence::Delete);
    m_menu->addAction(removeBreakpointActionName, "Options", MENU_ORDER_NORMAL);
    m_actionHandler.setActionContext([=]() { return m_view->actionContext(); });
    m_actionHandler.bindAction(removeBreakpointActionName, UIAction([&](){ remove(); }));
    m_actionHandler.setActionDisplayName(removeBreakpointActionName, "Remove");

    QString jumpToBreakpointActionName = QString::fromStdString("Jump To Breakpoint");
    UIAction::registerAction(jumpToBreakpointActionName);
    m_menu->addAction(jumpToBreakpointActionName, "Options", MENU_ORDER_NORMAL);
    m_actionHandler.setActionContext([=]() { return m_view->actionContext(); });
    m_actionHandler.bindAction(jumpToBreakpointActionName, UIAction([&](){ jump(); }));
    m_actionHandler.setActionDisplayName(jumpToBreakpointActionName, "Jump To");

    showInitialBreakpoints();
}


void DebugBreakpointsWidget::notifyBreakpointsChanged(std::vector<BreakpointItem> breakpoints)
{
    m_model->updateRows(breakpoints);
}


void DebugBreakpointsWidget::notifyFontChanged()
{
    m_delegate->updateFonts();
}


void DebugBreakpointsWidget::contextMenuEvent(QContextMenuEvent* /*event*/)
{
    m_contextMenuManager->show(m_menu, UIActionHandler::actionHandlerFromWidget(this));
}


void DebugBreakpointsWidget::showInitialBreakpoints()
{
    DebuggerState* state = DebuggerState::GetState(m_data);
    if (!state)
        return;

    // This duplicates the code in void DebuggerUI::UpdateBreakpoints(), need refactor
    std::vector<BreakpointItem> bps;
    std::vector<DebugBreakpoint> remoteList;
    if (state->IsConnected())
        std::vector<DebugBreakpoint> remoteList = state->GetAdapter()->GetBreakpointList();

    for (const ModuleNameAndOffset& address: state->GetBreakpoints()->GetBreakpointList())
    {
        uint64_t remoteAddress = state->GetModules()->RelativeAddressToAbsolute(address);
        bool enabled = false;
        for (const DebugBreakpoint& bp: remoteList)
        {
            if (bp.m_address == remoteAddress)
            {
                enabled = true;
                break;
            }
        }
        bps.emplace_back(enabled, address, remoteAddress);
    }

    notifyBreakpointsChanged(bps);
}


void DebugBreakpointsWidget::jump()
{
    const auto item_row = this->m_table->indexAt(this->m_last_selected_point).row();
    const auto item = this->m_table->model()->index(item_row, 2);

    auto view = this->m_data.GetPtr();
    auto address_or_offset = std::stoull(item.data().toString().toLocal8Bit().data(), nullptr, 16);
    if (!address_or_offset || !view)
        return;

    DebuggerState* state = DebuggerState::GetState(view);
    if (!state)
        return;

    DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
    if (!breakpoints)
        return;

    const auto is_absolute = state->IsConnected();
    if (!is_absolute)
        address_or_offset += view->GetStart();

    const auto filename = view->GetFile()->GetOriginalFilename();
    const auto breakpoint_offset = ModuleNameAndOffset(filename, address_or_offset - view->GetStart());

    ViewFrame* frame = ViewFrame::viewFrameForWidget(state->GetDebuggerUI()->GetDebugView());
    frame->navigate(state->GetData(), address_or_offset, true, true);
}


void DebugBreakpointsWidget::remove()
{
    LogWarn("DebugBreakpointsWidget::Remove()");

    DebuggerState* state = DebuggerState::GetState(m_data);
    if (!state)
        return;

    DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
    if (!breakpoints)
        return;

    QModelIndexList sel = m_table->selectionModel()->selectedRows();
    for (const QModelIndex& index: sel)
    {
        // Process the selection one by one
        BreakpointItem bp = m_model->getRow(index.row());
        state->DeleteBreakpoint(bp.address());
    }

//
//    const auto item_row = this->m_table->indexAt(this->m_last_selected_point).row();
//    const auto item = this->m_table->model()->index(item_row, 2);
//
//    auto view = this->m_data.GetPtr();
//    auto address_or_offset = std::stoull(item.data().toString().toLocal8Bit().data(), nullptr, 16);
//    if (!address_or_offset || !view)
//        return;
//
//
//
//    const auto is_absolute = state->IsConnected();
//    if (!is_absolute)
//        address_or_offset += view->GetStart();
//
//    const auto filename = view->GetFile()->GetOriginalFilename();
//    const auto breakpoint_offset = ModuleNameAndOffset(filename, address_or_offset - view->GetStart());
//
//    if (breakpoints->ContainsOffset(breakpoint_offset)) {
//        breakpoints->RemoveOffset(breakpoint_offset);
//        for (const auto& func : state->GetData()->GetAnalysisFunctionsContainingAddress(address_or_offset)) {
//            func->SetAutoInstructionHighlight(state->GetData()->GetDefaultArchitecture(), address_or_offset, NoHighlightColor);
//            for (const auto& tag : func->GetAddressTags(state->GetData()->GetDefaultArchitecture(), address_or_offset)) {
//                if (tag->GetType() != state->GetDebuggerUI()->GetBreakpointTagType())
//                    continue;
//
//                func->RemoveUserAddressTag(state->GetData()->GetDefaultArchitecture(), address_or_offset, tag);
//            }
//        }
//    }
//
//    state->GetDebuggerUI()->UpdateBreakpoints();
}
