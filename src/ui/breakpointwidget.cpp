#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include "breakpointwidget.h"

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


DebugBreakpointsWidget::DebugBreakpointsWidget(ViewFrame* view, const QString& name, BinaryViewRef data):
    QWidget(view), DockContextHandler(this, name), m_view(view), m_data(data)
{
    m_table = new QTableView(this);
    m_model = new DebugBreakpointsListModel(m_table, data, view);
    m_table->setModel(m_model);

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
}


void DebugBreakpointsWidget::notifyBreakpointsChanged(std::vector<BreakpointItem> breakpoints)
{
    m_model->updateRows(breakpoints);
}


void DebugBreakpointsWidget::notifyFontChanged()
{
    m_delegate->updateFonts();
}
