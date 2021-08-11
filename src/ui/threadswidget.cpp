#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include "threadswidget.h"

using namespace BinaryNinja;
using namespace std;

ThreadItem::ThreadItem(size_t tid, uint64_t location):
    m_tid(tid), m_location(location)
{
}


bool ThreadItem::operator==(const ThreadItem& other) const
{
    return (m_tid == other.tid()) && (m_location == other.location());
}


bool ThreadItem::operator!=(const ThreadItem& other) const
{
    return !(*this == other);
}


bool ThreadItem::operator<(const ThreadItem& other) const
{
    if (m_tid < other.tid())
        return true;
    else if (m_tid > other.tid())
        return false;

    return m_location < other.location();
}


DebugThreadsListModel::DebugThreadsListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view):
    QAbstractTableModel(parent), m_data(data), m_view(view)
{
}


DebugThreadsListModel::~DebugThreadsListModel()
{
}


ThreadItem DebugThreadsListModel::getRow(int row) const
{
    if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

    return m_items[row];
}


QModelIndex DebugThreadsListModel::index(int row, int column, const QModelIndex &) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugThreadsListModel::data(const QModelIndex& index, int role) const
{
    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	ThreadItem *item = static_cast<ThreadItem*>(index.internalPointer());
	if (!item)
		return QVariant();

    if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole))
        return QVariant();

    switch (index.column())
    {
    case DebugThreadsListModel::TIDColumn:
    {
        QString text = QString::fromStdString(fmt::format("{:x}", item->tid()));
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        return QVariant(text);
    }
    case DebugThreadsListModel::LocationColumn:
    {
        QString text = QString::fromStdString(fmt::format("{:x}", item->location()));
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        return QVariant(text);
    }
    }
    return QVariant();
}


QVariant DebugThreadsListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
		case DebugThreadsListModel::TIDColumn:
			return "TID";
		case DebugThreadsListModel::LocationColumn:
			return "Location";
	}
	return QVariant();
}


void DebugThreadsListModel::updateRows(std::vector<DebuggerThreadCache> threads)
{
    beginResetModel();
    std::vector<ThreadItem> newRows;
    for (const DebuggerThreadCache& thread: threads)
    {
        newRows.emplace_back(thread.thread.m_tid, thread.ip);
    }

    std::sort(newRows.begin(), newRows.end(), [=](const ThreadItem& a, const ThreadItem& b)
        {
            return a.tid() < b.tid();
        });

    m_items = newRows;
    endResetModel();
}


DebugThreadsItemDelegate::DebugThreadsItemDelegate(QWidget* parent):
    QStyledItemDelegate(parent)
{
    updateFonts();
}


void DebugThreadsItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
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
	case DebugThreadsListModel::TIDColumn:
	case DebugThreadsListModel::LocationColumn:
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


void DebugThreadsItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebugThreadsItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
    auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
    return QSize(totalWidth, m_charHeight + 2);
}


DebugThreadsWidget::DebugThreadsWidget(const QString& name, ViewFrame* view, BinaryViewRef data):
    SidebarWidget(name), m_view(view), m_data(data)
{
    m_table = new QTableView(this);
    m_model = new DebugThreadsListModel(m_table, data, view);
    m_table->setModel(m_model);

    m_delegate = new DebugThreadsItemDelegate(this);
    m_table->setItemDelegate(m_delegate);

    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);

    m_table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->verticalHeader()->setVisible(false);

    m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    m_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

    m_table->resizeColumnsToContents();
    m_table->resizeRowsToContents();

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(m_table);
    setLayout(layout);
}


void DebugThreadsWidget::notifyThreadsChanged(std::vector<DebuggerThreadCache> threads)
{
    m_model->updateRows(threads);
    m_table->resizeColumnsToContents();
}


void DebugThreadsWidget::notifyFontChanged()
{
    m_delegate->updateFonts();
}
