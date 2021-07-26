#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include "registerwidget.h"

using namespace BinaryNinja;
using namespace std;

DebugRegisterItem::DebugRegisterItem(const string& name, uint64_t value, bool update, const string& hint):
    m_name(name), m_value(value), m_updated(update), m_hint(hint)
{
}


bool DebugRegisterItem::operator==(const DebugRegisterItem& other) const
{
    return (m_name == other.name()) && (m_value == other.value()) && (m_updated == other.updated()) &&
        (m_hint == other.hint());
}


bool DebugRegisterItem::operator!=(const DebugRegisterItem& other) const
{
    return !(*this == other);
}


bool DebugRegisterItem::operator<(const DebugRegisterItem& other) const
{
    if (m_name < other.name())
        return true;
    else if (m_name > other.name())
        return false;
    else if (m_value < other.value())
        return true;
    else if (m_value > other.value())
        return false;
    else if (m_updated < other.updated())
        return true;
    else if (m_updated > other.updated())
        return false;
    return m_hint < other.hint();
}


DebugRegistersListModel::DebugRegistersListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view):
    QAbstractTableModel(parent), m_data(data), m_view(view)
{   
}


DebugRegistersListModel::~DebugRegistersListModel()
{
}



Qt::ItemFlags DebugRegistersListModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flag = QAbstractTableModel::flags(index);
    if (index.column() == DebugRegistersListModel::ValueColumn)
        flag |= Qt::ItemIsEditable;

    return flag;
}


DebugRegisterItem DebugRegistersListModel::getRow(int row) const
{
    if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

    return m_items[row];
}


QModelIndex DebugRegistersListModel::index(int row, int column, const QModelIndex &) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugRegistersListModel::data(const QModelIndex& index, int role) const
{
    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	DebugRegisterItem *item = static_cast<DebugRegisterItem*>(index.internalPointer());
	if (!item)
		return QVariant();


    if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole))
        return QVariant();

    switch (index.column())
    {
    case DebugRegistersListModel::NameColumn:
    {
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)item->name().size());

        QList<QVariant> line;
        line.push_back(getThemeColor(RegisterColor).rgba());
		line.push_back(QString::fromStdString(item->name()));
		return QVariant(line);
    }
    case DebugRegistersListModel::ValueColumn:
    {
        // TODO: We need better alignment for values
        uint64_t value = item->value();
        QString valueStr = QString::asprintf("%" PRIx64, value);
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)valueStr.size());

        QList<QVariant> line;
        if (item->updated())
            line.push_back(getThemeColor(OrangeStandardHighlightColor).rgba());
        else
            line.push_back(getThemeColor(NumberColor).rgba());

		line.push_back(valueStr);
		return QVariant(line);
    }
    case DebugRegistersListModel::HintColumn:
    {
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)item->hint().size());

        QList<QVariant> line;
        line.push_back(getThemeColor(StringColor).rgba());
		line.push_back(QString::fromStdString(item->hint()));
		return QVariant(line);
    }
    }
    return QVariant();
}


QVariant DebugRegistersListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
		case DebugRegistersListModel::NameColumn:
			return "Name";
		case DebugRegistersListModel::ValueColumn:
			return "Value";
		case DebugRegistersListModel::HintColumn:
			return "Hint";
	}
	return QVariant();
}


void DebugRegistersListModel::updateRows(std::vector<DebugRegister> newRows)
{
    // TODO: This might cause performance problems. We can instead only update the chagned registers.
    // However, the cost for that is we need to attach an index to each item and sort accordingly
    beginResetModel();
    std::map<std::string, uint64_t> oldRegValues;
    for (const DebugRegisterItem& item: m_items)
        oldRegValues[item.name()] = item.value();

    m_items.clear();
    if (newRows.size() == 0)
    {
        endResetModel();
        return;
    }

    for (const DebugRegister& reg: newRows)
    {
        bool updated;
        auto iter = oldRegValues.find(reg.m_name);
        if (iter == oldRegValues.end())
        {
            updated = false;
        }
        else
        {
            updated = (iter->second == reg.m_value);
        }
        m_items.emplace_back(reg.m_name, reg.m_value, updated, "");
    }
    endResetModel();
}


DebugRegistersItemDelegate::DebugRegistersItemDelegate(QWidget* parent):
    QStyledItemDelegate(parent)
{
    updateFonts();
}


void DebugRegistersItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
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
	case DebugRegistersListModel::NameColumn:
	case DebugRegistersListModel::ValueColumn:
	case DebugRegistersListModel::HintColumn:
	{
		auto tokenPair = data.toList();
		if (tokenPair.size() == 0)
			break;
		painter->setPen(QColor((QRgb)tokenPair[0].toInt()));
		painter->drawText(textRect, tokenPair[1].toString());
		break;
	}
	default:
		break;
	}
}


void DebugRegistersItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebugRegistersItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
    auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
    return QSize(totalWidth, m_charHeight + 2);
}


DebugRegistersWidget::DebugRegistersWidget(ViewFrame* view, const QString& name, BinaryViewRef data):
    QWidget(view), DockContextHandler(this, name), m_view(view), m_data(data)
{
    m_table = new QTableView(this);
    m_model = new DebugRegistersListModel(m_table, data, view);
    m_table->setModel(m_model);

    m_delegate = new DebugRegistersItemDelegate(this);
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


void DebugRegistersWidget::notifyRegistersChanged(std::vector<DebugRegister> regs)
{
    m_model->updateRows(regs);
    // TODO: we could also set the columns' ResizeMode to ResizeToContents
    m_table->resizeColumnsToContents();
}


void DebugRegistersWidget::notifyFontChanged()
{
    m_delegate->updateFonts();
}
