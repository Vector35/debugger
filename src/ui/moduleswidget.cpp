#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include "moduleswidget.h"

using namespace BinaryNinja;
using namespace std;

ModuleItem::ModuleItem(uint64_t address, size_t size, std::string name, std::string path):
    m_address(address), m_size(size), m_name(name), m_path(path)
{
}


bool ModuleItem::operator==(const ModuleItem& other) const
{
    return (m_address == other.address()) && (m_size == other.size()) && (m_name == other.name()) &&
        (m_path == other.path());
}


bool ModuleItem::operator!=(const ModuleItem& other) const
{
    return !(*this == other);
}


bool ModuleItem::operator<(const ModuleItem& other) const
{
    if (m_address < other.address())
        return true;
    else if (m_address > other.address())
        return false;
    else if (m_size < other.size())
        return true;
    else if (m_size > other.size())
        return false;
    else if (m_name < other.name())
        return true;
    else if (m_name > other.name())
        return false;
    return m_path < other.path();
}


DebugModulesListModel::DebugModulesListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view):
    QAbstractTableModel(parent), m_data(data), m_view(view)
{
}


DebugModulesListModel::~DebugModulesListModel()
{
}


ModuleItem DebugModulesListModel::getRow(int row) const
{
    if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

    return m_items[row];
}


QModelIndex DebugModulesListModel::index(int row, int column, const QModelIndex &) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugModulesListModel::data(const QModelIndex& index, int role) const
{
    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	ModuleItem *item = static_cast<ModuleItem*>(index.internalPointer());
	if (!item)
		return QVariant();

    if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole))
        return QVariant();

    switch (index.column())
    {
    case DebugModulesListModel::AddressColumn:
    {
        QString text = QString::asprintf("%" PRIx64, item->address());
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        return QVariant(text);
    }
    case DebugModulesListModel::SizeColumn:
    {
        QString text = QString::asprintf("%" PRIx64, item->size());
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        return QVariant(text);
    }
    case DebugModulesListModel::NameColumn:
    {
        QString text = QString::fromStdString(item->name());
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        return QVariant(text);
    }
    case DebugModulesListModel::PathColumn:
    {
        QString text = QString::fromStdString(item->path());
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        return QVariant(text);
    }
    }
    return QVariant();
}


QVariant DebugModulesListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
		case DebugModulesListModel::AddressColumn:
			return "Address";
		case DebugModulesListModel::SizeColumn:
			return "Size";
		case DebugModulesListModel::NameColumn:
			return "Name";
		case DebugModulesListModel::PathColumn:
			return "Path";
	}
	return QVariant();
}


void DebugModulesListModel::updateRows(std::vector<DebugModule> newModules)
{
    beginResetModel();
    std::vector<ModuleItem> newRows;
    for (const DebugModule& module: newModules)
    {
        newRows.emplace_back(module.m_address, module.m_size, module.m_short_name, module.m_name);
    }

    std::sort(newRows.begin(), newRows.end(), [=](const ModuleItem& a, const ModuleItem& b)
        {
            return a.address() < b.address();
        });

    m_items = newRows;
    endResetModel();
}


DebugModulesItemDelegate::DebugModulesItemDelegate(QWidget* parent):
    QStyledItemDelegate(parent)
{
    updateFonts();
}


void DebugModulesItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
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
	case DebugModulesListModel::AddressColumn:
	case DebugModulesListModel::SizeColumn:
	case DebugModulesListModel::NameColumn:
	case DebugModulesListModel::PathColumn:
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


void DebugModulesItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebugModulesItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
    auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
    return QSize(totalWidth, m_charHeight + 2);
}


DebugModulesWidget::DebugModulesWidget(const QString& name, ViewFrame* view, BinaryViewRef data):
    SidebarWidget(name), m_view(view)
{
    m_controller = DebuggerController::GetController(data);

    m_table = new QTableView(this);
    m_model = new DebugModulesListModel(m_table, data, view);
    m_table->setModel(m_model);

    m_delegate = new DebugModulesItemDelegate(this);
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

    updateContent();
}


void DebugModulesWidget::notifyModulesChanged(std::vector<DebugModule> modules)
{
    m_model->updateRows(modules);
    m_table->resizeColumnsToContents();
}


void DebugModulesWidget::notifyFontChanged()
{
    m_delegate->updateFonts();
}


void DebugModulesWidget::updateContent()
{
    if (!m_controller->IsConnected())
        return;

    std::vector<DebugModule> modules = m_controller->GetModules();
    notifyModulesChanged(modules);
}
