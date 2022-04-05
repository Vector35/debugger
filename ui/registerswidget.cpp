#include <QPainter>
#include <QHeaderView>
#include <QLineEdit>
 #include <QListView>
#include "registerswidget.h"

using namespace BinaryNinja;
using namespace std;

DebugRegisterItem::DebugRegisterItem(const string& name, uint64_t value, DebugRegisterValueStatus valueStatus,
    const string& hint):
    m_name(name), m_value(value), m_valueStatus(valueStatus), m_hint(hint)
{
}


bool DebugRegisterItem::operator==(const DebugRegisterItem& other) const
{
    return (m_name == other.name()) && (m_value == other.value()) && (m_valueStatus == other.valueStatus()) &&
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
    else if (m_valueStatus < other.valueStatus())
        return true;
    else if (m_valueStatus > other.valueStatus())
        return false;
    return m_hint < other.hint();
}


DebugRegistersListModel::DebugRegistersListModel(QWidget* parent, DebuggerController* controller, ViewFrame* view):
    QAbstractTableModel(parent), m_controller(controller), m_view(view)
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
        line.push_back(getThemeColor(WhiteStandardHighlightColor).rgba());
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
        switch (item->valueStatus())
        {
        case DebugRegisterValueNormal:
            line.push_back(getThemeColor(WhiteStandardHighlightColor).rgba());
            break;
        case DebugRegisterValueChanged:
            line.push_back(getThemeColor(BlueStandardHighlightColor).rgba());
            break;
        case DebugRegisterValueModified:
            line.push_back(getThemeColor(OrangeStandardHighlightColor).rgba());
            break;
        }

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
		// Do not display registers whose value is 0x0.
		// In the future we should make user decide if these should be hidden.
		if (reg.m_value == 0)
			continue;

        auto iter = oldRegValues.find(reg.m_name);
        DebugRegisterValueStatus status;
        if (iter == oldRegValues.end())
        {
            status = DebugRegisterValueNormal;
        }
        else
        {
            if (iter->second == reg.m_value)
            {
                status = DebugRegisterValueNormal;
            }
            else
            {
                status = DebugRegisterValueChanged;
            }
        }


        m_items.emplace_back(reg.m_name, reg.m_value, status, reg.m_hint);
    }
    endResetModel();
}


bool DebugRegistersListModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if ((flags(index) & Qt::ItemIsEditable) != Qt::ItemIsEditable)
        return false;

    QString valueStr = value.toString();
    if (valueStr.size() == 0)
        return false;

    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return false;

	DebugRegisterItem *item = static_cast<DebugRegisterItem*>(index.internalPointer());
	if (!item)
        return false;

    bool ok = false;
    uint64_t newValue = valueStr.toULongLong(&ok, 16);
    if (!ok)
        return false;

    if (newValue == item->value())
        return false;

    ok = m_controller->SetRegisterValue(item->name(), newValue);
    if (!ok)
        return false;

    item->setValue(newValue);
    item->setValueStatus(DebugRegisterValueModified);
    return true;
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


void DebugRegistersItemDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (index.column() == DebugRegistersListModel::ValueColumn)
    {
        QLineEdit* lineEditor = static_cast<QLineEdit*>(editor);
        if (lineEditor)
        {
            // index.data() returns a pair of colar and QString
            lineEditor->setText(index.data().toList()[1].toString());
        }
    }
}


DebugRegistersWidget::DebugRegistersWidget(const QString& name, ViewFrame* view, BinaryViewRef data):
    SidebarWidget(name), m_view(view)
{
    m_controller = DebuggerController::GetController(data);

    m_table = new QTableView(this);
    m_model = new DebugRegistersListModel(m_table, m_controller, view);
    m_table->setModel(m_model);

    m_delegate = new DebugRegistersItemDelegate(this);
    m_table->setItemDelegate(m_delegate);

    m_table->setSelectionBehavior(QAbstractItemView::SelectItems);

    m_table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->verticalHeader()->setVisible(false);

	m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
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


void DebugRegistersWidget::updateContent()
{
    if (!m_controller->IsConnected())
        return;

    std::vector<DebugRegister> registers = m_controller->GetRegisters();
    notifyRegistersChanged(registers);
}
