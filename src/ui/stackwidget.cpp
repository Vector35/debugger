#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include "stackwidget.h"
#include "../debuggercontroller.h"

using namespace BinaryNinja;
using namespace std;

DebugStackItem::DebugStackItem(ptrdiff_t offset, uint64_t address, uint64_t value, std::string hint,
    DebugStackValueStatus valueStatus):
    m_offset(offset), m_address(address), m_value(value), m_valueStatus(valueStatus), m_hint(std::move(hint))
{
}


bool DebugStackItem::operator==(const DebugStackItem& other) const
{
    return (m_offset == other.offset()) && (m_address == other.address()) && (m_value == other.value()) &&
        (m_valueStatus == other.valueStatus()) && (m_hint == other.hint());
}


bool DebugStackItem::operator!=(const DebugStackItem& other) const
{
    return !(*this == other);
}


bool DebugStackItem::operator<(const DebugStackItem& other) const
{
    if (m_offset < other.offset())
        return true;
    else if (m_offset > other.offset())
        return false;
    else if (m_address < other.address())
        return true;
    else if (m_address > other.address())
        return false;
    else if (m_value < other.value())
        return true;
    else if (m_value > other.value())
        return false;
    else if (m_valueStatus > other.valueStatus())
        return false;
    return m_hint < other.hint();
}


DebugStackListModel::DebugStackListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view):
    QAbstractTableModel(parent), m_view(view)
{
    m_controller = DebuggerController::GetController(data);
}


DebugStackListModel::~DebugStackListModel()
{
}



Qt::ItemFlags DebugStackListModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags flag = QAbstractTableModel::flags(index);
    if (index.column() == DebugStackListModel::ValueColumn)
        flag |= Qt::ItemIsEditable;

    return flag;
}


DebugStackItem DebugStackListModel::getRow(int row) const
{
    if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

    return m_items[row];
}


QModelIndex DebugStackListModel::index(int row, int column, const QModelIndex &) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugStackListModel::data(const QModelIndex& index, int role) const
{
    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	DebugStackItem *item = static_cast<DebugStackItem*>(index.internalPointer());
	if (!item)
		return QVariant();


    if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole))
        return QVariant();

    switch (index.column())
    {
    case DebugStackListModel::OffsetColumn:
    {
        ptrdiff_t value = item->offset();
        QString valueStr;
        if (value < 0)
            valueStr = QString::asprintf("-%" PRIx64, -value);
        else
            valueStr = QString::asprintf("%" PRIx64, value);

        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)valueStr.size());

        QList<QVariant> line;
        line.push_back(getThemeColor(WhiteStandardHighlightColor).rgba());
		line.push_back(valueStr);
		return QVariant(line);
    }
    case DebugStackListModel::AddressColumn:
    {
        uint64_t value = item->address();
        QString valueStr = QString::asprintf("%" PRIx64, value);
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)valueStr.size());

        QList<QVariant> line;
        line.push_back(getThemeColor(WhiteStandardHighlightColor).rgba());
		line.push_back(valueStr);
		return QVariant(line);
    }
    case DebugStackListModel::ValueColumn:
    {
        uint64_t value = item->value();
        QString valueStr = QString::asprintf("%" PRIx64, value);
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)valueStr.size());

        QList<QVariant> line;
        switch (item->valueStatus())
        {
        case DebugStackValueNormal:
            line.push_back(getThemeColor(WhiteStandardHighlightColor).rgba());
            break;
        case DebugStackValueChanged:
            line.push_back(getThemeColor(BlueStandardHighlightColor).rgba());
            break;
        case DebugStackValueModified:
            line.push_back(getThemeColor(OrangeStandardHighlightColor).rgba());
            break;
        }

		line.push_back(valueStr);
		return QVariant(line);
    }
    case DebugStackListModel::HintColumn:
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


QVariant DebugStackListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
		case DebugStackListModel::OffsetColumn:
			return "Offset";
		case DebugStackListModel::AddressColumn:
			return "Address";
		case DebugStackListModel::ValueColumn:
			return "Value";
	    case DebugStackListModel::HintColumn:
	        return "Hint";
	}
	return QVariant();
}


void DebugStackListModel::updateRows(std::vector<DebugStackItem> newRows)
{
    // TODO: This might cause performance problems. We can instead only update the chagned registers.
    // However, the cost for that is we need to attach an index to each item and sort accordingly
    std::map<ptrdiff_t, uint64_t> oldValues;
    for (const DebugStackItem& item: m_items)
        oldValues[item.offset()] = item.value();

    beginResetModel();

    m_items.clear();
    if (newRows.empty())
    {
        endResetModel();
        return;
    }

    for (const DebugStackItem& row: newRows)
    {
        auto iter = oldValues.find(row.offset());
        DebugStackValueStatus status;
        if (iter == oldValues.end())
        {
            status = DebugStackValueNormal;
        }
        else
        {
            if (iter->second == row.value())
            {
                status = DebugStackValueNormal;
            }
            else
            {
                status = DebugStackValueChanged;
            }
        }
        m_items.emplace_back(row.offset(), row.address(), row.value(), row.hint(), status);
    }
    endResetModel();
}


bool DebugStackListModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if ((flags(index) & Qt::ItemIsEditable) != Qt::ItemIsEditable)
        return false;

    QString valueStr = value.toString();
    if (valueStr.size() == 0)
        return false;

    if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return false;

	DebugStackItem *item = static_cast<DebugStackItem*>(index.internalPointer());
	if (!item)
        return false;

    bool ok = false;
    uint64_t newValue = valueStr.toULongLong(&ok, 16);
    if (!ok)
        return false;

    if (newValue == item->value())
        return false;

    size_t addressSize = m_controller->GetRemoteArchitecture()->GetAddressSize();
    BinaryWriter* writer = new BinaryWriter(m_controller->GetLiveView());
    ok = false;
    writer->Seek(item->address());
    switch (addressSize)
    {
    case 1:
        ok = writer->TryWrite8(newValue);
        break;
    case 2:
        ok = writer->TryWrite16(newValue);
        break;
    case 4:
        ok = writer->TryWrite32(newValue);
        break;
    case 8:
        ok = writer->TryWrite64(newValue);
        break;
    default:
        break;
    }
    if (!ok)
        return false;

    item->setValue(newValue);
    item->setValueStatus(DebugStackValueModified);
    return true;
}


DebugStackItemDelegate::DebugStackItemDelegate(QWidget* parent):
    QStyledItemDelegate(parent)
{
    updateFonts();
}


void DebugStackItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
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
	case DebugStackListModel::OffsetColumn:
	case DebugStackListModel::AddressColumn:
	case DebugStackListModel::ValueColumn:
	case DebugStackListModel::HintColumn:
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


void DebugStackItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebugStackItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
    auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
    return QSize(totalWidth, m_charHeight + 2);
}


void DebugStackItemDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    if (index.column() == DebugStackListModel::ValueColumn)
    {
        QLineEdit* lineEditor = static_cast<QLineEdit*>(editor);
        if (lineEditor)
        {
            // index.data() returns a pair of colar and QString
            lineEditor->setText(index.data().toList()[1].toString());
        }
    }
}


DebugStackWidget::DebugStackWidget(const QString& name, ViewFrame* view, BinaryViewRef data):
    m_view(view)
{
    m_controller = DebuggerController::GetController(data);

    m_table = new QTableView(this);
    m_model = new DebugStackListModel(m_table, data, view);
    m_table->setModel(m_model);

    m_delegate = new DebugStackItemDelegate(this);
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


void DebugStackWidget::notifyStackChanged(std::vector<DebugStackItem> stackItems)
{
    m_model->updateRows(stackItems);
    // TODO: we could also set the columns' ResizeMode to ResizeToContents
    m_table->resizeColumnsToContents();
}


//void DebugStackWidget::notifyFontChanged()
//{
//    m_delegate->updateFonts();
//}


void DebugStackWidget::updateContent()
{
    if (!m_controller->GetState()->IsConnected())
        return;

    if (!m_controller->GetLiveView())
        return;

    std::vector<DebugStackItem> stackItems;
    BinaryReader* reader = new BinaryReader(m_controller->GetLiveView());
    uint64_t stackPointer = m_controller->GetState()->StackPointer();
    size_t addressSize = m_controller->GetRemoteArchitecture()->GetAddressSize();
    for (ptrdiff_t i = -8; i < 60 + 1; i++)
    {
        ptrdiff_t offset = i * addressSize;
        if ((offset < 0) && (stackPointer < (uint64_t)-offset))
            continue;

        uint64_t address = stackPointer + offset;

        reader->Seek(address);

        uint64_t value = -1ULL;

        try
        {
            switch (addressSize)
            {
            case 1:
                value = reader->Read8();
                break;
            case 2:
                value = reader->Read16();
                break;
            case 4:
                value = reader->Read32();
                break;
            case 8:
                value = reader->Read64();
                break;
            default:
                break;
            }
        } catch (const std::exception& except)
        {
            /* TODO: just ignoring this is probably not a great idea... */
        }

        std::string hint{};
        if (m_controller) {
            const DataBuffer memory = m_controller->ReadMemory(value, 128);
            std::string reg_string;
            if (memory.GetLength() > 0)
                reg_string = std::string((const char*)memory.GetData(), memory.GetLength());
            else
                reg_string = "x";
            const auto can_print = std::all_of(reg_string.begin(), reg_string.end(), [](unsigned char c){
                return c == '\n' || std::isprint(c);
            });

            if (!reg_string.empty() && reg_string.size() > 3 && can_print)
            {
                hint = fmt::format("\"{}\"", reg_string);
            }
            else
            {
                DataBuffer buffer = m_controller->ReadMemory(value, addressSize);
                if (buffer.GetLength() > 0)
                {
                    hint = fmt::format("{:x}", *reinterpret_cast<std::uintptr_t*>(buffer.GetData()));
                }
                else
                {
                    hint = "";
                }
            }
        }

        stackItems.emplace_back(offset, address, value, hint);
    }
    delete reader;

    notifyStackChanged(stackItems);
}
