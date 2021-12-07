#include <QtGui/QPainter>
#include <QtWidgets/QHeaderView>
#include "threadswidget.h"
#include "../debuggercontroller.h"

using namespace BinaryNinja;
using namespace std;

ThreadItem::ThreadItem(size_t tid, uint64_t rip, bool isLastActive, DebugThreadValueStatus valueStatus):
    m_tid(tid), m_rip(rip), m_isLastActive(isLastActive), m_valueStatus(valueStatus)
{
}


bool ThreadItem::operator==(const ThreadItem& other) const
{
	// TODO: this needs to be changed after we added the m_isLastActive and m_valueStatus
    return (m_tid == other.tid()) && (m_rip == other.rip());
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

    return m_rip < other.rip();
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
		if (item->isLastActive())
			text += " (*)";
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        QList<QVariant> line;
        line.push_back(getThemeColor(WhiteStandardHighlightColor).rgba());
		line.push_back(text);
		return QVariant(line);
    }
    case DebugThreadsListModel::LocationColumn:
    {
        QString text = QString::fromStdString(fmt::format("{:x}", item->rip()));
        if (role == Qt::SizeHintRole)
            return QVariant((qulonglong)text.size());

        QList<QVariant> line;
        switch (item->valueStatus())
        {
        case DebugThreadValueNormal:
            line.push_back(getThemeColor(WhiteStandardHighlightColor).rgba());
            break;
        case DebugThreadValueChanged:
            line.push_back(getThemeColor(BlueStandardHighlightColor).rgba());
            break;
        case DebugThreadValueModified:
            line.push_back(getThemeColor(OrangeStandardHighlightColor).rgba());
            break;
        }

		line.push_back(text);
		return QVariant(line);
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
			return "PC";
	}
	return QVariant();
}


void DebugThreadsListModel::updateRows(std::vector<DebugThread> threads, DebugThread lastActiveThread)
{
    beginResetModel();
	std::map<uint64_t, uint64_t> oldThreads;
	for (const ThreadItem& item: m_items)
		oldThreads[item.tid()] = item.rip();

    std::vector<ThreadItem> newRows;
    for (const DebugThread& thread: threads)
    {
		bool isLastActive = false;
		// Since GetActiveThread() returns the wrong internal index, here we only compare the tid and rip
		if ((thread.m_tid == lastActiveThread.m_tid) && (thread.m_rip == lastActiveThread.m_rip))
			isLastActive = true;

		auto iter = oldThreads.find(thread.m_tid);
		DebugThreadValueStatus status = DebugThreadValueNormal;
		if ((iter == oldThreads.end()) || (iter->second != thread.m_rip))
		{
			// Treat new threads and threads that have a different rip as changed
			status = DebugThreadValueChanged;
		}
        newRows.emplace_back(thread.m_tid, thread.m_rip, isLastActive, status);
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
    m_view(view)
{
    m_controller = DebuggerController::GetController(data);

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

	setContextMenuPolicy(Qt::CustomContextMenu);
	connect(this, &QWidget::customContextMenuRequested, [this](QPoint pos){
		auto* jumpToAction = new QAction("Jump To");
		auto* setAsActiveAction = new QAction("Set As Active Thread");

		connect(jumpToAction, &QAction::triggered, this, &DebugThreadsWidget::jump);
		connect(setAsActiveAction, &QAction::triggered, this, &DebugThreadsWidget::setAsActive);

		auto* menu = new QMenu(this);
		menu->addAction(jumpToAction);
		menu->addAction(setAsActiveAction);

		// Disable everything if nothing is selected.
		QModelIndexList sel = m_table->selectionModel()->selectedRows();
		if (sel.size() == 0)
			for (auto* a : menu->actions())
				a->setEnabled(false);

		menu->popup(QCursor::pos() + QPoint(2, 2));
	});

	connect(m_table, &QTableView::doubleClicked, this, &DebugThreadsWidget::jump);

    updateContent();
}


void DebugThreadsWidget::notifyThreadsChanged(std::vector<DebugThread> threads, DebugThread lastActiveThread)
{
    m_model->updateRows(threads, lastActiveThread);
    m_table->resizeColumnsToContents();
}


//void DebugThreadsWidget::notifyFontChanged()
//{
//    m_delegate->updateFonts();
//}


void DebugThreadsWidget::updateContent()
{
    if (!m_controller->GetState()->IsConnected())
        return;

    std::vector<DebugThread> threads = m_controller->GetState()->GetThreads()->GetAllThreads();
	DebugThread lastActiveThread = m_controller->GetState()->GetThreads()->GetActiveThread();
    notifyThreadsChanged(threads, lastActiveThread);
}


void DebugThreadsWidget::jump()
{
	QModelIndexList sel = m_table->selectionModel()->selectedRows();
	if (sel.size() == 0)
		return;

	ThreadItem thread = m_model->getRow(sel[0].row());

	UIContext* context = UIContext::contextForWidget(this);
	ViewFrame* frame = context->getCurrentViewFrame();
	frame->navigate(m_controller->GetLiveView(), thread.rip(), true, true);
}


void DebugThreadsWidget::setAsActive()
{
	QModelIndexList sel = m_table->selectionModel()->selectedRows();
	if (sel.size() == 0)
		return;

	ThreadItem thread = m_model->getRow(sel[0].row());
	// Again, this is sending a DebugThread without an internal index to the backend. It works, which means the
	// internal index is rather useless.
	m_controller->SetActiveThread(DebugThread(thread.tid(), 0, thread.rip()));
	updateContent();
}
