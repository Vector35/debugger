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

#include "attachprocess.h"


using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

constexpr int SortFilterRole = Qt::UserRole + 1;

ProcessItem::ProcessItem(uint32_t pid, std::string processName) : m_pid(pid), m_processName(processName) {}


bool ProcessItem::operator==(const ProcessItem& other) const
{
	return (m_pid == other.pid()) && (m_processName == other.processName());
}


bool ProcessItem::operator!=(const ProcessItem& other) const
{
	return !(*this == other);
}


bool ProcessItem::operator<(const ProcessItem& other) const
{
	if (m_pid < other.pid())
		return true;
	else if (m_pid > other.pid())
		return false;
	return m_processName < other.processName();
}


ProcessListModel::ProcessListModel(QWidget* parent) : QAbstractTableModel(parent) {}


ProcessListModel::~ProcessListModel() {}


ProcessItem ProcessListModel::getRow(int row) const
{
	if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

	return m_items[row];
}


QModelIndex ProcessListModel::index(int row, int column, const QModelIndex&) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant ProcessListModel::data(const QModelIndex& index, int role) const
{
	if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	ProcessItem* item = static_cast<ProcessItem*>(index.internalPointer());
	if (!item)
		return QVariant();

	if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole) && (role != SortFilterRole))
		return QVariant();

	switch (index.column())
	{
	case ProcessListModel::PidColumn:
	{
		QString text = QString::asprintf("%d", item->pid());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ProcessListModel::ProcessNameColumn:
	{
		QString text = QString::fromStdString(item->processName());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	}
	return QVariant();
}


QVariant ProcessListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
	case ProcessListModel::PidColumn:
		return "PID";
	case ProcessListModel::ProcessNameColumn:
		return "Name";
	}
	return QVariant();
}


void ProcessListModel::updateRows(std::vector<DebugProcess> processList)
{
	beginResetModel();

	std::vector<ProcessItem> newProcessList;
	for (const DebugProcess& process : processList)
		newProcessList.emplace_back(process.m_pid, process.m_processName);

	m_items = newProcessList;

	endResetModel();
}

ProcessItemDelegate::ProcessItemDelegate(QWidget* parent) : QStyledItemDelegate(parent)
{
	updateFonts();
}


void ProcessItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	bool selected = (option.state & QStyle::State_Selected) != 0;
	if (selected)
		painter->setBrush(getThemeColor(SelectionColor));
	else
		painter->setBrush(option.backgroundBrush);

	painter->setPen(Qt::NoPen);
	painter->setFont(m_font);

	QRect textRect = option.rect;
	textRect.setBottom(textRect.top() + m_charHeight + 2);
	painter->drawRect(textRect);

	auto data = idx.data(Qt::DisplayRole);
	switch (idx.column())
	{
	case ProcessListModel::PidColumn:
		painter->setPen(getThemeColor(NumberColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case ProcessListModel::ProcessNameColumn:
		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	default:
		break;
	}
}


void ProcessItemDelegate::updateFonts()
{
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize ProcessItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
	return QSize(totalWidth, m_charHeight + 2);
}


ProcessListFilterProxyModel::ProcessListFilterProxyModel(QObject* parent) : QSortFilterProxyModel(parent)
{
	setFilterCaseSensitivity(Qt::CaseInsensitive);
}

void ProcessListModel::sort(int col, Qt::SortOrder order)
{
	std::sort(m_items.begin(), m_items.end(), [&](ProcessItem a, ProcessItem b) {
		if (col == ProcessListModel::PidColumn)
		{
			if (order == Qt::AscendingOrder)
				return a.pid() < b.pid();
			else
				return a.pid() > b.pid();
		}
		else if (col == ProcessListModel::ProcessNameColumn)
		{
			if (order == Qt::AscendingOrder)
				return a.processName() < b.processName();
			else
				return a.processName() > b.processName();
		}
		return false;
	});
}


void ProcessListFilterProxyModel::sort(int col, Qt::SortOrder order)
{
	beginResetModel();
	sourceModel()->sort(col, order);
	endResetModel();
}


bool ProcessListFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
{
	QRegularExpression regExp = filterRegularExpression();
	if (!regExp.isValid())
		return true;

	for (int column = 0; column < sourceModel()->columnCount(sourceParent); column++)
	{
		QModelIndex index = sourceModel()->index(sourceRow, column, sourceParent);
		QString data = index.data(SortFilterRole).toString();
		if (data.indexOf(regExp) != -1)
			return true;
	}
	return false;
}


void ProcessListWidget::contextMenuEvent(QContextMenuEvent* event)
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}


ProcessListWidget::ProcessListWidget(QWidget* parent, DbgRef<DebuggerController> controller) :
	QTableView(parent), m_controller(controller)
{
	m_model = new ProcessListModel(this);
	m_delegate = new ProcessItemDelegate(this);
	m_filter = new ProcessListFilterProxyModel(this);

	m_filter->setSourceModel(m_model);
	setModel(m_filter);
	setItemDelegate(m_delegate);

	setShowGrid(false);
	setSortingEnabled(true);

	horizontalHeader()->setStretchLastSection(true);
	horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
	horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

	verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	verticalHeader()->setVisible(false);

	setEditTriggers(QAbstractItemView::NoEditTriggers);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::SingleSelection);

	setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
	setAutoScroll(false);
	
	resizeColumnsToContents();
	resizeRowsToContents();

	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();

	QString actionName = QString::fromStdString("Refresh");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([=]() { updateContent(); }));

	// TODO: context menu copy

	updateContent();
}


ProcessListWidget::~ProcessListWidget(){}


void ProcessListWidget::updateColumnWidths()
{
	resizeColumnToContents(ProcessListModel::PidColumn);
	resizeColumnToContents(ProcessListModel::ProcessNameColumn);
}


void ProcessListWidget::updateContent()
{
	std::vector<DebugProcess> processList = m_controller->GetProcessList();
	m_model->updateRows(processList);
	updateColumnWidths();
}


void ProcessListWidget::setFilter(const string& filter)
{
	m_filter->setFilterFixedString(QString::fromStdString(filter));
	updateColumnWidths();
}


void ProcessListWidget::scrollToFirstItem() {}


void ProcessListWidget::scrollToCurrentItem() {}


void ProcessListWidget::selectFirstItem() {}


void ProcessListWidget::activateFirstItem() {}


AttachProcessDialog::AttachProcessDialog(QWidget* parent, DbgRef<DebuggerController> controller) : QDialog(parent)
{
	setWindowTitle("Attach to process");
	setMinimumSize(UIContext::getScaledWindowSize(450, 600));
	setSizeGripEnabled(true);
	setModal(true);

	m_processListWidget = new ProcessListWidget(this, controller);
	m_separateEdit = new FilterEdit(m_processListWidget);
	m_filter = new FilteredView(this, m_processListWidget, m_processListWidget, m_separateEdit);
	m_filter->setFilterPlaceholderText("Search process");

	auto headerLayout = new QHBoxLayout();
	headerLayout->addWidget(m_separateEdit, 1);

	auto filterLayout = new QVBoxLayout();
	filterLayout->setContentsMargins(0, 0, 0, 0);
	filterLayout->addLayout(headerLayout);
	filterLayout->addWidget(m_filter, 1);

	QVBoxLayout* layout = new QVBoxLayout();
	layout->addLayout(filterLayout);

	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->setContentsMargins(0, 0, 0, 0);

	QPushButton* cancelButton = new QPushButton("Cancel");
	connect(cancelButton, &QPushButton::clicked, [&]() { reject(); });

	QPushButton* acceptButton = new QPushButton("Attach");
	connect(acceptButton, &QPushButton::clicked, [&]() { apply(); });
	acceptButton->setDefault(true);

	connect(m_processListWidget, &QTableView::doubleClicked, [&]() { apply(); });

	buttonLayout->addStretch(1);
	buttonLayout->addWidget(cancelButton);
	buttonLayout->addWidget(acceptButton);

	layout->addSpacing(10);
	layout->addLayout(buttonLayout);

	setLayout(layout);
}

uint32_t AttachProcessDialog::GetSelectedPid()
{
	return m_processListWidget->GetSelectedPid();
}

void AttachProcessDialog::apply()
{
	m_selectedPid = m_processListWidget->GetSelectedPid();
	if (!m_selectedPid)
	{
		reject();
		return;
	}

	accept();
}
