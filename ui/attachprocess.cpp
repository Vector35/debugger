/*
Copyright 2020-2022 Vector 35 Inc.

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

ProcessItem::ProcessItem(uint32_t pid, std::string processName) :
	m_pid(pid), m_processName(processName)
{}


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

DebugProcessListModel::DebugProcessListModel(QWidget* parent) :
	QAbstractTableModel(parent)
{}


DebugProcessListModel::~DebugProcessListModel() {}


ProcessItem DebugProcessListModel::getRow(int row) const
{
	if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

	return m_items[row];
}


QModelIndex DebugProcessListModel::index(int row, int column, const QModelIndex&) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant DebugProcessListModel::data(const QModelIndex& index, int role) const
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
	case DebugProcessListModel::PidColumn:
	{
		QString text = QString::asprintf("%d", item->pid());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugProcessListModel::ProcessNameColumn:
	{
		QString text = QString::fromStdString(item->processName());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	}
	return QVariant();
}


QVariant DebugProcessListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
	case DebugProcessListModel::PidColumn:
		return "PID";
	case DebugProcessListModel::ProcessNameColumn:
		return "Name";
	}
	return QVariant();
}


void DebugProcessListModel::updateRows(std::vector<DebugProcess> newModules)
{
	beginResetModel();

	std::vector<ProcessItem> newRows;
	for (const DebugProcess& process : newModules)
	{
		newRows.emplace_back(process.m_pid, process.m_processName);
	}

	m_items = newRows;
	
	endResetModel();
}

DebugProcessItemDelegate::DebugProcessItemDelegate(QWidget* parent) : QStyledItemDelegate(parent)
{
	updateFonts();
}


void DebugProcessItemDelegate::paint(
	QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	painter->setFont(m_font);

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
	case DebugProcessListModel::PidColumn:
		painter->setPen(getThemeColor(NumberColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case DebugProcessListModel::ProcessNameColumn:
		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	default:
		break;
	}
}


void DebugProcessItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebugProcessItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
	return QSize(totalWidth, m_charHeight + 2);
}

DebugProcessFilterProxyModel::DebugProcessFilterProxyModel(QObject* parent) : QSortFilterProxyModel(parent)
{
	setFilterCaseSensitivity(Qt::CaseInsensitive);
}


bool DebugProcessFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
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

DebugProcessWidget::DebugProcessWidget(DebuggerController* controller)
{
	m_controller = controller;

	m_table = new QTableView(this);
	m_model = new DebugProcessListModel(m_table);
	m_filter = new DebugProcessFilterProxyModel(this);

	m_filter->setSourceModel(m_model);
	m_table->setModel(m_filter);

	m_delegate = new DebugProcessItemDelegate(this);
	m_table->setItemDelegate(m_delegate);

	m_table->setSelectionBehavior(QAbstractItemView::SelectItems);

	//m_table->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	m_table->verticalHeader()->setVisible(false);

	m_table->setShowGrid(false);
	//m_table->setAlternatingRowColors(true);

	m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
	m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
	m_table->setSelectionMode(QAbstractItemView::SingleSelection);

	m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	m_table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
	
	//m_table->horizontalHeader()->setStretchLastSection(true);
	m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	m_table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

	m_table->resizeColumnsToContents();
	m_table->resizeRowsToContents();

	QVBoxLayout* layout = new QVBoxLayout;
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);
	layout->addWidget(m_table);
	setLayout(layout);
	// TODO: ESC close dialog
	// TODO: context menu refresh
	// TODO: double click attach
	// TODO: context menu copy
	updateContent();
}


DebugProcessWidget::~DebugProcessWidget()
{
	//if (m_controller)
	//	m_controller->RemoveEventCallback(m_debuggerEventCallback);
}


void DebugProcessWidget::notifyModulesChanged(std::vector<DebugProcess> modules)
{
	m_model->updateRows(modules);
	m_table->resizeColumnsToContents();
}


void DebugProcessWidget::updateContent()
{
	std::vector<DebugProcess> modules = m_controller->GetProcessList();
	notifyModulesChanged(modules);
}


void DebugProcessWidget::setFilter(const string& filter)
{
	m_filter->setFilterFixedString(QString::fromStdString(filter));
}


void DebugProcessWidget::scrollToFirstItem() {}


void DebugProcessWidget::scrollToCurrentItem() {}


void DebugProcessWidget::selectFirstItem() {}


void DebugProcessWidget::activateFirstItem() {}

DebugProcessWidgetWithFilter::DebugProcessWidgetWithFilter(DebuggerController* controller)
{
	m_processes = new DebugProcessWidget(controller);
	m_separateEdit = new FilterEdit(m_processes);
	m_filter = new FilteredView(this, m_processes, m_processes, m_separateEdit);
	m_filter->setFilterPlaceholderText("Search process");

	auto headerLayout = new QHBoxLayout();
	headerLayout->addWidget(m_separateEdit, 1);
	//headerLayout->setAlignment(Qt::AlignBaseline);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addLayout(headerLayout);
	layout->addWidget(m_filter, 1);
}

AttachProcessDialog::AttachProcessDialog(QWidget* parent, DebuggerController* controller) :
	QDialog(), m_controller(controller)
{
	setWindowTitle("Attach to process");
	setMinimumSize(UIContext::getScaledWindowSize(350, 600));
	setAttribute(Qt::WA_DeleteOnClose);
	setSizeGripEnabled(true);
	setModal(true);

	QVBoxLayout* layout = new QVBoxLayout();
	layout->setSpacing(0);

	m_processWidget = new DebugProcessWidgetWithFilter(m_controller);
	layout->addWidget(m_processWidget);

	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->setContentsMargins(0, 0, 0, 0);

	QPushButton* cancelButton = new QPushButton("Cancel");
	connect(cancelButton, &QPushButton::clicked, [&]() { reject(); });

	QPushButton* acceptButton = new QPushButton("Attach");
	connect(acceptButton, &QPushButton::clicked, [&]() { apply(); });
	acceptButton->setDefault(true);

	buttonLayout->addStretch(1);
	buttonLayout->addWidget(cancelButton);
	buttonLayout->addWidget(acceptButton);

	layout->addSpacing(10);
	layout->addLayout(buttonLayout);

	setLayout(layout);
}

uint32_t AttachProcessDialog::GetSelectedPid()
{
	return m_pid;
}

void AttachProcessDialog::apply()
{
	// TODO get selected pid from table
	// if (!m_processTable->selectionModel()->hasSelection())
	// {
	// 	reject();
	// 	return;
	// }

	// QModelIndexList sel = m_processTable->selectionModel()->selectedIndexes();
	// if (sel.empty() || !sel[0].isValid())
	// {
	// 	reject();
	// 	return;
	// }

	// QTableWidgetItem* processSelected = m_processTable->item(sel[0].row(), 0);
	// m_pid = processSelected->text().toInt();

	accept();
}
