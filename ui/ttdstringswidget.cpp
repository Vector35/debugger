/*
Copyright 2020-2026 Vector 35 Inc.

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

#include "ttdstringswidget.h"
#include "ui.h"
#include "clickablelabel.h"
#include <QPainter>
#include <QApplication>
#include <QHeaderView>
#include <QClipboard>
#include <QGroupBox>

using namespace BinaryNinja;
using namespace std;

constexpr int SortFilterRole = Qt::UserRole + 1;


// TTDStringsListModel implementation

TTDStringsListModel::TTDStringsListModel(QWidget* parent) : QAbstractTableModel(parent)
{
}

TTDStringsListModel::~TTDStringsListModel() {}

QModelIndex TTDStringsListModel::index(int row, int column, const QModelIndex&) const
{
	if (row < 0 || (size_t)row >= m_entries.size() || column >= columnCount())
		return QModelIndex();

	return createIndex(row, column, (void*)&m_entries[row]);
}

int TTDStringsListModel::rowCount(const QModelIndex&) const
{
	return (int)m_entries.size();
}

int TTDStringsListModel::columnCount(const QModelIndex&) const
{
	return 7;
}

QVariant TTDStringsListModel::data(const QModelIndex& index, int role) const
{
	if (index.column() >= columnCount() || (size_t)index.row() >= m_entries.size())
		return QVariant();

	const TTDStringEntry* entry = static_cast<const TTDStringEntry*>(index.internalPointer());
	if (!entry)
		return QVariant();

	if (role == Qt::ToolTipRole && index.column() == StringColumn)
		return QString::fromStdString(entry->data);

	if (role != Qt::DisplayRole && role != Qt::SizeHintRole && role != SortFilterRole)
		return QVariant();

	switch (index.column())
	{
	case IndexColumn:
	{
		QString text = QString::number(index.row());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());
		return QVariant(text);
	}
	case StringColumn:
	{
		QString text = QString::fromStdString(entry->data);
		if (text.length() > 200)
			text = text.left(200) + "...";
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());
		return QVariant(text);
	}
	case AddressColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, entry->address);
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());
		return QVariant(text);
	}
	case SizeColumn:
	{
		QString text = QString::number(entry->size);
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());
		return QVariant(text);
	}
	case FirstAccessColumn:
	{
		QString text = QString("%1:%2")
			.arg(entry->firstAccess.sequence, 0, 16)
			.arg(entry->firstAccess.step, 0, 16);
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());
		return QVariant(text);
	}
	case LastAccessColumn:
	{
		QString text = QString("%1:%2")
			.arg(entry->lastAccess.sequence, 0, 16)
			.arg(entry->lastAccess.step, 0, 16);
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());
		return QVariant(text);
	}
	case EncodingColumn:
	{
		QString text = QString::fromStdString(entry->encoding);
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());
		return QVariant(text);
	}
	}
	return QVariant();
}

QVariant TTDStringsListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
	case IndexColumn:
		return "Index";
	case StringColumn:
		return "String";
	case AddressColumn:
		return "Address";
	case SizeColumn:
		return "Size";
	case FirstAccessColumn:
		return "First Access";
	case LastAccessColumn:
		return "Last Access";
	case EncodingColumn:
		return "Encoding";
	}
	return QVariant();
}

void TTDStringsListModel::updateRows(const std::vector<TTDStringEntry>& entries)
{
	beginResetModel();
	m_entries = entries;
	endResetModel();
}

const TTDStringEntry& TTDStringsListModel::getRow(int row) const
{
	return m_entries[row];
}


// TTDStringsFilterProxyModel implementation

TTDStringsFilterProxyModel::TTDStringsFilterProxyModel(QObject* parent) : QSortFilterProxyModel(parent)
{
	setFilterKeyColumn(-1);  // Search all columns
}

bool TTDStringsFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
{
	return QSortFilterProxyModel::filterAcceptsRow(sourceRow, sourceParent);
}


// TTDStringsItemDelegate implementation

TTDStringsItemDelegate::TTDStringsItemDelegate(QWidget* parent) : QStyledItemDelegate(parent)
{
	updateFonts();
}

void TTDStringsItemDelegate::updateFonts()
{
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(QObject::parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}

void TTDStringsItemDelegate::paint(
	QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const
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
	case TTDStringsListModel::AddressColumn:
		painter->setPen(getThemeColor(AddressColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case TTDStringsListModel::SizeColumn:
	case TTDStringsListModel::IndexColumn:
		painter->setPen(getThemeColor(NumberColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case TTDStringsListModel::FirstAccessColumn:
	case TTDStringsListModel::LastAccessColumn:
		painter->setPen(getThemeColor(AddressColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	default:
		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
}

QSize TTDStringsItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
	return QSize(totalWidth, m_charHeight + 2);
}


// TTDStringsWidget implementation

TTDStringsWidget::TTDStringsWidget(BinaryViewRef data, QWidget* parent) : QTableView(parent), m_data(data)
{
	m_controller = DebuggerController::GetController(data);

	m_model = new TTDStringsListModel(this);
	m_filter = new TTDStringsFilterProxyModel(this);
	m_filter->setSourceModel(m_model);
	setModel(m_filter);
	setShowGrid(false);

	m_delegate = new TTDStringsItemDelegate(this);
	setItemDelegate(m_delegate);

	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::SingleSelection);

	verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	verticalHeader()->setVisible(false);

	horizontalHeader()->setStretchLastSection(true);
	horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

	setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

	setSortingEnabled(true);

	connect(this, &QTableView::doubleClicked, this, &TTDStringsWidget::onDoubleClicked);

	// Setup actions and context menu
	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();

	m_menu->addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&]() { copy(); }, [&]() { return canCopy(); }));

	m_menu->addAction("Copy Row", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy Row", UIAction([&]() { copySelectedRow(); }, [&]() { return canCopy(); }));

	m_menu->addAction("Copy Table", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy Table", UIAction([&]() { copyEntireTable(); }, [&]() { return m_model->rowCount() > 0; }));
}

TTDStringsWidget::~TTDStringsWidget()
{
	delete m_contextMenuManager;
}

void TTDStringsWidget::setFilter(const string& filter, FilterOptions options)
{
	if (options.testFlag(UseRegexOption))
		m_filter->setFilterRegularExpression(QString::fromStdString(filter));
	else
		m_filter->setFilterFixedString(QString::fromStdString(filter));
	m_filter->setFilterCaseSensitivity(
		options.testFlag(CaseSensitiveOption) ? Qt::CaseSensitive : Qt::CaseInsensitive);
	updateColumnWidths();
}

void TTDStringsWidget::scrollToFirstItem() {}
void TTDStringsWidget::scrollToCurrentItem() {}
void TTDStringsWidget::ensureSelection() {}
void TTDStringsWidget::activateSelection() {}

void TTDStringsWidget::updateColumnWidths()
{
	resizeColumnsToContents();
}

void TTDStringsWidget::updateFonts()
{
	m_delegate->updateFonts();
}

bool TTDStringsWidget::canCopy()
{
	return selectionModel()->hasSelection();
}

void TTDStringsWidget::contextMenuEvent(QContextMenuEvent* event)
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}

void TTDStringsWidget::showContextMenu()
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}

void TTDStringsWidget::performQuery(uint64_t maxResults)
{
	if (!m_controller)
		return;

	if (!m_controller->IsConnected() || !m_controller->IsTTD())
	{
		emit statusUpdated("Not connected to a TTD target.");
		return;
	}

	emit statusUpdated("Querying strings...");
	QApplication::processEvents();

	auto entries = m_controller->GetTTDStrings("", maxResults);
	m_model->updateRows(entries);

	updateColumnWidths();

	emit statusUpdated(QString("Found %1 strings.").arg(entries.size()));
}

void TTDStringsWidget::clearResults()
{
	m_model->updateRows({});
	emit statusUpdated("Results cleared.");
}

void TTDStringsWidget::onDoubleClicked(const QModelIndex& proxyIndex)
{
	if (!m_controller)
		return;

	QModelIndex sourceIndex = m_filter->mapToSource(proxyIndex);
	if (!sourceIndex.isValid())
		return;

	int sourceRow = sourceIndex.row();
	int column = sourceIndex.column();

	const TTDStringEntry& entry = m_model->getRow(sourceRow);

	// Navigate to TTD position on First Access or Last Access columns
	if (column == TTDStringsListModel::FirstAccessColumn)
	{
		TTDPosition position(entry.firstAccess.sequence, entry.firstAccess.step);
		if (m_controller->SetTTDPosition(position))
			emit statusUpdated(QString("Navigated to position %1:%2")
				.arg(entry.firstAccess.sequence, 0, 16).arg(entry.firstAccess.step, 0, 16));
		else
			emit statusUpdated("Failed to navigate to position");
	}
	else if (column == TTDStringsListModel::LastAccessColumn)
	{
		TTDPosition position(entry.lastAccess.sequence, entry.lastAccess.step);
		if (m_controller->SetTTDPosition(position))
			emit statusUpdated(QString("Navigated to position %1:%2")
				.arg(entry.lastAccess.sequence, 0, 16).arg(entry.lastAccess.step, 0, 16));
		else
			emit statusUpdated("Failed to navigate to position");
	}
	// Navigate to address on Address column
	else if (column == TTDStringsListModel::AddressColumn)
	{
		ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
		if (frame)
		{
			frame->navigate(m_data, entry.address);
			emit statusUpdated(QString("Navigated to address 0x%1").arg(entry.address, 0, 16));
		}
	}
}

void TTDStringsWidget::copy()
{
	copySelectedRow();
}

void TTDStringsWidget::copySelectedRow()
{
	if (!selectionModel()->hasSelection())
		return;

	QModelIndexList selected = selectionModel()->selectedRows();
	if (selected.isEmpty())
		return;

	QStringList rowData;
	int row = selected.first().row();

	for (int col = 0; col < m_filter->columnCount(); ++col)
	{
		QModelIndex idx = m_filter->index(row, col);
		rowData << idx.data(Qt::DisplayRole).toString();
	}

	QApplication::clipboard()->setText(rowData.join('\t'));
}

void TTDStringsWidget::copyEntireTable()
{
	QStringList tableData;

	// Header row
	QStringList headers;
	for (int col = 0; col < m_filter->columnCount(); ++col)
		headers << m_model->headerData(col, Qt::Horizontal, Qt::DisplayRole).toString();
	tableData << headers.join('\t');

	// Data rows
	for (int row = 0; row < m_filter->rowCount(); ++row)
	{
		QStringList rowData;
		for (int col = 0; col < m_filter->columnCount(); ++col)
		{
			QModelIndex idx = m_filter->index(row, col);
			rowData << idx.data(Qt::DisplayRole).toString();
		}
		tableData << rowData.join('\t');
	}

	QApplication::clipboard()->setText(tableData.join('\n'));
}


// TTDStringsWithFilter implementation

TTDStringsWithFilter::TTDStringsWithFilter(BinaryViewRef data, QWidget* parent)
	: QWidget(parent), m_data(data)
{
	m_stringsWidget = new TTDStringsWidget(data, this);

	m_separateEdit = new FilterEdit(m_stringsWidget);
	m_separateEdit->showRegexToggle(true);
	m_filteredView = new FilteredView(this, m_stringsWidget, m_stringsWidget, m_separateEdit);
	m_filteredView->setFilterPlaceholderText("Filter strings");

	auto headerLayout = new QHBoxLayout;
	headerLayout->addWidget(m_separateEdit, 1);
	headerLayout->setContentsMargins(1, 1, 6, 0);
	headerLayout->setAlignment(Qt::AlignBaseline);

	auto* icon = new ClickableIcon(QImage(":/debugger/menu"), QSize(16, 16));
	connect(icon, &ClickableIcon::clicked, m_stringsWidget, &TTDStringsWidget::showContextMenu);
	headerLayout->addWidget(icon);

	// Query controls
	auto controlLayout = new QHBoxLayout;
	controlLayout->setContentsMargins(5, 2, 5, 2);
	controlLayout->addWidget(new QLabel("Max Results:"));
	m_maxResultsSpinBox = new QSpinBox();
	m_maxResultsSpinBox->setRange(1, 0x7FFFFFFF);
	m_maxResultsSpinBox->setValue(100000);
	controlLayout->addWidget(m_maxResultsSpinBox);

	controlLayout->addSpacing(10);

	auto* queryButton = new QPushButton("Query");
	queryButton->setDefault(true);
	connect(queryButton, &QPushButton::clicked, this, &TTDStringsWithFilter::performQuery);
	controlLayout->addWidget(queryButton);

	auto* clearButton = new QPushButton("Clear");
	connect(clearButton, &QPushButton::clicked, this, &TTDStringsWithFilter::clearResults);
	controlLayout->addWidget(clearButton);

	controlLayout->addStretch();

	// Status label
	m_statusLabel = new QLabel("Ready to query TTD strings.");
	m_statusLabel->setContentsMargins(5, 2, 5, 2);

	connect(m_stringsWidget, &TTDStringsWidget::statusUpdated, this, &TTDStringsWithFilter::updateStatus);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addLayout(headerLayout);
	layout->addLayout(controlLayout);
	layout->addWidget(m_filteredView, 1);
	layout->addWidget(m_statusLabel);
}

void TTDStringsWithFilter::updateFonts()
{
	m_stringsWidget->updateFonts();
}

void TTDStringsWithFilter::performQuery()
{
	uint64_t maxResults = static_cast<uint64_t>(m_maxResultsSpinBox->value());
	m_stringsWidget->performQuery(maxResults);
}

void TTDStringsWithFilter::clearResults()
{
	m_stringsWidget->clearResults();
}

void TTDStringsWithFilter::updateStatus(const QString& message)
{
	m_statusLabel->setText(message);
}


// TTDStringsSidebarWidget implementation

TTDStringsSidebarWidget::TTDStringsSidebarWidget(BinaryViewRef data)
	: SidebarWidget("TTD Strings"), m_data(data), m_debuggerEventCallback(0)
{
	m_controller = DebuggerController::GetController(data);

	m_widget = new TTDStringsWithFilter(data, this);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_widget);

	if (m_controller)
	{
		connect(this, &TTDStringsSidebarWidget::debuggerEvent, this, &TTDStringsSidebarWidget::onDebuggerEvent);

		m_debuggerEventCallback = m_controller->RegisterEventCallback(
			[&](const DebuggerEvent& event) {
				emit debuggerEvent(event);
			},
			"TTD Strings Widget");
	}
}

TTDStringsSidebarWidget::~TTDStringsSidebarWidget()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_debuggerEventCallback);
}

void TTDStringsSidebarWidget::onDebuggerEvent(const DebuggerEvent& event)
{
	switch (event.type)
	{
		case TargetExitedEventType:
		case DetachedEventType:
			if (m_widget)
				m_widget->clearResults();
			break;
		default:
			break;
	}
}


// TTDStringsWidgetType implementation

TTDStringsWidgetType::TTDStringsWidgetType()
	: SidebarWidgetType(QImage(":/debugger/ttd-events"), "TTD Strings")
{
}

SidebarWidget* TTDStringsWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new TTDStringsSidebarWidget(data);
}

SidebarContentClassifier* TTDStringsWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}
