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

#include <QPainter>
#include <QHeaderView>
#include <QGuiApplication>
#include <QMimeData>
#include <QClipboard>
#include "ui.h"
#include "moduleswidget.h"
#include "clickablelabel.h"

using namespace BinaryNinja;
using namespace std;

constexpr int SortFilterRole = Qt::UserRole + 1;

ModuleItem::ModuleItem(uint64_t address, size_t size, std::string name, std::string path) :
	m_address(address), m_size(size), m_name(name), m_path(path)
{}


bool ModuleItem::operator==(const ModuleItem& other) const
{
	return (m_address == other.address()) && (m_size == other.size()) && (m_name == other.name())
		&& (m_path == other.path());
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


DebugModulesListModel::DebugModulesListModel(QWidget* parent, ViewFrame* view) :
	QAbstractTableModel(parent), m_view(view)
{}


DebugModulesListModel::~DebugModulesListModel() {}


ModuleItem DebugModulesListModel::getRow(int row) const
{
	if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

	return m_items[row];
}


QModelIndex DebugModulesListModel::index(int row, int column, const QModelIndex&) const
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

	ModuleItem* item = static_cast<ModuleItem*>(index.internalPointer());
	if (!item)
		return QVariant();

	if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole) && (role != SortFilterRole))
		return QVariant();

	switch (index.column())
	{
	case DebugModulesListModel::AddressColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->address());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugModulesListModel::EndAddressColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->endAddress());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case DebugModulesListModel::SizeColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, (uint64_t)item->size());
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
		return "Start";
	case DebugModulesListModel::EndAddressColumn:
		return "End";
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
	for (const DebugModule& module : newModules)
	{
		newRows.emplace_back(module.m_address, module.m_size, module.m_short_name, module.m_name);
	}

	std::sort(newRows.begin(), newRows.end(), [=](const ModuleItem& a, const ModuleItem& b) {
		return a.address() < b.address();
	});

	m_items = newRows;
	endResetModel();
}


DebugModulesItemDelegate::DebugModulesItemDelegate(QWidget* parent) : QStyledItemDelegate(parent)
{
	updateFonts();
}


void DebugModulesItemDelegate::paint(
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
	case DebugModulesListModel::AddressColumn:
		painter->setPen(getThemeColor(AddressColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case DebugModulesListModel::EndAddressColumn:
		painter->setPen(getThemeColor(AddressColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case DebugModulesListModel::SizeColumn:
		painter->setPen(getThemeColor(NumberColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	case DebugModulesListModel::NameColumn:
	case DebugModulesListModel::PathColumn:
	{
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


DebugModulesWidget::DebugModulesWidget(ViewFrame* view, BinaryViewRef data) : QTableView(view), m_view(view)
{
	m_controller = DebuggerController::GetController(data);
	if (!m_controller)
		return;

	m_model = new DebugModulesListModel(this, view);
	m_filter = new DebugModulesFilterProxyModel(this);
	m_filter->setSourceModel(m_model);
	setModel(m_filter);
	setShowGrid(false);

	m_delegate = new DebugModulesItemDelegate(this);
	setItemDelegate(m_delegate);

	setSelectionBehavior(QAbstractItemView::SelectItems);

	verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	verticalHeader()->setVisible(false);

	horizontalHeader()->setStretchLastSection(true);
	horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

	setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

	resizeColumnsToContents();
	resizeRowsToContents();

	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();

	QString actionName = QString::fromStdString("Jump To Start");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([=]() { jumpToStart(); }));

	actionName = QString::fromStdString("Jump To End");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([=]() { jumpToEnd(); }));

	m_menu->addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&]() { copy(); }, [&]() { return canCopy(); }));
	m_actionHandler.setActionDisplayName("Copy", [&]() {
		QModelIndexList sel = selectionModel()->selectedIndexes();
		if (sel.empty())
			return "Copy";

		switch (sel[0].column())
		{
		case DebugModulesListModel::AddressColumn:
			return "Copy Start";
		case DebugModulesListModel::EndAddressColumn:
			return "Copy End";
		case DebugModulesListModel::SizeColumn:
			return "Copy Size";
		case DebugModulesListModel::NameColumn:
			return "Copy Name";
		case DebugModulesListModel::PathColumn:
			return "Copy Path";
		default:
			return "Copy";
		}
	});

	connect(this, &QTableView::doubleClicked, this, &DebugModulesWidget::onDoubleClicked);

	m_debuggerEventCallback = m_controller->RegisterEventCallback(
		[&](const DebuggerEvent& event) {
			switch (event.type)
			{
			case TargetStoppedEventType:
			case TargetExitedEventType:
				// These updates ensure the widgets become empty after the target stops
			case DetachedEventType:
			case QuitDebuggingEventType:
			case BackEndDisconnectedEventType:
				updateContent();
				break;
			default:
				break;
			}
		},
		"Modules Widget");

	updateContent();
}


DebugModulesWidget::~DebugModulesWidget()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_debuggerEventCallback);
}


void DebugModulesWidget::updateColumnWidths()
{
	resizeColumnToContents(DebugModulesListModel::AddressColumn);
	resizeColumnToContents(DebugModulesListModel::EndAddressColumn);
	resizeColumnToContents(DebugModulesListModel::SizeColumn);
	resizeColumnToContents(DebugModulesListModel::NameColumn);
	resizeColumnToContents(DebugModulesListModel::PathColumn);
}


void DebugModulesWidget::notifyModulesChanged(std::vector<DebugModule> modules)
{
	m_model->updateRows(modules);
	updateColumnWidths();
}


void DebugModulesWidget::updateContent()
{
	if (!m_controller->IsConnected())
		return;

	std::vector<DebugModule> modules = m_controller->GetModules();
	notifyModulesChanged(modules);
}


void DebugModulesWidget::contextMenuEvent(QContextMenuEvent* event)
{
	showContextMenu();
}


void DebugModulesWidget::showContextMenu()
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}


void DebugModulesWidget::jumpToStart()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto module = m_model->getRow(sourceIndex.row());
	uint64_t address = module.address();

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_controller->GetLiveView())
		frame->navigate(m_controller->GetLiveView(), address, true, true);
	else
		frame->navigate(m_controller->GetData(), address, true, true);
}


void DebugModulesWidget::jumpToEnd()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto module = m_model->getRow(sourceIndex.row());
	uint64_t address = module.endAddress();

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_controller->GetLiveView())
		frame->navigate(m_controller->GetLiveView(), address, true, true);
	else
		frame->navigate(m_controller->GetData(), address, true, true);
}


bool DebugModulesWidget::canCopy()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	return !sel.empty();
}


void DebugModulesWidget::copy()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto module = m_model->getRow(sourceIndex.row());
	QString text;

	switch (sel[0].column())
	{
	case DebugModulesListModel::AddressColumn:
		text = QString::asprintf("0x%" PRIx64, module.address());
		break;
	case DebugModulesListModel::EndAddressColumn:
		text = QString::asprintf("0x%" PRIx64, module.endAddress());
		break;
	case DebugModulesListModel::SizeColumn:
		text = QString::asprintf("0x%" PRIx64, (uint64_t)module.size());
		break;
	case DebugModulesListModel::NameColumn:
		text = QString::fromStdString(module.name());
		break;
	case DebugModulesListModel::PathColumn:
		text = QString::fromStdString(module.path());
		break;
	default:
		break;
	}

	auto* clipboard = QGuiApplication::clipboard();
	clipboard->clear();
	auto* mime = new QMimeData();
	mime->setText(text);
	clipboard->setMimeData(mime);
}


void DebugModulesWidget::onDoubleClicked()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	if (sel[0].column() != DebugModulesListModel::AddressColumn
		&& sel[0].column() != DebugModulesListModel::EndAddressColumn)
		return;

	auto sourceIndex = m_filter->mapToSource(sel[0]);
	if (!sourceIndex.isValid())
		return;

	auto module = m_model->getRow(sourceIndex.row());
	uint64_t address;

	if (sourceIndex.column() == DebugModulesListModel::AddressColumn)
		address = module.address();
	else
		address = module.endAddress();

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_controller->GetLiveView())
		frame->navigate(m_controller->GetLiveView(), address, true, true);
	else
		frame->navigate(m_controller->GetData(), address, true, true);
};


void DebugModulesWidget::setFilter(const string& filter)
{
	m_filter->setFilterRegularExpression(QString::fromStdString(filter));
	updateColumnWidths();
}


void DebugModulesWidget::updateFonts()
{
	m_delegate->updateFonts();
}


void DebugModulesWidget::scrollToFirstItem() {}


void DebugModulesWidget::scrollToCurrentItem() {}


void DebugModulesWidget::selectFirstItem() {}


void DebugModulesWidget::activateFirstItem() {}


DebugModulesWithFilter::DebugModulesWithFilter(ViewFrame* view, BinaryViewRef data) : m_view(view)
{
	m_modules = new DebugModulesWidget(view, data);
	m_separateEdit = new FilterEdit(m_modules);
	m_filter = new FilteredView(this, m_modules, m_modules, m_separateEdit);
	m_filter->setFilterPlaceholderText("Search modules");

	auto headerLayout = new QHBoxLayout;
	headerLayout->addWidget(m_separateEdit, 1);

	// Vertically-align the hamburger icon with the text field and give the
	// layout just a bit more breathing room since it's really close to
	// the surrounding elements.
	headerLayout->setContentsMargins(1, 1, 6, 0);
	headerLayout->setAlignment(Qt::AlignBaseline);

	auto* icon = new ClickableIcon(QImage(":/debugger_icons/icons/menu.png"), QSize(16, 16));
	connect(icon, &ClickableIcon::clicked, m_modules, &DebugModulesWidget::showContextMenu);
	headerLayout->addWidget(icon);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addLayout(headerLayout);
	layout->addWidget(m_filter, 1);
}


void DebugModulesWithFilter::updateFonts()
{
	m_modules->updateFonts();
}


GlobalDebugModulesContainer::GlobalDebugModulesContainer(const QString& title) :
	GlobalAreaWidget(title), m_currentFrame(nullptr), m_consoleStack(new QStackedWidget)
{
	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_consoleStack);

	auto* noViewLabel = new QLabel("No active view.");
	noViewLabel->setStyleSheet("QLabel { background: palette(base); }");
	noViewLabel->setAlignment(Qt::AlignCenter);

	m_consoleStack->addWidget(noViewLabel);
}


DebugModulesWithFilter* GlobalDebugModulesContainer::currentWidget() const
{
	if (m_consoleStack->currentIndex() == 0)
		return nullptr;

	return qobject_cast<DebugModulesWithFilter*>(m_consoleStack->currentWidget());
}


void GlobalDebugModulesContainer::freeWidgetForView(QObject* obj)
{
	// A old-style cast must be used here since qobject_cast will fail because
	// the object is on the brink of deletion.
	auto* vf = (ViewFrame*)obj;

	// Confirm there is a record of this view.
	if (!m_widgetMap.count(vf))
	{
		LogWarn("Attempted to free DebuggerConsole for untracked view %p", obj);
		return;
	}

	auto* console = m_widgetMap[vf];
	m_consoleStack->removeWidget(console);
	m_widgetMap.remove(vf);

	// Must be called so the ChatBox is guaranteed to be destoryed. If two
	// instances for the same view/database exist, things will break.
	console->deleteLater();
}


void GlobalDebugModulesContainer::notifyViewChanged(ViewFrame* frame)
{
	// The "no active view" message widget is always located at index 0. If the
	// frame passed is nullptr, show it.
	if (!frame)
	{
		m_consoleStack->setCurrentIndex(0);
		m_currentFrame = nullptr;

		return;
	}

	// The notifyViewChanged event can fire multiple times for the same frame
	// even if there is no apparent change. Compare the new frame to the
	// current one before continuing to avoid unnecessary work.
	if (frame == m_currentFrame)
		return;
	m_currentFrame = frame;

	// Get the appropriate DebuggerConsole for this ViewFrame, or create a new one if it
	// doesn't yet exist. The default value for non-existent keys of pointer
	// types in Qt containers is nullptr, which allows this logic below to work.
	auto* currentConsole = m_widgetMap.value(frame);
	if (!currentConsole)
	{
		currentConsole = new DebugModulesWithFilter(frame, frame->getCurrentBinaryView());

		// DockWidgets related to a ViewFrame are automatically cleaned up as
		// part of the ViewFrame destructor. To ensure there is never a DebuggerConsole
		// for a non-existent ViewFrame, the cleanup must be configured manually.
		connect(frame, &QObject::destroyed, this, &GlobalDebugModulesContainer::freeWidgetForView);

		m_widgetMap.insert(frame, currentConsole);
		m_consoleStack->addWidget(currentConsole);
	}

	m_consoleStack->setCurrentWidget(currentConsole);
}


void GlobalDebugModulesContainer::notifyFontChanged()
{
	for (auto it = m_widgetMap.begin(); it != m_widgetMap.end(); it++)
	{
		if (it.value())
			it.value()->updateFonts();
	}
}


DebugModulesFilterProxyModel::DebugModulesFilterProxyModel(QObject* parent) : QSortFilterProxyModel(parent)
{
	setFilterCaseSensitivity(Qt::CaseInsensitive);
}


bool DebugModulesFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
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
