/*
Copyright 2020-2025 Vector 35 Inc.

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

#include "threadframes.h"
#include <algorithm>

FrameItem::~FrameItem()
{
	qDeleteAll(m_childItems);
}


void FrameItem::appendChild(FrameItem* item)
{
	m_childItems.append(item);
}


FrameItem* FrameItem::child(int row)
{
	if (row < 0 || row >= m_childItems.size())
		return nullptr;
	return m_childItems.at(row);
}


int FrameItem::childCount() const
{
	return m_childItems.count();
}


FrameItem* FrameItem::parentItem()
{
	return m_parentItem;
}


int FrameItem::row() const
{
	if (m_parentItem)
		return m_parentItem->m_childItems.indexOf(const_cast<FrameItem*>(this));

	return 0;
}


ThreadFrameModel::ThreadFrameModel(QObject* parent, DebuggerControllerRef controller) :
	QAbstractItemModel(parent), m_controller(controller)
{
	rootItem = new FrameItem();
}


ThreadFrameModel::~ThreadFrameModel()
{
	delete rootItem;
}


QVariant ThreadFrameModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid())
		return QVariant();

	if (role != Qt::DisplayRole && role != Qt::SizeHintRole)
		return QVariant();

	if (index.column() >= columnCount())
		return QVariant();

	FrameItem* item = static_cast<FrameItem*>(index.internalPointer());
	if (!item)
		return QVariant();

	// do not use columns other than thread info & state for thread rows
	if (!item->isFrame() && index.column() > ThreadFrameModel::ThreadColumn)
		return QVariant();

	switch (index.column())
	{
	case ThreadFrameModel::StateColumn:
	{
		if (item->isFrame())
			return QVariant();

		QString text = item->isFrozen() ? "Frozen" : "Unfrozen";
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::ThreadColumn:
	{
		if (item->isFrame())
			return QVariant();

		auto isActiveThread = m_controller->GetActiveThread().m_tid == item->tid();

		QString text =
			QString::asprintf("%s0x%x @ 0x%" PRIx64, isActiveThread ? "(*) " : "", item->tid(), item->threadPc());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::FrameIndexColumn:
	{
		QString text = QString::asprintf("%lu", item->frameIndex());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::ModuleColumn:
	{
		QString text = QString::fromStdString(item->module());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::FunctionColumn:
	{
		QString text = QString::fromStdString(item->function());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::PcColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->framePc());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::SpColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->sp());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::FpColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->fp());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	}
	return QVariant();
}


void ThreadFrameModel::updateRows(DebuggerController* controller)
{
	beginResetModel();

	if (rootItem)
	{
		delete rootItem;
		rootItem = new FrameItem();
	}

	QList<FrameItem*> parents;
	parents << rootItem;

	std::vector<DebugThread> threads = controller->GetThreads();

	// Sort threads so that the active thread appears first
	uint32_t activeThreadId = controller->GetActiveThread().m_tid;
	std::sort(threads.begin(), threads.end(), [activeThreadId](const DebugThread& a, const DebugThread& b) {
		// Active thread comes first, then sort by thread ID for consistent ordering
		bool aIsActive = (a.m_tid == activeThreadId);
		bool bIsActive = (b.m_tid == activeThreadId);

		if (aIsActive && !bIsActive)
			return true;
		if (!aIsActive && bIsActive)
			return false;

		return a.m_tid < b.m_tid;
	});

	for (const DebugThread& thread : threads)
	{
		parents.last()->appendChild(new FrameItem(thread, parents.last()));

		parents << parents.last()->child(parents.last()->childCount() - 1);

		std::vector<DebugFrame> frames = controller->GetFramesOfThread(thread.m_tid);
		for (const DebugFrame& frame : frames)
		{
			parents.last()->appendChild(new FrameItem(thread, frame, parents.last()));
		}

		parents.pop_back();
	}

	endResetModel();
}


QVariant ThreadFrameModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
	case ThreadFrameModel::StateColumn:
		return "State";
	case ThreadFrameModel::ThreadColumn:
		return "Thread";
	case ThreadFrameModel::FrameIndexColumn:
		return "Frame #";
	case ThreadFrameModel::ModuleColumn:
		return "Module";
	case ThreadFrameModel::FunctionColumn:
		return "Function";
	case ThreadFrameModel::PcColumn:
		return "PC";
	case ThreadFrameModel::SpColumn:
		return "SP";
	case ThreadFrameModel::FpColumn:
		return "FP";
	}

	return QVariant();
}


QModelIndex ThreadFrameModel::index(int row, int column, const QModelIndex& parent) const
{
	if (!hasIndex(row, column, parent))
		return QModelIndex();

	FrameItem* parentItem;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<FrameItem*>(parent.internalPointer());

	FrameItem* childItem = parentItem->child(row);
	if (childItem)
		return createIndex(row, column, childItem);
	return QModelIndex();
}


QModelIndex ThreadFrameModel::parent(const QModelIndex& index) const
{
	if (!index.isValid())
		return QModelIndex();

	FrameItem* childItem = static_cast<FrameItem*>(index.internalPointer());
	FrameItem* parentItem = childItem->parentItem();

	if (parentItem == rootItem)
		return QModelIndex();

	return createIndex(parentItem->row(), 0, parentItem);
}


int ThreadFrameModel::rowCount(const QModelIndex& parent) const
{
	FrameItem* parentItem;
	if (parent.column() > 0)
		return 0;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<FrameItem*>(parent.internalPointer());

	return parentItem->childCount();
}


ThreadFramesItemDelegate::ThreadFramesItemDelegate(QWidget* parent, DebuggerController* controller) :
	QStyledItemDelegate(parent)
{
	m_debugger = controller;
	updateFonts();
}


void ThreadFramesItemDelegate::paint(
	QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const
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
	case ThreadFrameModel::StateColumn:
	{
		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	case ThreadFrameModel::ThreadColumn:
	{
		// make thread column bold, if this is active thread
		FrameItem* threadItem = static_cast<FrameItem*>(idx.internalPointer());
		if (threadItem)
		{
			auto currentTid = m_debugger->GetActiveThread().m_tid;
			if (!threadItem->isFrame() && (currentTid == threadItem->tid()))
			{
				QFont font = m_font;
				font.setBold(true);
				painter->setFont(font);
			}
		}

		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	case ThreadFrameModel::FrameIndexColumn:
	{
		painter->setPen(getThemeColor(NumberColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	case ThreadFrameModel::ModuleColumn:
	case ThreadFrameModel::FunctionColumn:
	{
		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	case ThreadFrameModel::PcColumn:
	case ThreadFrameModel::FpColumn:
	case ThreadFrameModel::SpColumn:
	{
		painter->setPen(getThemeColor(AddressColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	default:
		break;
	}
}


void ThreadFramesItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize ThreadFramesItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
	return QSize(totalWidth, m_charHeight + 2);
}


void ThreadFramesWidget::contextMenuEvent(QContextMenuEvent* event)
{
	m_contextMenuManager->show(m_menu, &m_actionHandler);
}

void ThreadFramesWidget::makeItSoloThread()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	FrameItem* item = static_cast<FrameItem*>(sel[0].internalPointer());
	if (!item)
		return;

	auto soloTid = item->tid();
	auto isSoloFrozen = item->isFrozen();

	auto threads = m_debugger->GetThreads();
	for (const DebugThread& thread : threads)
	{
		if (thread.m_tid != soloTid && !thread.m_isFrozen)
			m_debugger->SuspendThread(thread.m_tid);
	}

	// make sure solo thread is unfrozen and activated
	if (isSoloFrozen)
		m_debugger->ResumeThread(soloTid);

	if (m_debugger->GetActiveThread().m_tid != soloTid)
		m_debugger->SetActiveThread(soloTid);
}

void ThreadFramesWidget::updateFonts()
{
	m_delegate->updateFonts();
}

void ThreadFramesWidget::resumeThread()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	FrameItem* item = static_cast<FrameItem*>(sel[0].internalPointer());
	if (!item)
		return;

	// resume & suspend only works at thread rows
	if (item->isFrame())
		return;

	m_debugger->ResumeThread(item->tid());
}


void ThreadFramesWidget::suspendThread()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	FrameItem* item = static_cast<FrameItem*>(sel[0].internalPointer());
	if (!item)
		return;

	if (item->isFrame())
		return;

	m_debugger->SuspendThread(item->tid());
}


bool ThreadFramesWidget::selectionNotEmpty()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	return (!sel.empty()) && sel[0].isValid();
}


bool ThreadFramesWidget::canSuspendOrResume()
{
	if (!m_debugger->IsConnected() || m_debugger->IsRunning())
		return false;

	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty() || !sel[0].isValid())
		return false;

	FrameItem* item = static_cast<FrameItem*>(sel[0].internalPointer());
	if (!item)
		return false;

	if (item->isFrame())
		return false;

	return true;
}


void ThreadFramesWidget::copy()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty() || !sel[0].isValid())
		return;

	FrameItem* item = static_cast<FrameItem*>(sel[0].internalPointer());
	if (!item)
		return;

	QString text;

	switch (sel[0].column())
	{
	case ThreadFrameModel::StateColumn:
		if (item->isFrame())
			return;

		text = item->isFrozen() ? "Frozen" : "Unfrozen";
		break;
	case ThreadFrameModel::ThreadColumn:
		if (item->isFrame())
			return;

		text = QString::asprintf("0x%x @ 0x%" PRIx64, item->tid(), item->threadPc());
		break;
	case ThreadFrameModel::FrameIndexColumn:
		text = QString::asprintf("%lu", item->frameIndex());
		break;
	case ThreadFrameModel::ModuleColumn:
		text = QString::fromStdString(item->module());
		break;
	case ThreadFrameModel::FunctionColumn:
		text = QString::fromStdString(item->function());
		break;
	case ThreadFrameModel::PcColumn:
		text = QString::asprintf("0x%" PRIx64, item->framePc());
		break;
	case ThreadFrameModel::SpColumn:
		text = QString::asprintf("0x%" PRIx64, item->sp());
		break;
	case ThreadFrameModel::FpColumn:
		text = QString::asprintf("0x%" PRIx64, item->fp());
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


void ThreadFramesWidget::copyCurrentFrame()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	QString text;
	QSet<int> processedRows;

	for (const QModelIndex& index : sel)
	{
		if (!index.isValid())
			continue;

		int row = index.row();
		if (processedRows.contains(row))
			continue;

		processedRows.insert(row);

		FrameItem* item = static_cast<FrameItem*>(index.internalPointer());
		if (!item || !item->isFrame())
			continue;

		if (!text.isEmpty())
			text += "\n";

		// Format: FrameIndex Module Function PC SP FP
		text += QString::asprintf("%lu %s %s 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64, item->frameIndex(),
			item->module().c_str(), item->function().c_str(), item->framePc(), item->sp(), item->fp());
	}

	if (text.isEmpty())
		return;

	auto* clipboard = QGuiApplication::clipboard();
	clipboard->clear();
	auto* mime = new QMimeData();
	mime->setText(text);
	clipboard->setMimeData(mime);
}


void ThreadFramesWidget::copyAllFrames()
{
	QString text;

	// Iterate through all top-level items (threads)
	for (int i = 0; i < m_model->rowCount(); i++)
	{
		QModelIndex threadIndex = m_model->index(i, 0);
		if (!threadIndex.isValid())
			continue;

		FrameItem* threadItem = static_cast<FrameItem*>(threadIndex.internalPointer());
		if (!threadItem)
			continue;

		// Skip if thread has no frames
		if (threadItem->childCount() == 0)
			continue;

		// Add separator between threads
		if (!text.isEmpty())
			text += "\n";

		// Add thread header
		text += QString::asprintf("Thread %d (0x%x):\n", i, threadItem->tid());

		// Iterate through all frames in this thread
		for (int j = 0; j < threadItem->childCount(); j++)
		{
			FrameItem* frameItem = threadItem->child(j);
			if (!frameItem || !frameItem->isFrame())
				continue;

			// Format: FrameIndex Module Function PC SP FP
			text += QString::asprintf("%lu %s %s 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64, frameItem->frameIndex(),
				frameItem->module().c_str(), frameItem->function().c_str(), frameItem->framePc(), frameItem->sp(),
				frameItem->fp());

			// Add newline after each frame
			text += "\n";
		}
	}

	if (text.isEmpty())
		return;

	auto* clipboard = QGuiApplication::clipboard();
	clipboard->clear();
	auto* mime = new QMimeData();
	mime->setText(text);
	clipboard->setMimeData(mime);
}


ThreadFramesWidget::ThreadFramesWidget(QWidget* parent, ViewFrame* frame, BinaryViewRef data) :
	QTreeView(parent), m_view(frame)
{
	m_debugger = DebuggerController::GetController(data);
	if (!m_debugger)
		return;

	setExpandsOnDoubleClick(false);
	setSelectionBehavior(QAbstractItemView::SelectItems);
	setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
	header()->setSectionResizeMode(QHeaderView::ResizeToContents);

	m_model = new ThreadFrameModel(this, m_debugger);
	setModel(m_model);

	m_delegate = new ThreadFramesItemDelegate(this, m_debugger);
	setItemDelegate(m_delegate);

	// Set up colors
	QPalette widgetPalette = this->palette();

	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();

	QString actionName = QString::fromStdString("Suspend Thread");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(
		actionName, UIAction([this]() { suspendThread(); }, [this]() { return canSuspendOrResume(); }));

	actionName = QString::fromStdString("Resume Thread");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(
		actionName, UIAction([this]() { resumeThread(); }, [this]() { return canSuspendOrResume(); }));

	actionName = QString::fromStdString("Make It Solo Thread");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(
		actionName, UIAction([this]() { makeItSoloThread(); }, [this]() { return canSuspendOrResume(); }));

	m_menu->addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&]() { copy(); }, [&]() { return selectionNotEmpty(); }));
	m_actionHandler.setActionDisplayName("Copy", [&]() {
		QModelIndexList sel = selectionModel()->selectedIndexes();
		if (sel.empty())
			return "Copy";

		switch (sel[0].column())
		{
		case ThreadFrameModel::StateColumn:
			return "Copy State";
		case ThreadFrameModel::ThreadColumn:
			return "Copy Thread";
		case ThreadFrameModel::FrameIndexColumn:
			return "Copy Frame Index";
		case ThreadFrameModel::ModuleColumn:
			return "Copy Module";
		case ThreadFrameModel::FunctionColumn:
			return "Copy Function";
		case ThreadFrameModel::PcColumn:
			return "Copy PC";
		case ThreadFrameModel::SpColumn:
			return "Copy SP";
		case ThreadFrameModel::FpColumn:
			return "Copy FP";
		default:
			return "Copy";
		}
	});

	actionName = QString::fromStdString("Copy Current Stack Trace");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(
		actionName, UIAction([this]() { copyCurrentFrame(); }, [this]() { return selectionNotEmpty(); }));

	actionName = QString::fromStdString("Copy All Stack Traces");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction(actionName, UIAction([this]() { copyAllFrames(); }));

	// TODO: set as active thread action?

	connect(this, &QTreeView::doubleClicked, this, &ThreadFramesWidget::onDoubleClicked);
	connect(this, &ThreadFramesWidget::debuggerEvent, this, &ThreadFramesWidget::onDebuggerEvent);

	m_debuggerEventCallback = m_debugger->RegisterEventCallback(
		[&](const DebuggerEvent& event) { emit debuggerEvent(event); }, "Thread Frame");

	updateContent();
}


ThreadFramesWidget::~ThreadFramesWidget()
{
	if (m_debugger)
		m_debugger->RemoveEventCallback(m_debuggerEventCallback);
}


void ThreadFramesWidget::expandCurrentThread()
{
	for (int i = 0; i < m_model->rowCount(); i++)
	{
		auto index = m_model->index(i, 0);
		if (!index.isValid())
			return;

		FrameItem* item = static_cast<FrameItem*>(index.internalPointer());
		if (!item)
			return;

		if (m_debugger->GetActiveThread().m_tid == item->tid())
		{
			expand(index);
			return;
		}
	}
}


void ThreadFramesWidget::onDebuggerEvent(const DebuggerEvent& event)
{
	switch (event.type)
	{
	case TargetStoppedEventType:
	case TargetExitedEventType:
	case DetachedEventType:
	case ActiveThreadChangedEvent:
	case RegisterChangedEvent:
	case ThreadStateChangedEvent:
	{
		updateContent();
	}
	default:
		break;
	}
}


void ThreadFramesWidget::updateContent()
{
	if (!m_debugger->IsConnected())
		return;

	m_model->updateRows(m_debugger);
	expandCurrentThread();
}


void ThreadFramesWidget::onDoubleClicked()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto column = sel[0].column();

	if (column == ThreadFrameModel::FrameIndexColumn || column == ThreadFrameModel::ModuleColumn)
		return;

	FrameItem* frameItem = static_cast<FrameItem*>(sel[0].internalPointer());
	if (!frameItem)
		return;

	if (!frameItem->isFrame() && column > ThreadFrameModel::ThreadColumn)
		return;

	if (frameItem->isFrame() && column <= ThreadFrameModel::ThreadColumn)
		return;

	// Double clicking on thread column changes active thread
	if (!frameItem->isFrame() && column == ThreadFrameModel::ThreadColumn)
	{
		uint32_t tid = frameItem->tid();
		uint32_t currentTid = m_debugger->GetActiveThread().m_tid;

		if (tid != currentTid && !m_debugger->IsRunning())
			m_debugger->SetActiveThread(tid);

		return;
	}

	// double clicking on state column toggles thread state
	if (!frameItem->isFrame() && column == ThreadFrameModel::StateColumn)
	{
		if (frameItem->isFrozen())
			m_debugger->ResumeThread(frameItem->tid());
		else
			m_debugger->SuspendThread(frameItem->tid());

		return;
	}

	uint64_t addrToJump = 0;
	switch (column)
	{
	case ThreadFrameModel::FunctionColumn:
	case ThreadFrameModel::PcColumn:
		addrToJump = frameItem->framePc();
		break;
	case ThreadFrameModel::SpColumn:
		addrToJump = frameItem->sp();
		break;
	case ThreadFrameModel::FpColumn:
		addrToJump = frameItem->fp();
		break;
	}

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_debugger->GetData())
		frame->navigate(m_debugger->GetData(), addrToJump, true, true);
}


ThreadFramesContainer::ThreadFramesContainer(ViewFrame* frame, BinaryViewRef data) : SidebarWidget("Stack Trace")
{
	m_widget = new ThreadFramesWidget(this, frame, data);

	auto* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_widget);
}


void ThreadFramesContainer::notifyFontChanged()
{
	m_widget->updateFonts();
}


ThreadFramesSidebarWidgetType::ThreadFramesSidebarWidgetType() :
	SidebarWidgetType(QImage(":/icons/images/stack-trace.png"), "Stack Trace")
{}


SidebarWidget* ThreadFramesSidebarWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new ThreadFramesContainer(frame, data);
}


SidebarContentClassifier* ThreadFramesSidebarWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}
