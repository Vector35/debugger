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

#include "threadframes.h"

FrameItem::~FrameItem()
{
	qDeleteAll(m_childItems);
}


void FrameItem::appendChild(FrameItem *item)
{
	m_childItems.append(item);
}


FrameItem *FrameItem::child(int row)
{
	if (row < 0 || row >= m_childItems.size())
		return nullptr;
	return m_childItems.at(row);
}


int FrameItem::childCount() const
{
	return m_childItems.count();
}


FrameItem *FrameItem::parentItem()
{
	return m_parentItem;
}


int FrameItem::row() const
{
	if (m_parentItem)
		return m_parentItem->m_childItems.indexOf(const_cast<FrameItem *>(this));

	return 0;
}


ThreadFrameModel::ThreadFrameModel(DebuggerController* m_debugger, QObject *parent) : 
	QAbstractItemModel(parent)
{
	rootItem = new FrameItem();
}


ThreadFrameModel::~ThreadFrameModel()
{
	delete rootItem;
}


QVariant ThreadFrameModel::data(const QModelIndex &index, int role) const
{
	if (!index.isValid())
		return QVariant();

	if (role != Qt::DisplayRole && role != Qt::SizeHintRole)
		return QVariant();

	if (index.column() >= columnCount())
		return QVariant();

	FrameItem *item = static_cast<FrameItem *>(index.internalPointer());
	if (!item)
		return QVariant();

	// do not use columns other than thread info for thread rows
	if (!item->isFrame() && index.column() != ThreadFrameModel::ThreadColumn)
		return QVariant();

	switch (index.column())
	{
	case ThreadFrameModel::ThreadColumn:
	{
		QString text = QString::asprintf("0x%x @ 0x%" PRIx64, item->tid(), item->threadPc());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFrameModel::FrameIndexColumn:
	{
		QString text = QString::asprintf("%d", item->frameIndex());
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


void ThreadFrameModel::updateRows(DebuggerController *controller)
{
	beginResetModel();

	if (rootItem)
	{
		delete rootItem;
		rootItem = new FrameItem();
	}
	
	QList<FrameItem *> parents;
	parents << rootItem;

	std::vector<DebugThread> threads = controller->GetThreads();
	for (const DebugThread &thread : threads)
	{
		parents.last()->appendChild(new FrameItem(thread, parents.last()));

		parents << parents.last()->child(parents.last()->childCount() - 1);

		std::vector<DebugFrame> frames = controller->GetFramesOfThread(thread.m_tid);
		for (const DebugFrame &frame : frames)
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


QModelIndex ThreadFrameModel::index(int row, int column, const QModelIndex &parent) const
{
	if (!hasIndex(row, column, parent))
		return QModelIndex();

	FrameItem *parentItem;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<FrameItem*>(parent.internalPointer());

	FrameItem *childItem = parentItem->child(row);
	if (childItem)
		return createIndex(row, column, childItem);
	return QModelIndex();
}


QModelIndex ThreadFrameModel::parent(const QModelIndex &index) const
{
	if (!index.isValid())
		return QModelIndex();

	FrameItem *childItem = static_cast<FrameItem *>(index.internalPointer());
	FrameItem *parentItem = childItem->parentItem();

	if (parentItem == rootItem)
		return QModelIndex();

	return createIndex(parentItem->row(), 0, parentItem);
}


int ThreadFrameModel::rowCount(const QModelIndex &parent) const
{
	FrameItem *parentItem;
	if (parent.column() > 0)
		return 0;

	if (!parent.isValid())
		parentItem = rootItem;
	else
		parentItem = static_cast<FrameItem *>(parent.internalPointer());

	return parentItem->childCount();
}


ThreadFramesItemDelegate::ThreadFramesItemDelegate(QWidget* parent, DebuggerController* controller):
    QStyledItemDelegate(parent)
{
	m_debugger = controller;
	updateFonts();
}


void ThreadFramesItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
    const QModelIndex& idx) const
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
	case ThreadFrameModel::ThreadColumn:
	{
		// make thread column bold, if this is active thread
		FrameItem *threadItem = static_cast<FrameItem*>(idx.internalPointer());
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


void ThreadFramesWidget::resumeThread()
{
	QModelIndexList sel = m_threadFramesTree->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	FrameItem *item = static_cast<FrameItem *>(sel[0].internalPointer());
	if (!item)
		return;

	// resume & suspend only works at thread rows
	if (item->isFrame())
		return;

	if (m_debugger->GetActiveThread().m_tid == item->tid())
	{
		LogInfo("Can not resume current thread.");
		return;
	}

	LogInfo("resumeThread called with column=%d row=%d is_frame=%d, tid=%x", sel[0].column(), sel[0].row(), item->isFrame(), item->tid());

	m_debugger->ResumeThread(item->tid());
}


void ThreadFramesWidget::suspendThread()
{
	QModelIndexList sel = m_threadFramesTree->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	FrameItem *item = static_cast<FrameItem *>(sel[0].internalPointer());
	if (!item)
		return;

	if (item->isFrame())
		return;

	if (m_debugger->GetActiveThread().m_tid == item->tid())
	{
		LogInfo("Can not suspend current thread.");
		return;
	}

	LogInfo("suspendThread called with column=%d row=%d is_frame=%d, tid=%x", sel[0].column(), sel[0].row(), item->isFrame(), item->tid());
	
	m_debugger->SuspendThread(item->tid());
}

bool ThreadFramesWidget::selectionNotEmpty()
{
	QModelIndexList sel = m_threadFramesTree->selectionModel()->selectedIndexes();
	return (!sel.empty()) && sel[0].isValid();
}

void ThreadFramesWidget::copy()
{
	QModelIndexList sel = m_threadFramesTree->selectionModel()->selectedIndexes();
	if (sel.empty() || !sel[0].isValid())
		return;

	FrameItem *item = static_cast<FrameItem *>(sel[0].internalPointer());
	if (!item)
		return;

	QString text;

	switch (sel[0].column())
	{
	case ThreadFrameModel::ThreadColumn:
		text = QString::asprintf("0x%x @ 0x%" PRIx64, item->tid(), item->threadPc());
		break;
	case ThreadFrameModel::FrameIndexColumn:
		text = QString::asprintf("%d", item->frameIndex());
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


ThreadFramesWidget::ThreadFramesWidget(QWidget* parent, ViewFrame* frame, BinaryViewRef data):
    QWidget(parent), m_view(frame)
{
    m_debugger = DebuggerController::GetController(data);
    if (!m_debugger)
        return;

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    setFont(getMonospaceFont(this));

	m_threadFramesTree = new QTreeView(this);
	m_threadFramesTree->setExpandsOnDoubleClick(false);
	m_threadFramesTree->setSelectionBehavior(QAbstractItemView::SelectItems);
	m_threadFramesTree->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	m_threadFramesTree->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
	m_threadFramesTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);

	m_model = new ThreadFrameModel(m_debugger);
    m_threadFramesTree->setModel(m_model);

    m_delegate = new ThreadFramesItemDelegate(this, m_debugger);
    m_threadFramesTree->setItemDelegate(m_delegate);

    layout->addWidget(m_threadFramesTree);
    setLayout(layout);

    // Set up colors
    QPalette widgetPalette = this->palette();

	m_actionHandler.setupActionHandler(this);
	m_contextMenuManager = new ContextMenuManager(this);
	m_menu = new Menu();

	// TODO: show suspend and resume only for thread rows
 	QString actionName = QString::fromStdString("Suspend");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([=](){ suspendThread(); }, [=]() { return m_debugger->IsConnected() && (!m_debugger->IsRunning()); }));

	actionName = QString::fromStdString("Resume");
	UIAction::registerAction(actionName);
	m_menu->addAction(actionName, "Options", MENU_ORDER_FIRST);
	m_actionHandler.bindAction(actionName, UIAction([=]() { resumeThread(); }, [=]() { return m_debugger->IsConnected() && (!m_debugger->IsRunning()); }));

	m_menu->addAction("Copy", "Options", MENU_ORDER_NORMAL);
	m_actionHandler.bindAction("Copy", UIAction([&](){ copy(); }, [&]() { return selectionNotEmpty(); }));
	m_actionHandler.setActionDisplayName("Copy", [&]() {
	 	QModelIndexList sel = m_threadFramesTree->selectionModel()->selectedIndexes();
     	if (sel.empty())
         	return "Copy";
 		
		switch (sel[0].column())
	 	{
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

	// TODO: set as active thread action?

    connect(m_threadFramesTree, &QTreeView::doubleClicked, this, &ThreadFramesWidget::onDoubleClicked);

    m_debuggerEventCallback = m_debugger->RegisterEventCallback([&](const DebuggerEvent& event){
        switch (event.type)
        {
        case TargetStoppedEventType:
        case ActiveThreadChangedEvent:
        case RegisterChangedEvent:
        {
            updateContent();
        }
        default:
            break;
        }
    }, "Thread Frame");

    updateContent();
}


ThreadFramesWidget::~ThreadFramesWidget()
{
    if (m_debugger)
        m_debugger->RemoveEventCallback(m_debuggerEventCallback);
}


void ThreadFramesWidget::updateContent()
{
	m_model->updateRows(m_debugger);
}


void ThreadFramesWidget::onDoubleClicked()
{
    QModelIndexList sel = m_threadFramesTree->selectionModel()->selectedIndexes();
    if (sel.empty())
        return;

	auto column = sel[0].column();
	
	if (column == ThreadFrameModel::FrameIndexColumn ||
		column == ThreadFrameModel::ModuleColumn)
		return;	

	FrameItem *frameItem = static_cast<FrameItem *>(sel[0].internalPointer());
	if (!frameItem)
		return;

	if (!frameItem->isFrame() && column > ThreadFrameModel::ThreadColumn)
		return;

	if (frameItem->isFrame() && column == ThreadFrameModel::ThreadColumn)
		return;
    
    LogInfo("double click called");

	// Double clicking on thread column changes active thread
	if (!frameItem->isFrame() && column == ThreadFrameModel::ThreadColumn)
	{
		uint32_t tid = frameItem->tid();
		uint32_t currentTid = m_debugger->GetActiveThread().m_tid;
		if (tid != currentTid)
		{
			LogInfo("set active thread");
			m_debugger->SetActiveThread(tid);
		}

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
    	addrToJump = frameItem->sp();
    	break;
     }

    UIContext* context = UIContext::contextForWidget(this);
    if (!context)
    	return;

    ViewFrame* frame = context->getCurrentViewFrame();
    if (!frame)
    	return;

    if (m_debugger->GetLiveView())
    	frame->navigate(m_debugger->GetLiveView(), addrToJump, true, true);
    else
    	frame->navigate(m_debugger->GetData(), addrToJump, true, true);
}


GlobalThreadFramesContainer::GlobalThreadFramesContainer(const QString& title) : GlobalAreaWidget(title),
    m_currentFrame(nullptr), m_consoleStack(new QStackedWidget)
{
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_consoleStack);

    auto* noViewLabel = new QLabel("No active view.");
    noViewLabel->setStyleSheet("QLabel { background: palette(base); }");
    noViewLabel->setAlignment(Qt::AlignCenter);

    m_consoleStack->addWidget(noViewLabel);
}


ThreadFramesWidget* GlobalThreadFramesContainer::currentConsole() const
{
    if (m_consoleStack->currentIndex() == 0)
        return nullptr;

    return qobject_cast<ThreadFramesWidget*>(m_consoleStack->currentWidget());
}


void GlobalThreadFramesContainer::freeDebuggerConsoleForView(QObject* obj)
{
    // A old-style cast must be used here since qobject_cast will fail because
    // the object is on the brink of deletion.
    auto* vf = (ViewFrame*)obj;

    // Confirm there is a record of this view.
    if (!m_consoleMap.count(vf)) {
        LogWarn("Attempted to free DebuggerConsole for untracked view %p", obj);
        return;
    }

    auto* console = m_consoleMap[vf];
    m_consoleStack->removeWidget(console);
    m_consoleMap.remove(vf);

    // Must be called so the ChatBox is guaranteed to be destoryed. If two
    // instances for the same view/database exist, things will break.
    console->deleteLater();
}


void GlobalThreadFramesContainer::notifyViewChanged(ViewFrame* frame)
{
    // The "no active view" message widget is always located at index 0. If the
    // frame passed is nullptr, show it.
    if (!frame) {
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
    auto* currentConsole = m_consoleMap.value(frame);
    if (!currentConsole)
    {
        currentConsole = new ThreadFramesWidget(this, frame, frame->getCurrentBinaryView());

        // DockWidgets related to a ViewFrame are automatically cleaned up as
        // part of the ViewFrame destructor. To ensure there is never a DebuggerConsole
        // for a non-existent ViewFrame, the cleanup must be configured manually.
        connect(frame, &QObject::destroyed, this, &GlobalThreadFramesContainer::freeDebuggerConsoleForView);

        m_consoleMap.insert(frame, currentConsole);
        m_consoleStack->addWidget(currentConsole);
    }

    m_consoleStack->setCurrentWidget(currentConsole);
}
