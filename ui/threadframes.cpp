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
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "inttypes.h"


constexpr int SortFilterRole = Qt::UserRole + 1;

FrameItem::FrameItem(int index, std::string module, std::string function, uint64_t pc, uint64_t sp, uint64_t fp):
	m_frameIndex(index), m_module(module), m_function(function), m_pc(pc), m_sp(sp), m_fp(fp)
{
}


bool FrameItem::operator==(const FrameItem& other) const
{
	return (m_module == other.module()) && (m_function == other.function()) && (m_pc == other.pc()) &&
		(m_fp == other.fp()) && (m_sp == other.sp());
}


bool FrameItem::operator!=(const FrameItem& other) const
{
	return !(*this == other);
}


bool FrameItem::operator<(const FrameItem& other) const
{
	if (m_module < other.module())
		return true;
	else if (m_module > other.module())
		return false;
	else if (m_function < other.function())
		return true;
	else if (m_function > other.function())
		return false;
	else if (m_pc < other.pc())
		return true;
	else if (m_pc > other.pc())
		return false;
	else if (m_sp < other.sp())
		return true;
	else if (m_sp > other.sp())
		return false;
	return m_fp < other.fp();
}


ThreadFramesListModel::ThreadFramesListModel(QWidget* parent, ViewFrame* view):
	QAbstractTableModel(parent), m_view(view)
{
}


ThreadFramesListModel::~ThreadFramesListModel()
{
}


FrameItem ThreadFramesListModel::getRow(int row) const
{
	if ((size_t)row >= m_items.size())
		throw std::runtime_error("row index out-of-bound");

	return m_items[row];
}


QModelIndex ThreadFramesListModel::index(int row, int column, const QModelIndex &) const
{
	if (row < 0 || (size_t)row >= m_items.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_items[row]);
}


QVariant ThreadFramesListModel::data(const QModelIndex& index, int role) const
{
	if (index.column() >= columnCount() || (size_t)index.row() >= m_items.size())
		return QVariant();

	FrameItem *item = static_cast<FrameItem*>(index.internalPointer());
	if (!item)
		return QVariant();

	if ((role != Qt::DisplayRole) && (role != Qt::SizeHintRole) && (role != SortFilterRole))
		return QVariant();

	switch (index.column())
	{
	case ThreadFramesListModel::IndexColumn:
	{
		QString text = QString::asprintf("%d", item->frameIndex());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFramesListModel::ModuleColumn:
	{
		QString text = QString::fromStdString(item->module());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFramesListModel::FunctionColumn:
	{
		QString text = QString::fromStdString(item->function());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFramesListModel::PcColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->pc());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFramesListModel::SpColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->sp());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	case ThreadFramesListModel::FpColumn:
	{
		QString text = QString::asprintf("0x%" PRIx64, item->fp());
		if (role == Qt::SizeHintRole)
			return QVariant((qulonglong)text.size());

		return QVariant(text);
	}
	}
	return QVariant();
}


QVariant ThreadFramesListModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
	case ThreadFramesListModel::IndexColumn:
		return "#";
	case ThreadFramesListModel::ModuleColumn:
		return "Module";
	case ThreadFramesListModel::FunctionColumn:
		return "Function";
	case ThreadFramesListModel::PcColumn:
		return "PC";
	case ThreadFramesListModel::SpColumn:
		return "SP";
	case ThreadFramesListModel::FpColumn:
		return "FP";
	}
	return QVariant();
}


void ThreadFramesListModel::updateRows(std::vector<BinaryNinjaDebuggerAPI::DebugFrame> frames)
{
	beginResetModel();

	//TODO: add one more element for FunctionName + offset?
	std::vector<FrameItem> newRows;
	for (const DebugFrame& frame: frames)
	{
		newRows.emplace_back((int)frame.m_index, frame.m_module, frame.m_functionName, frame.m_pc, frame.m_sp, frame.m_fp);
	}

	m_items = newRows;
	endResetModel();
}


ThreadFramesItemDelegate::ThreadFramesItemDelegate(QWidget* parent):
	QStyledItemDelegate(parent)
{
	updateFonts();
}


void ThreadFramesItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
	const QModelIndex& idx) const
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
	case ThreadFramesListModel::IndexColumn:
	{
		painter->setPen(getThemeColor(NumberColor).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	case ThreadFramesListModel::ModuleColumn:
	case ThreadFramesListModel::FunctionColumn:
	{
		painter->setPen(option.palette.color(QPalette::WindowText).rgba());
		painter->drawText(textRect, data.toString());
		break;
	}
	case ThreadFramesListModel::PcColumn:
	case ThreadFramesListModel::FpColumn:
	case ThreadFramesListModel::SpColumn:
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

	m_threadList = new QComboBox(this);

	m_threadFramesTable = new QTableView(this);
	m_model = new ThreadFramesListModel(m_threadFramesTable, frame);
	
	m_threadFramesTable->setModel(m_model);
	m_threadFramesTable->setShowGrid(false);

	m_delegate = new ThreadFramesItemDelegate(this);
	m_threadFramesTable->setItemDelegate(m_delegate);

	m_threadFramesTable->setSelectionBehavior(QAbstractItemView::SelectItems);

	m_threadFramesTable->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
	m_threadFramesTable->verticalHeader()->setVisible(false);

	m_threadFramesTable->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
	m_threadFramesTable->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

	m_threadFramesTable->resizeColumnsToContents();
	m_threadFramesTable->resizeRowsToContents();

	layout->addWidget(new QLabel("Thread:"));
	layout->addWidget(m_threadList);
	layout->addWidget(m_threadFramesTable);
	setLayout(layout);

	// Set up colors
	QPalette widgetPalette = this->palette();

	connect(m_threadFramesTable, &QTableView::doubleClicked, this, &ThreadFramesWidget::onDoubleClicked);

	connect(m_threadList, &QComboBox::activated, [&](int index){
		uint32_t tid = m_threadList->currentData().toInt();
		uint32_t currentTid = m_debugger->GetActiveThread().m_tid;
		if (tid != currentTid)
			m_debugger->SetActiveThread(tid);
	});

	m_debuggerEventCallback = m_debugger->RegisterEventCallback([&](const DebuggerEvent& event){
		switch (event.type)
		{
		case TargetStoppedEventType:
		case ActiveThreadChangedEvent:
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
	std::vector<DebugThread> threads = m_debugger->GetThreads();
	m_threadList->clear();
	for (const DebugThread thread: threads)
	{
		m_threadList->addItem(QString::asprintf("0x%" PRIx64 " @ 0x%" PRIx64, (uint64_t)thread.m_tid, (uint64_t)thread.m_rip),
							  QVariant(thread.m_tid));
	}

	DebugThread activeThread = m_debugger->GetActiveThread();
	int index = m_threadList->findData(QVariant(activeThread.m_tid));
	if (index == -1)
		return;

	m_threadList->setCurrentIndex(index);

	std::vector<DebugFrame> frames = m_debugger->GetFramesOfThread(activeThread.m_tid);
	m_model->updateRows(frames);
	m_threadFramesTable->resizeColumnsToContents();
}


void ThreadFramesWidget::onDoubleClicked()
{
	QModelIndexList sel = m_threadFramesTable->selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	//TODO: support for function column?
	if (sel[0].column() != ThreadFramesListModel::PcColumn && 
		sel[0].column() != ThreadFramesListModel::SpColumn &&
		sel[0].column() != ThreadFramesListModel::FpColumn)
		return;


	auto frameItem = m_model->getRow(sel[0].row());

	uint64_t addrToJump = 0;
	switch (sel[0].column())
	{
	case ThreadFramesListModel::PcColumn:
		addrToJump = frameItem.pc();
		break;
	case ThreadFramesListModel::SpColumn:
		addrToJump = frameItem.sp();
		break;
	case ThreadFramesListModel::FpColumn:
		addrToJump = frameItem.fp();
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
