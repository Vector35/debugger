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

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

ThreadFramesWidget::ThreadFramesWidget(QWidget* parent, ViewFrame* frame, BinaryViewRef data):
	QWidget(parent), m_view(frame)
{
	m_debugger = DebuggerController::GetController(data);
	// In rare cases, m_debugger could be nullptr. This only happens when 1. a target exits and the live view of the
	// DebuggerController is set to nullptr, 2. the UI still shows the live view. This is a short time span, since
	// the debugger UI will reopen the file context after the target exits, which no longer contains teh live view.
	if (!m_debugger)
		return;

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);
	setFont(getMonospaceFont(this));

	m_threadList = new QComboBox(this);
	m_threadFrames = new QListWidget(this);

	layout->addWidget(new QLabel("Thread:"));
	layout->addWidget(m_threadList);
	layout->addWidget(m_threadFrames);
	setLayout(layout);

	// Set up colors
	QPalette widgetPalette = this->palette();

	connect(m_threadList, &QComboBox::activated, [&](int index){
		uint32_t tid = m_threadList->currentData().toInt();
		uint32_t currentTid = m_debugger->GetActiveThread().m_tid;
		if (tid != currentTid)
			m_debugger->SetActiveThread(tid);
	});

	connect(m_threadFrames, &QListWidget::itemDoubleClicked, [&](QListWidgetItem* item){
		std::string text = item->text().toStdString();
		auto pos = text.find("0x");
		if (pos == std::string::npos)
			return;

		text = text.substr(pos, text.length());
		pos = text.find(" ");
		if (pos != std::string::npos)
			text = text.substr(0, pos);

		uint64_t address = strtoull(text.c_str(), nullptr, 16);
		if (address != 0)
		{
			UIContext* context = UIContext::contextForWidget(this);
			ViewFrame* frame = context->getCurrentViewFrame();
			frame->navigate(m_debugger->GetLiveView(), address, true, true);
		}
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
	m_threadFrames->clear();
	for (const DebugFrame& frame: frames)
	{
		QString text = QString::asprintf("#%d: 0x%" PRIx64, (int)frame.m_index, frame.m_pc);
		uint64_t offset = frame.m_pc - frame.m_functionStart;
		QString symbolizedInfo = QString::asprintf("%s`%s + 0x%" PRIx64 ", sp: 0x%" PRIx64 ", fp: 0x%" PRIx64,
												   frame.m_module.c_str(), frame.m_functionName.c_str(), offset,
												   frame.m_sp, frame.m_fp);
		m_threadFrames->addItem(text + ' ' + symbolizedInfo);
	}
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
