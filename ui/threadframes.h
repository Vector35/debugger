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

#pragma once

#include <QtWidgets/QTreeView>
#include <QStyledItemDelegate>
#include <QAbstractItemModel>
#include <QHeaderView>
#include <QGuiApplication>
#include <QMimeData>
#include <QClipboard>
#include "binaryninjaapi.h"
#include "globalarea.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "debuggerapi.h"
#include "inttypes.h"
#include "ui.h"


using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

class FrameItem
{
public:
	FrameItem() = default;

	FrameItem(const DebugThread& thread, FrameItem* parentItem = nullptr) :
		m_tid(thread.m_tid), m_threadPc(thread.m_rip), m_isFrozen(thread.m_isFrozen), m_parentItem(parentItem)
	{}

	FrameItem(const DebugThread& thread, const DebugFrame& frame, FrameItem* parentItem = nullptr) :
		m_tid(thread.m_tid), m_threadPc(thread.m_rip), m_frameIndex(frame.m_index), m_module(frame.m_module),
		m_framePc(frame.m_pc), m_sp(frame.m_sp), m_fp(frame.m_fp), m_isFrame(true), m_parentItem(parentItem)
	{
		uint64_t offset = frame.m_pc - frame.m_functionStart;
		QString funcName = QString::asprintf("%s + 0x%" PRIx64, frame.m_functionName.c_str(), offset);

		m_function = funcName.toStdString();
	}

	~FrameItem();

	void appendChild(FrameItem* child);

	FrameItem* child(int row);
	int childCount() const;
	int row() const;
	FrameItem* parentItem();

	bool isFrame() const { return m_isFrame; }
	bool isFrozen() const { return m_isFrozen; }
	uint32_t tid() const { return m_tid; }
	uint64_t threadPc() const { return m_threadPc; }
	uint64_t framePc() const { return m_framePc; }
	uint64_t sp() const { return m_sp; }
	uint64_t fp() const { return m_fp; }
	size_t frameIndex() const { return m_frameIndex; }
	std::string module() const { return m_module; }
	std::string function() const { return m_function; }

private:
	bool m_isFrame {false};
	bool m_isFrozen {false};
	uint32_t m_tid {};
	uint64_t m_threadPc {};
	size_t m_frameIndex {};
	std::string m_module {};
	std::string m_function {};
	uint64_t m_framePc {};
	uint64_t m_sp {};
	uint64_t m_fp {};

	QList<FrameItem*> m_childItems;
	FrameItem* m_parentItem;
};

Q_DECLARE_METATYPE(FrameItem);

class ThreadFrameModel : public QAbstractItemModel
{
	Q_OBJECT

public:
	enum ColumnHeaders
	{
		StateColumn,
		ThreadColumn,
		FrameIndexColumn,
		ModuleColumn,
		FunctionColumn,
		PcColumn,
		SpColumn,
		FpColumn,
	};

	explicit ThreadFrameModel(QObject* parent = nullptr, DebuggerControllerRef controller = nullptr);
	~ThreadFrameModel();

	QVariant data(const QModelIndex& index, int role) const override;
	QVariant headerData(int column, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	QModelIndex parent(const QModelIndex& index) const override;
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return 8;
	}
	void updateRows(DebuggerController* controller);

private:
	FrameItem* rootItem;
	DebuggerControllerRef m_controller = nullptr;
};


class ThreadFramesItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;
	DbgRef<DebuggerController> m_debugger;

public:
	ThreadFramesItemDelegate(QWidget* parent, DebuggerController* controller);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};

class ThreadFramesWidget : public QWidget
{
	Q_OBJECT

	ViewFrame* m_view;
	DbgRef<DebuggerController> m_debugger;

	QTreeView* m_threadFramesTree;
	ThreadFrameModel* m_model;
	ThreadFramesItemDelegate* m_delegate;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	size_t m_debuggerEventCallback;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	bool selectionNotEmpty();
	bool canSuspendOrResume();
	void expandCurrentThread();

public slots:
	void updateContent();

public:
	ThreadFramesWidget(QWidget* parent, ViewFrame* view, BinaryViewRef debugger);
	~ThreadFramesWidget();

	void notifyFontChanged();

private slots:
	void onDoubleClicked();
	void suspendThread();
	void resumeThread();
	void makeItSoloThread();
	void copy();
};

class GlobalThreadFramesContainer : public GlobalAreaWidget
{
	ViewFrame* m_currentFrame;
	QHash<ViewFrame*, ThreadFramesWidget*> m_consoleMap;

	QStackedWidget* m_consoleStack;

	//! Get the current active DebuggerConsole. Returns nullptr in the event of an error
	//! or if there is no active ChatBox.
	ThreadFramesWidget* currentConsole() const;

	//! Delete the DebuggerConsole for the given view.
	void freeDebuggerConsoleForView(QObject*);

public:
	GlobalThreadFramesContainer(const QString& title);

	//! Send text to the actively-focused ChatBox. If there is no active ChatBox,
	//! no action will be taken.
	void sendText(const QString& msg) const;

	void notifyViewChanged(ViewFrame*) override;
};
