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

#include <QtWidgets/QTableView>
#include <QtWidgets/QComboBox>
#include <QStyledItemDelegate>
#include <QAbstractItemModel>
#include <QItemSelectionModel>
#include <QModelIndex>
#include <QStyledItemDelegate>
#include <QHeaderView>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "globalarea.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

class FrameItem
{
private:
    int m_frameIndex;
	std::string m_module;
	std::string m_function;
	uint64_t m_pc;
	uint64_t m_sp;
	uint64_t m_fp;

public:
    FrameItem(int index, std::string module, std::string function, uint64_t pc, uint64_t sp, uint64_t fp);
    uint64_t pc() const { return m_pc; }
    uint64_t sp() const { return m_sp; }
    uint64_t fp() const { return m_fp; }
    int frameIndex() const { return m_frameIndex; }
    std::string module() const { return m_module; }
    std::string function() const { return m_function; }
    bool operator==(const FrameItem& other) const;
    bool operator!=(const FrameItem& other) const;
    bool operator<(const FrameItem& other) const;
};

Q_DECLARE_METATYPE(FrameItem);


class ThreadFramesListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    ViewFrame* m_view;
    std::vector<FrameItem> m_items;

public:
    enum ColumnHeaders
    {
        IndexColumn,
        ModuleColumn,
        FunctionColumn,
        PcColumn,
        SpColumn,
        FpColumn,
    };

    ThreadFramesListModel(QWidget* parent, ViewFrame* view);
    virtual ~ThreadFramesListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
        { (void) parent; return (int)m_items.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 6; }
    FrameItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugFrame> frames);
};


class ThreadFramesItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    ThreadFramesItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};

class ThreadFramesWidget: public QWidget
{
	Q_OBJECT

	ViewFrame* m_view;
	DbgRef<DebuggerController> m_debugger;

	QComboBox* m_threadList;
	QTableView* m_threadFrames;
	ThreadFramesListModel* m_model;
	ThreadFramesItemDelegate* m_delegate;

	size_t m_debuggerEventCallback;

	void updateContent();

public:
	ThreadFramesWidget(QWidget* parent, ViewFrame* view, BinaryViewRef debugger);
	~ThreadFramesWidget();

	void notifyFontChanged();
};

class GlobalThreadFramesContainer : public GlobalAreaWidget
{
	ViewFrame *m_currentFrame;
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

	void notifyViewChanged(ViewFrame *) override;
};
