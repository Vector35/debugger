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

#include <QAbstractItemModel>
#include <QItemSelectionModel>
#include <QModelIndex>
#include <QTableView>
#include <QStyledItemDelegate>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;

enum DebugThreadValueStatus
{
	DebugThreadValueNormal,
	// The current value is different from the last value
	DebugThreadValueChanged,
	// The value has been modified by the user
	DebugThreadValueModified
};


class ThreadItem
{
private:
    size_t m_tid;
    uint64_t m_rip;
	bool m_isLastActive;
	DebugThreadValueStatus m_valueStatus;

public:
    ThreadItem(size_t tid, uint64_t rip, bool isLastActive, DebugThreadValueStatus valueStatus);
    uint64_t tid() const { return m_tid; }
    size_t rip() const { return m_rip; }
	bool isLastActive() const { return m_isLastActive; }
	DebugThreadValueStatus valueStatus() const { return m_valueStatus; }
    bool operator==(const ThreadItem& other) const;
    bool operator!=(const ThreadItem& other) const;
    bool operator<(const ThreadItem& other) const;
};

Q_DECLARE_METATYPE(ThreadItem);


class DebugThreadsListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    ViewFrame* m_view;
    std::vector<ThreadItem> m_items;

public:
    enum ColumnHeaders
    {
        TIDColumn,
        LocationColumn
    };

    DebugThreadsListModel(QWidget* parent, ViewFrame* view);
    virtual ~DebugThreadsListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
        { (void) parent; return (int)m_items.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 2; }
    ThreadItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugThread> newThreads, DebugThread lastActiveThread);
};


class DebugThreadsItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    DebugThreadsItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class DebugThreadsWidget: public QWidget
{
    Q_OBJECT

    ViewFrame* m_view;
    DbgRef<DebuggerController> m_controller;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;
    DebugThreadsListModel* m_model;
    DebugThreadsItemDelegate* m_delegate;

    // void shouldBeVisible()
//    virtual void notifyFontChanged() override;


public:
    DebugThreadsWidget(const QString& name, ViewFrame* view, BinaryViewRef data);

    void notifyThreadsChanged(std::vector<DebugThread> threads, DebugThread lastActiveThread);

    void updateContent();

private slots:
	void jump();
	void setAsActive();
};
