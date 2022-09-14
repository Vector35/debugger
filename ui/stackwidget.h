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

enum DebugStackValueStatus
{
    DebugStackValueNormal,
    // The current value is different from the last value
    DebugStackValueChanged,
    // The value has been modified by the user
    DebugStackValueModified
};


class DebugStackItem
{
private:
    ptrdiff_t m_offset;
    uint64_t m_address;
    uint64_t m_value;
    std::string m_hint;
    // TODO: add references later
    DebugStackValueStatus m_valueStatus;

public:
    DebugStackItem(ptrdiff_t offset, uint64_t address, uint64_t value, std::string hint,
        DebugStackValueStatus valueStatus = DebugStackValueNormal);
    ptrdiff_t offset() const { return m_offset; }
    uint64_t address() const { return m_address; }
    uint64_t value() const { return m_value; }
    std::string hint() const { return m_hint; }
    void setValue(uint64_t value) { m_value = value; }
    DebugStackValueStatus valueStatus() const { return m_valueStatus; }
    void setValueStatus(DebugStackValueStatus newStatus) { m_valueStatus = newStatus; }
    bool operator==(const DebugStackItem& other) const;
    bool operator!=(const DebugStackItem& other) const;
    bool operator<(const DebugStackItem& other) const;
};

Q_DECLARE_METATYPE(DebugStackItem);


class DebugStackListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    DbgRef<DebuggerController> m_controller;
    ViewFrame* m_view;
    std::vector<DebugStackItem> m_items;

public:
    enum ColumnHeaders
    {
        OffsetColumn,
        AddressColumn,
        ValueColumn,
        HintColumn
    };

    DebugStackListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
    virtual ~DebugStackListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
        { (void) parent; return (int)m_items.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 4; }
    DebugStackItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugStackItem> newRows);
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;
};


class DebugStackItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    DebugStackItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    void setEditorData(QWidget *editor, const QModelIndex &index) const;
};


class DebugStackWidget: public QWidget
{
    Q_OBJECT;

    ViewFrame* m_view;
    DbgRef<DebuggerController> m_controller;

    QTableView* m_table;
    DebugStackListModel* m_model;
    DebugStackItemDelegate* m_delegate;

    // void shouldBeVisible()

//    virtual void notifyFontChanged() override;


public:
    DebugStackWidget(const QString& name, ViewFrame* view, BinaryViewRef data);
    void notifyStackChanged(std::vector<DebugStackItem> stackItems);

public slots:
    void updateContent();
};
