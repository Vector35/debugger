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
using namespace BinaryNinja;
using namespace std;

class ModuleItem
{
private:
    uint64_t m_address;
    size_t m_size;
    std::string m_name;
    std::string m_path;

public:
    ModuleItem(uint64_t address, size_t size, std::string name, std::string path);
    uint64_t address() const { return m_address; }
    size_t size() const { return m_size; }
    std::string name() const { return m_name; }
    std::string path() const { return m_path; }
    bool operator==(const ModuleItem& other) const;
    bool operator!=(const ModuleItem& other) const;
    bool operator<(const ModuleItem& other) const;
};

Q_DECLARE_METATYPE(ModuleItem);


class DebugModulesListModel: public QAbstractTableModel
{
    Q_OBJECT

protected:
    QWidget* m_owner;
    BinaryViewRef m_data;
    ViewFrame* m_view;
    std::vector<ModuleItem> m_items;

public:
    enum ColumnHeaders
    {
        AddressColumn,
        SizeColumn,
        NameColumn,
        PathColumn,
    };

    DebugModulesListModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
    virtual ~DebugModulesListModel();

    virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

    virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
        { (void) parent; return (int)m_items.size(); }
    virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 4; }
    ModuleItem getRow(int row) const;
    virtual QVariant data(const QModelIndex& i, int role) const override;
    virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
    void updateRows(std::vector<DebugModule> newModules);
};


class DebugModulesItemDelegate: public QStyledItemDelegate
{
    Q_OBJECT

    QFont m_font;
    int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
    DebugModulesItemDelegate(QWidget* parent);
    void updateFonts();
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class DebugModulesWidget: public SidebarWidget
{
    Q_OBJECT

    ViewFrame* m_view;
    DebuggerController* m_controller;

    UIActionHandler* M_actionHandler;
    QTableView* m_table;
    DebugModulesListModel* m_model;
    DebugModulesItemDelegate* m_delegate;

    // void shouldBeVisible()
    virtual void notifyFontChanged() override;


public:
    DebugModulesWidget(const QString& name, ViewFrame* view, BinaryViewRef data);

    void notifyModulesChanged(std::vector<DebugModule> modules);

public slots:
    void updateContent();
};


class DebugModulesWidgetType : public SidebarWidgetType {
public:
    DebugModulesWidgetType(const QImage& icon, const QString& name) : SidebarWidgetType(icon, name) { }

    bool isInReferenceArea() const override { return false; }

    SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override {
        return new DebugModulesWidget("Debugger Modules", frame, data);
    }
};
