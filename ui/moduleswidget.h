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
#include "globalarea.h"
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

    DebugModulesListModel(QWidget* parent, ViewFrame* view);
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


class DebugModulesFilterProxyModel : public QSortFilterProxyModel
{
Q_OBJECT

//	bool m_hideZeroRegister = false;
//	bool m_onlyShowFullWidthRegisters = false;
//	bool m_hideUnusedRegisters = true;

public:
	DebugModulesFilterProxyModel(QObject* parent);

protected:
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

public:
//	bool getHideUnusedRegisters() const { return m_hideUnusedRegisters; }
//	void toggleHideUnusedRegisters() { m_hideUnusedRegisters = !m_hideUnusedRegisters; invalidate(); }
};


class DebugModulesWidget: public QWidget, public FilterTarget
{
    Q_OBJECT

    ViewFrame* m_view;
    DbgRef<DebuggerController> m_controller;

    QTableView* m_table;
    DebugModulesListModel* m_model;
    DebugModulesItemDelegate* m_delegate;
	DebugModulesFilterProxyModel* m_filter;

	size_t m_debuggerEventCallback;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

	bool canCopy();

	virtual void setFilter(const std::string& filter) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;

public:
    DebugModulesWidget(ViewFrame* view, BinaryViewRef data);
	~DebugModulesWidget();

    void notifyModulesChanged(std::vector<DebugModule> modules);

private slots:
	void jumpToStart();
	void jumpToEnd();
	void copy();
	void onDoubleClicked();

public slots:
    void updateContent();
	void showContextMenu();
};


class DebugModulesWithFilter: public QWidget
{
Q_OBJECT

	ViewFrame* m_view;
	DebugModulesWidget* m_modules;
	FilteredView* m_filter;
	FilterEdit* m_separateEdit = nullptr;

public:
	DebugModulesWithFilter(ViewFrame* view, BinaryViewRef data);
	void updateContent();
};


class GlobalDebugModulesContainer : public GlobalAreaWidget
{
	ViewFrame *m_currentFrame;
	QHash<ViewFrame*, DebugModulesWithFilter*> m_widgetMap;

	QStackedWidget* m_consoleStack;

	//! Get the current active DebuggerConsole. Returns nullptr in the event of an error
	//! or if there is no active ChatBox.
	DebugModulesWithFilter* currentWidget() const;

	//! Delete the DebuggerConsole for the given view.
	void freeWidgetForView(QObject*);

public:
	GlobalDebugModulesContainer(const QString& title);

	void notifyViewChanged(ViewFrame *) override;
};
