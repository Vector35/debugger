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
#include <QSortFilterProxyModel>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "debuggerapi.h"
#include "menus.h"
#include "filter.h"
#include "uitypes.h"

using namespace BinaryNinjaDebuggerAPI;


enum DebugRegisterValueStatus
{
	DebugRegisterValueNormal,
	// The current value is different from the last value
	DebugRegisterValueChanged,
	// The value has been modified by the user
	DebugRegisterValueModified
};


class DebugRegisterItem
{
private:
	std::string m_name;
	uint64_t m_value;
	DebugRegisterValueStatus m_valueStatus;
	// TODO: We probably need a more robust mechanism for this
	std::string m_hint;
	bool m_used;

public:
	DebugRegisterItem(const std::string& name, uint64_t value,
		DebugRegisterValueStatus valueStatus = DebugRegisterValueNormal, const std::string& hint = "",
		bool used = false);
	std::string name() const { return m_name; }
	uint64_t value() const { return m_value; }
	bool used() const { return m_used; }
	void setValue(uint64_t value) { m_value = value; }
	DebugRegisterValueStatus valueStatus() const { return m_valueStatus; }
	void setValueStatus(DebugRegisterValueStatus newStatus) { m_valueStatus = newStatus; }
	std::string hint() const { return m_hint; }
	bool operator==(const DebugRegisterItem& other) const;
	bool operator!=(const DebugRegisterItem& other) const;
	bool operator<(const DebugRegisterItem& other) const;
};

Q_DECLARE_METATYPE(DebugRegisterItem);


class DebugRegistersListModel : public QAbstractTableModel
{
	Q_OBJECT

protected:
	QWidget* m_owner;
	DbgRef<DebuggerController> m_controller;
	ViewFrame* m_view;
	std::vector<DebugRegisterItem> m_items;

public:
	enum ColumnHeaders
	{
		NameColumn,
		ValueColumn,
		HintColumn,
	};

	DebugRegistersListModel(QWidget* parent, DebuggerControllerRef m_controller, ViewFrame* view);
	virtual ~DebugRegistersListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual Qt::ItemFlags flags(const QModelIndex& index) const override;

	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return (int)m_items.size();
	}
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return 3;
	}
	DebugRegisterItem getRow(int row) const;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	void updateRows(std::vector<DebugRegister> newRows);
	bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

	std::set<std::string> getUsedRegisterNames();
};


class DebugRegistersItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
	DebugRegistersItemDelegate(QWidget* parent);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	void setEditorData(QWidget* editor, const QModelIndex& index) const;
};


class DebugRegisterFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

	bool m_hideZeroRegister = false;
	bool m_onlyShowFullWidthRegisters = false;
	bool m_hideUnusedRegisters = true;

public:
	DebugRegisterFilterProxyModel(QObject* parent);

protected:
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

public:
	bool getHideUnusedRegisters() const { return m_hideUnusedRegisters; }
	void toggleHideUnusedRegisters();
};


class DebugRegistersWidget : public QWidget, public FilterTarget
{
	Q_OBJECT;

	ViewFrame* m_view;
	DbgRef<DebuggerController> m_controller;

	QTableView* m_table;
	DebugRegistersListModel* m_model;
	DebugRegistersItemDelegate* m_delegate;
	DebugRegisterFilterProxyModel* m_filter;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

	bool selectionNotEmpty();
	bool canPaste();

	virtual void setFilter(const std::string& filter) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;

public:
	DebugRegistersWidget(ViewFrame* view, BinaryViewRef data, Menu* menu);
	void notifyRegistersChanged(std::vector<DebugRegister> regs);

private slots:
	void setToZero();
	void jump();
	void copy();
	void paste();
	void editValue();
	void onDoubleClicked();

public slots:
	void updateContent();
	void showContextMenu();
};


class DebugRegistersContainer : public QWidget
{
	Q_OBJECT

	ViewFrame* m_view;
	DebugRegistersWidget* m_register;
	FilteredView* m_filter;
	FilterEdit* m_separateEdit = nullptr;

public:
	DebugRegistersContainer(ViewFrame* view, BinaryViewRef data, Menu* menu);
	void updateContent();
};
