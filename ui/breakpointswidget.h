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

class BreakpointItem
{
private:
	// TODO: this field actually means whether the breakpoint is active in the target. E.g., when the target is not
	// running, it will be false. However, we do need to support disable/enable breakpoints while the target is running
	bool m_enabled;
	ModuleNameAndOffset m_location;
	uint64_t m_address;

public:
	BreakpointItem(bool enabled, const ModuleNameAndOffset location, uint64_t remoteAddress);
	bool enabled() const { return m_enabled; }
	ModuleNameAndOffset location() const { return m_location; }
	uint64_t address() const { return m_address; }
	bool operator==(const BreakpointItem& other) const;
	bool operator!=(const BreakpointItem& other) const;
	bool operator<(const BreakpointItem& other) const;
};

Q_DECLARE_METATYPE(BreakpointItem);


class DebugBreakpointsListModel : public QAbstractTableModel
{
	Q_OBJECT

protected:
	QWidget* m_owner;
	ViewFrame* m_view;
	std::vector<BreakpointItem> m_items;

public:
	enum ColumnHeaders
	{
		//EnabledColumn,
		LocationColumn,
		AddressColumn,
	};

	DebugBreakpointsListModel(QWidget* parent, ViewFrame* view);
	virtual ~DebugBreakpointsListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return (int)m_items.size();
	}
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return 2;
	}
	BreakpointItem getRow(int row) const;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	void updateRows(std::vector<BreakpointItem> newRows);
};


class DebugBreakpointsItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
	DebugBreakpointsItemDelegate(QWidget* parent);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class DebugBreakpointsWidget : public QWidget
{
	Q_OBJECT

	ViewFrame* m_view;
	DbgRef<DebuggerController> m_controller;

	QTableView* m_table;
	DebugBreakpointsListModel* m_model;
	DebugBreakpointsItemDelegate* m_delegate;

	QPoint m_last_selected_point {};
	QHeaderView* m_horizontal_header;
	QHeaderView* m_vertical_header;
	QAction* m_remove_action;
	QAction* m_jump_action;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	bool selectionNotEmpty();

	//void shouldBeVisible()
	//virtual void notifyFontChanged() override;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

public:
	DebugBreakpointsWidget(ViewFrame* view, BinaryViewRef data, Menu* menu);
	~DebugBreakpointsWidget();

	void uiEventHandler(const DebuggerEvent& event);

private slots:
	void jump();
	void remove();
	void onDoubleClicked();

public slots:
	void updateContent();
};


class DebuggerUI;
class BreakpointSideBarWidget : public SidebarWidget
{
	Q_OBJECT;

	ViewFrame* m_view;

	DebugBreakpointsWidget* m_breakpointsWidget;

	DebuggerUI* m_ui;

	virtual void notifyFontChanged() override;

private slots:
	void uiEventHandler(const DebuggerEvent& event);

public:
	BreakpointSideBarWidget(const QString& name, ViewFrame* view, BinaryViewRef data);
	~BreakpointSideBarWidget();

	void updateContent();
};


// class BreakpointWidgetType : public SidebarWidgetType {
// public:
//	BreakpointWidgetType(const QImage& icon, const QString& name) : SidebarWidgetType(icon, name) { }
//
//	bool isInReferenceArea() const override { return false; }
//
//	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override {
//		return new BreakpointSideBarWidget("Breakpoint", frame, data);
//	}
// };