/*
Copyright 2020-2026 Vector 35 Inc.

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
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "globalarea.h"
#include "filter.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

class MemoryRegionItem
{
private:
	uint64_t m_start;
	size_t m_size;
	std::string m_name;
	bool m_read;
	bool m_write;
	bool m_execute;
	bool m_shared;

public:
	MemoryRegionItem(uint64_t start, size_t size, std::string name, bool read, bool write, bool execute, bool shared);
	uint64_t start() const { return m_start; }
	uint64_t endAddress() const { return m_start + m_size; }
	size_t size() const { return m_size; }
	std::string name() const { return m_name; }
	bool read() const { return m_read; }
	bool write() const { return m_write; }
	bool execute() const { return m_execute; }
	bool shared() const { return m_shared; }
	// A string like "r-xp" / "rw-s" describing the region's permissions and sharing.
	std::string permissions() const;
	bool operator==(const MemoryRegionItem& other) const;
	bool operator!=(const MemoryRegionItem& other) const;
	bool operator<(const MemoryRegionItem& other) const;
};

Q_DECLARE_METATYPE(MemoryRegionItem);


class DebugMemoryMapListModel : public QAbstractTableModel
{
	Q_OBJECT

protected:
	QWidget* m_owner;
	ViewFrame* m_view;
	std::vector<MemoryRegionItem> m_items;

public:
	enum ColumnHeaders
	{
		StartColumn,
		EndColumn,
		SizeColumn,
		PermissionsColumn,
		NameColumn,
	};

	DebugMemoryMapListModel(QWidget* parent, ViewFrame* view);
	virtual ~DebugMemoryMapListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return (int)m_items.size();
	}
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return 5;
	}
	MemoryRegionItem getRow(int row) const;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	void updateRows(std::vector<DebugMemoryRegion> newRegions);
};


class DebugMemoryMapItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
	DebugMemoryMapItemDelegate(QWidget* parent);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class DebugMemoryMapFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

public:
	DebugMemoryMapFilterProxyModel(QObject* parent);

protected:
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
};


class DebugMemoryMapWidget : public QTableView, public FilterTarget
{
	Q_OBJECT

	ViewFrame* m_view;
	DbgRef<DebuggerController> m_controller;

	DebugMemoryMapListModel* m_model;
	DebugMemoryMapItemDelegate* m_delegate;
	DebugMemoryMapFilterProxyModel* m_filter;

	size_t m_debuggerEventCallback;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu m_menu;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

	bool canCopy();
	bool canCopyAll();

	virtual void setFilter(const std::string& filter, FilterOptions options) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void ensureSelection() override;
	virtual void activateSelection() override;

	void updateContent();

public:
	DebugMemoryMapWidget(ViewFrame* view, BinaryViewRef data);
	~DebugMemoryMapWidget();

	void updateColumnWidths();
	void notifyRegionsChanged(std::vector<DebugMemoryRegion> regions);
	void updateFonts();

signals:
	void debuggerEvent(const DebuggerEvent& event);

private slots:
	void jumpToStart();
	void jumpToEnd();
	void copy();
	void copyAll();
	void onDoubleClicked();

public slots:
	void onDebuggerEvent(const DebuggerEvent& event);
	void showContextMenu();
};


class DebugMemoryMapWithFilter : public QWidget
{
	Q_OBJECT

	ViewFrame* m_view;
	DebugMemoryMapWidget* m_memoryMap;
	FilteredView* m_filter;
	FilterEdit* m_separateEdit = nullptr;

public:
	DebugMemoryMapWithFilter(ViewFrame* view, BinaryViewRef data);
	void updateFonts();
};


class DebugMemoryMapContainer : public SidebarWidget
{
	DebugMemoryMapWithFilter* m_widget;

public:
	DebugMemoryMapContainer(ViewFrame* frame, BinaryViewRef data);
	void notifyFontChanged() override;
};


class DebugMemoryMapSidebarWidgetType : public SidebarWidgetType
{
public:
	DebugMemoryMapSidebarWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
};
