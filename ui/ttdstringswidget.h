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

#include <QAbstractTableModel>
#include <QTableView>
#include <QSortFilterProxyModel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QSpinBox>
#include <QStyledItemDelegate>
#include <QContextMenuEvent>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"
#include "filter.h"
#include "fontsettings.h"
#include "theme.h"
#include "debuggeruicommon.h"
#include "menus.h"
#include "uitypes.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;


class TTDStringsListModel : public QAbstractTableModel
{
	Q_OBJECT

public:
	enum ColumnHeaders
	{
		IndexColumn = 0,
		StringColumn,
		AddressColumn,
		SizeColumn,
		FirstAccessColumn,
		LastAccessColumn,
		EncodingColumn,
	};

	TTDStringsListModel(QWidget* parent);
	virtual ~TTDStringsListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;

	void updateRows(const std::vector<TTDStringEntry>& entries);
	const TTDStringEntry& getRow(int row) const;

private:
	std::vector<TTDStringEntry> m_entries;
};


class TTDStringsFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

public:
	TTDStringsFilterProxyModel(QObject* parent);

protected:
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
};


class TTDStringsItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
	TTDStringsItemDelegate(QWidget* parent);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
};


class TTDStringsWidget : public QTableView, public FilterTarget
{
	Q_OBJECT

	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	TTDStringsListModel* m_model;
	TTDStringsItemDelegate* m_delegate;
	TTDStringsFilterProxyModel* m_filter;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

	bool canCopy();

	virtual void setFilter(const std::string& filter, FilterOptions options) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void ensureSelection() override;
	virtual void activateSelection() override;

public:
	TTDStringsWidget(BinaryViewRef data, QWidget* parent = nullptr);
	~TTDStringsWidget();

	void updateColumnWidths();
	void updateFonts();
	void performQuery(uint64_t maxResults);
	void clearResults();
	void showContextMenu();

signals:
	void statusUpdated(const QString& message);

private slots:
	void onDoubleClicked(const QModelIndex& index);
	void copy();
	void copySelectedRow();
	void copyEntireTable();
};


class TTDStringsWithFilter : public QWidget
{
	Q_OBJECT

	BinaryViewRef m_data;
	TTDStringsWidget* m_stringsWidget;
	FilteredView* m_filteredView;
	FilterEdit* m_separateEdit;
	QSpinBox* m_maxResultsSpinBox;
	QLabel* m_statusLabel;

public:
	TTDStringsWithFilter(BinaryViewRef data, QWidget* parent = nullptr);
	void updateFonts();
	void performQuery();
	void clearResults();
	void updateStatus(const QString& message);
};


class TTDStringsSidebarWidget : public SidebarWidget
{
	Q_OBJECT

private:
	TTDStringsWithFilter* m_widget;
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	size_t m_debuggerEventCallback;

public:
	TTDStringsSidebarWidget(BinaryViewRef data);
	~TTDStringsSidebarWidget();

signals:
	void debuggerEvent(const DebuggerEvent& event);

private slots:
	void onDebuggerEvent(const DebuggerEvent& event);
};


class TTDStringsWidgetType : public SidebarWidgetType
{
public:
	TTDStringsWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
};
