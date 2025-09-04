/*
Copyright 2020-2025 Vector 35 Inc.

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
#include <QDateTime>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;

class BookmarkItem
{
private:
	std::string m_description;
	std::string m_ttdPosition;  // TTD position string (e.g., from !tt command)
	uint64_t m_address;         // View address when bookmark was created
	QDateTime m_timestamp;      // When bookmark was created

public:
	BookmarkItem(const std::string& description, const std::string& ttdPosition, uint64_t address, const QDateTime& timestamp = QDateTime::currentDateTime());
	std::string description() const { return m_description; }
	std::string ttdPosition() const { return m_ttdPosition; }
	uint64_t address() const { return m_address; }
	QDateTime timestamp() const { return m_timestamp; }
	void setDescription(const std::string& description) { m_description = description; }
	bool operator==(const BookmarkItem& other) const;
	bool operator!=(const BookmarkItem& other) const;
	bool operator<(const BookmarkItem& other) const;
};

Q_DECLARE_METATYPE(BookmarkItem);


class DebugBookmarksListModel : public QAbstractTableModel
{
	Q_OBJECT

protected:
	QWidget* m_owner;
	ViewFrame* m_view;
	std::vector<BookmarkItem> m_items;

public:
	enum ColumnHeaders
	{
		DescriptionColumn,
		PositionColumn,
		AddressColumn,
		TimestampColumn,
	};

	DebugBookmarksListModel(QWidget* parent, ViewFrame* view);
	virtual ~DebugBookmarksListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return (int)m_items.size();
	}
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return 4;
	}
	BookmarkItem getRow(int row) const;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	void updateRows(std::vector<BookmarkItem> newRows);
	void addBookmark(const BookmarkItem& bookmark);
	void removeBookmark(int row);
	const std::vector<BookmarkItem>& getItems() const { return m_items; }
};


class DebugBookmarksItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
	DebugBookmarksItemDelegate(QWidget* parent);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};


class DebugBookmarksWidget : public QTableView
{
	Q_OBJECT

	ViewFrame* m_view;
	DbgRef<DebuggerController> m_controller;

	DebugBookmarksListModel* m_model;
	DebugBookmarksItemDelegate* m_delegate;

	QPoint m_last_selected_point {};
	QHeaderView* m_horizontal_header;
	QHeaderView* m_vertical_header;
	QAction* m_remove_action;
	QAction* m_jump_action;
	QAction* m_add_action;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	bool selectionNotEmpty();
	std::string getCurrentTTDPosition();

	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void showEvent(QShowEvent* event) override;

public:
	DebugBookmarksWidget(ViewFrame* view, BinaryViewRef data, Menu* menu);
	~DebugBookmarksWidget();

	void uiEventHandler(const DebuggerEvent& event);
	void updateFonts();
	void saveBookmarks();
	void loadBookmarks();

private slots:
	void jump();
	void remove();
	void onDoubleClicked();
	void add();

public slots:
	void updateContent();
};


class DebuggerUI;