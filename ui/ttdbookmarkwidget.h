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

#include <QWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QMenu>
#include <QAction>
#include <QClipboard>
#include <QPoint>
#include <QContextMenuEvent>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "viewframe.h"
#include "debuggeruicommon.h"
#include "menus.h"
#include "uitypes.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;


class TTDBookmarkEditDialog : public QDialog
{
	Q_OBJECT

public:
	TTDBookmarkEditDialog(QWidget* parent, const QString& position = "", const QString& note = "",
		const QString& viewAddress = "");
	QString getPosition() const;
	QString getNote() const;
	QString getViewAddress() const;

private:
	QLineEdit* m_positionEdit;
	QLineEdit* m_noteEdit;
	QLineEdit* m_viewAddressEdit;
};


class TTDBookmarkWidget : public QWidget
{
	Q_OBJECT

public:
	enum LogicalColumn
	{
		IndexColumn = 0,
		PositionColumn,
		ViewAddressColumn,
		NoteColumn
	};

private:
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;

	QTableWidget* m_resultsTable;
	QLabel* m_statusLabel;
	QPushButton* m_addButton;

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu m_menu;

	std::vector<TTDBookmark> m_bookmarks;
	uint64_t m_pendingViewAddress = 0;

	void setupUI();
	void setupTable();
	void setupUIActions();
	void setupContextMenu();
	void updateStatus(const QString& message);
	bool canCopy();

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

public:
	TTDBookmarkWidget(QWidget* parent, BinaryViewRef data);
	virtual ~TTDBookmarkWidget();

	void loadBookmarksFromMetadata();
	void refreshTable();

	void addBookmark(const TTDPosition& position, const std::string& note = "", uint64_t viewAddress = 0);
	void removeBookmark(int index);
	void updateBookmark(int index, const TTDPosition& position, const std::string& note, uint64_t viewAddress);

	// Called on TargetStoppedEvent to navigate to the view address saved in the bookmark
	void navigateToPendingViewAddress();

private Q_SLOTS:
	void onCellDoubleClicked(int row, int column);
	void showContextMenu(const QPoint& position);
	void addBookmarkFromDialog();
	void addBookmarkFromCurrentPosition();
	void editSelectedBookmark();
	void removeSelectedBookmark();
	void copy();
	void copySelectedRow();
	void copyEntireTable();
};


class TTDBookmarkSidebarWidget : public SidebarWidget
{
	Q_OBJECT

private:
	TTDBookmarkWidget* m_bookmarkWidget;
	BinaryViewRef m_data;
	DbgRef<DebuggerController> m_controller;
	size_t m_debuggerEventCallback;

public:
	TTDBookmarkSidebarWidget(BinaryViewRef data);
	~TTDBookmarkSidebarWidget();

	TTDBookmarkWidget* getBookmarkWidget() { return m_bookmarkWidget; }

signals:
	void debuggerEvent(const DebuggerEvent& event);

private slots:
	void onDebuggerEvent(const DebuggerEvent& event);
};


class TTDBookmarkWidgetType : public SidebarWidgetType
{
public:
	TTDBookmarkWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightContent; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	SidebarIconVisibility defaultIconVisibility() const override { return HideSidebarIconIfNoContent; }
	SidebarContentClassifier* contentClassifier(ViewFrame*, BinaryViewRef) override;
};
