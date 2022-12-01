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

#include <QDialog>
#include <QPushButton>
#include <QFormLayout>
#include <QAbstractItemModel>
#include <QItemSelectionModel>
#include <QModelIndex>
#include <QTableView>
#include <QHeaderView>
#include <QStyledItemDelegate>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "debuggerapi.h"
#include "ui.h"

class ProcessItem
{
private:
	uint32_t m_pid;
	std::string m_processName;

public:
	ProcessItem(uint32_t pid, std::string processName);
	uint32_t pid() const { return m_pid; }
	std::string processName() const { return m_processName; }
	bool operator==(const ProcessItem& other) const;
	bool operator!=(const ProcessItem& other) const;
	bool operator<(const ProcessItem& other) const;
};

Q_DECLARE_METATYPE(ProcessItem);

class DebugProcessListModel : public QAbstractTableModel
{
	Q_OBJECT

protected:
	QWidget* m_owner;
	std::vector<ProcessItem> m_items;

public:
	enum ColumnHeaders
	{
		PidColumn,
		ProcessNameColumn,
	};

	DebugProcessListModel(QWidget* parent);
	virtual ~DebugProcessListModel();

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
	ProcessItem getRow(int row) const;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	void updateRows(std::vector<DebugProcess> newModules);
};

class DebugProcessItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

public:
	DebugProcessItemDelegate(QWidget* parent);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};

class DebugProcessFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

public:
	DebugProcessFilterProxyModel(QObject* parent);

protected:
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

public:
	//
};

class DebugProcessWidget : public QWidget, public FilterTarget
{
	Q_OBJECT

	DebuggerController* m_controller;

	QTableView* m_table;
	DebugProcessListModel* m_model;
	DebugProcessItemDelegate* m_delegate;
	DebugProcessFilterProxyModel* m_filter;

	// size_t m_debuggerEventCallback;

	// UIActionHandler m_actionHandler;
	// ContextMenuManager* m_contextMenuManager;
	// Menu* m_menu;

	// virtual void contextMenuEvent(QContextMenuEvent* event) override;

	// bool canCopy();

	virtual void setFilter(const std::string& filter) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;

public:
	DebugProcessWidget(QWidget* parent, DebuggerController* controller);
	~DebugProcessWidget();

	QTableView* getProcessTableView() const { return m_table; }

	uint32_t getSelectedPid()
	{
		QModelIndexList sel = m_table->selectionModel()->selectedIndexes();
		if (sel.empty())
			return 0;

		auto sourceIndex = m_filter->mapToSource(sel[0]);
		if (!sourceIndex.isValid())
			return 0;

		auto item = m_model->getRow(sourceIndex.row());
		return item.pid();
	}

	void updateColumnWidths();
	void notifyModulesChanged(std::vector<DebugProcess> modules);

	// private slots:
	// void jumpToStart();
	// void jumpToEnd();
	// void copy();
	// void onDoubleClicked();

public slots:
	void updateContent();
	// void showContextMenu();
};


class AttachProcessDialog : public QDialog
{
	Q_OBJECT

private:
	DebuggerController* m_controller;
	ViewFrame* m_view;
	DebugProcessWidget* m_processes;
	FilteredView* m_filter;
	FilterEdit* m_separateEdit;
	uint32_t m_pid {};


public:
	AttachProcessDialog(QWidget* parent, DebuggerController* controller);
	uint32_t GetSelectedPid();

private Q_SLOTS:
	void apply();
};
