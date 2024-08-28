/*
Copyright 2020-2024 Vector 35 Inc.

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
//#include "globalarea.h"
#include "debuggerapi.h"


using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;



class BINARYNINJAUIAPI DebugInfoSidebarWidget : public SidebarWidget
{
Q_OBJECT
	QListView* m_entryList;
//	HistoryEntryItemModel* m_model;
//	HistoryEntryItemDelegate* m_itemDelegate;

	QWidget* m_header;
	BinaryViewRef m_data;
	DebuggerControllerRef m_debugger;

	QLabel* m_label;

	bool m_updating = false;
	bool m_atBottom = true;

//	virtual void contextMenuEvent(QContextMenuEvent*) override;

	virtual void notifyViewLocationChanged(View* /*view*/, const ViewLocation& /*viewLocation*/) override;

	void itemDoubleClicked(const QModelIndex& index);
	void scrollBarValueChanged(int value);
	void scrollBarRangeChanged(int min, int max);

	void resetToSelectedEntry(std::function<bool(size_t, size_t)> progress);

public:
	DebugInfoSidebarWidget(BinaryViewRef data);
	~DebugInfoSidebarWidget();
//	void notifyFontChanged() override;
//	QWidget* headerWidget() override { return m_header; }
};


class DebugInfoWidgetType : public SidebarWidgetType
{
public:
	DebugInfoWidgetType();
	SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
//	bool hideIfNoContent() const override { return true; }
};
