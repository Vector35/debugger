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
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "render.h"
//#include "globalarea.h"
#include "debuggerapi.h"


using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;


enum ColumnHeaders
{
	ExprColumn,
	ValueColumn,
	HintColumn,
};


struct DebuggerInfoEntry
{
	std::vector<InstructionTextToken> tokens;
	uint64_t value;
	std::string hints;
	size_t instrIndex;
	size_t operandIndex;
	uint64_t address;

	DebuggerInfoEntry(const std::vector<InstructionTextToken>& t, uint64_t v, const std::string& h, size_t i, size_t o,
					  uint64_t a): tokens(t), value(v), hints(h), instrIndex(i), operandIndex(o), address(a)
	{}
};


class DebuggerInfoEntryItemModel : public QAbstractTableModel
{
	std::vector<DebuggerInfoEntry> m_infoEntries;

	FileMetadataRef m_file;
	std::vector<BinaryViewRef> m_views;
	QSettings m_settings;

public:
	DebuggerInfoEntryItemModel(QWidget* parent, BinaryViewRef data);
	~DebuggerInfoEntryItemModel();

	virtual QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
	virtual QModelIndex parent(const QModelIndex& child) const override;

	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;

	virtual QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	void updateRows(std::vector<DebuggerInfoEntry>& newRows);
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	DebuggerInfoEntry getRow(int row) const;
};


class DebuggerInfoEntryItemDelegate : public QStyledItemDelegate
{
Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

	RenderContext m_render;

public:
	DebuggerInfoEntryItemDelegate(QWidget* parent = nullptr);

	void updateFonts();

	QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};


class DebuggerInfoTable : public QTableView
{
Q_OBJECT;

	DebuggerInfoEntryItemModel* m_model;
	DebuggerInfoEntryItemDelegate* m_itemDelegate;

	BinaryViewRef m_data;
	DebuggerControllerRef m_debugger;

	std::vector<DebuggerInfoEntry> getILInfoEntries(const ViewLocation& location);
	std::vector<DebuggerInfoEntry> getInfoForLLIL(LowLevelILFunctionRef llil, const LowLevelILInstruction& instr);
	std::vector<DebuggerInfoEntry> getInfoForLLILCalls(LowLevelILFunctionRef llil, const LowLevelILInstruction& instr);
	std::vector<DebuggerInfoEntry> getInfoForLLILConditions(LowLevelILFunctionRef llil, const LowLevelILInstruction& instr);

	std::vector<DebuggerInfoEntry> getInfoForMLIL(MediumLevelILFunctionRef mlil, const MediumLevelILInstruction& instr);
	std::vector<DebuggerInfoEntry> getInfoForMLILCalls(MediumLevelILFunctionRef mlil, const MediumLevelILInstruction& instr);
	std::vector<DebuggerInfoEntry> getInfoForMLILConditions(MediumLevelILFunctionRef mlil, const MediumLevelILInstruction& instr);

	std::vector<DebuggerInfoEntry> getInfoForHLIL(HighLevelILFunctionRef hlil, const HighLevelILInstruction& instr);
	std::vector<DebuggerInfoEntry> getInfoForHLILCalls(HighLevelILFunctionRef hlil, const HighLevelILInstruction& instr);
	std::vector<DebuggerInfoEntry> getInfoForHLILConditions(HighLevelILFunctionRef hlil, const HighLevelILInstruction& instr);

	void updateColumnWidths();

private slots:
	void onDoubleClicked();

public:
	DebuggerInfoTable(BinaryViewRef data);
	void updateFonts();

	void updateContents(const ViewLocation& location);
};


class DebugInfoSidebarWidget : public SidebarWidget
{
Q_OBJECT
	DebuggerInfoTable* m_entryList;

	QWidget* m_header;
	BinaryViewRef m_data;
	DebuggerControllerRef m_debugger;

//	virtual void contextMenuEvent(QContextMenuEvent*) override;

	virtual void notifyViewLocationChanged(View* /*view*/, const ViewLocation& /*viewLocation*/) override;

	void itemDoubleClicked(const QModelIndex& index);
	void scrollBarValueChanged(int value);
	void scrollBarRangeChanged(int min, int max);

	void resetToSelectedEntry(std::function<bool(size_t, size_t)> progress);

public:
	DebugInfoSidebarWidget(BinaryViewRef data);
	~DebugInfoSidebarWidget();
	void notifyFontChanged() override;
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
