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

#include <QPainter>
#include <QHeaderView>
#include <QGuiApplication>
#include <QMimeData>
#include <QClipboard>
#include "ui.h"
#include "debuggerinfowidget.h"
#include "lowlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


DebugInfoSidebarWidget::DebugInfoSidebarWidget(BinaryViewRef data): SidebarWidget("Debugger Info"), m_data(data)
{
	m_debugger = DebuggerController::GetController(data);
	auto* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);

	m_entryList = new DebuggerInfoTable(data);
	layout->addWidget(m_entryList);

	setLayout(layout);
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForLLIL(LowLevelILFunctionRef llil, const LowLevelILInstruction &instr)
{
	std::vector<DebuggerInfoEntry> result;
	auto func = llil->GetFunction();
	for (const auto operand: instr.GetOperands())
	{
		switch (operand.GetType())
		{
		case ExprLowLevelOperand:
		{
			uint64_t value;
			if (!m_debugger->ComputeExprValue(llil, operand.GetExpr(), value))
				continue;
			std::vector<InstructionTextToken> tokens;
			if (!llil->GetExprText(func->GetArchitecture(), operand.GetExpr().exprIndex, tokens))
				continue;
			auto hints = m_debugger->GetAddressInformation(value);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, operand.GetExpr().exprIndex, instr.address);
			break;
		}
		case RegisterLowLevelOperand:
		{
			auto reg = operand.GetRegister();
			auto name = func->GetArchitecture()->GetRegisterName(reg);
			auto value = m_debugger->GetRegisterValue(name);
			auto hints = m_debugger->GetAddressInformation(value);
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(RegisterToken, name);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		default:
			break;
		}
	}
	return result;
}


vector<DebuggerInfoEntry> DebuggerInfoTable::getILInfoEntries(const ViewLocation &location)
{
	vector<DebuggerInfoEntry> result;
	if (!m_debugger->IsConnected())
		return result;

//	auto info = QString::asprintf("View type: %s, offset: 0x%llx, il: %d", location.getViewType().toStdString().c_str(), location.getOffset(), location.getILViewType());
//	if (!m_debugger->IsConnected())
//		return info;
//
//	info += "\n\n";

	switch (location.getILViewType())
	{
	case NormalFunctionGraph:
	{
		auto func = location.getFunction();
		if (!func)
			break;
		auto addr = location.getOffset();
		auto llil = func->GetLowLevelILIfAvailable();
		if (!llil)
			break;
		auto llils = func->GetLowLevelILInstructionsForAddress(func->GetArchitecture(), addr);
		for (const auto index: llils)
		{
			auto instr = llil->GetInstruction(index);
			auto entries = getInfoForLLIL(llil, instr);
			result.insert(result.end(), entries.begin(), entries.end());
		}
		break;
	}
	case LowLevelILFunctionGraph:
	{
		auto func = location.getFunction();
		if (!func)
			break;
		auto llil = func->GetLowLevelILIfAvailable();
		if (!llil)
			break;
		if (location.getInstrIndex() == BN_INVALID_EXPR)
			break;
		auto instr = llil->GetInstruction(location.getInstrIndex());
		auto entries = getInfoForLLIL(llil, instr);
		result.insert(result.end(), entries.begin(), entries.end());
		break;
	}
	default:
		break;
	}

	return result;
}


void DebugInfoSidebarWidget::notifyViewLocationChanged(View* view, const ViewLocation& location)
{
	m_entryList->updateContents(location);
}


DebugInfoSidebarWidget::~DebugInfoSidebarWidget()
{

}


DebuggerInfoEntryItemDelegate::DebuggerInfoEntryItemDelegate(QWidget* parent): m_render(parent)
{

}


void DebuggerInfoEntryItemDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
										  const QModelIndex &index) const
{

}


DebuggerInfoEntryItemModel::DebuggerInfoEntryItemModel(QWidget *parent, BinaryViewRef data)
{

}


DebuggerInfoEntryItemModel::~DebuggerInfoEntryItemModel()
{

}


QModelIndex DebuggerInfoEntryItemModel::index(int row, int column, const QModelIndex &parent) const
{
	return {};
}


QModelIndex DebuggerInfoEntryItemModel::parent(const QModelIndex &child) const
{
	return {};
}


int DebuggerInfoEntryItemModel::rowCount(const QModelIndex &parent) const
{
	return 0;
}

int DebuggerInfoEntryItemModel::columnCount(const QModelIndex &parent) const
{
	return 3;
}


QVariant DebuggerInfoEntryItemModel::data(const QModelIndex &index, int role) const
{
	return {};
}


void DebuggerInfoEntryItemModel::updateRows(std::vector<DebuggerInfoEntry>& newRows)
{
	beginResetModel();
	m_infoEntries = newRows;
	endResetModel();
}


QVariant DebuggerInfoEntryItemModel::headerData(int column, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole)
		return QVariant();

	if (orientation == Qt::Vertical)
		return QVariant();

	switch (column)
	{
	case ExprColumn:
		return "Expr";
	case ValueColumn:
		return "Value";
	case HintColumn:
		return "Hint";
	}
	return QVariant();
}


DebuggerInfoTable::DebuggerInfoTable(BinaryViewRef data): m_data(data)
{
	m_debugger = DebuggerController::GetController(data);

	m_model = new DebuggerInfoEntryItemModel(this, data);
	m_itemDelegate = new DebuggerInfoEntryItemDelegate(this);

	setModel(m_model);
	setSelectionMode(QListView::SingleSelection);
	setSelectionBehavior(QListView::SelectRows);
	setEditTriggers(QListView::NoEditTriggers);
	setDragEnabled(false);
	setDragDropMode(QListView::NoDragDrop);
	setItemDelegate(m_itemDelegate);
}


void DebuggerInfoTable::updateContents(const ViewLocation &location)
{
	auto info = getILInfoEntries(location);
	m_model->updateRows(info);
}


//int Debugger

DebugInfoWidgetType::DebugInfoWidgetType():
	SidebarWidgetType(QIcon(":/debugger/debugger").pixmap(QSize(64, 64)).toImage(), "Debugger Info")
{
}


SidebarWidget* DebugInfoWidgetType::createWidget(ViewFrame*, BinaryViewRef data)
{
	return new DebugInfoSidebarWidget(data);
}
