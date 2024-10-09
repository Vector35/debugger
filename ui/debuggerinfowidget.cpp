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


void DebugInfoSidebarWidget::notifyFontChanged()
{
	m_entryList->updateFonts();
}


DebuggerInfoEntryItemDelegate::DebuggerInfoEntryItemDelegate(QWidget* parent): m_render(parent)
{
	updateFonts();
}


void DebuggerInfoEntryItemDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option,
										  const QModelIndex &index) const
{
	// Draw the item background, highlighting it if selected.
	bool selected = (option.state & QStyle::State_Selected) != 0;
	if (selected)
		painter->setBrush(getThemeColor(SelectionColor));
	else
		painter->setBrush(option.backgroundBrush);

	auto* entry = qvariant_cast<DebuggerInfoEntry*>(index.data(Qt::DisplayRole));
	if (!entry)
	{
		QStyledItemDelegate::paint(painter, option, index);
		return;
	}

	painter->setPen(Qt::NoPen);
	painter->drawRect(option.rect);

	painter->setPen(option.palette.text().color());
	painter->setFont(m_font);

	QRect textRect = option.rect;
//	textRect.setLeft(textRect.left() + 8);

	switch (index.column())
	{
	case ExprColumn:
	{
		HighlightTokenState highlight;
		m_render.drawDisassemblyLine(*painter, textRect.left(), textRect.top(), entry->tokens, highlight);
		break;
	}
	case ValueColumn:
		painter->setPen(getThemeColor(AddressColor));
		painter->drawText(textRect, "0x" + QString::number(entry->value, 16));
		break;
	case HintColumn:
		painter->setPen(getThemeColor(StringColor));
		painter->drawText(textRect, QString::fromStdString(entry->hints));
		break;
	default:
		break;
	}

}


void DebuggerInfoEntryItemDelegate::updateFonts()
{
	// Get font and compute character sizes
	m_font = getMonospaceFont(dynamic_cast<QWidget*>(parent()));
	m_font.setKerning(false);
	m_baseline = (int)QFontMetricsF(m_font).ascent();
	m_charWidth = getFontWidthAndAdjustSpacing(m_font);
	m_charHeight = (int)(QFontMetricsF(m_font).height() + getExtraFontSpacing());
	m_charOffset = getFontVerticalOffset();
}


QSize DebuggerInfoEntryItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const
{
	auto totalWidth = (idx.data(Qt::SizeHintRole).toInt() + 2) * m_charWidth + 4;
	return QSize(totalWidth, m_charHeight + 2);
}


DebuggerInfoEntryItemModel::DebuggerInfoEntryItemModel(QWidget *parent, BinaryViewRef data)
{

}


DebuggerInfoEntryItemModel::~DebuggerInfoEntryItemModel()
{

}


QModelIndex DebuggerInfoEntryItemModel::index(int row, int column, const QModelIndex &parent) const
{
	if (row < 0 || (size_t)row >= m_infoEntries.size() || column >= columnCount())
	{
		return QModelIndex();
	}

	return createIndex(row, column, (void*)&m_infoEntries[row]);
}


QModelIndex DebuggerInfoEntryItemModel::parent(const QModelIndex &child) const
{
	return {};
}


int DebuggerInfoEntryItemModel::rowCount(const QModelIndex &parent) const
{
	return m_infoEntries.size();
}


int DebuggerInfoEntryItemModel::columnCount(const QModelIndex &parent) const
{
	return 3;
}


QVariant DebuggerInfoEntryItemModel::data(const QModelIndex &index, int role) const
{
	if (index.column() >= columnCount() || (size_t)index.row() >= m_infoEntries.size())
		return QVariant();

	DebuggerInfoEntry* item = static_cast<DebuggerInfoEntry*>(index.internalPointer());
	if (!item)
		return QVariant();

	QVariant result;
	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case ExprColumn:
		case ValueColumn:
		case HintColumn:
			result.setValue(item);
			break;
		default:
			break;
		}
	}
	else if (role == Qt::SizeHintRole)
	{
		switch (index.column())
		{
		case ExprColumn:
		{
			std::string expr;
			for (const auto& token: item->tokens)
				expr += token.text;

			result.setValue(expr.size());
			break;
		}
		case ValueColumn:
		{
			auto str = "0x" + QString::number(item->value, 16);
			result.setValue(str.size());
			break;
		}
		case HintColumn:
			result.setValue(item->hints.size());
			break;
		default:
			break;
		}
	}

	return result;
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

	horizontalHeader()->setStretchLastSection(true);
}


void DebuggerInfoTable::updateContents(const ViewLocation &location)
{
	auto info = getILInfoEntries(location);
	m_model->updateRows(info);
	updateColumnWidths();
}


void DebuggerInfoTable::updateColumnWidths()
{
	resizeColumnToContents(ExprColumn);
	resizeColumnToContents(ValueColumn);
	resizeColumnToContents(HintColumn);
}


void DebuggerInfoTable::updateFonts()
{
	m_itemDelegate->updateFonts();
}


DebugInfoWidgetType::DebugInfoWidgetType():
	SidebarWidgetType(QIcon(":/debugger/debugger").pixmap(QSize(64, 64)).toImage(), "Debugger Info")
{
}


SidebarWidget* DebugInfoWidgetType::createWidget(ViewFrame*, BinaryViewRef data)
{
	return new DebugInfoSidebarWidget(data);
}
