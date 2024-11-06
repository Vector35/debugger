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
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "binaryninjaapi.h"

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


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForLLILCalls(LowLevelILFunctionRef llil,
	const LowLevelILInstruction &instr)
{
	std::vector<DebuggerInfoEntry> result;
	if (instr.operation != LLIL_CALL && instr.operation != LLIL_TAILCALL)
		return result;

	auto dest = instr.GetDestExpr();
	if (dest.operation != LLIL_CONST_PTR && dest.operation != LLIL_CONST)
		return result;

	auto callTarget = dest.GetConstant();
	auto functions = m_data->GetAnalysisFunctionsForAddress(callTarget);
	if (functions.empty())
		return result;

	auto func = functions[0];
	if (!func)
		return result;

	auto arch = func->GetArchitecture();
	if (!arch)
		return result;

	for (const auto& param: func->GetParameterVariables().GetValue())
	{
		switch (param.type)
		{
		case RegisterVariableSourceType:
		{
			auto paramName = func->GetVariableName(param);
			auto reg = param.storage;
			auto regName = arch->GetRegisterName(reg);
			auto value = m_debugger->GetRegisterValue(regName);
			auto hints = m_debugger->GetAddressInformation(value);
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(LocalVariableToken, paramName);
			tokens.emplace_back(TextToken, " @ ");
			tokens.emplace_back(RegisterToken, regName);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case StackVariableSourceType:
		{
			auto offset = param.storage;
			// Account for the return address on the stack for x64/x86_64, not sure if we should do it for other arch
			offset -= arch->GetAddressSize();
			auto realOffset = offset + m_debugger->StackPointer();

			BinaryReader reader(m_data);
			reader.Seek(realOffset);
			auto value = reader.ReadPointer();
			auto hints = m_debugger->GetAddressInformation(value);

			auto paramName = func->GetVariableName(param);
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(LocalVariableToken, paramName);
			tokens.emplace_back(TextToken, " @ ");

			auto stackReg = arch->GetStackPointerRegister();
			auto stackRegName = arch->GetRegisterName(stackReg);
			tokens.emplace_back(RegisterToken, stackRegName);
			if (offset != 0)
			{
				tokens.emplace_back(TextToken, " + ");
				char buf[64] = {0};
				snprintf(buf, sizeof(buf), "%#llx", offset);
				tokens.emplace_back(IntegerToken, buf, offset);
			}
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case FlagVariableSourceType:
			break;
		}
	}

	return result;
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForLLILConditions(LowLevelILFunctionRef llil,
	const LowLevelILInstruction &instr)
{
	std::vector<DebuggerInfoEntry> result;
	if (instr.operation != LLIL_IF)
		return result;

	auto func = llil->GetFunction();
	auto condition = instr.GetConditionExpr<LLIL_IF>();
	uint64_t value;
	if (!m_debugger->ComputeExprValue(llil, condition, value))
		return result;

	// The value of a conditional expression must be 0 or 1 if it can be evaluated
	if ((value != 1) && (value != 0))
		return result;

	std::vector<InstructionTextToken> tokens;
	if (!llil->GetExprText(func->GetArchitecture(), condition.exprIndex, tokens))
		return result;

	auto trueBranch = instr.GetTrueTarget<LLIL_IF>();
	auto falseBranch = instr.GetFalseTarget<LLIL_IF>();
	auto targetIL = value == 1 ? trueBranch : falseBranch;
	auto il = llil->GetInstruction(targetIL);
	auto targetAddr = il.address;

	string hints = fmt::format("Branch to {} @ {:#x}", targetIL, targetAddr);
	result.emplace_back(tokens, value, hints, instr.instructionIndex, instr.exprIndex, instr.address);
	return result;
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
			if (LLIL_REG_IS_TEMP(reg))
				break;
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

	// Display the info of the function arguments if the current LLIL is a call instruction
	auto lines = getInfoForLLILCalls(llil, instr);
	if (!lines.empty())
		result.insert(result.end(), lines.begin(), lines.end());

	// Display the info of the conditional expressions
	lines = getInfoForLLILConditions(llil, instr);
	if (!lines.empty())
		result.insert(result.end(), lines.begin(), lines.end());

	return result;
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForMLIL(MediumLevelILFunctionRef mlil,
	const MediumLevelILInstruction& instr)
{
	std::vector<DebuggerInfoEntry> result;
	auto func = mlil->GetFunction();
	for (const auto operand: instr.GetOperands())
	{
		switch (operand.GetType())
		{
		case ExprMediumLevelOperand:
		{
			uint64_t value;
			if (!m_debugger->ComputeExprValue(mlil, operand.GetExpr(), value))
				continue;
			std::vector<InstructionTextToken> tokens;
			if (!mlil->GetExprText(func->GetArchitecture(), operand.GetExpr().exprIndex, tokens))
				continue;
			auto hints = m_debugger->GetAddressInformation(value);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, operand.GetExpr().exprIndex, instr.address);
			break;
		}
		case VariableMediumLevelOperand:
		{
			uint64_t value;
			auto var = operand.GetVariable();
			if (!m_debugger->GetVariableValue(var, instr.address, instr.size, value))
				break;
			auto hints = m_debugger->GetAddressInformation(value);
			std::vector<InstructionTextToken> tokens;
			auto name = func->GetVariableName(var);
			tokens.emplace_back(LocalVariableToken, name);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		default:
			break;
		}
	}

	// Display the info of the function arguments if the current MLIL is a call instruction
	auto lines = getInfoForMLILCalls(mlil, instr);
	if (!lines.empty())
		result.insert(result.end(), lines.begin(), lines.end());

	// Display the info of the conditional expressions
	lines = getInfoForMLILConditions(mlil, instr);
	if (!lines.empty())
		result.insert(result.end(), lines.begin(), lines.end());

	return result;
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForMLILCalls(MediumLevelILFunctionRef mlil,
	const MediumLevelILInstruction &instr)
{
	std::vector<DebuggerInfoEntry> result;
	if (instr.operation != MLIL_CALL && instr.operation != MLIL_TAILCALL)
		return result;

	auto dest = instr.GetDestExpr();
	if (dest.operation != MLIL_CONST_PTR && dest.operation != MLIL_CONST)
		return result;

	auto callTarget = dest.GetConstant();
	auto functions = m_data->GetAnalysisFunctionsForAddress(callTarget);
	if (functions.empty())
		return result;

	auto func = functions[0];
	if (!func)
		return result;

	auto arch = func->GetArchitecture();
	if (!arch)
		return result;

	for (const auto& param: func->GetParameterVariables().GetValue())
	{
		switch (param.type)
		{
		case RegisterVariableSourceType:
		{
			auto paramName = func->GetVariableName(param);
			auto reg = param.storage;
			auto regName = arch->GetRegisterName(reg);
			auto value = m_debugger->GetRegisterValue(regName);
			auto hints = m_debugger->GetAddressInformation(value);
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(LocalVariableToken, paramName);
			tokens.emplace_back(TextToken, " @ ");
			tokens.emplace_back(RegisterToken, regName);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case StackVariableSourceType:
		{
			auto offset = param.storage;
			// Account for the return address on the stack for x64/x86_64, not sure if we should do it for other arch
			offset -= arch->GetAddressSize();
			auto realOffset = offset + m_debugger->StackPointer();

			BinaryReader reader(m_data);
			reader.Seek(realOffset);
			auto value = reader.ReadPointer();
			auto hints = m_debugger->GetAddressInformation(value);

			auto paramName = func->GetVariableName(param);
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(LocalVariableToken, paramName);
			tokens.emplace_back(TextToken, " @ ");

			auto stackReg = arch->GetStackPointerRegister();
			auto stackRegName = arch->GetRegisterName(stackReg);
			tokens.emplace_back(RegisterToken, stackRegName);
			if (offset != 0)
			{
				tokens.emplace_back(TextToken, " + ");
				char buf[64] = {0};
				snprintf(buf, sizeof(buf), "%#llx", offset);
				tokens.emplace_back(IntegerToken, buf, offset);
			}
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case FlagVariableSourceType:
			break;
		}
	}

	return result;
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForMLILConditions(MediumLevelILFunctionRef mlil,
	const MediumLevelILInstruction &instr)
{
	std::vector<DebuggerInfoEntry> result;
	if (instr.operation != MLIL_IF)
		return result;

	auto func = mlil->GetFunction();
	auto condition = instr.GetConditionExpr<MLIL_IF>();
	uint64_t value;
	if (!m_debugger->ComputeExprValue(mlil, condition, value))
		return result;

	// The value of a conditional expression must be 0 or 1 if it can be evaluated
	if ((value != 1) && (value != 0))
		return result;

	std::vector<InstructionTextToken> tokens;
	if (!mlil->GetExprText(func->GetArchitecture(), condition.exprIndex, tokens))
		return result;

	auto trueBranch = instr.GetTrueTarget<MLIL_IF>();
	auto falseBranch = instr.GetFalseTarget<MLIL_IF>();
	auto targetIL = value == 1 ? trueBranch : falseBranch;
	auto il = mlil->GetInstruction(targetIL);
	auto targetAddr = il.address;

	string hints = fmt::format("Branch to {} @ {:#x}", targetIL, targetAddr);
	result.emplace_back(tokens, value, hints, instr.instructionIndex, instr.exprIndex, instr.address);
	return result;
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForHLIL(HighLevelILFunctionRef hlil,
	const HighLevelILInstruction& instr)
{
	std::vector<DebuggerInfoEntry> result;
	auto func = hlil->GetFunction();
	for (const auto operand: instr.GetOperands())
	{
		switch (operand.GetType())
		{
		case ExprHighLevelOperand:
		{
			uint64_t value;
			if (!m_debugger->ComputeExprValue(hlil, operand.GetExpr(), value))
				continue;
			std::vector<DisassemblyTextLine> lines = hlil->GetExprText(operand.GetExpr().exprIndex);
			if (lines.empty())
				continue;
			std::vector<InstructionTextToken> tokens;
			for (const auto& line: lines)
				tokens.insert(tokens.end(), line.tokens.begin(), line.tokens.end());
			if (tokens.empty())
				continue;

			auto hints = m_debugger->GetAddressInformation(value);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, operand.GetExpr().exprIndex, instr.address);
			break;
		}
		case VariableHighLevelOperand:
		{
			uint64_t value;
			auto var = operand.GetVariable();
			if (!m_debugger->GetVariableValue(var, instr.address, instr.size, value))
				break;
			auto hints = m_debugger->GetAddressInformation(value);
			std::vector<InstructionTextToken> tokens;
			auto name = func->GetVariableName(var);
			tokens.emplace_back(LocalVariableToken, name);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		default:
			break;
		}
	}

	// Display the info of the function arguments if the current HLIL is a call instruction
	auto lines = getInfoForHLILCalls(hlil, instr);
	if (!lines.empty())
		result.insert(result.end(), lines.begin(), lines.end());

	// Display the info of the conditional expressions
	lines = getInfoForHLILConditions(hlil, instr);
	if (!lines.empty())
		result.insert(result.end(), lines.begin(), lines.end());

	return result;
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForHLILCalls(HighLevelILFunctionRef hlil,
	const HighLevelILInstruction &instr)
{
	std::vector<DebuggerInfoEntry> result;
	if (instr.operation != HLIL_CALL && instr.operation != HLIL_TAILCALL)
		return result;

	auto dest = instr.GetDestExpr();
	if (dest.operation != HLIL_CONST_PTR && dest.operation != HLIL_CONST)
		return result;

	auto callTarget = dest.GetConstant();
	auto functions = m_data->GetAnalysisFunctionsForAddress(callTarget);
	if (functions.empty())
		return result;

	auto func = functions[0];
	if (!func)
		return result;

	auto arch = func->GetArchitecture();
	if (!arch)
		return result;

	for (const auto& param: func->GetParameterVariables().GetValue())
	{
		switch (param.type)
		{
		case RegisterVariableSourceType:
		{
			auto paramName = func->GetVariableName(param);
			auto reg = param.storage;
			auto regName = arch->GetRegisterName(reg);
			auto value = m_debugger->GetRegisterValue(regName);
			auto hints = m_debugger->GetAddressInformation(value);
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(LocalVariableToken, paramName);
			tokens.emplace_back(TextToken, " @ ");
			tokens.emplace_back(RegisterToken, regName);
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case StackVariableSourceType:
		{
			auto offset = param.storage;
			// Account for the return address on the stack for x64/x86_64, not sure if we should do it for other arch
			offset -= arch->GetAddressSize();
			auto realOffset = offset + m_debugger->StackPointer();

			BinaryReader reader(m_data);
			reader.Seek(realOffset);
			auto value = reader.ReadPointer();
			auto hints = m_debugger->GetAddressInformation(value);

			auto paramName = func->GetVariableName(param);
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(LocalVariableToken, paramName);
			tokens.emplace_back(TextToken, " @ ");

			auto stackReg = arch->GetStackPointerRegister();
			auto stackRegName = arch->GetRegisterName(stackReg);
			tokens.emplace_back(RegisterToken, stackRegName);
			if (offset != 0)
			{
				tokens.emplace_back(TextToken, " + ");
				char buf[64] = {0};
				snprintf(buf, sizeof(buf), "%#llx", offset);
				tokens.emplace_back(IntegerToken, buf, offset);
			}
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case FlagVariableSourceType:
			break;
		}
	}

	return result;
}


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getInfoForHLILConditions(HighLevelILFunctionRef hlil,
	const HighLevelILInstruction &instr)
{
	std::vector<DebuggerInfoEntry> result;
	if (instr.operation != HLIL_IF)
		return result;

	auto func = hlil->GetFunction();
	auto condition = instr.GetConditionExpr<HLIL_IF>();
	uint64_t value;
	if (!m_debugger->ComputeExprValue(hlil, condition, value))
		return result;

	// The value of a conditional expression must be 0 or 1 if it can be evaluated
	if ((value != 1) && (value != 0))
		return result;

	std::vector<DisassemblyTextLine> lines = hlil->GetExprText(condition.exprIndex);
	if (lines.empty())
		return result;
	std::vector<InstructionTextToken> tokens;
	for (const auto& line: lines)
		tokens.insert(tokens.end(), line.tokens.begin(), line.tokens.end());
	if (tokens.empty())
		return result;

	auto trueBranch = instr.GetTrueExpr<HLIL_IF>();
	auto falseBranch = instr.GetFalseExpr<HLIL_IF>();
	auto targetIL = value == 1 ? trueBranch : falseBranch;
	string hints = fmt::format("Branch to {} @ {:#x}", targetIL.instructionIndex, targetIL.address);
	result.emplace_back(tokens, value, hints, instr.instructionIndex, instr.exprIndex, instr.address);
	return result;
}


vector<DebuggerInfoEntry> DebuggerInfoTable::getILInfoEntries(const ViewLocation &location)
{
	vector<DebuggerInfoEntry> result;
	if (!m_debugger->IsConnected())
		return result;

	switch (location.getILViewType().type)
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
	case MediumLevelILFunctionGraph:
	{
		auto func = location.getFunction();
		if (!func)
			break;
		auto mlil = func->GetMediumLevelILIfAvailable();
		if (!mlil)
			break;
		if (location.getInstrIndex() == BN_INVALID_EXPR)
			break;
		auto instr = mlil->GetInstruction(location.getInstrIndex());
		auto entries = getInfoForMLIL(mlil, instr);
		result.insert(result.end(), entries.begin(), entries.end());
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		auto func = location.getFunction();
		if (!func)
			break;
		auto hlil = func->GetHighLevelILIfAvailable();
		if (!hlil)
			break;
		if (location.getInstrIndex() == BN_INVALID_EXPR)
			break;
		auto instr = hlil->GetInstruction(location.getInstrIndex());
		auto entries = getInfoForHLIL(hlil, instr);
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


DebuggerInfoEntry DebuggerInfoEntryItemModel::getRow(int row) const
{
	if ((size_t)row >= m_infoEntries.size())
		throw std::runtime_error("row index out-of-bound");

	return m_infoEntries[row];
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

	connect(this, &QTableView::doubleClicked, this, &DebuggerInfoTable::onDoubleClicked);
}


void DebuggerInfoTable::updateContents(const ViewLocation &location)
{
	if (!location.isValid() || !location.getFunction())
		return;

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


void DebuggerInfoTable::onDoubleClicked()
{
	QModelIndexList sel = selectionModel()->selectedIndexes();
	if (sel.empty())
		return;

	auto info = m_model->getRow(sel[0].row());
	uint64_t value = info.value;

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_debugger->GetData())
		frame->navigate(m_debugger->GetData(), value, true, true);
}


DebugInfoWidgetType::DebugInfoWidgetType():
	SidebarWidgetType(QIcon(":/debugger/cctv-camera").pixmap(QSize(64, 64)).toImage(), "Debugger Info")
{
}


SidebarWidget* DebugInfoWidgetType::createWidget(ViewFrame*, BinaryViewRef data)
{
	return new DebugInfoSidebarWidget(data);
}
