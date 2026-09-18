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

#include <QPainter>
#include <QHeaderView>
#include <QGuiApplication>
#include <QMimeData>
#include <QClipboard>
#include <QMenu>
#include <QAction>
#include <QContextMenuEvent>
#include "ui.h"
#include "debuggerinfowidget.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "binaryninjaapi.h"
#include "fmt/format.h"

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

			uint64_t value = 0;
			try
			{
				BinaryReader reader(m_data);
				reader.Seek(realOffset);
				value = reader.ReadPointer();
			}
			catch (const ReadException&)
			{
				// realOffset is outside the binary view; skip this entry
				break;
			}
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
				snprintf(buf, sizeof(buf), "%#" PRIx64, offset);
				tokens.emplace_back(IntegerToken, buf, offset);
			}
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case FlagVariableSourceType:
		case CompositeReturnValueSourceType:
		case CompositeParameterSourceType:
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
	intx::uint512 value;
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
			intx::uint512 value;
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
			intx::uint512 value;
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
			intx::uint512 value;
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

			uint64_t value = 0;
			try
			{
				BinaryReader reader(m_data);
				reader.Seek(realOffset);
				value = reader.ReadPointer();
			}
			catch (const ReadException&)
			{
				// realOffset is outside the binary view; skip this entry
				break;
			}
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
				snprintf(buf, sizeof(buf), "%#" PRIx64, offset);
				tokens.emplace_back(IntegerToken, buf, offset);
			}
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case FlagVariableSourceType:
		case CompositeReturnValueSourceType:
		case CompositeParameterSourceType:
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
	intx::uint512 value;
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
			intx::uint512 value;
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
			intx::uint512 value;
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

			uint64_t value = 0;
			try
			{
				BinaryReader reader(m_data);
				reader.Seek(realOffset);
				value = reader.ReadPointer();
			}
			catch (const ReadException&)
			{
				// realOffset is outside the binary view; skip this entry
				break;
			}
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
				snprintf(buf, sizeof(buf), "%#" PRIx64, offset);
				tokens.emplace_back(IntegerToken, buf, offset);
			}
			result.emplace_back(tokens, value, hints, instr.instructionIndex, BN_INVALID_EXPR, instr.address);
			break;
		}
		case FlagVariableSourceType:
		case CompositeReturnValueSourceType:
		case CompositeParameterSourceType:
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
	intx::uint512 value;
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


std::vector<DebuggerInfoEntry> DebuggerInfoTable::getStackInfo(const ViewLocation& location)
{
	std::vector<DebuggerInfoEntry> result;
	
	if (!m_debugger->IsConnected())
		return result;
	
	auto func = location.getFunction();
	if (!func)
		return result;
		
	auto arch = func->GetArchitecture();
	if (!arch)
		return result;
	
	uint64_t stackPointer = m_debugger->StackPointer();
	size_t addressSize = arch->GetAddressSize();
	
	// Get stack register name for display
	auto stackReg = arch->GetStackPointerRegister();
	auto stackRegName = arch->GetRegisterName(stackReg);
	
	// Read stack contents - show configurable number of entries
	BinaryReader reader(m_data);
	for (int i = 0; i < m_stackEntryCount; i++)
	{
		ptrdiff_t offset = i * addressSize;
		uint64_t stackAddress = stackPointer + offset;
		
		try 
		{
			reader.Seek(stackAddress);
			uint64_t value = 0;
			
			switch (addressSize)
			{
			case 1:
				value = reader.Read8();
				break;
			case 2:
				value = reader.Read16();
				break;
			case 4:
				value = reader.Read32();
				break;
			case 8:
				value = reader.Read64();
				break;
			default:
				continue;
			}
			
			// Create tokens for stack entry display
			std::vector<InstructionTextToken> tokens;
			tokens.emplace_back(RegisterToken, stackRegName);
			if (offset != 0)
			{
				tokens.emplace_back(TextToken, " + ");
				tokens.emplace_back(IntegerToken, fmt::format("0x{:x}", offset), offset);
			}
			
			// Get hint information using the existing API
			std::string hint = m_debugger->GetAddressInformation(value);
			
			// Check if this looks like a return address by checking if it's in a function
			// and the previous instruction is a call
			if (hint.empty() && value != 0)
			{
				auto targetFunc = m_data->GetAnalysisFunction(m_data->GetDefaultPlatform(), value);
				if (targetFunc)
				{
					// Check if the previous address contains a call instruction
					auto prevAddr = value - 1;  // Rough approximation
					auto callingFunc = m_data->GetAnalysisFunction(m_data->GetDefaultPlatform(), prevAddr);
					if (callingFunc)
					{
						hint = fmt::format("Return address to {}", targetFunc->GetSymbol() ? 
							targetFunc->GetSymbol()->GetShortName() : 
							fmt::format("func_{:x}", targetFunc->GetStart()));
					}
				}
			}
			
			// Create stack entry with storage address and stack flag
			result.emplace_back(tokens, value, hint, BN_INVALID_EXPR, BN_INVALID_EXPR, stackAddress, stackAddress, true);
		}
		catch (const std::exception&)
		{
			// Skip this entry if we can't read it
			continue;
		}
	}
	
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
		auto llils = llil->GetInstructionsAt(func->GetArchitecture(), addr);
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

	// Add stack information
	auto stackEntries = getStackInfo(location);
	result.insert(result.end(), stackEntries.begin(), stackEntries.end());

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


DebuggerInfoEntryItemDelegate::DebuggerInfoEntryItemDelegate(QWidget* parent): QStyledItemDelegate(parent), m_render(parent)
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
	case StorageColumn:
		if (entry->isStackEntry)
		{
			painter->setPen(getThemeColor(AddressColor));
			painter->drawText(textRect, QString::asprintf("0x%llx", entry->storageAddress));
		}
		// Draw nothing for non-stack entries (empty column)
		break;
	case ValueColumn:
		painter->setPen(getThemeColor(AddressColor));
		painter->drawText(textRect, QString::fromStdString("0x") + QString::fromStdString(intx::hex(entry->value)));
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
	return (int)m_infoEntries.size();
}


int DebuggerInfoEntryItemModel::columnCount(const QModelIndex &parent) const
{
	return 4;  // Added StorageColumn
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
		case StorageColumn:
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
		case StorageColumn:
		{
			if (item->isStackEntry)
			{
				auto str = QString::asprintf("0x%llx", item->storageAddress);
				result.setValue(str.size());
			}
			else
			{
				result.setValue(0);  // Empty for non-stack entries
			}
			break;
		}
		case ValueColumn:
		{
			auto str = QString::fromStdString("0x") + QString::fromStdString(intx::hex(item->value));
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
	case StorageColumn:
		return "Storage";
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


DebuggerInfoTable::DebuggerInfoTable(BinaryViewRef data): m_data(data), m_stackEntryCount(16)
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

	m_currentLocation = location;  // Store for context menu updates
	auto info = getILInfoEntries(location);
	m_model->updateRows(info);
	updateColumnWidths();
}


void DebuggerInfoTable::updateColumnWidths()
{
	resizeColumnToContents(ExprColumn);
	resizeColumnToContents(StorageColumn);
	resizeColumnToContents(ValueColumn);
	resizeColumnToContents(HintColumn);
}


void DebuggerInfoTable::updateFonts()
{
	m_itemDelegate->updateFonts();
}


void DebuggerInfoTable::onDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid())
		return;

	auto info = m_model->getRow(index.row());
	uint64_t targetAddress = 0;
	
	// Check which column was clicked and determine the target address
	switch (index.column())
	{
	case ValueColumn:
		targetAddress = (uint64_t)info.value;
		break;
	case StorageColumn:
		if (info.isStackEntry)
			targetAddress = info.storageAddress;
		else
			return;  // No navigation for empty storage column
		break;
	default:
		// For other columns, navigate to the value address (original behavior)
		targetAddress = (uint64_t)info.value;
		break;
	}

	if (targetAddress == 0)
		return;

	UIContext* context = UIContext::contextForWidget(this);
	if (!context)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (m_debugger->GetData())
		frame->navigate(m_debugger->GetData(), targetAddress, true, true);
}


void DebuggerInfoTable::contextMenuEvent(QContextMenuEvent* event)
{
	QMenu menu(this);
	
	QAction* increaseAction = menu.addAction("Show More Stack Entries");
	QAction* decreaseAction = menu.addAction("Show Fewer Stack Entries");
	
	// Add current count info
	menu.addSeparator();
	QAction* infoAction = menu.addAction(QString("Currently showing %1 entries").arg(m_stackEntryCount));
	infoAction->setEnabled(false);
	
	// Disable actions if at limits
	if (m_stackEntryCount >= 64)  // Set reasonable upper limit
		increaseAction->setEnabled(false);
	if (m_stackEntryCount <= 4)   // Set reasonable lower limit  
		decreaseAction->setEnabled(false);
	
	connect(increaseAction, &QAction::triggered, this, &DebuggerInfoTable::increaseStackEntries);
	connect(decreaseAction, &QAction::triggered, this, &DebuggerInfoTable::decreaseStackEntries);
	
	menu.exec(event->globalPos());
}


void DebuggerInfoTable::increaseStackEntries()
{
	if (m_stackEntryCount < 64)
	{
		m_stackEntryCount += 4;  // Increase by 4 entries at a time
		if (m_currentLocation.isValid())
			updateContents(m_currentLocation);
	}
}


void DebuggerInfoTable::decreaseStackEntries() 
{
	if (m_stackEntryCount > 4)
	{
		m_stackEntryCount -= 4;  // Decrease by 4 entries at a time
		if (m_currentLocation.isValid())
			updateContents(m_currentLocation);
	}
}


DebugInfoWidgetType::DebugInfoWidgetType():
	SidebarWidgetType(QIcon(":/debugger/cctv-camera").pixmap(QSize(64, 64)).toImage(), "Debugger Info")
{
}


SidebarWidget* DebugInfoWidgetType::createWidget(ViewFrame*, BinaryViewRef data)
{
	return new DebugInfoSidebarWidget(data);
}


SidebarContentClassifier* DebugInfoWidgetType::contentClassifier(ViewFrame*, BinaryViewRef data)
{
	return new ActiveDebugSessionSidebarContentClassifier(data);
}
