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
	m_label = new QLabel("nothing");
	auto* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_label);
	setLayout(layout);
}


QString DebugInfoSidebarWidget::getInfoString(const ViewLocation &location)
{
	auto info = QString::asprintf("View type: %s, offset: 0x%llx, il: %d", location.getViewType().toStdString().c_str(), location.getOffset(), location.getILViewType());
	if (!m_debugger->IsConnected())
		return info;

	info += "\n\n";

	switch (location.getILViewType())
	{
	case NormalFunctionGraph:
		break;
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
				QString line;
				for (const auto& token: tokens)
					line += token.text;
				line += QString::asprintf(" = 0x%llx", value);
				info += line;
				auto hint = m_debugger->GetAddressInformation(value);
				if (!hint.empty())
					info += QString::asprintf(" {%s}", hint.c_str());
				info += '\n';
				break;
			}
			case RegisterLowLevelOperand:
			{
				auto reg = operand.GetRegister();
				auto name = func->GetArchitecture()->GetRegisterName(reg);
				auto value = m_debugger->GetRegisterValue(name);
				info += QString::asprintf("%s = 0x%llx", name.c_str(), value);
				auto hint = m_debugger->GetAddressInformation(value);
				if (!hint.empty())
					info += QString::asprintf(" {%s}", hint.c_str());
				info += '\n';
				break;
			}
			default:
				break;
			}
		}
		break;
	}
	default:
		break;
	}

	return info;
}


void DebugInfoSidebarWidget::notifyViewLocationChanged(View* view, const ViewLocation& location)
{
	auto info = getInfoString(location);
	m_label->setText(info);
}


DebugInfoSidebarWidget::~DebugInfoSidebarWidget()
{

}


DebugInfoWidgetType::DebugInfoWidgetType():
	SidebarWidgetType(QIcon(":/icons/images/history.png").pixmap(QSize(64, 64)).toImage(), "Debugger Info")
{
}


SidebarWidget* DebugInfoWidgetType::createWidget(ViewFrame*, BinaryViewRef data)
{
	return new DebugInfoSidebarWidget(data);
}
