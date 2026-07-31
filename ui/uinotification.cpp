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

#include "inttypes.h"
#include "uinotification.h"
#include "filecontext.h"
#include "viewframe.h"
#include "linearview.h"
#include "flowgraphwidget.h"
#include "hexeditor.h"
#include <QMessageBox>
#include <QFileInfo>
#include <QPushButton>
#include <QObject>
#include "ui.h"
#include <thread>

using namespace BinaryNinja;

NotificationListener* NotificationListener::m_instance = nullptr;

void NotificationListener::init()
{
	m_instance = new NotificationListener;
	UIContext::registerNotification(m_instance);
}


void NotificationListener::OnContextOpen(UIContext* context)
{
	[[maybe_unused]] GlobalDebuggerUI* ui = GlobalDebuggerUI::CreateForContext(context);
}


void NotificationListener::OnContextClose(UIContext* context)
{
	GlobalDebuggerUI::RemoveForContext(context);
}


bool NotificationListener::OnBeforeOpenDatabase(UIContext* context, FileMetadataRef metadata)
{
	return true;
}


bool NotificationListener::OnAfterOpenDatabase(UIContext* context, FileMetadataRef metadata, BinaryViewRef data)
{
	return true;
}


bool NotificationListener::OnBeforeOpenFile(UIContext* context, FileContext* file)
{
	return true;
}


void NotificationListener::OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame) {}


bool NotificationListener::OnBeforeSaveFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	return true;
}


void NotificationListener::OnAfterSaveFile(UIContext* context, FileContext* file, ViewFrame* frame) {}


bool NotificationListener::OnBeforeCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	auto mainWindow = context->mainWindow();

	size_t count = 0;
	for (const auto& ctx: UIContext::allContexts())
	{
		auto tabs = ctx->getTabs();
		for (auto tab : tabs)
		{
			auto viewFrame = ctx->getViewFrameForTab(tab);
			if (viewFrame && (viewFrame->getFileContext() == file))
				count++;
		}
	}

	// If this is not the last tab of the file being closed, return
	if (count != 1)
		return true;

	auto controller = DebuggerController::GetController(file->getMetadata());
	if (!controller)
		return true;

	if (controller->IsConnected())
	{
		QMessageBox* msgBox = new QMessageBox(mainWindow);
		msgBox->setAttribute(Qt::WA_DeleteOnClose);
		msgBox->setIcon(QMessageBox::Question);
		msgBox->setText(QObject::tr("The debugger file ") + file->getShortFileName(mainWindow)
			+ QObject::tr(" is active. Do you want to stop it before closing?"));
		msgBox->setWindowTitle(QObject::tr("Debugger Active"));
		msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
		msgBox->setDefaultButton(QMessageBox::Yes);
		msgBox->show();
		msgBox->move(mainWindow->frameGeometry().center() - msgBox->rect().center());
		msgBox->setAttribute(Qt::WA_KeyboardFocusChange);
		int result = msgBox->exec();
		if (result == QMessageBox::Cancel)
			return false;
		else if (result == QMessageBox::Yes)
		{
			std::thread([=]() {
				// Since we cannot wait for the target to stop on the main thread, we must create a new thread and
				// wait from there.
				controller->QuitAndWait();
				controller->Destroy();
			}).detach();
			return true;
		}
	}
	else
	{
		controller->Destroy();
	}
	return true;
}


void NotificationListener::OnAfterCloseFile(UIContext* context, FileContext* file, ViewFrame* frame) {}


void NotificationListener::OnViewChange(UIContext* context, ViewFrame* frame, const QString& type)
{
	auto ui = GlobalDebuggerUI::GetForContext(context);
	if (ui != nullptr)
		ui->SetActiveFrame(frame);
}


void NotificationListener::OnAddressChange(
	UIContext* context, ViewFrame* frame, View* view, const ViewLocation& location)
{}


bool NotificationListener::GetNameForFile(UIContext* context, FileContext* file, QString& name)
{
	return false;
}


bool NotificationListener::GetNameForPath(UIContext* context, const QString& path, QString& name)
{
	return false;
}


void NotificationListener::OnContextMenuCreated(UIContext *context, View* view, Menu &menu)
{
	// Only add the context menu to the linear/graph/hex views
	if (!dynamic_cast<LinearView*>(view) && !dynamic_cast<FlowGraphWidget*>(view)
		&& !dynamic_cast<HexEditor*>(view))
		return;

	menu.addAction("Debugger", "Toggle Breakpoint", "Breakpoint");
	menu.addAction("Debugger", "Enable Breakpoint", "Breakpoint");
	menu.addAction("Debugger", "Solo Breakpoint", "Breakpoint");
	menu.addAction("Debugger", "Edit Condition...", "Breakpoint");
	menu.addAction("Debugger", "Add Hardware Breakpoint...", "Breakpoint");
	menu.addAction("Debugger", "Launch", "Control");
	menu.addAction("Debugger", "Pause", "Control");
	menu.addAction("Debugger", "Restart", "Control");
	menu.addAction("Debugger", "Resume", "Control");
	menu.addAction("Debugger", "Step Into", "Control");
	menu.addAction("Debugger", "Step Over", "Control");
	menu.addAction("Debugger", "Step Return", "Control");
	menu.addAction("Debugger", "Run To Here", "Control");
	menu.addAction("Debugger", "Run Back To Here", "Control");
	menu.addAction("Debugger", "Create Stack View", "Misc");
	menu.addAction("Debugger", "Override IP", "Misc");
	menu.addAction("Debugger", "Rebase to Remote Base...", "Misc");
	// TTD Memory Access context menu items
	menu.addAction("Debugger", "Navigate to TTD Timestamp...", "TTD");
	menu.addAction("Debugger", "Add TTD Bookmark...", "TTD");
	menu.addAction("Debugger", "TTD Memory Access\\Read", "TTD");
	menu.addAction("Debugger", "TTD Memory Access\\Write", "TTD");
	menu.addAction("Debugger", "TTD Memory Access\\Read/Write", "TTD");
	menu.addAction("Debugger", "TTD Memory Access\\Execute", "TTD");
	menu.addAction("Debugger", "TTD Memory Access\\Read/Write/Execute", "TTD");
	// TTD Memory Access (Next/Prev) — single dialog entry
	menu.addAction("Debugger", "TTD Memory Access (Next/Prev)", "TTD");
	// TTD Register Write navigation — only enabled when a register token is under the cursor
	menu.addAction("Debugger", "Go to Previous Register Write", "TTD");
	menu.addAction("Debugger", "Go to Next Register Write", "TTD");
	// TTD Calls context menu item
	menu.addAction("Debugger", "TTD Calls\\Kernel32 Calls", "TTD");
}


bool NotificationListener::OnTokenDoubleClicked(UIContext* context, ViewFrame* frame, View* view,
	const ViewLocation& location, const HighlightTokenState& token)
{
	// When a debug session is active and the user double-clicks a register or a
	// variable, navigate to the address it refers to at the current stop location.
	// If we cannot resolve it, return false so the default double-click behavior
	// (navigation, rename dialog, etc.) still runs.
	if (!view)
		return false;

	auto data = view->getData();
	if (!data)
		return false;

	// Only act when a controller already exists for this view; don't spin one up
	// just because a token was double-clicked.
	if (!DebuggerController::ControllerExists(data))
		return false;

	auto controller = DebuggerController::GetController(data);
	if (!controller || !controller->IsConnected() || controller->IsRunning())
		return false;

	uint64_t target = 0;
	bool haveTarget = false;

	if ((token.type == IntegerToken || token.type == PossibleAddressToken
			|| token.type == CodeRelativeAddressToken)
		&& token.addrValid)
	{
		// An address-literal token (a raw address/number in the operand) that resolves to an
		// address. The default behavior navigates to it in the same view; while debugging we
		// instead open it in another pane so the disassembly the user is looking at stays put.
		// AddressDisplayToken is intentionally left out: those keep navigating in the current view.
		// NOTE: opening address-valued literals in a new pane is arguably a better default
		// and should probably become the standard behavior even outside of a debug session.

		// If the target lands inside the function the user is already looking at, they most
		// likely want to jump to it in place rather than open a second pane. Fall through to
		// the default double-click behavior (in-pane navigation) in that case.
		auto func = location.getFunction();
		if (!func)
		{
			auto funcs = data->GetAnalysisFunctionsContainingAddress(location.getOffset());
			if (!funcs.empty())
				func = funcs[0];
		}
		if (func)
		{
			for (const auto& range : func->GetAddressRanges())
			{
				if ((token.addr >= range.start) && (token.addr < range.end))
					return false;
			}
		}

		target = token.addr;
		haveTarget = true;
	}
	else if (token.type == DataSymbolToken || token.type == StringToken)
	{
		// A data symbol (e.g. data_100003fa9) or a string reference. The default behavior
		// navigates to it in the same view; while debugging we instead open it in another
		// pane so the disassembly the user is looking at stays put.

		if ((token.type == StringToken) && (token.token.context != StringReferenceTokenContext)
			&& (token.token.context != StringDataVariableTokenContext))
			return false;

		if (!token.addrValid)
			return false;

		target = token.addr;
		haveTarget = true;
	}
	else if (token.type == RegisterToken)
	{
		// A raw register token: navigate to the address currently held in the register.
		target = (uint64_t)controller->GetRegisterValue(token.token.text);
		haveTarget = true;
	}
	else if ((token.type == LocalVariableToken || token.type == StackVariableToken) && token.localVarValid)
	{
		const auto& var = token.localVar;
		if (var.type == RegisterVariableSourceType)
		{
			// The variable lives in a register: navigate to the address it holds.
			auto arch = data->GetDefaultArchitecture();
			if (!arch)
				return false;
			auto regName = arch->GetRegisterName((uint32_t)var.storage);
			// GetRegisterValue expects the adapter's name for the frame pointer on arm64.
			if (regName == "x29")
				regName = "fp";
			target = (uint64_t)controller->GetRegisterValue(regName);
			haveTarget = true;
		}
		else if (var.type == StackVariableSourceType)
		{
			// A stack variable: navigate to its live address in the current stack frame.
			// var.storage is an offset relative to the stack pointer at function entry.
			auto arch = data->GetDefaultArchitecture();
			if (!arch)
				return false;

			// Preferred: recover the entry-time stack pointer using the analyzed stack-frame
			// offset at the current instruction, so we stay correct mid-function once the
			// prologue has adjusted the stack.
			// Fallback: if there is no clean frame offset here (e.g. we are stopped at the
			// function entry before the prologue has run, so the variable has not been created
			// yet), assume the current stack pointer is the frame base. This is exact at entry
			// and a best effort otherwise.
			uint64_t stackAtFuncEntry = controller->StackPointer();

			auto func = location.getFunction();
			if (!func)
			{
				auto funcs = data->GetAnalysisFunctionsContainingAddress(location.getOffset());
				if (!funcs.empty())
					func = funcs[0];
			}
			if (func)
			{
				auto stackReg = arch->GetStackPointerRegister();
				auto stackValue = func->GetRegisterValueAtInstruction(arch, controller->GetLastIP(), stackReg);
				if (stackValue.state == StackFrameOffset)
					stackAtFuncEntry = controller->StackPointer() - stackValue.value;
			}

			target = stackAtFuncEntry + var.storage;
			haveTarget = true;
		}
	}

	if (!haveTarget)
		return false;

	// Open the target in another pane so the disassembly the user is looking at stays put.
	view->navigateOnOtherPane(target);
	return true;
}
