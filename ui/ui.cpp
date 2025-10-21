/*
Copyright 2020-2025 Vector 35 Inc.

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

#include "ui.h"
#include "binaryninjaapi.h"
#include "breakpointswidget.h"
#include "moduleswidget.h"
#include "renderlayer.h"
#include "stackwidget.h"
#include "uinotification.h"
#include "platformdialog.h"
#include "QPainter"
#include <QStatusBar>
#include <QCoreApplication>
#include <QProgressDialog>
#include <QTimer>
#include "fmt/format.h"
#include "threadframes.h"
#include "syncgroup.h"
#include "codedatarenderer.h"
#include "adaptersettings.h"
#include <thread>
#include <QInputDialog>
#include <filesystem>
#include <QMessageBox>
#include "debugadapterscriptingprovider.h"
#include "targetscriptingprovider.h"
#include "progresstask.h"
#include "attachprocess.h"
#include "progresstask.h"
#include "debuggerinfowidget.h"
#include "ttdmemorywidget.h"
#include "ttdcallswidget.h"
#include "ttdeventswidget.h"
#include "ttdanalysisdialog.h"
#include "timestampnavigationdialog.h"
#include "freeversion.h"
#include <QTimer>

#ifdef WIN32
	#include "ttdrecord.h"
	#include "scriptingconsole.h"
	#include "install_windbg.h"
#endif


using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

std::map<ViewFrame*, std::unique_ptr<DebuggerUI>> g_viewFrameMap;
std::map<UIContext*, std::unique_ptr<GlobalDebuggerUI>> g_contextMap;

GlobalDebuggerUI::GlobalDebuggerUI(UIContext* context) : m_context(context)
{
	m_window = context->mainWindow();
	if (m_window && m_window->statusBar())
	{
		m_status = new DebuggerStatusBarContainer;
		auto statusBar = m_window->statusBar();
		if (statusBar)
		{
			statusBar->addWidget(m_status);
		}
	}

	m_displayingGlobalAreaWidgets = false;

	SetupMenu(context);
}


GlobalDebuggerUI::~GlobalDebuggerUI() {}

static void BreakpointToggleCallback(BinaryView* view, uint64_t addr)
{
	auto controller = DebuggerController::GetController(view);
	bool isAbsoluteAddress = false;
	if (controller->IsConnected())
		isAbsoluteAddress = true;

	if (isAbsoluteAddress)
	{
		if (controller->ContainsBreakpoint(addr))
		{
			controller->DeleteBreakpoint(addr);
		}
		else
		{
			controller->AddBreakpoint(addr);
		}
	}
	else
	{
		std::string filename = controller->GetInputFile();
		uint64_t offset = addr - controller->GetViewFileSegmentsStart();
		ModuleNameAndOffset info = {filename, offset};
		if (controller->ContainsBreakpoint(info))
		{
			controller->DeleteBreakpoint(info);
		}
		else
		{
			controller->AddBreakpoint(info);
		}
	}
}

static void JumpToIPCallback(BinaryView* view, UIContext* context)
{
	auto controller = DebuggerController::GetController(view);
	if (!controller)
		return;

	ViewFrame* frame = context->getCurrentViewFrame();
	if (!frame)
		return;

	if (controller->GetData())
		frame->navigate(controller->GetData(), controller->IP(), true, true);
}


static bool ShowAsCode(BinaryView* view, uint64_t addr)
{
	DataVariable var;
	if (view->GetDataVariableAtAddress(addr, var))
	{
		auto sym = view->GetSymbolByAddress(addr);
		if (sym)
		{
			auto name = sym->GetFullName();
			if (name.substr(0, 14) == "BN_CODE_start_")
			{
				return true;
			}
		}
	}
	return false;
}


static void MakeCodeHelper(BinaryView* view, BNAddressRange selection)
{
	if (!view)
		return;

	auto addr = selection.start;
	auto end = selection.end;
	if (end - addr <= 1)
	{
		end = view->GetEnd();
		auto nextData = view->GetNextDataVariableStartAfterAddress(addr);
		auto nextCode = view->GetNextBasicBlockStartAfterAddress(addr);
		auto localSegment = view->GetSegmentAt(addr);
		if (nextData != 0)
			end = std::min(nextData, end);
		if (nextCode != 0)
			end = std::min(nextCode, end);
		if (localSegment)
			end = std::min(localSegment->GetEnd(), end);

		if (end <= addr)
			end = addr + 0x30;
	}

	if (ShowAsCode(view, addr))
	{
		auto id = view->BeginUndoActions();
		view->UndefineUserDataVariable(addr);
		auto sym = view->GetSymbolByAddress(addr);
		view->UndefineUserSymbol(sym);
		view->CommitUndoActions(id);
		view->UpdateAnalysis();
		return;
	}

	auto id = view->BeginUndoActions();
	view->DefineUserDataVariable(addr, Type::ArrayType(Type::IntegerType(1, false), end - addr));
	const std::string name = fmt::format("BN_CODE_start_0x{:x}_size_0x{:x}", addr, end - addr);
	SymbolRef sym = new Symbol(DataSymbol, name, name, name, addr);
	view->DefineUserSymbol(sym);
	view->CommitUndoActions(id);
	view->UpdateAnalysis();
}

void GlobalDebuggerUI::GetAddressRange(const UIActionContext& ctxt, uint64_t& startAddr, uint64_t& endAddr)
{
	if (ctxt.view && ctxt.view->getSelectionOffsets().start != ctxt.view->getSelectionOffsets().end)
	{
		// Use selection range
		auto selection = ctxt.view->getSelectionOffsets();
		startAddr = selection.start;
		endAddr = selection.end;
	}
	else
	{
		// Use current address, default to 1 byte
		startAddr = ctxt.address;
		endAddr = ctxt.address + 1;
	}
}

void GlobalDebuggerUI::QueryTTDMemoryAccess(const UIActionContext& ctxt, uint64_t startAddr, uint64_t endAddr, BNDebuggerTTDMemoryAccessType accessType)
{
	// Focus the TTD Memory sidebar widget
	if (!ctxt.context)
		return;

	auto sidebar = ctxt.context->sidebar();
	if (!sidebar)
		return;

	// Get the current view frame
	ViewFrame* frame = ctxt.context->getCurrentViewFrame();
	if (!frame)
		return;

	auto controller = DebuggerController::GetController(ctxt.binaryView);
	if (!controller)
		return;

	// Convert BNDebuggerTTDMemoryAccessType to TTDMemoryAccessType
	TTDMemoryAccessType accessTypeEnum = static_cast<TTDMemoryAccessType>(accessType);
	
	// Set pending query first
	TTDMemoryWidgetType::SetPendingQuery(frame, ctxt.binaryView, startAddr, endAddr, accessTypeEnum);
	
	// Activate the sidebar widget
	sidebar->activate("TTD Memory");
	
	// Try to find the widget that was just created/activated and apply the query immediately
	// We'll give it a moment to be created if needed
	QTimer::singleShot(100, [sidebar, ctxt, startAddr, endAddr, accessTypeEnum]() {
		// Try to find the active TTD Memory widget
		auto* sidebarWidget = sidebar->widget("TTD Memory");
		if (auto* ttdWidget = qobject_cast<TTDMemorySidebarWidget*>(sidebarWidget))
		{
			ttdWidget->setParametersAndQueryInNewTab(startAddr, endAddr, accessTypeEnum);
		}
	});
}


void GlobalDebuggerUI::QueryTTDCalls(const UIActionContext& ctxt, const std::string& symbols, uint64_t startReturnAddr, uint64_t endReturnAddr)
{
	// Focus the TTD Calls sidebar widget
	if (!ctxt.context)
		return;

	ViewFrame* frame = ctxt.context->getCurrentViewFrame();
	if (!frame)
		return;

	auto sidebar = frame->getSidebar();
	if (!sidebar)
		return;

	auto controller = DebuggerController::GetController(ctxt.binaryView);
	if (!controller)
		return;

	// Set pending query first
	TTDCallsWidgetType::SetPendingQuery(frame, ctxt.binaryView, symbols, startReturnAddr, endReturnAddr);

	// Activate the sidebar widget
	sidebar->activate("TTD Calls");

	// Try to find the widget that was just created/activated and apply the query immediately
	// We'll give it a moment to be created if needed
	QTimer::singleShot(100, [sidebar, ctxt, symbols, startReturnAddr, endReturnAddr]() {
		// Try to find the active TTD Calls widget
		auto* sidebarWidget = sidebar->widget("TTD Calls");
		if (auto* ttdWidget = qobject_cast<TTDCallsSidebarWidget*>(sidebarWidget))
		{
			ttdWidget->setParametersAndQueryInNewTab(symbols, startReturnAddr, endReturnAddr);
		}
	});
}


void GlobalDebuggerUI::SetupMenu(UIContext* context)
{
	auto requireBinaryView = [](const UIActionContext& ctxt) {
		return ctxt.binaryView;
	};

	auto notConnected = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		// TODO: these two calls should be combined into something like GetControllerIfExists
		// The reason why we must avoid creating a new debugger controller here is because these enable callbacks
		// are called in unpredictable order compared to the destroy of the controller when we close a tab.
		// There is a chance that we first destroy the controller, and they quickly recreate it, causing a memory
		// leak for the underlying binary view.
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return !controller->IsConnected();
	};

	auto connected = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected();
	};

	auto connectedAndStopped = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected() && (!controller->IsRunning());
	};

	auto connectedAndStoppedWithTTD = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected() && (!controller->IsRunning()) && controller->IsTTD();
	};

	auto connectedToTTD = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected() && controller->IsTTD();
	};

	auto connectedAndRunning = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected() && controller->IsRunning();
	};

	auto connectedToDebugServer = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnectedToDebugServer();
	};

	auto notConnectedToDebugServer = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		if (!DebuggerController::ControllerExists(ctxt.binaryView))
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return !controller->IsConnectedToDebugServer();
	};

	auto ensureBinaryViewHasPlatform = [&](BinaryViewRef data, QWidget* parent) -> bool
	{
		if (!data->GetDefaultPlatform())
		{
			// No default platform, prompt user to choose one
			PlatformDialog dlg(parent);
			if (dlg.exec() != QDialog::Accepted)
			{
				QMessageBox::warning(parent, "No Platform",
									 "The debugger cannot work if the binary view has no platform and architecture");
				return false;
			}

			auto platform = dlg.getPlatform();
			if (platform)
			{
				dlg.saveDefaults();
			}
			else
			{
				QMessageBox::warning(parent, "Invalid Platform",
									 "The debugger cannot work if the binary view has no platform and architecture");
				return false;
			}

			data->SetDefaultArchitecture(platform->GetArchitecture());
			data->SetDefaultPlatform(platform);
		}
		return true;
	};

	UIAction::registerAction("Debug Adapter Settings...");
	context->globalActions()->bindAction("Debug Adapter Settings...",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				if (!context->mainWindow())
					return;

				auto* dialog = new AdapterSettingsDialog(context->mainWindow(), controller);
				dialog->show();
			},
			requireBinaryView));

	Menu* debuggerMenu = Menu::mainMenu("Debugger");
	Menu::setMainMenuOrder("Debugger", MENU_ORDER_LATE);
	debuggerMenu->addAction("Debug Adapter Settings...", "Settings", MENU_ORDER_FIRST);

	UIAction::registerAction("Launch", QKeySequence(Qt::Key_F6));
	context->globalActions()->bindAction("Launch",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				bool firstLaunch = controller->IsFirstLaunch();
                if (firstLaunch)
                {
                	auto adapterSettings = new AdapterSettingsDialog(context->mainWindow(), controller, "launch");
                	if (adapterSettings->exec() != QDialog::Accepted)
                		return;
                }

				// TODO: we should have the adapter returns this property
				bool isLocalLaunch = true;
				auto adapter = controller->GetAdapterType();
				if ((adapter == "DBGENG_TTD") || (adapter == "LOCAL_WINDOWS_KERNEL") || (adapter == "WINDOWS_KERNEL") ||
					(adapter == "WINDOWS_DUMP_FILE") || (adapter == "Corellium") || (adapter == "GDB RSP"))
				{
					isLocalLaunch = false;
				}
				
				bool connectedToDebugServer = controller->IsConnectedToDebugServer();

				if (isLocalLaunch && firstLaunch && Settings::Instance()->Get<bool>("debugger.confirmFirstLaunch"))
				{
					auto prompt = QString("You are about to launch \n\n%1\n\non your machine. "
						"This may harm your machine. Are you sure to continue?").
					  	arg(QString::fromStdString(controller->GetExecutablePath()));
					if (QMessageBox::question(context->mainWindow(), "Launch Target", prompt) != QMessageBox::Yes)
						return;
				}
				else if (!isLocalLaunch && connectedToDebugServer && firstLaunch &&
					Settings::Instance()->Get<bool>("debugger.confirmFirstLaunch"))
				{
					auto remoteHost = QString::fromStdString(controller->GetRemoteHost());
					auto remotePort = controller->GetRemotePort();
					auto prompt = QString("You are about to launch \n\n%1\n\non remote host %2:%3. "
						"Are you sure to continue?").arg(QString::fromStdString(controller->GetExecutablePath()))
						.arg(remoteHost).arg(remotePort);
					if (QMessageBox::question(context->mainWindow(), "Launch Target", prompt) != QMessageBox::Yes)
						return;
				}

				if (!ensureBinaryViewHasPlatform(controller->GetData(), context->mainWindow()))
					return;

				QString text = QString(
					"The debugger is launching the target and preparing the debugger binary view. \n"
					"This might take a while.");
				ProgressTask* task = new ProgressTask(
					context->mainWindow(), "Launching", text, "", [&](ProgressFunction progress) {
						controller->Launch();

						// For now, this cant be canceled, as the Debugger model wasn't
			            // designed with that in mind. This function below can return false if canceling is enabled
						progress(1, 1);
						return;
					});
				task->wait();
			},
			notConnected));
	debuggerMenu->addAction("Launch", "Launch");

	UIAction::registerAction("Kill");
	context->globalActions()->bindAction("Kill",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				std::thread([=]() { controller->Quit(); }).detach();
			},
			connected));
	debuggerMenu->addAction("Kill", "Launch");

	UIAction::registerAction("Resume", QKeySequence(Qt::Key_F9));
	context->globalActions()->bindAction("Resume",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->Go();
				m_context->refreshCurrentViewContents();
			},
			connectedAndStopped));
	debuggerMenu->addAction("Resume", "Control");

	UIAction::registerAction("Go Backwards", QKeySequence(Qt::ShiftModifier | Qt::Key_F9));
	context->globalActions()->bindAction("Go Backwards",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->GoReverse();
				m_context->refreshCurrentViewContents();
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Step Into", QKeySequence(Qt::Key_F7));
	context->globalActions()->bindAction("Step Into",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType().type;
				controller->StepInto(graphType);
				m_context->refreshCurrentViewContents();
			},
			connectedAndStopped));
	debuggerMenu->addAction("Step Into", "Control");

	UIAction::registerAction("Step Into Backwards", QKeySequence(Qt::ShiftModifier | Qt::Key_F7));
	context->globalActions()->bindAction("Step Into Backwards",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType().type;
				controller->StepIntoReverse(graphType);
				m_context->refreshCurrentViewContents();
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Step Over", QKeySequence(Qt::Key_F8));
	context->globalActions()->bindAction("Step Over",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType().type;
				controller->StepOver(graphType);
				m_context->refreshCurrentViewContents();
			},
			connectedAndStopped));
	debuggerMenu->addAction("Step Over", "Control");

	UIAction::registerAction("Step Over Backwards", QKeySequence(Qt::ShiftModifier | Qt::Key_F8));
	context->globalActions()->bindAction("Step Over Backwards",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType().type;
				controller->StepOverReverse(graphType);
				m_context->refreshCurrentViewContents();
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Step Return", QKeySequence(Qt::ControlModifier | Qt::Key_F9));
	context->globalActions()->bindAction("Step Return",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->StepReturn();
				m_context->refreshCurrentViewContents();
			},
			connectedAndStopped));
	debuggerMenu->addAction("Step Return", "Control");

	UIAction::registerAction("Step Return Backwards", QKeySequence( Qt::ControlModifier | Qt::ShiftModifier | Qt::Key_F9 ));
	context->globalActions()->bindAction("Step Return Backwards",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->StepReturnReverse();
				m_context->refreshCurrentViewContents();
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Run To Here", QKeySequence(Qt::Key_F4));
	context->globalActions()->bindAction("Run To Here",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->RunTo(ctxt.address);
				m_context->refreshCurrentViewContents();
			},
			connectedAndStopped));
	debuggerMenu->addAction("Run To Here", "Control");

	UIAction::registerAction("Run Back To Here", QKeySequence(Qt::ShiftModifier | Qt::Key_F4));
	context->globalActions()->bindAction("Run Back To Here",
		UIAction(
			[this](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->RunToReverse(ctxt.address);
				m_context->refreshCurrentViewContents();
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Detach");
	context->globalActions()->bindAction("Detach",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				std::thread([=]() { controller->Detach(); }).detach();
			},
			connected));
	debuggerMenu->addAction("Detach", "Launch");

	UIAction::registerAction("Restart");
	context->globalActions()->bindAction("Restart",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				std::thread([=]() { controller->Restart(); }).detach();
			},
			connected));
	debuggerMenu->addAction("Restart", "Launch");

	UIAction::registerAction("Pause", QKeySequence(Qt::Key_F12));
	context->globalActions()->bindAction("Pause",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				std::thread([=]() { controller->Pause(); }).detach();
			},
			connectedAndRunning));
	debuggerMenu->addAction("Pause", "Control");

	UIAction::registerAction("Attach To Process...");
	context->globalActions()->bindAction("Attach To Process...",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				if (controller->IsFirstAttach())
				{
					auto adapterSettings = new AdapterSettingsDialog(context->mainWindow(), controller, "attach");
					if (adapterSettings->exec() != QDialog::Accepted)
						return;
				}

				auto dialog = new AttachProcessDialog(context->mainWindow(), controller);
				if (dialog->exec() != QDialog::Accepted)
					return;

				uint32_t pid = dialog->GetSelectedPid();
				if (pid == 0)
					return;

				controller->SetPIDAttach(pid);

				if (!ensureBinaryViewHasPlatform(controller->GetData(), context->mainWindow()))
					return;

				QString text = QString(
					"The debugger is attaching to the target and preparing the debugger binary view. \n"
					"This might take a while.");
				ProgressTask* task = new ProgressTask(
					context->mainWindow(), "Attaching", text, "", [&](ProgressFunction progress) {
						controller->Attach();

						// For now, this cant be canceled, as the Debugger model wasn't
			            // designed with that in mind. This function below can return false if canceling is enabled
						progress(1, 1);
						return;
					});
				task->wait();
			},
			notConnected));
	debuggerMenu->addAction("Attach To Process...", "Launch");

	UIAction::registerAction("Toggle Breakpoint", QKeySequence(Qt::Key_F2));
	context->globalActions()->bindAction("Toggle Breakpoint",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BreakpointToggleCallback(ctxt.binaryView, ctxt.address);
			},
			requireBinaryView));
	debuggerMenu->addAction("Toggle Breakpoint", "Breakpoint");

	// Helper function to check if there's a breakpoint at the current address and return its enabled state
	auto getBreakpointEnabledState = [](BinaryView* view, uint64_t addr) -> std::pair<bool, bool> {
		auto controller = DebuggerController::GetController(view);
		if (!controller)
			return {false, false}; // {hasBreakpoint, isEnabled}
		
		std::vector<DebugBreakpoint> breakpoints = controller->GetBreakpoints();
		for (const auto& bp : breakpoints)
		{
			if (bp.address == addr)
				return {true, bp.enabled};
		}
		return {false, false};
	};

	// Register dynamic "Enable/Disable Breakpoint" action
	UIAction::registerAction("Enable Breakpoint");
	
	context->globalActions()->bindAction("Enable Breakpoint",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				auto [hasBreakpoint, isEnabled] = getBreakpointEnabledState(ctxt.binaryView, ctxt.address);
				bool isAbsoluteAddress = controller->IsConnected();
				
				if (isAbsoluteAddress)
				{
					if (isEnabled)
						controller->DisableBreakpoint(ctxt.address);
					else
						controller->EnableBreakpoint(ctxt.address);
				}
				else
				{
					std::string filename = controller->GetInputFile();
					uint64_t offset = ctxt.address - controller->GetViewFileSegmentsStart();
					ModuleNameAndOffset info = {filename, offset};
					if (isEnabled)
						controller->DisableBreakpoint(info);
					else
						controller->EnableBreakpoint(info);
				}
			},
			[=](const UIActionContext& ctxt) {
				auto [hasBreakpoint, isEnabled] = getBreakpointEnabledState(ctxt.binaryView, ctxt.address);
				return ctxt.binaryView && hasBreakpoint;
			}));
	
	// Dynamically change the action name based on the current breakpoint state
	UIAction::setActionDisplayName("Enable Breakpoint", [=](const UIActionContext& ctxt) -> QString {
		if (!ctxt.binaryView)
			return "Enable Breakpoint";
		
		auto [hasBreakpoint, isEnabled] = getBreakpointEnabledState(ctxt.binaryView, ctxt.address);
		if (hasBreakpoint && isEnabled)
			return "Disable Breakpoint";
		
		return "Enable Breakpoint";
	});
	
	debuggerMenu->addAction("Enable Breakpoint", "Breakpoint");

	// Register "Solo Breakpoint" action
	UIAction::registerAction("Solo Breakpoint");
	context->globalActions()->bindAction("Solo Breakpoint",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				// Get the current address breakpoint location
				bool isAbsoluteAddress = controller->IsConnected();
				ModuleNameAndOffset currentInfo;
				if (!isAbsoluteAddress)
				{
					std::string filename = controller->GetInputFile();
					uint64_t offset = ctxt.address - controller->GetViewFileSegmentsStart();
					currentInfo = {filename, offset};
				}

				// Disable all breakpoints
				std::vector<DebugBreakpoint> breakpoints = controller->GetBreakpoints();
				for (const auto& bp : breakpoints)
				{
					ModuleNameAndOffset info;
					info.module = bp.module;
					info.offset = bp.offset;
					controller->DisableBreakpoint(info);
				}

				// Enable the current breakpoint
				if (isAbsoluteAddress)
				{
					controller->EnableBreakpoint(ctxt.address);
				}
				else
				{
					controller->EnableBreakpoint(currentInfo);
				}
			},
			[=](const UIActionContext& ctxt) {
				auto [hasBreakpoint, isEnabled] = getBreakpointEnabledState(ctxt.binaryView, ctxt.address);
				return ctxt.binaryView && hasBreakpoint;
			}));
	debuggerMenu->addAction("Solo Breakpoint", "Breakpoint");

	UIAction::registerAction("Connect to Debug Server");
	context->globalActions()->bindAction("Connect to Debug Server",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

                if (controller->IsFirstConnectToDebugServer())
                {
                	auto adapterSettings = new AdapterSettingsDialog(context->mainWindow(), controller, "debug_server");
                	if (adapterSettings->exec() != QDialog::Accepted)
                		return;
                }

				if (controller->ConnectToDebugServer())
				{
					QMessageBox::information(context->mainWindow(), "Successfully connected",
						"Successfully connected to the debug server. Now you can launch or attach to a process.");
				}
				else
				{
					QMessageBox::warning(context->mainWindow(), "Failed to connect",
						"Cannot connect to the debug server. Please check the connection configuration.");
				}
			},
			notConnectedToDebugServer));
	debuggerMenu->addAction("Connect to Debug Server", "Launch");

	UIAction::registerAction("Disconnect from Debug Server");
	context->globalActions()->bindAction("Disconnect from Debug Server",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				if (controller->DisconnectDebugServer())
				{
					QMessageBox::information(context->mainWindow(), "Successfully disconnected",
						"Successfully disconnected from the debug server");
				}
				else
				{
					QMessageBox::warning(
						context->mainWindow(), "Failed to disconnect", "Cannot disconnect from the debug server.");
				}
			},
			connectedToDebugServer));
	debuggerMenu->addAction("Disconnect from Debug Server", "Launch");

	UIAction::registerAction("Connect to Remote Process");
	context->globalActions()->bindAction("Connect to Remote Process",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				if (controller->IsFirstConnect())
				{
					auto adapterSettings = new AdapterSettingsDialog(context->mainWindow(), controller, "connect");
					if (adapterSettings->exec() != QDialog::Accepted)
						return;
				}

				if (!ensureBinaryViewHasPlatform(controller->GetData(), context->mainWindow()))
					return;

				QString text = QString(
					"The debugger is connecting to the target and preparing the debugger binary view. \n"
					"This might take a while.");
				ProgressTask* task = new ProgressTask(
					context->mainWindow(), "Connecting", text, "", [&](ProgressFunction progress) {
						controller->Connect();

						// For now, this cant be canceled, as the Debugger model wasn't
			            // designed with that in mind. This function below can return false if canceling is enabled
						progress(1, 1);
						return;
					});
				task->wait();
			},
			notConnected));
	debuggerMenu->addAction("Connect to Remote Process", "Launch");

	QString showAreaWidgets = "Show Debugger Sidebar Widgets";
	UIAction::registerAction(showAreaWidgets);

	context->globalActions()->bindAction(showAreaWidgets, UIAction([](const UIActionContext& ctxt) {
		auto uiContext = ctxt.context;
		if (uiContext)
		{
			auto globalUI = GlobalDebuggerUI::GetForContext(uiContext);
			if (globalUI)
			{
				globalUI->SetDisplayingGlobalAreaWidgets(!globalUI->m_displayingGlobalAreaWidgets);
			}
		}
	}));
	context->globalActions()->setChecked(showAreaWidgets, [=](const UIActionContext& ctxt) {
		auto uiContext = ctxt.context;
		if (uiContext)
		{
			auto* globalUI = GlobalDebuggerUI::GetForContext(uiContext);
			if (globalUI)
				return globalUI->m_displayingGlobalAreaWidgets;
		}
		return false;
	});

	debuggerMenu->addAction(showAreaWidgets, "Options");

	UIAction::registerAction("Make Code", QKeySequence(Qt::Key_C));
	context->globalActions()->bindAction("Make Code",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if ((!ctxt.binaryView) || (!ctxt.view))
					return;

				auto selection = ctxt.view->getSelectionOffsets();
				MakeCodeHelper(ctxt.binaryView, selection);
			},
			requireBinaryView));
	debuggerMenu->addAction("Make Code", "Misc");

	UIAction::setActionDisplayName("Make Code", [](const UIActionContext& ctxt) -> QString {
		if (!ctxt.binaryView)
			return "Make Code";

		if (ShowAsCode(ctxt.binaryView, ctxt.address))
			return "Undefine Code";

		return "Make Code";
	});

	UIAction::registerAction("Jump to IP");
	context->globalActions()->bindAction("Jump to IP",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				JumpToIPCallback(ctxt.binaryView, context);
			},
			connectedAndStopped));
	debuggerMenu->addAction("Jump to IP", "Misc");

	UIAction::registerAction("Override IP");
	context->globalActions()->bindAction("Override IP",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				uint64_t address = ctxt.address;
				if (!controller->SetIP(ctxt.address))
					LogWarn("Failed to override IP to 0x%" PRIx64, address);
			},
			connectedAndStopped));
	debuggerMenu->addAction("Override IP", "Misc");

	UIAction::registerAction("Create Stack View");
	context->globalActions()->bindAction("Create Stack View",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				auto view = ctxt.context->getCurrentView();
				if (!view)
					return;

				view->navigateOnOtherPane(controller->StackPointer());
			},
			connectedAndStopped));
	debuggerMenu->addAction("Create Stack View", "Misc");

	UIAction::registerAction("Force Update Memory Cache");
	context->globalActions()->bindAction("Force Update Memory Cache",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				DebuggerEvent event;
				event.type = ForceMemoryCacheUpdateEvent;
				controller->PostDebuggerEvent(event);
			},
			connectedAndStopped));
	debuggerMenu->addAction("Force Update Memory Cache", "Misc");

	// Register actions for TTD widget context menus
	UIAction::registerAction("Copy Row");
	UIAction::registerAction("Copy Table");
	UIAction::registerAction("Column Visibility...");
	UIAction::registerAction("Reset Columns to Default");
  UIAction::registerAction("Refresh");

#ifdef WIN32
	UIAction::registerAction("Record TTD Trace");
	context->globalActions()->bindAction("Record TTD Trace",
		UIAction(
			[=](const UIActionContext& ctxt) {
				auto* dialog = new TTDRecordDialog(context->mainWindow(), ctxt.binaryView);
				dialog->show();
			}));
	debuggerMenu->addAction("Record TTD Trace", "TTD");

	UIAction::registerAction("Install WinDbg/TTD");
	context->globalActions()->bindAction("Install WinDbg/TTD",
		UIAction(
			[=](const UIActionContext& ctxt) { installTTD(ctxt); }));
	debuggerMenu->addAction("Install WinDbg/TTD", "TTD");

	// TTD Memory Access context menu items
	UIAction::registerAction("TTD Memory Access\\Read");
	context->globalActions()->bindAction("TTD Memory Access\\Read",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller || !controller->IsConnected())
					return;
				
				uint64_t startAddr, endAddr;
				GetAddressRange(ctxt, startAddr, endAddr);
				QueryTTDMemoryAccess(ctxt, startAddr, endAddr, DebuggerTTDMemoryRead);
			},
			connectedToTTD));
	debuggerMenu->addAction("TTD Memory Access\\Read", "TTD");

	UIAction::registerAction("TTD Memory Access\\Write");
	context->globalActions()->bindAction("TTD Memory Access\\Write",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller || !controller->IsConnected())
					return;
				
				uint64_t startAddr, endAddr;
				GetAddressRange(ctxt, startAddr, endAddr);
				QueryTTDMemoryAccess(ctxt, startAddr, endAddr, DebuggerTTDMemoryWrite);
			},
			connectedToTTD));
	debuggerMenu->addAction("TTD Memory Access\\Write", "TTD");

	UIAction::registerAction("TTD Memory Access\\Read/Write");
	context->globalActions()->bindAction("TTD Memory Access\\Read/Write",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller || !controller->IsConnected())
					return;
				
				uint64_t startAddr, endAddr;
				GetAddressRange(ctxt, startAddr, endAddr);
				QueryTTDMemoryAccess(ctxt, startAddr, endAddr, static_cast<BNDebuggerTTDMemoryAccessType>(DebuggerTTDMemoryRead | DebuggerTTDMemoryWrite));
			},
			connectedToTTD));
	debuggerMenu->addAction("TTD Memory Access\\Read/Write", "TTD");

	UIAction::registerAction("TTD Memory Access\\Execute");
	context->globalActions()->bindAction("TTD Memory Access\\Execute",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller || !controller->IsConnected())
					return;
				
				uint64_t startAddr, endAddr;
				GetAddressRange(ctxt, startAddr, endAddr);
				QueryTTDMemoryAccess(ctxt, startAddr, endAddr, DebuggerTTDMemoryExecute);
			},
			connectedToTTD));
	debuggerMenu->addAction("TTD Memory Access\\Execute", "TTD");

	UIAction::registerAction("TTD Memory Access\\Read/Write/Execute");
	context->globalActions()->bindAction("TTD Memory Access\\Read/Write/Execute",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller || !controller->IsConnected())
					return;
				
				uint64_t startAddr, endAddr;
				GetAddressRange(ctxt, startAddr, endAddr);
				QueryTTDMemoryAccess(ctxt, startAddr, endAddr, static_cast<BNDebuggerTTDMemoryAccessType>(DebuggerTTDMemoryRead | DebuggerTTDMemoryWrite | DebuggerTTDMemoryExecute));
			},
			connectedToTTD));
	debuggerMenu->addAction("TTD Memory Access\\Read/Write/Execute", "TTD");

	// TTD Calls menu actions
	UIAction::registerAction("TTD Calls\\Kernel32 Calls");
	context->globalActions()->bindAction("TTD Calls\\Kernel32 Calls", UIAction([=](const UIActionContext& ctxt) {
			auto controller = DebuggerController::GetController(ctxt.binaryView);
			if (!controller || !controller->IsConnected())
				return;

			// Query kernel32 calls
			QueryTTDCalls(ctxt, "kernel32!*");
		},
		connectedToTTD));
	debuggerMenu->addAction("TTD Calls\\Kernel32 Calls", "TTD");

	UIAction::registerAction("Navigate to TTD Timestamp...", QKeySequence(Qt::ShiftModifier | Qt::Key_G));
	context->globalActions()->bindAction("Navigate to TTD Timestamp...",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller || !controller->IsTTD())
					return;

				auto dialog = new TimestampNavigationDialog(ctxt.context->mainWindow(), controller);
				dialog->show();
				dialog->raise();
				dialog->activateWindow();
			},
			connectedToTTD));
	debuggerMenu->addAction("Navigate to TTD Timestamp...", "TTD");

	UIAction::registerAction("TTD Analysis...");
	context->globalActions()->bindAction("TTD Analysis...",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;

				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller || !controller->IsTTD())
					return;

				auto dialog = new TTDAnalysisDialog(ctxt.binaryView, nullptr);
				dialog->show();
				dialog->raise();
				dialog->activateWindow();
			},
			connectedToTTD));
	debuggerMenu->addAction("TTD Analysis...", "TTD");

#endif
}


#ifdef WIN32
void GlobalDebuggerUI::installTTD(const UIActionContext& ctxt)
{
	// Create and show progress dialog with actual progress range
	QProgressDialog* progress = new QProgressDialog("Initializing installation...", nullptr, 0, 100, ctxt.context->mainWindow());
	progress->setWindowModality(Qt::WindowModal);
	progress->setMinimumDuration(0);
	progress->setCancelButton(nullptr); // No cancel button since we can't safely cancel mid-installation
	progress->show();
	QCoreApplication::processEvents();

	// Use QTimer to run installation asynchronously
	QTimer::singleShot(100, [progress]() {
		bool success = false;
		try 
		{
			// Create progress callback to update the dialog
			auto progressCallback = [progress](const std::string& step, int progressPercent) {
				QMetaObject::invokeMethod(progress, [progress, step, progressPercent]() {
					progress->setLabelText(QString::fromStdString(step));
					if (progressPercent >= 0 && progressPercent <= 100)
					{
						progress->setValue(progressPercent);
					}
					QCoreApplication::processEvents();
				}, Qt::QueuedConnection);
			};

			success = BinaryNinjaDebugger::InstallWinDbg(progressCallback);
		}
		catch (...)
		{
			success = false;
		}

		progress->close();
		progress->deleteLater();
		
		if (success)
		{
			QMessageBox::information(nullptr, "Installation Complete", 
				"WinDbg/TTD has been successfully installed!\n\n"
				"Please restart Binary Ninja to make the changes take effect.");
		}
		else
		{
			QMessageBox::warning(nullptr, "Installation Failed",
				"Failed to install WinDbg/TTD. Please check the log for details.\n\n"
				"You can also install WinDbg manually by following the documentation:\n"
				"https://docs.binary.ninja/guide/debugger/dbgeng-ttd.html#install-windbg-manually");
		}
	});
}
#endif


DebuggerUI::DebuggerUI(UIContext* context, DebuggerControllerRef controller) :
	m_context(context), m_controller(controller)
{
	connect(this, &DebuggerUI::debuggerEvent, this, &DebuggerUI::updateUI);

	m_eventCallback = m_controller->RegisterEventCallback(
		[this](const DebuggerEvent& event) {
			emit debuggerEvent(event);
		},
		"UI");

	// Since the Controller is constructed earlier than the UI, any breakpoints added before the construction of the UI,
	// e.g. the entry point breakpoint, will be missing the visual indicator.
	// Here, we forcibly add them.
	for (auto bp : m_controller->GetBreakpoints())
	{
		DebuggerEvent event;
		event.type = RelativeBreakpointAddedEvent;
		event.data.relativeAddress.module = bp.module;
		event.data.relativeAddress.offset = bp.offset;
		updateUI(event);
	}

	m_uiCallbacks = new DebuggerUICallbacks;
	m_uiCallbacks->rebaseBinaryViewImpl = [&](uint64_t address)
	{
		checkRebaseBinaryView(address);
	};
	m_controller->SetDebuggerUICallbacks(m_uiCallbacks);
}


DebuggerUI::~DebuggerUI()
{
	if (m_uiCallbacks)
	{
		delete m_uiCallbacks;
		m_uiCallbacks = nullptr;
	}
	m_controller->RemoveEventCallback(m_eventCallback);
}


static void DebuggerUIRebaseCallback(void* ctxt, uint64_t address)
{
	DebuggerUICallbacks* object = (DebuggerUICallbacks* )ctxt;
	if (object)
		object->rebaseBinaryViewImpl(address);
}


DebuggerUICallbacks::DebuggerUICallbacks()
{
	m_callbacks.rebaseBinaryView = DebuggerUIRebaseCallback;
}


void GlobalDebuggerUI::SetDisplayingGlobalAreaWidgets(bool display)
{
	if (display)
		CreateGlobalAreaWidgets(m_context);
	else
		CloseGlobalAreaWidgets(m_context);

	m_displayingGlobalAreaWidgets = display;
}

void GlobalDebuggerUI::CreateGlobalAreaWidgets(UIContext* context)
{
	auto sidebar = context->sidebar();
	if (!sidebar)
		return;

	// Hacky way to create the Debugger Console. Note, since MainWindow internally keeps a list of scripting consoles,
	// even if we construct a ScriptingConsole instance in the very same way, the instance will not be tracked by the
	// MainWindow. The end result is the ScriptInstance will not be receiving callbacks like SetCurrentBinaryView, etc.
	// However, since MainWindow registers these operations in the command palette, we can trigger the action here to
	// emulate what happens when the user clicks the "Create Debugger Console" item.
	if (context->contentActionHandler())
	{
		if (!sidebar->hasWidgetWithTitle("Console", "Debugger"))
			context->contentActionHandler()->executeAction("Create Debugger Console");

		if (!sidebar->hasWidgetWithTitle("Console", "Target"))
			context->contentActionHandler()->executeAction("Create Target Console");
	}
}


void GlobalDebuggerUI::CloseGlobalAreaWidgets(UIContext* context)
{
	auto sidebar = context->sidebar();
	if (!sidebar)
		return;

	auto widget = sidebar->widgetWithTitle("Console", "Debugger");
	if (widget)
		sidebar->removeWidget("Console", widget);

	widget = sidebar->widgetWithTitle("Console", "Target");
	if (widget)
		sidebar->removeWidget("Console", widget);
}


// Navigate to the address. This has some special handling of the process which is useful for a debugging scenario.
// I believe at least some logic should be built into the default navigation behavior.
void DebuggerUI::navigateDebugger(uint64_t address)
{
	ViewFrame* frame = m_context->getCurrentViewFrame();
	View* view = m_context->getCurrentView();
	FunctionRef function = view->getCurrentFunction();
	if (function)
	{
		// If the user is viewing a function in the current View, then navigate the current frame.
		frame->navigate(m_controller->GetData(), address, true, true);
	}
	else
	{
		// Otherwise, the user is viewing some data. Do not navigate the current SyncGroup.
		// Instead, find a SyncGroup which is viewing a function. If none, fallback to navigating in the current frame.
		bool navigated = false;
		auto fileContext = frame->getFileContext();
		if (fileContext)
		{
			auto syncGroups = fileContext->allSyncGroups();
			for (const auto& syncGroup : syncGroups)
			{
				for (auto i : syncGroup->members())
				{
					View* groupView = i->getCurrentViewInterface();
					auto data = groupView->getData();
					bool dataMatch = data && (data == m_controller->GetData());
					if (dataMatch && groupView->getCurrentFunction())
					{
						navigated |= i->navigate(m_controller->GetData(), address, true, true);
						if (navigated)
							break;
					}
				}
			}
		}

		if (!navigated)
			frame->navigate(m_controller->GetData(), address, true, true);
	}

	openDebuggerSideBar(frame);
	m_context->refreshCurrentViewContents();
}


void DebuggerUI::openDebuggerSideBar(ViewFrame* frame)
{
	Sidebar* sidebar = nullptr;
	if (frame)
		sidebar = frame->getSidebar();

	if (!sidebar)
		sidebar = Sidebar::current();

	if (sidebar)
		sidebar->activate("Debugger", false);
}


void DebuggerUI::navigateToCurrentIP()
{
	uint64_t address = m_controller->IP();
	uint64_t lastIp = m_controller->GetLastIP();
	if (address == lastIp)
		return;

	BinaryViewRef liveView = m_controller->GetData();
	if (!liveView)
		return;

	auto functions = liveView->GetAnalysisFunctionsContainingAddress(address);
	if (functions.empty() && !m_controller->FunctionExistsInOldView(address))
	{
		auto data = m_controller->GetData();
		auto id = data->BeginUndoActions();
		liveView->CreateUserFunction(data->GetDefaultPlatform(), address);
		data->ForgetUndoActions(id);
	}

	navigateDebugger(address);
}


void DebuggerUI::checkFocusDebuggerConsole()
{
	auto context = UIContext::activeContext();
	if (!context)
		return;

	auto globalArea = context->globalArea();
	if (!globalArea)
		return;

	auto widget = globalArea->widget("Debugger Console");
	if (widget)
		globalArea->focusWidget("Debugger Console");
}


void DebuggerUI::navigateToMappedAddress()
{
	auto frame = m_context->getCurrentViewFrame();
	if (!frame)
		return;

	auto address = frame->getCurrentOffset();
	auto data = m_controller->GetData();
	if (!data || data->GetSegmentAt(address))
		return;

	auto entryFunction = data->GetAnalysisEntryPoint();
	if (entryFunction)
	{
		if (frame->navigate(data, entryFunction->GetStart(), true, true))
			return;
	}

	frame->navigate(data, data->GetStart(), true, true);
}


void DebuggerUI::checkRebaseBinaryView(uint64_t remoteBase)
{
	Ref<BinaryView> data = m_controller->GetData();
	FileMetadataRef fileMetadata = data->GetFile();
	ViewFrame* frame = m_context->getCurrentViewFrame();

	// Halt analysis when replacing a BinaryView in the UI. If the view is replaced and the tab or
	// application closes, then the old view may continue analysis without the updated UI having a
	// reference to properly terminate it before UI destruction.
	data->AbortAnalysis();
	data->UpdateAnalysisAndWait();

	ExecuteOnMainThreadAndWait([&]()
	{
		m_controller->RemoveDebuggerMemoryRegion();
		bool result = false;
		QString text = QString("Rebasing the input view...");
		ProgressTask* task =
			new ProgressTask(frame, "Rebase", text, "Cancel", [&](ProgressFunction progress) {
				// If analysis hold during debugging is active, we must first turn it off, rebase, wait for the
				// analysis to complete, and then set the analysis hold back on. This is because during rebasing,
				// all the advanced analysis data is discarded has to be regenerated. If we still holds the
				// analysis, these function will become un-analyzed and not show up in the linear view
				auto shouldHoldAnalysis = Settings::Instance()->Get<bool>("debugger.holdAnalysis");
				if (shouldHoldAnalysis)
					data->SetAnalysisHold(false);

				auto viewType = data->GetTypeName();
				result = fileMetadata->Rebase(data, remoteBase, progress);
				if (!result)
					return;

				auto rebasedView = fileMetadata->GetViewOfType(viewType);
				if (!rebasedView)
					return;

				if (shouldHoldAnalysis)
				{
					static auto completionEvent = rebasedView->AddAnalysisCompletionEvent([=](){
						rebasedView->SetAnalysisHold(true);
					});
					rebasedView->UpdateAnalysis();
				}
			});
		task->wait();

		if (!result)
		{
			LogWarn("failed to rebase the input view");
			return;
		}

		m_controller->ReAddDebuggerMemoryRegion();

		ViewFrame* frame = m_context->getCurrentViewFrame();
		if (!frame)
			return;

		FileContext* fileContext = frame->getFileContext();
		if (!fileContext)
			return;

		fileContext->refreshDataViewCache();
		m_context->recreateViewFrames(fileContext);
		navigateToCurrentIP();
		QCoreApplication::processEvents();
	});
}


void DebuggerUI::updateUI(const DebuggerEvent& event)
{
	if ((event.type == LaunchEventType) || (event.type == AttachEventType) || (event.type == ConnectEventType))
	{
		auto* globalUI = GlobalDebuggerUI::GetForContext(m_context);
		if (globalUI)
			globalUI->SetDisplayingGlobalAreaWidgets(true);
	}

	switch (event.type)
	{
	case DetachedEventType:
	case TargetExitedEventType:
	{
		ViewFrame* frame = m_context->getCurrentViewFrame();
		if (!frame)
			break;

		FileContext* fileContext = frame->getFileContext();
		if (!fileContext)
			break;

		fileContext->refreshDataViewCache();
		m_context->recreateViewFrames(fileContext);
		navigateToMappedAddress();
		QCoreApplication::processEvents();
		break;
	}

	case LaunchFailureEventType:
	{
		QMessageBox::critical(nullptr, QString::fromStdString(event.data.errorData.shortError),
			QString::fromStdString(event.data.errorData.error));
		break;
	}

	case TargetStoppedEventType:
	case ActiveThreadChangedEvent:
	{
		// If there is no function at the current address, define one. This might be a little aggressive,
		// but given that we are lacking the ability to "show as code", this feels like an OK workaround.
		BinaryViewRef liveView = m_controller->GetData();
		if (!liveView)
			break;

		navigateToCurrentIP();
		checkFocusDebuggerConsole();
		break;
	}

	case RelativeBreakpointAddedEvent:
	case AbsoluteBreakpointAddedEvent:
	case RelativeBreakpointRemovedEvent:
	case AbsoluteBreakpointRemovedEvent:
	case RelativeBreakpointEnabledEvent:
	case AbsoluteBreakpointEnabledEvent:
	case RelativeBreakpointDisabledEvent:
	case AbsoluteBreakpointDisabledEvent:
	{
		m_context->refreshCurrentViewContents();
		break;
	}
	case RegisterChangedEvent:
	{
		navigateToCurrentIP();
		break;
	}
	case ResumeEventType:
	{
		m_context->refreshCurrentViewContents();
		break;
	}

	default:
		break;
	}
}


void GlobalDebuggerUI::InitializeUI()
{
	Sidebar::addSidebarWidgetType(new DebuggerWidgetType(QImage(":/debugger/debugger"), "Debugger"));
	Sidebar::addSidebarWidgetType(new DebugModulesSidebarWidgetType());
	Sidebar::addSidebarWidgetType(new ThreadFramesSidebarWidgetType());
	Sidebar::addSidebarWidgetType(new DebugInfoWidgetType());
	Sidebar::addSidebarWidgetType(new TTDMemoryWidgetType());
	Sidebar::addSidebarWidgetType(new TTDCallsWidgetType());
	Sidebar::addSidebarWidgetType(new TTDEventsWidgetType());
}


DebuggerUI* DebuggerUI::CreateForViewFrame(ViewFrame* frame)
{
	if (!frame)
		return nullptr;

	UIContext* context = UIContext::contextForWidget(frame);
	BinaryViewRef data = frame->getCurrentBinaryView();
	if (!data)
		return nullptr;

	auto controller = DebuggerController::GetController(data);
	if (!controller)
		return nullptr;

	if (g_viewFrameMap.find(frame) != g_viewFrameMap.end())
	{
		return g_viewFrameMap[frame].get();
	}
	g_viewFrameMap.try_emplace(frame, std::make_unique<DebuggerUI>(context, controller));
	connect(frame, &QObject::destroyed, [&](QObject* obj) {
		auto* vf = (ViewFrame*)obj;
		g_viewFrameMap.erase(vf);
	});
	return g_viewFrameMap[frame].get();
}


DebuggerUI* DebuggerUI::GetForViewFrame(ViewFrame* frame)
{
	if (g_viewFrameMap.find(frame) != g_viewFrameMap.end())
	{
		return g_viewFrameMap[frame].get();
	}
	return nullptr;
}


void DebuggerUI::DeleteForViewFrame(ViewFrame* frame)
{
	g_viewFrameMap.erase(frame);
}


GlobalDebuggerUI* GlobalDebuggerUI::CreateForContext(UIContext* context)
{
	if (g_contextMap.find(context) != g_contextMap.end())
	{
		return g_contextMap[context].get();
	}
	g_contextMap.try_emplace(context, std::make_unique<GlobalDebuggerUI>(context));
	return g_contextMap[context].get();
}


GlobalDebuggerUI* GlobalDebuggerUI::GetForContext(UIContext* context)
{
	if (g_contextMap.find(context) != g_contextMap.end())
	{
		return g_contextMap[context].get();
	}
	return nullptr;
}


void GlobalDebuggerUI::RemoveForContext(UIContext* context)
{
	g_contextMap.erase(context);
}


void GlobalDebuggerUI::SetActiveFrame(ViewFrame* frame)
{
	[[maybe_unused]] auto ui = DebuggerUI::CreateForViewFrame(frame);
	m_status->notifyViewChanged(frame);
}


extern "C"
{
	BN_DECLARE_UI_ABI_VERSION
	BN_DECLARE_CORE_ABI_VERSION

// In Demo, plugins are explicitly loaded. So there is no need to specify dependencies
#ifndef DEMO_EDITION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		SetCurrentPluginLoadOrder(LatePluginLoadOrder);
	}
#endif

#ifdef DEMO_EDITION
	bool DebuggerUIPluginInit()
#else
	BINARYNINJAPLUGIN bool UIPluginInit()
#endif
	{
		GlobalDebuggerUI::InitializeUI();
		NotificationListener::init();
		DataRendererContainer::RegisterTypeSpecificDataRenderer(new CodeDataRenderer);
		RegisterDebugAdapterScriptingProvider();
		RegisterTargetScriptingProvider();
		RegisterRenderLayers();
		return true;
	}
}


ActiveDebugSessionSidebarContentClassifier::ActiveDebugSessionSidebarContentClassifier(BinaryViewRef data)
{
	m_debugger = DebuggerController::GetController(data);
	if (m_debugger)
	{
		if (m_debugger->IsConnected())
			m_contentClassification = SidebarHasRelevantContent;

		m_eventIndex = m_debugger->RegisterEventCallback(
			[this](const DebuggerEvent& event) {
				switch (event.type)
				{
				case LaunchEventType:
				case ResumeEventType:
				case StepIntoEventType:
				case TargetStoppedEventType:
					m_contentClassification = SidebarHasRelevantContent;
					Q_EMIT contentClassificationChanged();
					break;
				case DetachedEventType:
				case LaunchFailureEventType:
					m_contentClassification = SidebarHasNoContent;
					Q_EMIT contentClassificationChanged();
					break;
				default:
					break;
				}
			},
			"Active Debug Session Sidebar Content Classifier");
	}
}


ActiveDebugSessionSidebarContentClassifier::~ActiveDebugSessionSidebarContentClassifier()
{
	if (m_debugger)
		m_debugger->RemoveEventCallback(m_eventIndex);
}
