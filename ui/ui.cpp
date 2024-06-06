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

#include "ui.h"
#include "binaryninjaapi.h"
#include "breakpointswidget.h"
#include "moduleswidget.h"
#include "stackwidget.h"
#include "uinotification.h"
#include "platformdialog.h"
#include "QPainter"
#include <QStatusBar>
#include <QCoreApplication>
#include "fmt/format.h"
#include "threadframes.h"
#include "syncgroup.h"
#include "codedatarenderer.h"
#include "adaptersettings.h"
#include <thread>
#include <QInputDialog>
#include <filesystem>
#include <QMessageBox>
#include "debugserversetting.h"
#include "remoteprocess.h"
#include "debugadapterscriptingprovider.h"
#include "targetscriptingprovier.h"
#include "progresstask.h"
#include "attachprocess.h"
#include "progresstask.h"

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
	// TODO: check if this works
	if (view->GetTypeName() == "Debugger")
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
		uint64_t offset = addr - view->GetStart();
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

	if (controller->GetLiveView())
		frame->navigate(controller->GetLiveView(), controller->IP(), true, true);
	else
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
		return;
	}

	auto id = view->BeginUndoActions();
	view->DefineUserDataVariable(addr, Type::ArrayType(Type::IntegerType(1, false), end - addr));
	const std::string name = fmt::format("BN_CODE_start_0x{:x}_size_0x{:x}", addr, end - addr);
	SymbolRef sym = new Symbol(DataSymbol, name, name, name, addr);
	view->DefineUserSymbol(sym);
	view->CommitUndoActions(id);
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
				if (controller->IsFirstLaunch() && Settings::Instance()->Get<bool>("debugger.confirmFirstLaunch"))
				{
					auto prompt = QString("You are about to launch \n\n%1\n\non your machine. "
						"This may harm your machine. Are you sure to continue?").
					  	arg(QString::fromStdString(controller->GetExecutablePath()));
					if (QMessageBox::question(context->mainWindow(), "Launch Target", prompt) != QMessageBox::Yes)
						return;
				}

				if (!ensureBinaryViewHasPlatform(controller->GetData(), context->mainWindow()))
					return;

				QString text = QString(
					"The debugger is launching the target and preparing the debugger binary view. \n"
					"This might take a while.");
				ProgressTask* task = new ProgressTask(
					context->mainWindow(), "Launching", text, "", [&](std::function<bool(size_t, size_t)> progress) {
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
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->Go();
			},
			connectedAndStopped));
	debuggerMenu->addAction("Resume", "Control");

	UIAction::registerAction("Go Backwards", QKeySequence(Qt::ShiftModifier | Qt::Key_F9));
	context->globalActions()->bindAction("Go Backwards",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->GoReverse();
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Step Into", QKeySequence(Qt::Key_F7));
	context->globalActions()->bindAction("Step Into",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType();
				controller->StepInto(graphType);
			},
			connectedAndStopped));
	debuggerMenu->addAction("Step Into", "Control");

	UIAction::registerAction("Step Into Backwards", QKeySequence(Qt::ShiftModifier | Qt::Key_F7));
	context->globalActions()->bindAction("Step Into Backwards",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType();
				controller->StepIntoReverse(graphType);
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Step Over", QKeySequence(Qt::Key_F8));
	context->globalActions()->bindAction("Step Over",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType();
				controller->StepOver(graphType);
			},
			connectedAndStopped));
	debuggerMenu->addAction("Step Over", "Control");

	UIAction::registerAction("Step Over Backwards", QKeySequence(Qt::ShiftModifier | Qt::Key_F8));
	context->globalActions()->bindAction("Step Over Backwards",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				BNFunctionGraphType graphType = NormalFunctionGraph;
				if (ctxt.context && ctxt.context->getCurrentView())
					graphType = ctxt.context->getCurrentView()->getILViewType();
				controller->StepOverReverse(graphType);
			},
			connectedAndStoppedWithTTD));

	UIAction::registerAction("Step Return", QKeySequence(Qt::ControlModifier | Qt::Key_F9));
	context->globalActions()->bindAction("Step Return",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->StepReturn();
			},
			connectedAndStopped));
	debuggerMenu->addAction("Step Return", "Control");

	UIAction::registerAction("Step Return Backwards", QKeySequence( Qt::ControlModifier | Qt::ShiftModifier | Qt::Key_F9 ));
	context->globalActions()->bindAction("Step Return Backwards",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				controller->StepReturnReverse();
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

				controller->Restart();
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
					context->mainWindow(), "Attaching", text, "", [&](std::function<bool(size_t, size_t)> progress) {
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

	UIAction::registerAction("Connect to Debug Server");
	context->globalActions()->bindAction("Connect to Debug Server",
		UIAction(
			[=](const UIActionContext& ctxt) {
				if (!ctxt.binaryView)
					return;
				auto controller = DebuggerController::GetController(ctxt.binaryView);
				if (!controller)
					return;

				auto dialog = new DebugServerSettingsDialog(context->mainWindow(), controller);
				if (dialog->exec() != QDialog::Accepted)
					return;

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

				auto dialog = new RemoteProcessSettingsDialog(context->mainWindow(), controller);
				if (dialog->exec() != QDialog::Accepted)
					return;

				if (!ensureBinaryViewHasPlatform(controller->GetData(), context->mainWindow()))
					return;

				QString text = QString(
					"The debugger is connecting to the target and preparing the debugger binary view. \n"
					"This might take a while.");
				ProgressTask* task = new ProgressTask(
					context->mainWindow(), "Connecting", text, "", [&](std::function<bool(size_t, size_t)> progress) {
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

	//	There is no longer a need to manually create the debug adapter. It will be automatically created if it is
	//  accessed but not created yet.
	//	UIAction::registerAction("Activate Debug Adapter");
	//	context->globalActions()->bindAction("Activate Debug Adapter", UIAction([=](const UIActionContext& ctxt) {
	//		if (!ctxt.binaryView)
	//			return;
	//		auto controller = DebuggerController::GetController(ctxt.binaryView);
	//		if (!controller)
	//			return;
	//
	//		if (controller->ActivateDebugAdapter())
	//        {
	//            QMessageBox::information(context->mainWindow(), "Successfully activated",
	//                                     "Successfully activated the debug adapter. Now you can run backend commands directly.");
	//        }
	//		else
	//        {
	//            QMessageBox::information(context->mainWindow(), "Failed to activate",
	//                                     "Cannot activate to the debug adapter.");
	//        }
	//	}));
	//	debuggerMenu->addAction("Activate Debug Adapter", "Launch");

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

				uint64_t address = 0;
				if (!ViewFrame::getAddressFromInput(ctxt.context->getCurrentViewFrame(), ctxt.binaryView, address,
						ctxt.address, "Override IP", "New instruction pointer value:", true))
					return;

				if (!controller->SetIP(address))
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
}


DebuggerUI::DebuggerUI(UIContext* context, DebuggerControllerRef controller) :
	m_context(context), m_controller(controller)
{
	connect(this, &DebuggerUI::debuggerEvent, this, &DebuggerUI::updateUI);

	m_eventCallback = m_controller->RegisterEventCallback(
		[this](const DebuggerEvent& event) {
			if ((event.type == LaunchEventType) || (event.type == AttachEventType) || (event.type == ConnectEventType))
			{
				auto* globalUI = GlobalDebuggerUI::GetForContext(m_context);
				if (globalUI)
					globalUI->SetDisplayingGlobalAreaWidgets(true);
			}
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
}


DebuggerUI::~DebuggerUI()
{
	m_controller->RemoveEventCallback(m_eventCallback);
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

	auto widget = sidebar->widget("Stack Trace");
	if (!widget)
	{
		auto* globalThreadFramesContainer = new GlobalThreadFramesContainer("Stack Trace");
		sidebar->addWidget("Stack Trace", globalThreadFramesContainer);
	}

	widget = sidebar->widget("Debugger Modules");
	if (!widget)
	{
		auto* globalDebugModulesContainer = new GlobalDebugModulesContainer("Debugger Modules");
		sidebar->addWidget("Debugger Modules", globalDebugModulesContainer);
	}
}


void GlobalDebuggerUI::CloseGlobalAreaWidgets(UIContext* context)
{
	auto sidebar = context->sidebar();
	if (!sidebar)
		return;

	auto widget = sidebar->widget("Stack Trace");
	if (widget)
		sidebar->removeWidget("Stack Trace", widget);

	widget = sidebar->widget("Debugger Modules");
	if (widget)
		sidebar->removeWidget("Debugger Modules", widget);

	widget = sidebar->widgetWithTitle("Console", "Debugger");
	if (widget)
		sidebar->removeWidget("Console", widget);

	widget = sidebar->widgetWithTitle("Console", "Target");
	if (widget)
		sidebar->removeWidget("Console", widget);
}


TagTypeRef DebuggerUI::getPCTagType(BinaryViewRef data)
{
	TagTypeRef type = data->GetTagType("Program Counter");
	if (type)
		return type;

	TagTypeRef pcTagType = new TagType(data, "Program Counter", "=>");
	data->AddTagType(pcTagType);
	return pcTagType;
}


TagTypeRef DebuggerUI::getBreakpointTagType(BinaryViewRef data)
{
	TagTypeRef type = data->GetTagType("Breakpoints");
	if (type)
		return type;

	TagTypeRef pcTagType = new TagType(data, "Breakpoints", "🛑");
	data->AddTagType(pcTagType);
	return pcTagType;
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
		frame->navigate(m_controller->GetLiveView(), address, true, true);
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
					bool dataMatch = (data && (data == m_controller->GetLiveView() || data == m_controller->GetData()));
					if (dataMatch && groupView->getCurrentFunction())
					{
						navigated |= i->navigate(m_controller->GetLiveView(), address, true, true);
						if (navigated)
							break;
					}
				}
			}
		}

		if (!navigated)
			frame->navigate(m_controller->GetLiveView(), address, true, true);
	}

	openDebuggerSideBar(frame);
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


void DebuggerUI::updateIPHighlight()
{
	uint64_t lastIP = m_controller->GetLastIP();
	uint64_t address = m_controller->IP();
	if (address == lastIP)
		return;

	BinaryViewRef data = m_controller->GetLiveView();
	if (!data)
		return;

	// Remove old instruction pointer highlight
	for (FunctionRef func : data->GetAnalysisFunctionsContainingAddress(lastIP))
	{
		ModuleNameAndOffset addr;
		addr.module = m_controller->GetInputFile();
		addr.offset = lastIP - data->GetStart();

		BNHighlightStandardColor oldColor = NoHighlightColor;
		if (m_controller->ContainsBreakpoint(addr))
			oldColor = RedHighlightColor;

		func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), lastIP, oldColor);
		for (TagRef tag : func->GetAddressTags(data->GetDefaultArchitecture(), lastIP))
		{
			if (tag->GetType() != getPCTagType(data))
				continue;

			auto id = data->BeginUndoActions();
			func->RemoveUserAddressTag(data->GetDefaultArchitecture(), lastIP, tag);
			data->ForgetUndoActions(id);
		}
	}

	// Add new instruction pointer highlight
	for (FunctionRef func : data->GetAnalysisFunctionsContainingAddress(address))
	{
		bool tagFound = false;
		for (TagRef tag : func->GetAddressTags(data->GetDefaultArchitecture(), address))
		{
			if (tag->GetType() == getPCTagType(data))
			{
				tagFound = true;
				break;
			}
		}

		if (!tagFound)
		{
			auto id = data->BeginUndoActions();
			func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, BlueHighlightColor);
			func->CreateUserAddressTag(data->GetDefaultArchitecture(), address, getPCTagType(data), "program counter");
			data->ForgetUndoActions(id);
		}
	}
}


void DebuggerUI::navigateToCurrentIP()
{
	uint64_t address = m_controller->IP();
	uint64_t lastIp = m_controller->GetLastIP();
	if (address == lastIp)
		return;

	BinaryViewRef liveView = m_controller->GetLiveView();
	if (!liveView)
		return;

	auto functions = liveView->GetAnalysisFunctionsContainingAddress(address);
	if (functions.empty())
	{
		auto data = m_controller->GetLiveView();
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


void DebuggerUI::updateUI(const DebuggerEvent& event)
{
	switch (event.type)
	{
	case DetachedEventType:
	case QuitDebuggingEventType:
	case TargetExitedEventType:
	{
		ViewFrame* frame = m_context->getCurrentViewFrame();
		if (!frame)
			break;

		// Workaround for https://github.com/Vector35/debugger/issues/367
		auto settings = Settings::Instance();
		bool oldRestoreView = false;
		if (settings->Contains("ui.files.restore.viewState"))
		{
			oldRestoreView = settings->Get<bool>("ui.files.restore.viewState");
			if (oldRestoreView)
				settings->Set("ui.files.restore.viewState", false);
		}

		FileContext* fileContext = frame->getFileContext();
		auto tab = m_context->getTabForFile(fileContext);
		ViewFrame* newFrame = m_context->openFileContext(fileContext);
		QCoreApplication::processEvents();

		if (newFrame)
		{
			newFrame->navigate(m_controller->GetData(), m_controller->GetData()->GetEntryPoint(), true, true);
			m_context->closeTab(tab);
			fileContext->refreshDataViewCache();
			openDebuggerSideBar(newFrame);
			QCoreApplication::processEvents();
		}
		else
		{
			LogWarn("fail to navigate to the original view");
		}

		if (oldRestoreView)
			settings->Set("ui.files.restore.viewState", true);

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
		BinaryViewRef liveView = m_controller->GetLiveView();
		if (!liveView)
			break;

		if (event.type == TargetStoppedEventType
			&& event.data.targetStoppedData.reason == DebugStopReason::InitialBreakpoint)
		{
			ViewFrame* frame = m_context->getCurrentViewFrame();
			FileContext* fileContext = frame->getFileContext();
			fileContext->refreshDataViewCache();
			m_context->recreateViewFrames(fileContext);
			navigateToCurrentIP();
			QCoreApplication::processEvents();
		}
		else
		{
			navigateToCurrentIP();
		}

		updateIPHighlight();
		checkFocusDebuggerConsole();
		break;
	}

	case ModuleLoadedEvent:
	{
		uint64_t remoteBase = event.data.absoluteAddress;
		Ref<BinaryView> data = m_controller->GetData();
		FileMetadataRef fileMetadata = data->GetFile();
		ViewFrame* frame = m_context->getCurrentViewFrame();

		if (remoteBase != data->GetStart())
		{
			bool result = false;
			QString text = QString("Rebasing the input view...");
			ProgressTask* task =
				new ProgressTask(frame, "Rebase", text, "Cancel", [&](std::function<bool(size_t, size_t)> progress) {
					result = fileMetadata->Rebase(data, remoteBase, progress);
				});
			task->wait();

			if (!result)
			{
				LogWarn("failed to rebase the input view");
				break;
			}
		}

		Ref<BinaryView> rebasedView = fileMetadata->GetViewOfType(data->GetTypeName());

		bool result = false;
		QString text = QString("Adding the input view into the debugger view...");
		ProgressTask* task =
			new ProgressTask(frame, "Adding view", text, "Cancel", [&](std::function<bool(size_t, size_t)> progress) {
				result = fileMetadata->CreateSnapshotedView(rebasedView, "Debugger", progress);
			});
		task->wait();

		if (!result)
		{
			LogWarn("failed add the input view into the debugger view");
			break;
		}

		break;
	}

	case RelativeBreakpointAddedEvent:
	{
		uint64_t address = m_controller->RelativeAddressToAbsolute(event.data.relativeAddress);

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		if (m_controller->GetLiveView())
			dataAndAddress.emplace_back(m_controller->GetLiveView(), address);

		if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module, m_controller->GetInputFile()))
		{
			dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + event.data.relativeAddress.offset);
		}

		for (auto& [data, addr] : dataAndAddress)
		{
			for (FunctionRef func : data->GetAnalysisFunctionsContainingAddress(addr))
			{
				bool tagFound = false;
				for (TagRef tag : func->GetAddressTags(data->GetDefaultArchitecture(), addr))
				{
					if (tag->GetType() == getBreakpointTagType(data))
					{
						tagFound = true;
						break;
					}
				}

				if (!tagFound)
				{
					auto id = data->BeginUndoActions();
					func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), addr, RedHighlightColor);
					func->CreateUserAddressTag(data->GetDefaultArchitecture(), addr, getBreakpointTagType(data), "breakpoint");
					data->ForgetUndoActions(id);
				}
			}
		}
		break;
	}
	case AbsoluteBreakpointAddedEvent:
	{
		uint64_t address = event.data.absoluteAddress;

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		BinaryViewRef data = m_controller->GetLiveView();
		if (data)
			dataAndAddress.emplace_back(data, address);

		ModuleNameAndOffset relative = m_controller->AbsoluteAddressToRelative(address);
		if (DebugModule::IsSameBaseModule(relative.module, m_controller->GetInputFile()))
		{
			dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + relative.offset);
		}

		for (auto& [data, address] : dataAndAddress)
		{
			for (FunctionRef func : data->GetAnalysisFunctionsContainingAddress(address))
			{
				bool tagFound = false;
				for (TagRef tag : func->GetAddressTags(data->GetDefaultArchitecture(), address))
				{
					if (tag->GetType() == getBreakpointTagType(data))
					{
						tagFound = true;
						break;
					}
				}

				if (!tagFound)
				{
					auto id = data->BeginUndoActions();
					func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, RedHighlightColor);
					func->CreateUserAddressTag(data->GetDefaultArchitecture(), address, getBreakpointTagType(data), "breakpoint");
					data->ForgetUndoActions(id);
				}
			}
		}
		break;
	}
	case RelativeBreakpointRemovedEvent:
	{
		uint64_t address = m_controller->RelativeAddressToAbsolute(event.data.relativeAddress);

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		if (m_controller->GetLiveView())
			dataAndAddress.emplace_back(m_controller->GetLiveView(), address);

		if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module, m_controller->GetInputFile()))
		{
			dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + event.data.relativeAddress.offset);
		}

		for (auto& [data, address] : dataAndAddress)
		{
			for (FunctionRef func : data->GetAnalysisFunctionsContainingAddress(address))
			{
				func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, NoHighlightColor);
				for (TagRef tag : func->GetAddressTags(data->GetDefaultArchitecture(), address))
				{
					if (tag->GetType() != getBreakpointTagType(data))
						continue;

					auto id = data->BeginUndoActions();
					func->RemoveUserAddressTag(data->GetDefaultArchitecture(), address, tag);
					data->ForgetUndoActions(id);
				}
			}
		}
		break;
	}
	case AbsoluteBreakpointRemovedEvent:
	{
		uint64_t address = event.data.absoluteAddress;

		std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
		BinaryViewRef data = m_controller->GetLiveView();
		if (data)
			dataAndAddress.emplace_back(data, address);

		ModuleNameAndOffset relative = m_controller->AbsoluteAddressToRelative(address);
		if (DebugModule::IsSameBaseModule(relative.module, m_controller->GetInputFile()))
		{
			dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + relative.offset);
		}

		for (auto& [data, address] : dataAndAddress)
		{
			for (FunctionRef func : data->GetAnalysisFunctionsContainingAddress(address))
			{
				func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, NoHighlightColor);
				for (TagRef tag : func->GetAddressTags(data->GetDefaultArchitecture(), address))
				{
					if (tag->GetType() != getBreakpointTagType(data))
						continue;

					auto id = data->BeginUndoActions();
					func->RemoveUserAddressTag(data->GetDefaultArchitecture(), address, tag);
					data->ForgetUndoActions(id);
				}
			}
		}
		break;
	}
	case RegisterChangedEvent:
	{
		navigateToCurrentIP();
		updateIPHighlight();
		break;
	}

	default:
		break;
	}
}


static bool BinaryViewValid(BinaryView* view, uint64_t addr)
{
	return true;
}


static void RunToHereCallback(BinaryView* view, uint64_t addr)
{
	auto controller = DebuggerController::GetController(view);
	if (!controller)
		return;
	std::thread([=]() { controller->RunTo(addr); }).detach();
}


static bool ConnectedAndStopped(BinaryView* view, uint64_t addr)
{
	if (!DebuggerController::ControllerExists(view))
		return false;
	auto controller = DebuggerController::GetController(view);
	if (!controller)
		return false;
	return controller->IsConnected() && (!controller->IsRunning());
}


static bool ConnectedAndRunning(BinaryView* view, uint64_t addr)
{
	if (!DebuggerController::ControllerExists(view))
		return false;
	auto controller = DebuggerController::GetController(view);
	if (!controller)
		return false;
	return controller->IsConnected() && controller->IsRunning();
}


void GlobalDebuggerUI::InitializeUI()
{
	Sidebar::addSidebarWidgetType(new DebuggerWidgetType(QImage(":/debugger/debugger"), "Debugger"));
	Sidebar::addSidebarWidgetType(new DebugModulesSidebarWidgetType());
	Sidebar::addSidebarWidgetType(new ThreadFramesSidebarWidgetType());

	// We must use the sequence of these four calls to do the job, otherwise the keybinding does not work.
	// Though it really should be the case where I can specify the keybinding in the first registerAction() call.
	UIAction::registerAction("Debugger\\Toggle Breakpoint");
	UIAction::registerAction("Selection Target\\Debugger\\Toggle Breakpoint");
	PluginCommand::RegisterForAddress("Debugger\\Toggle Breakpoint", "Sets/clears breakpoint at right-clicked address",
		BreakpointToggleCallback, BinaryViewValid);

	UIAction::registerAction("Debugger\\Run To Here");
	UIAction::registerAction("Selection Target\\Debugger\\Run To Here");
	PluginCommand::RegisterForAddress(
		"Debugger\\Run To Here", "Run until the current address", RunToHereCallback, ConnectedAndStopped);

	std::string actionName = "Run";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
		QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(), "Launch or resume the target",
		[](BinaryView* view, uint64_t addr) {
			auto controller = DebuggerController::GetController(view);
			if (!controller)
				return;
			if (controller->IsConnected() && (!controller->IsRunning()))
			{
				std::thread([=]() { controller->Go(); }).detach();
			}
			else if (!controller->IsConnected())
			{
				QString text = QString(
					"The debugger is launching the target and preparing the debugger binary view. \n"
					"This might take a while.");
				ProgressTask* task =
					new ProgressTask(nullptr, "Launching", text, "", [&](std::function<bool(size_t, size_t)> progress) {
						controller->Launch();

						// For now, this cant be canceled, as the Debugger model wasn't
				        // designed with that in mind. This function below can return false if canceling is enabled
						progress(1, 1);
						return;
					});
				task->wait();
			}
		},
		BinaryViewValid);

	actionName = "Step Into";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
		QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(), "Step into",
		[](BinaryView* view, uint64_t) {
			auto controller = DebuggerController::GetController(view);
			if (!controller)
				return;
			BNFunctionGraphType graphType = NormalFunctionGraph;
			UIContext* context = UIContext::activeContext();
			if (context && context->getCurrentView())
				graphType = context->getCurrentView()->getILViewType();
			std::thread([=]() { controller->StepInto(graphType); }).detach();
		},
		ConnectedAndStopped);

	actionName = "Step Over";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
		QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(), "Step over",
		[](BinaryView* view, uint64_t) {
			auto controller = DebuggerController::GetController(view);
			if (!controller)
				return;
			BNFunctionGraphType graphType = NormalFunctionGraph;
			UIContext* context = UIContext::activeContext();
			if (context && context->getCurrentView())
				graphType = context->getCurrentView()->getILViewType();
			std::thread([=]() { controller->StepOver(graphType); }).detach();
		},
		ConnectedAndStopped);

	actionName = "Step Return";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
		QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(), "Step return",
		[](BinaryView* view, uint64_t) {
			auto controller = DebuggerController::GetController(view);
			if (!controller)
				return;
			std::thread([=]() { controller->StepReturn(); }).detach();
		},
		ConnectedAndStopped);

	actionName = "Pause";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
		QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(), "Pause the target",
		[](BinaryView* view, uint64_t) {
			auto controller = DebuggerController::GetController(view);
			if (!controller)
				return;
			std::thread([=]() { controller->Pause(); }).detach();
		},
		ConnectedAndRunning);

//	actionName = "Make Code";
//	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()), QKeySequence(Qt::Key_C));
//	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
//	PluginCommand::RegisterForAddress(
//			QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(),
//			"Create raw disassembly",
//			[](BinaryView* view, uint64_t addr){
//					MakeCodeHelper(view, addr);
//				},
//			BinaryViewValid);
//
//	UIAction::setActionDisplayName("Debugger\\Make Code", [](const UIActionContext& ctxt) -> QString {
//		if (!ctxt.binaryView)
//			return "Make Code";
//
//		if (ShowAsCode(ctxt.binaryView, ctxt.address))
//			return "Undefine Code";
//
//		return "Make Code";
//	});
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
#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		SetCurrentPluginLoadOrder(LatePluginLoadOrder);
	}
#endif

#ifdef DEMO_VERSION
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
		return true;
	}
}
