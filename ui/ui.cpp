/*
Copyright 2020-2022 Vector 35 Inc.

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
#include "threadswidget.h"
#include "stackwidget.h"
#include "uinotification.h"
#include "QPainter"
#include <QStatusBar>
#include <QCoreApplication>
#include "fmt/format.h"
#include "console.h"
#include "adapterconsole.h"
#include "threadframes.h"
#include "syncgroup.h"
#include "codedatarenderer.h"
#include "adaptersettings.h"
#include <thread>
#include <QInputDialog>
#include <filesystem>
#include <QMessageBox>
#include "debugserversetting.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

std::map<Ref<DebuggerController>, std::unique_ptr<DebuggerUI>> g_controllerMap;
std::map<UIContext*, std::unique_ptr<GlobalDebuggerUI>> g_contextMap;

GlobalDebuggerUI::GlobalDebuggerUI(UIContext* context):	m_context(context)
{
	m_window = context->mainWindow();
	if (m_window && m_window->statusBar())
	{
		m_status = new DebuggerStatusBarContainer;
		m_window->statusBar()->insertWidget(0, m_status);
	}

	SetupMenu(context);

	auto* globalDebuggerConsoleContainer = new GlobalConsoleContainer("Target I/O");
	context->globalArea()->addWidget(globalDebuggerConsoleContainer);

	auto* globalAdapterConsoleContainer = new GlobalAdapterConsoleContainer("Debugger Console");
	context->globalArea()->addWidget(globalAdapterConsoleContainer);

	auto* globalThreadFramesContainer = new GlobalThreadFramesContainer("Stack Trace");
	context->globalArea()->addWidget(globalThreadFramesContainer);

	auto ui = DebuggerUI::CreateForViewFrame(context->getCurrentViewFrame());
}


GlobalDebuggerUI::~GlobalDebuggerUI()
{
}


static void BreakpointToggleCallback(BinaryView* view, uint64_t addr)
{
    DebuggerController* controller = DebuggerController::GetController(view);
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
        std::string filename = controller->GetExecutablePath();
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


#ifdef WIN32
#include "msi.h"
#include <Shlobj.h>

static bool InstallDbgEngRedistributable()
{
    std::filesystem::path dbgEngPath;
    if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
    {
        auto pluginsPath = BinaryNinja::GetUserPluginDirectory();
        if (pluginsPath.empty())
            return false;

        auto path = std::filesystem::path(pluginsPath);
        dbgEngPath = path / "dbgeng";
    }
    else
    {
        auto installPath = BinaryNinja::GetInstallDirectory();
        if (installPath.empty())
            return false;

        auto path = std::filesystem::path(installPath);
        dbgEngPath = path / "plugins" / "dbgeng";
    }

    if (!std::filesystem::exists(dbgEngPath))
    {
        LogWarn("path %d does not exists", dbgEngPath.string().c_str());
        return false;
    }

	string cmdLine = "ACTION=ADMIN TARGETDIR=";

	char appData[MAX_PATH];
	if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData)))
		return false;

	auto debuggerRoot = filesystem::path(appData) / "Binary Ninja" / "dbgeng";
	cmdLine = cmdLine + '"' + debuggerRoot.string() + '"';

	auto x64Path = dbgEngPath / "X64 Debuggers And Tools-x64_en-us.msi";
	auto ret = MsiInstallProductA(x64Path.string().c_str(), cmdLine.c_str());
	if (ret != ERROR_SUCCESS)
		return false;

	auto x86Path = dbgEngPath / "X86 Debuggers And Tools-x86_en-us.msi";
	ret = MsiInstallProductA((char*)x86Path.string().c_str(), cmdLine.c_str());
	if (ret != ERROR_SUCCESS)
		return false;

	auto versionFilePath = debuggerRoot / "version.txt";
	auto file = fopen(versionFilePath.string().c_str(), "w");
	if (file == nullptr)
		return false;

	const char* DEBUGGER_REDIST_VERSION = "10.0.22621.1";
	fwrite(DEBUGGER_REDIST_VERSION, 1, strlen(DEBUGGER_REDIST_VERSION), file);
	fclose(file);
	return true;
}
#endif


void GlobalDebuggerUI::SetupMenu(UIContext* context)
{
	auto notConnected = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return !controller->IsConnected();
	};

	auto connected = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected();
	};

	auto connectedAndStopped = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected() && (!controller->IsRunning());
	};

	auto connectedAndRunning = [=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return false;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return false;

		return controller->IsConnected() && controller->IsRunning();
	};

    auto connectedToDebugServer = [=](const UIActionContext& ctxt) {
        if (!ctxt.binaryView)
            return false;
        auto controller = DebuggerController::GetController(ctxt.binaryView);
        if (!controller)
            return false;

        return controller->IsConnectedToDebugServer();
    };

    auto notConnectedToDebugServer = [=](const UIActionContext& ctxt) {
        if (!ctxt.binaryView)
            return false;
        auto controller = DebuggerController::GetController(ctxt.binaryView);
        if (!controller)
            return false;

        return !controller->IsConnectedToDebugServer();
    };

	UIAction::registerAction("Launch/Connect Settings...");
	context->globalActions()->bindAction("Launch/Connect Settings...", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		if (!context->mainWindow())
			return;

		auto* dialog = new AdapterSettingsDialog(context->mainWindow(), controller);
		dialog->show();
	}));

	Menu* debuggerMenu = Menu::mainMenu("Debugger");
	Menu::setMainMenuOrder("Debugger", MENU_ORDER_LATE);
	debuggerMenu->addAction("Launch/Connect Settings...", "Settings", MENU_ORDER_FIRST);

	UIAction::registerAction("Launch");
	context->globalActions()->bindAction("Launch", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

        std::thread([&, controller](){
            controller->Launch();
        }).detach();
	}, notConnected));
	debuggerMenu->addAction("Launch", "Launch");

	UIAction::registerAction("Kill");
	context->globalActions()->bindAction("Kill", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		controller->Quit();
	}, connected));
	debuggerMenu->addAction("Kill", "Launch");

	UIAction::registerAction("Resume", QKeySequence(Qt::Key_F9));
	context->globalActions()->bindAction("Resume", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		controller->Go();
	}, connectedAndStopped));
	debuggerMenu->addAction("Resume", "Control");

	UIAction::registerAction("Step Into", QKeySequence(Qt::Key_F7));
	context->globalActions()->bindAction("Step Into", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		BNFunctionGraphType graphType = NormalFunctionGraph;
		if (ctxt.context && ctxt.context->getCurrentView())
			graphType = ctxt.context->getCurrentView()->getILViewType();
		controller->StepInto(graphType);
	}, connectedAndStopped));
	debuggerMenu->addAction("Step Into", "Control");

	UIAction::registerAction("Step Over", QKeySequence(Qt::Key_F8));
	context->globalActions()->bindAction("Step Over", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		BNFunctionGraphType graphType = NormalFunctionGraph;
		if (ctxt.context && ctxt.context->getCurrentView())
			graphType = ctxt.context->getCurrentView()->getILViewType();
		controller->StepOver(graphType);
	}, connectedAndStopped));
	debuggerMenu->addAction("Step Over", "Control");

	UIAction::registerAction("Step Return", QKeySequence(Qt::ControlModifier | Qt::Key_F9));
	context->globalActions()->bindAction("Step Return", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		controller->StepReturn();
	}, connectedAndStopped));
	debuggerMenu->addAction("Step Return", "Control");

	UIAction::registerAction("Detach");
	context->globalActions()->bindAction("Detach", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		controller->Detach();
	}, connected));
	debuggerMenu->addAction("Detach", "Launch");

	UIAction::registerAction("Restart");
	context->globalActions()->bindAction("Restart", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		controller->Restart();
	}, connected));
	debuggerMenu->addAction("Restart", "Launch");

	UIAction::registerAction("Pause", QKeySequence(Qt::Key_F12));
	context->globalActions()->bindAction("Pause", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		controller->Pause();
	}, connectedAndRunning));
	debuggerMenu->addAction("Pause", "Control");

	UIAction::registerAction("Attach To Process...");
	context->globalActions()->bindAction("Attach To Process...", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		int pid = QInputDialog::getInt(context->mainWindow(), "PID", "Input PID:");
		if (pid == 0)
			return;

		controller->Attach(pid);
	}, notConnected));
	debuggerMenu->addAction("Attach To Process...", "Launch");

	UIAction::registerAction("Toggle Breakpoint", QKeySequence(Qt::Key_F2));
	context->globalActions()->bindAction("Toggle Breakpoint", UIAction([=](const UIActionContext& ctxt) {
		if (!ctxt.binaryView)
			return;
		auto controller = DebuggerController::GetController(ctxt.binaryView);
		if (!controller)
			return;

		BreakpointToggleCallback(ctxt.binaryView, ctxt.address);
	}, connectedAndStopped));
	debuggerMenu->addAction("Toggle Breakpoint", "Breakpoint");

#ifdef WIN32
    UIAction::registerAction("Reinstall DbgEng Redistributable");
    context->globalActions()->bindAction("Reinstall DbgEng Redistributable", UIAction([=](const UIActionContext& ctxt) {
        if (!InstallDbgEngRedistributable())
        {
            QMessageBox::warning(nullptr, QString("Failed to install"), QString("Failed to install DbgEng redistributable. "
                                                                    "The debugger is likely to malfunction"));
        }
        else
        {
            QMessageBox::warning(nullptr, QString("Successfully installed"),
                                 QString("Successfully installed DbgEng redistributable."));
        }
    }));
    debuggerMenu->addAction("Reinstall DbgEng Redistributable", "Misc");

    UIAction::registerAction("Connect to Debug Server");
    context->globalActions()->bindAction("Connect to Debug Server", UIAction([=](const UIActionContext& ctxt) {
        if (!ctxt.binaryView)
            return;
        auto controller = DebuggerController::GetController(ctxt.binaryView);
        if (!controller)
            return;

        auto dialog = new DebugServerSettingsDialog(context->mainWindow(), controller);
        if (dialog->exec () != QDialog::Accepted)
            return;

        if (controller->ConnectToDebugServer())
        {
            QMessageBox::information(context->mainWindow(), "Successfully connected",
                                     "Successfully connected to the debug server. Now you can launch or attach to a process.");
        }
        else
        {
            QMessageBox::information(context->mainWindow(), "Failed to connect",
                                     "Cannot connect to the debug server. Please check the connection configuration.");
        }
    }, notConnectedToDebugServer));
    debuggerMenu->addAction("Connect to Debug Server", "Launch");

    UIAction::registerAction("Disconnect from Debug Server");
    context->globalActions()->bindAction("Disconnect from Debug Server", UIAction([=](const UIActionContext& ctxt) {
        if (!ctxt.binaryView)
            return;
        auto controller = DebuggerController::GetController(ctxt.binaryView);
        if (!controller)
            return;

        controller->DisconnectDebugServer();
    }, connectedToDebugServer));
    debuggerMenu->addAction("Disconnect from Debug Server", "Launch");

#endif
}


DebuggerUI::DebuggerUI(UIContext* context, DebuggerController* controller):
	m_context(context), m_controller(controller)
{
	connect(this, &DebuggerUI::debuggerEvent, this, &DebuggerUI::updateUI);

    m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
		ExecuteOnMainThreadAndWait([=](){
			emit debuggerEvent(event);
		});
    });

	// Since the Controller is constructed earlier than the UI, any breakpoints added before the construction of the UI,
	// e.g. the entry point breakpoint, will be missing the visual indicator.
	// Here, we forcibly add them.
	for (auto bp: m_controller->GetBreakpoints())
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
		// Instead, find a SyncGroup which is viewing a function. If none, do not navigate anything.
		auto fileContext = frame->getFileContext();
		if (fileContext)
		{
			auto syncGroups = frame->getFileContext()->allSyncGroups();
			for (const auto& syncGroup: syncGroups)
			{
				for (auto i: syncGroup->members())
				{
					View* groupView = i->getCurrentViewInterface();
					if (groupView->getCurrentFunction())
					{
						i->navigate(m_controller->GetLiveView(), address, true, true);
						break;
					}
				}
			}
		}
	}
}


static void MakeCodeHelper(BinaryView* view, uint64_t addr)
{
	view->DefineDataVariable(addr, Type::ArrayType(Type::IntegerType(1, false), 1));
	const std::string name = fmt::format("CODE_start_{:08x}", addr);
	SymbolRef sym = new Symbol(DataSymbol, name, name, name, addr);
	view->DefineUserSymbol(sym);
}


void DebuggerUI::updateUI(const DebuggerEvent &event)
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
			FileContext* fileContext = frame->getFileContext();
			fileContext->refreshDataViewCache();
			ViewFrame* newFrame = m_context->openFileContext(fileContext);
			QCoreApplication::processEvents();

			if (newFrame)
			{
				newFrame->navigate(m_controller->GetData(), m_controller->GetData()->GetEntryPoint(), true, true);
				m_context->closeTab(m_context->getTabForFile(fileContext));
				QCoreApplication::processEvents();
			}
			else
			{
				LogWarn("fail to navigate to the original view");
			}
			break;
		}

        case TargetStoppedEventType:
		case ActiveThreadChangedEvent:
        {
            uint64_t address = m_controller->IP();
			// If there is no function at the current address, define one. This might be a little aggressive,
			// but given that we are lacking the ability to "show as code", this feels like an OK workaround.
            BinaryViewRef liveView = m_controller->GetLiveView();
            if (!liveView)
                break;

			if (event.type == TargetStoppedEventType &&
				event.data.targetStoppedData.reason == DebugStopReason::InitialBreakpoint)
			{
				ViewFrame* frame = m_context->getCurrentViewFrame();
				FileContext* fileContext = frame->getFileContext();
				fileContext->refreshDataViewCache();
				ViewFrame* newFrame = m_context->openFileContext(fileContext);
				QCoreApplication::processEvents();

				if (newFrame)
				{
					m_context->closeTab(m_context->getTabForFile(fileContext));
					navigateDebugger(address);
					QCoreApplication::processEvents();
				}
			}
			else
			{
				auto functions = liveView->GetAnalysisFunctionsContainingAddress(address);
				if (functions.size() == 0)
					m_controller->GetLiveView()->CreateUserFunction(m_controller->GetLiveView()->GetDefaultPlatform(), address);

				navigateDebugger(address);
				QCoreApplication::processEvents();
			}

            // Remove old instruction pointer highlight
            uint64_t lastIP = m_controller->GetLastIP();
            BinaryViewRef data = m_controller->GetLiveView();
            if (!data)
                break;

            for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(lastIP))
            {
                ModuleNameAndOffset addr;
                addr.module = m_controller->GetExecutablePath();
                addr.offset = lastIP - data->GetStart();

                BNHighlightStandardColor oldColor = NoHighlightColor;
                if (m_controller->ContainsBreakpoint(addr))
                    oldColor = RedHighlightColor;

                func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), lastIP, oldColor);
                for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), lastIP))
                {
                    if (tag->GetType() != getPCTagType(data))
                        continue;

                    func->RemoveUserAddressTag(data->GetDefaultArchitecture(), lastIP, tag);
                }
            }

            // Add new instruction pointer highlight
            for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
            {
                bool tagFound = false;
                for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
                {
                    if (tag->GetType() == getPCTagType(data))
                    {
                        tagFound = true;
                        break;
                    }
                }

                if (!tagFound)
                {
                    func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, BlueHighlightColor);
                    func->CreateUserAddressTag(data->GetDefaultArchitecture(), address, getPCTagType(data),
                                               "program counter");
                }
            }
            break;
        }

		case RelativeBreakpointAddedEvent:
		{
			uint64_t address = m_controller->RelativeAddressToAbsolute(event.data.relativeAddress);

			std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
			if (m_controller->GetLiveView())
				dataAndAddress.emplace_back(m_controller->GetLiveView(), address);

			if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module, m_controller->GetExecutablePath()))
			{
				dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + event.data.relativeAddress.offset);
			}

			for (auto& [data, addr]: dataAndAddress)
			{
				for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(addr))
				{
					bool tagFound = false;
					for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), addr))
					{
						if (tag->GetType() == getBreakpointTagType(data))
						{
							tagFound = true;
							break;
						}
					}

					if (!tagFound)
					{
						func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), addr, RedHighlightColor);
						func->CreateUserAddressTag(data->GetDefaultArchitecture(), addr, getBreakpointTagType(data),
													   "breakpoint");
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
			if (DebugModule::IsSameBaseModule(relative.module, m_controller->GetExecutablePath()))
			{
				dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + relative.offset);
			}

			for (auto& [data, address]: dataAndAddress)
			{
				for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
				{
					bool tagFound = false;
					for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
					{
						if (tag->GetType() == getBreakpointTagType(data))
						{
							tagFound = true;
							break;
						}
					}

					if (!tagFound)
					{
						func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, RedHighlightColor);
						func->CreateUserAddressTag(data->GetDefaultArchitecture(), address, getBreakpointTagType(data),
													   "breakpoint");
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

			if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module, m_controller->GetExecutablePath()))
			{
				dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + event.data.relativeAddress.offset);
			}

			for (auto& [data, address]: dataAndAddress)
			{
				for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
				{
					func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, NoHighlightColor);
					for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
					{
						if (tag->GetType() != getBreakpointTagType(data))
							continue;

						func->RemoveUserAddressTag(data->GetDefaultArchitecture(), address, tag);
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
			if (DebugModule::IsSameBaseModule(relative.module, m_controller->GetExecutablePath()))
			{
				dataAndAddress.emplace_back(m_controller->GetData(), m_controller->GetData()->GetStart() + relative.offset);
			}

			for (auto& [data, address]: dataAndAddress)
			{
				for (FunctionRef func: data->GetAnalysisFunctionsContainingAddress(address))
				{
					func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, NoHighlightColor);
					for (TagRef tag: func->GetAddressTags(data->GetDefaultArchitecture(), address))
					{
						if (tag->GetType() != getBreakpointTagType(data))
							continue;

						func->RemoveUserAddressTag(data->GetDefaultArchitecture(), address, tag);
					}
				}
			}
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
	DebuggerController* controller = DebuggerController::GetController(view);
	if (!controller)
		return;
	std::thread([=](){
		controller->RunTo(addr);
	}).detach();
}


static bool ConnectedAndStopped(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	if (!controller)
		return false;
	return controller->IsConnected() && (!controller->IsRunning());
}


static bool ConnectedAndRunning(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	if (!controller)
		return false;
	return controller->IsConnected() && controller->IsRunning();
}


void GlobalDebuggerUI::InitializeUI()
{
    Sidebar::addSidebarWidgetType(
        new DebuggerWidgetType(QImage(":/icons/images/debugger/debugger.svg"), "Debugger"));

	// We must use the sequence of these four calls to do the job, otherwise the keybinding does not work.
	// Though it really should be the case where I can specify the keybinding in the first registerAction() call.
	UIAction::registerAction("Debugger\\Toggle Breakpoint");
	UIAction::registerAction("Selection Target\\Debugger\\Toggle Breakpoint");
	PluginCommand::RegisterForAddress("Debugger\\Toggle Breakpoint",
            "Sets/clears breakpoint at right-clicked address",
            BreakpointToggleCallback, BinaryViewValid);

	UIAction::registerAction("Debugger\\Run To Here");
	UIAction::registerAction("Selection Target\\Debugger\\Run To Here");
	PluginCommand::RegisterForAddress("Debugger\\Run To Here",
            "Run until the current address",
            RunToHereCallback, ConnectedAndStopped);

	std::string actionName = "Run";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(),
			"Launch, connect to or resume the target",
			[](BinaryView* view, uint64_t addr){
					DebuggerController* controller = DebuggerController::GetController(view);
					if (!controller)
						return;
					if (controller->IsConnected() && (!controller->IsRunning()))
					{
						std::thread([=](){
							controller->Go();
						}).detach();
					}
					else if (!controller->IsConnected())
					{
						std::thread([=](){
							controller->LaunchOrConnect();
						}).detach();
					}
				},
			BinaryViewValid);

	actionName = "Step Into";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(),
			"Step into",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					if (!controller)
						return;
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					std::thread([=](){
						controller->StepInto(graphType);
					}).detach();
				},
			ConnectedAndStopped);

	actionName = "Step Over";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(),
			"Step over",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					if (!controller)
						return;
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					std::thread([=](){
						controller->StepOver(graphType);
					}).detach();
				},
			ConnectedAndStopped);

	actionName = "Step Return";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(),
			"Step return",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					if (!controller)
						return;
					std::thread([=](){
						controller->StepReturn();
					}).detach();
				},
			ConnectedAndStopped);

	actionName = "Pause";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(),
			"Pause the target",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					if (!controller)
						return;
					std::thread([=](){
						controller->Pause();
					}).detach();
				},
			ConnectedAndRunning);

	actionName = "Make Code";
	UIAction::registerAction(QString::asprintf("Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Debugger\\%s", actionName.c_str()).toStdString(),
			"Pause the target",
			[](BinaryView* view, uint64_t addr){
					MakeCodeHelper(view, addr);
				},
			BinaryViewValid);
}


DebuggerUI* DebuggerUI::CreateForViewFrame(ViewFrame* frame)
{
	if (!frame)
		return nullptr;

	UIContext* context = UIContext::contextForWidget(frame);
	BinaryViewRef data = frame->getCurrentBinaryView();
	if (!data)
		return nullptr;

	Ref<DebuggerController> controller = DebuggerController::GetController(data);
	if (!controller)
		return nullptr;

	if (g_controllerMap.find(controller) != g_controllerMap.end())
	{
		return g_controllerMap[controller].get();
	}
	g_controllerMap.try_emplace(controller, std::make_unique<DebuggerUI>(context, controller));
	return g_controllerMap[controller].get();
}


DebuggerUI* DebuggerUI::GetForViewFrame(ViewFrame* frame)
{
	BinaryViewRef data = frame->getCurrentBinaryView();
	if (!data)
		return nullptr;

	Ref<DebuggerController> controller = DebuggerController::GetController(data);
	if (!controller)
		return nullptr;

	if (g_controllerMap.find(controller) != g_controllerMap.end())
	{
		return g_controllerMap[controller].get();
	}
	return nullptr;
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


void GlobalDebuggerUI::RemoveForContext(UIContext *context)
{
	g_contextMap.erase(context);
}


void GlobalDebuggerUI::SetActiveFrame(ViewFrame *frame)
{
	auto ui = DebuggerUI::CreateForViewFrame(frame);
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
		return true;
	}
}
