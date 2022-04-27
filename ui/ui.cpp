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

	auto* globalDebuggerConsoleContainer = new GlobalConsoleContainer("Target Terminal");
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
//					newFrame->navigate(m_controller->GetLiveView(), address, true, true);
					m_context->closeTab(m_context->getTabForFile(fileContext));
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
                addr.module = data->GetFile()->GetOriginalFilename();
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

			if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module,
											  m_controller->GetData()->GetFile()->GetOriginalFilename()))
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
			if (DebugModule::IsSameBaseModule(relative.module, m_controller->GetData()->GetFile()->GetOriginalFilename()))
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

			if (DebugModule::IsSameBaseModule(event.data.relativeAddress.module,
											  m_controller->GetData()->GetFile()->GetOriginalFilename()))
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
			if (DebugModule::IsSameBaseModule(relative.module, m_controller->GetData()->GetFile()->GetOriginalFilename()))
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
        std::string filename = view->GetFile()->GetOriginalFilename();
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


static bool BinaryViewValid(BinaryView* view, uint64_t addr)
{
    return true;
}


static void RunToHereCallback(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	if (!controller)
		return;
	controller->RunTo(addr);
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
    UIAction::setUserKeyBinding("Debugger\\Toggle Breakpoint", { QKeySequence(Qt::Key_F2) });

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
						controller->Go();
					}
					else if (!controller->IsConnected())
					{
						controller->LaunchOrConnect();
					}
				},
			BinaryViewValid);
	UIAction::setUserKeyBinding(QString::asprintf("Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F9) });

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
					controller->StepInto(graphType);
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F7) });

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
					controller->StepOver(graphType);
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F8) });

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
					controller->StepReturn();
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::ControlModifier | Qt::Key_F9) });

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
					controller->Pause();
				},
			ConnectedAndRunning);
	UIAction::setUserKeyBinding(QString::asprintf("Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F12) });

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
	UIAction::setUserKeyBinding(QString::asprintf("Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_C) });
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

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		SetCurrentPluginLoadOrder(LatePluginLoadOrder);
	}

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		GlobalDebuggerUI::InitializeUI();
		NotificationListener::init();
		DataRendererContainer::RegisterTypeSpecificDataRenderer(new CodeDataRenderer);
		return true;
	}
}
