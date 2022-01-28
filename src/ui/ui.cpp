#include "ui.h"
#include "binaryninjaapi.h"
#include "breakpointswidget.h"
#include "moduleswidget.h"
#include "threadswidget.h"
#include "stackwidget.h"
#include "QPainter"
#include <QtWidgets/QStatusBar>
#include <QtCore/QCoreApplication>


using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;

std::unordered_map<DebuggerController*, std::unique_ptr<DebuggerUI>> g_contextMap;

DebuggerUI::DebuggerUI(UIContext* context, DebuggerController* controller):
	m_context(context), m_controller(controller)
{
	m_window = context->mainWindow();
	m_status = new QLabel("Inactive");
	if (m_window && m_window->statusBar())
		m_window->statusBar()->insertWidget(0, m_status);

	connect(this, &DebuggerUI::debuggerEvent, this, &DebuggerUI::updateStatusText);
	connect(this, &DebuggerUI::debuggerEvent, this, &DebuggerUI::updateUI);

    m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
		ExecuteOnMainThreadAndWait([&](){
			emit debuggerEvent(event);
		});
    });
}


DebuggerUI::~DebuggerUI()
{
	m_controller->RemoveEventCallback(m_eventCallback);
}


void DebuggerUI::setStatusText(const QString &text)
{
	m_status->setText(text);
}


void DebuggerUI::updateStatusText(const DebuggerEvent &event)
{
	switch (event.type)
	{
	case LaunchEventType:
		setStatusText("Launching");
		break;
	case ResumeEventType:
		setStatusText("Running");
		break;
	case StepIntoEventType:
		setStatusText("Stepping into");
		break;
	case StepOverEventType:
		setStatusText("Stepping over");
		break;
	case StepReturnEventType:
		setStatusText("Stepping return");
		break;
	case StepToEventType:
		setStatusText("Stepping to");
		break;
	case RestartEventType:
		setStatusText("Restarting");
		break;
	case AttachEventType:
		setStatusText("Attaching");
		break;

    case TargetStoppedEventType:
	{
		BNDebugStopReason reason = event.data.targetStoppedData.reason;
		setStatusText(QString::fromStdString(fmt::format("Stopped {}", reason)));
		break;
	}
	case TargetExitedEventType:
	{
		uint8_t exitCode = event.data.exitData.exitCode;
		setStatusText(QString::fromStdString(fmt::format("Exited with code {}", exitCode)));
		break;
	}
    case DetachedEventType:
		setStatusText("Detached");
		break;
    case QuitDebuggingEventType:
		setStatusText("Aborted");
		break;
    case BackEndDisconnectedEventType:
		setStatusText("Backend disconnected");
		break;
	default:
		break;
	}
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
        {
            uint64_t address = m_controller->GetState()->IP();
			// If there is no function at the current address, define one. This might be a little aggressive,
			// but given that we are lacking the ability to "show as code", this feels like an OK workaround.
            BinaryViewRef liveView = m_controller->GetLiveView();
            if (!liveView)
                break;

			auto functions = liveView->GetAnalysisFunctionsContainingAddress(address);
			if (functions.size() == 0)
				m_controller->GetLiveView()->CreateUserFunction(m_controller->GetLiveView()->GetDefaultPlatform(), address);

			if (event.data.targetStoppedData.reason == BNDebugStopReason::InitialBreakpoint)
			{
				ViewFrame* frame = m_context->getCurrentViewFrame();
				FileContext* fileContext = frame->getFileContext();
				fileContext->refreshDataViewCache();
				ViewFrame* newFrame = m_context->openFileContext(fileContext);
				QCoreApplication::processEvents();

				if (newFrame)
				{
					newFrame->navigate(m_controller->GetLiveView(), address, true, true);
					m_context->closeTab(m_context->getTabForFile(fileContext));
					QCoreApplication::processEvents();
				}
			}
			else
			{
				ViewFrame* frame = m_context->getCurrentViewFrame();
				frame->navigate(m_controller->GetLiveView(), address, true, true);
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
                if (m_controller->GetState()->GetBreakpoints()->ContainsOffset(addr))
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
			DebuggerModules* modules = m_controller->GetState()->GetModules();
			uint64_t address = modules->RelativeAddressToAbsolute(event.data.relativeAddress);

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
		case AbsoluteBreakpointAddedEvent:
		{
			uint64_t address = event.data.absoluteAddress;

			std::vector<std::pair<BinaryViewRef, uint64_t>> dataAndAddress;
			BinaryViewRef data = m_controller->GetLiveView();
			if (data)
				dataAndAddress.emplace_back(data, address);

			DebuggerModules* modules = m_controller->GetState()->GetModules();
			ModuleNameAndOffset relative = modules->AbsoluteAddressToRelative(address);
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
			DebuggerModules* modules = m_controller->GetState()->GetModules();
			uint64_t address = modules->RelativeAddressToAbsolute(event.data.relativeAddress);

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

			DebuggerModules* modules = m_controller->GetState()->GetModules();
			ModuleNameAndOffset relative = modules->AbsoluteAddressToRelative(address);
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
    DebuggerState* state = controller->GetState();

    bool isAbsoluteAddress = false;
    // TODO: check if this works
    if (view->GetTypeName() == "Debugger")
        isAbsoluteAddress = true;

    DebuggerBreakpoints* breakpoints = state->GetBreakpoints();
    if (isAbsoluteAddress)
    {
		ModuleNameAndOffset relativeAddress = state->GetModules()->AbsoluteAddressToRelative(addr);
        if (breakpoints->ContainsOffset(relativeAddress))
        {
            controller->DeleteBreakpoint(relativeAddress);
        }
        else
        {
            controller->AddBreakpoint(relativeAddress);
        }
    }
    else
    {
        std::string filename = view->GetFile()->GetOriginalFilename();
        uint64_t offset = addr - view->GetStart();
        ModuleNameAndOffset info = {filename, offset};
        if (breakpoints->ContainsOffset(info))
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


static void StepToHereCallback(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	controller->StepTo({addr});
}


static bool ConnectedAndStopped(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	return controller->GetState()->IsConnected() && (!controller->IsRunning());
}


static bool ConnectedAndRunning(BinaryView* view, uint64_t addr)
{
	DebuggerController* controller = DebuggerController::GetController(view);
	return controller->GetState()->IsConnected() && controller->IsRunning();
}


void DebuggerUI::InitializeUI()
{
    auto create_icon_with_letter = [](const QString& letter) {
        auto icon = QImage(56, 56, QImage::Format_RGB32);
        icon.fill(0);
        auto painter = QPainter();
        painter.begin(&icon);
        painter.setFont(QFont("Open Sans", 56));
        painter.setPen(QColor(255, 255, 255, 255));
        painter.drawText(QRectF(0, 0, 56, 56), Qt::Alignment(Qt::AlignCenter), letter);
        painter.end();
        return icon;
    };

    Sidebar::addSidebarWidgetType(
        new DebuggerWidgetType(create_icon_with_letter("D"), "Native Debugger"));

	// We must use the sequence of these four calls to do the job, otherwise the keybinding does not work.
	// Though it really should be the case where I can specify the keybinding in the first registerAction() call.
	UIAction::registerAction("Native Debugger\\Toggle Breakpoint");
	UIAction::registerAction("Selection Target\\Native Debugger\\Toggle Breakpoint");
	PluginCommand::RegisterForAddress("Native Debugger\\Toggle Breakpoint",
            "Sets/clears breakpoint at right-clicked address",
            BreakpointToggleCallback, BinaryViewValid);
    UIAction::setUserKeyBinding("Native Debugger\\Toggle Breakpoint", { QKeySequence(Qt::Key_F2) });

	UIAction::registerAction("Native Debugger\\Step To Here");
	UIAction::registerAction("Selection Target\\Native Debugger\\Step To Here");
	PluginCommand::RegisterForAddress("Native Debugger\\Step To Here",
            "Steps over until the current address",
            StepToHereCallback, ConnectedAndStopped);

	std::string actionName = "Run";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Launch, connect to or resume the target",
			[](BinaryView* view, uint64_t addr){
					DebuggerController* controller = DebuggerController::GetController(view);
					if (controller->GetState()->IsConnected() && (!controller->GetState()->IsRunning()))
					{
						controller->Go();
					}
					else if (!controller->GetState()->IsConnected())
					{
						controller->LaunchOrConnect();
					}
				},
			BinaryViewValid);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F9) });

	actionName = "Step Into";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Step into",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					controller->StepInto(graphType);
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F7) });

	actionName = "Step Over";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Step over",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					BNFunctionGraphType graphType = NormalFunctionGraph;
					UIContext* context = UIContext::activeContext();
					if (context && context->getCurrentView())
						graphType = context->getCurrentView()->getILViewType();
					controller->StepOver(graphType);
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F8) });

	actionName = "Step Return";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Step return",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					controller->StepReturn();
				},
			ConnectedAndStopped);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::ControlModifier | Qt::Key_F9) });

	actionName = "Pause";
	UIAction::registerAction(QString::asprintf("Native Debugger\\%s", actionName.c_str()));
	UIAction::registerAction(QString::asprintf("Selection Target\\Native Debugger\\%s", actionName.c_str()));
	PluginCommand::RegisterForAddress(
			QString::asprintf("Native Debugger\\%s", actionName.c_str()).toStdString(),
			"Pause the target",
			[](BinaryView* view, uint64_t){
					DebuggerController* controller = DebuggerController::GetController(view);
					controller->Pause();
				},
			ConnectedAndRunning);
	UIAction::setUserKeyBinding(QString::asprintf("Native Debugger\\%s", actionName.c_str()),
								{ QKeySequence(Qt::Key_F12) });
}


DebuggerUI* DebuggerUI::CreateForViewFrame(ViewFrame* frame)
{
	if (!frame)
		return nullptr;

	UIContext* context = UIContext::contextForWidget(frame);
	BinaryViewRef data = frame->getCurrentBinaryView();
	if (!data)
		return nullptr;

	DebuggerController* controller = DebuggerController::GetController(data);
	if (!controller)
		return nullptr;

	if (g_contextMap.find(controller) != g_contextMap.end())
	{
		return g_contextMap[controller].get();
	}
	g_contextMap.try_emplace(controller, std::make_unique<DebuggerUI>(context, controller));
	return g_contextMap[controller].get();
}


DebuggerUI* DebuggerUI::GetForViewFrame(ViewFrame* frame)
{
	BinaryViewRef data = frame->getCurrentBinaryView();
	if (!data)
		return nullptr;

	DebuggerController* controller = DebuggerController::GetController(data);
	if (!controller)
		return nullptr;

	if (g_contextMap.find(controller) != g_contextMap.end())
	{
		return g_contextMap[controller].get();
	}
	return nullptr;
}
