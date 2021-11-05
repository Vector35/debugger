#include "controlswidget.h"
#include "adaptersettings.h"
#include <QtGui/QPixmap>
#include "binaryninjaapi.h"
#include "disassemblyview.h"
#include "ui.h"
#include "../debuggerexceptions.h"
#include <thread>

using namespace BinaryNinja;


DebugControlsWidget::DebugControlsWidget(QWidget* parent, const std::string name, BinaryViewRef data):
    QToolBar(parent), m_name(name)
{
    m_controller = DebuggerController::GetController(data);

    m_actionRun = addAction(QIcon(":/icons/images/debugger/run.svg"), "Run",
                        [this](){ performRun(); });
    m_actionRestart = addAction(QIcon(":/icons/images/debugger/restart.svg"), "Restart",
                                [this](){ performRestart(); });
    m_actionQuit = addAction(QIcon(":/icons/images/debugger/cancel.svg"), "Quit",
                             [this](){ performQuit(); });
    addSeparator();

    m_actionAttach = addAction(QIcon(":/icons/images/debugger/connect.svg"), "Attach",
                            [this](){ performAttach(); });
    m_actionDetach = addAction(QIcon(":/icons/images/debugger/disconnect.svg"), "Detach",
                               [this](){ performDetach(); });
    addSeparator();

    m_actionPause = addAction(QIcon(":/icons/images/debugger/pause.svg"), "Pause",
                              [this](){ performPause(); });
    m_actionResume = addAction(QIcon(":/icons/images/debugger/resume.svg"), "Resume",
                               [this](){ performResume(); });
    addSeparator();

    m_actionStepInto = addAction(QIcon(":/icons/images/debugger/stepinto.svg"), "Step Into",
                                 [this](){ performStepInto(); });
    m_actionStepOver = addAction(QIcon(":/icons/images/debugger/stepover.svg"), "Step Over",
                                 [this](){ performStepOver(); });
    m_actionStepReturn = addAction(QIcon(":/icons/images/debugger/stepout.svg"), "Step Out",
                               [this](){ performStepReturn(); });
    addSeparator();

    m_actionSettings = addAction("Settings...",[this](){ performSettings(); });

    updateButtons();

    m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
        uiEventHandler(event);
    });
}


DebugControlsWidget::~DebugControlsWidget()
{
// This does not resolve the issue of the callback getting called multiple times, because the widget is not necessarily
// destructed
    m_controller->RemoveEventCallback(m_eventCallback);
    LogWarn("removing event callback");
}


void DebugControlsWidget::performRun()
{
    m_controller->Run();

//    auto performRunAfter = [&](){
//        stateStopped();
//        m_state->OnStep();
//    };
//
//    auto performRunError = [&](const std::string& e){
//        stateError(e);
//    };
//
//    auto performRunThread = [=](){
//        while (true)
//        {
//            try
//            {
//                m_controller->Run();
//                ExecuteOnMainThreadAndWait(performRunAfter);
//            }
//            catch (const ConnectionRefusedError& e)
//            {
//                ExecuteOnMainThreadAndWait([&](){ performRunError(e.what()); });
//            }
//            catch (const ProcessStartError& e)
//            {
//                ExecuteOnMainThreadAndWait([&](){ performRunError(e.what()); });
//            }
//            catch (const NotExecutableError& e)
//            {
//                // TODO: offer to change permission of the file
//                ExecuteOnMainThreadAndWait([&](){ performRunError("ERROR: Target Not Executable"); });
//            }
//            catch (const NotInstalledError& e)
//            {
//                ExecuteOnMainThreadAndWait([&](){ performRunError(e.what()); });
//                ExecuteOnMainThreadAndWait([&](){ performRunError("ERROR: Debugger Not Installed"); });
//            }
//            catch (const PermissionDeniedError& e)
//            {
//                // TODO: prompt for developer tools
//                ExecuteOnMainThreadAndWait([&](){ performRunError("ERROR: Permission denied"); });
//            }
//            catch (const std::exception& e)
//            {
//                ExecuteOnMainThreadAndWait([&](){ performRunError("ERROR: " + std::string(e.what())); });
//            }
//            break;
//        }
//
//    };
//
//    stateStarting("STARTING");
//    std::thread t(performRunThread);
//    t.detach();
}


void DebugControlsWidget::performRestart()
{
    m_controller->Restart();
}


void DebugControlsWidget::performQuit()
{
    m_controller->Quit();
}


void DebugControlsWidget::performAttach()
{
    m_controller->Attach();
}


void DebugControlsWidget::performDetach()
{
    m_controller->Detach();
}


void DebugControlsWidget::performSettings()
{
//    AdapterSettingsDialog* dialog = new AdapterSettingsDialog(this, m_data);
//    dialog->show();
//    QObject::connect(dialog, &QDialog::finished, [this](){
//        if (!m_state->IsConnected())
//            stateInactive();
//    });
}


void DebugControlsWidget::performPause()
{
////    stateStopped();
//    m_state->Pause();
////    Don't update state here-- one of the other buttons is running in a thread and updating for us
}


void DebugControlsWidget::performResume()
{
    m_controller->Go();
}


void DebugControlsWidget::performStepInto()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

    m_controller->StepInto(graphType);
}


void DebugControlsWidget::performStepOver()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

    m_controller->StepOver(graphType);
}


void DebugControlsWidget::performStepReturn()
{
    m_controller->StepReturn();
}


bool DebugControlsWidget::canExec()
{
    return true;
//    return DebugAdapterType::UseExec(m_state->GetAdapterType());
}


bool DebugControlsWidget::canConnect()
{
    return true;
    //    return DebugAdapterType::UseConnect(m_state->GetAdapterType());
}


void DebugControlsWidget::setStepIntoEnabled(bool enabled)
{
    m_actionStepInto->setEnabled(enabled);
}


void DebugControlsWidget::setStepOverEnabled(bool enabled)
{
    m_actionStepOver->setEnabled(enabled);
}


void DebugControlsWidget::setStartingEnabled(bool enabled)
{
    m_actionRun->setEnabled(enabled && canExec());
    m_actionAttach->setEnabled(enabled && canConnect());
}


void DebugControlsWidget::setStoppingEnabled(bool enabled)
{
    m_actionRestart->setEnabled(enabled);
    m_actionQuit->setEnabled(enabled);
    m_actionDetach->setEnabled(enabled);
}


void DebugControlsWidget::setSteppingEnabled(bool enabled)
{
    m_actionStepInto->setEnabled(enabled);
    m_actionStepOver->setEnabled(enabled);
    m_actionStepReturn->setEnabled(enabled);    
}


void DebugControlsWidget::setDebuggerStatus(const std::string &status)
{
//    if (m_state->GetDebuggerUI() && m_state->GetDebuggerUI()->GetDebugView())
//    {
//        m_state->GetDebuggerUI()->GetDebugView()->setDebuggerStatus(status);
//    }
}


void DebugControlsWidget::uiEventHandler(const DebuggerEvent &event)
{
    updateButtons();

    switch (event.type)
    {
		case DetachedEventType:
		case QuitDebuggingEventType:
			break;

        case InitialViewRebasedEventType:
        {
            LogWarn("InitialViewRebasedEventType event");
            UIContext* context = UIContext::contextForWidget(this);
            ViewFrame* frame = context->getCurrentViewFrame();

            ViewLocation viewLocation = frame->getViewLocation();
//            FileMetadata* fileMetadata = m_controller->GetData()->GetFile();
            FileContext* fileContext = frame->getFileContext();
            fileContext->refreshDataViewCache();

            DebuggerWidget* parentWidget = dynamic_cast<DebuggerWidget*>(parent());
            if (!parentWidget)
                break;

            ViewFrame* newFrame = UIContext::contextForWidget(parentWidget)->openFileContext(fileContext);

//            if (newFrame)
//            {
////                tabCloseRequested(m_tab, curTabIdx);
////                QCoreApplication::processEvents(); // allow existing tab to be closed
////                viewLocation.setOffset(viewLocation.getOffset());
//                LogWarn("view type is: %s", viewLocation.getViewType().toStdString().c_str());
//                viewLocation.setViewType("Graph:Debugged Process");
//                if (auto func = viewLocation.getFunction(); func) // update function with function from new view
//                {
//                    View* view = newFrame->getViewForType(viewLocation.getViewType());
//                    if (view && view->getData())
//                        viewLocation.setFunction(view->getData()->GetAnalysisFunction(func->GetPlatform(), func->GetStart()));
//                }
//                newFrame->setViewLocation(viewLocation);
//            }

            break;
        }
        case TargetStoppedEventType:
        {
			if (event.data.targetStoppedData.reason == DebugStopReason::ProcessExited)
			{
				return;
			}

            uint64_t address = m_controller->GetState()->IP();
            // TODO: maybe we should do the navigate using the ViewFrame
//            m_controller->GetLiveView()->Navigate("Graph:Debugged Process", address);

            // Navigate to the address
            UIContext* context = UIContext::contextForWidget(this);
            View* view = context->getCurrentView();
            view->navigate(address);

            // Remove old instruction pointer highlight
            uint64_t lastIP = m_controller->GetLastIP();
            BinaryViewRef data = m_controller->GetLiveView();
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
        case AbsoluteBreakpointAddedEvent:
        {
            uint64_t address;
            if (event.type == RelativeBreakpointAddedEvent)
                address = event.data.relativeAddress.offset;
            else
                address = event.data.absoluteAddress;

            BinaryViewRef data = m_controller->GetLiveView();

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
            break;
        }
        case RelativeBreakpointRemovedEvent:
        case AbsoluteBreakpointRemovedEvent:
        {
            uint64_t address;
            if (event.type == RelativeBreakpointAddedEvent)
                address = event.data.relativeAddress.offset;
            else
                address = event.data.absoluteAddress;

            BinaryViewRef data = m_controller->GetLiveView();

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
            break;
        }

        default:
            break;
    }
}


TagTypeRef DebugControlsWidget::getPCTagType(BinaryViewRef data)
{
    TagTypeRef type = data->GetTagType("Program Counter");
    if (type)
        return type;

    TagTypeRef pcTagType = new TagType(data, "Program Counter", "==>");
    data->AddTagType(pcTagType);
    return pcTagType;
}


TagTypeRef DebugControlsWidget::getBreakpointTagType(BinaryViewRef data)
{
    TagTypeRef type = data->GetTagType("Breakpoints");
    if (type)
        return type;

    TagTypeRef pcTagType = new TagType(data, "Breakpoints", "🛑");
    data->AddTagType(pcTagType);
    return pcTagType;
}


void DebugControlsWidget::updateButtons()
{
    DebugAdapterConnectionStatus connection = m_controller->GetState()->GetConnectionStatus();
    DebugAdapterTargetStatus status = m_controller->GetState()->GetTargetStatus();

    if (connection == DebugAdapterNotConnectedStatus)
    {
        setStartingEnabled(true);
        setStoppingEnabled(false);
        setSteppingEnabled(false);
        m_actionPause->setEnabled(false);
        m_actionResume->setEnabled(false);
    }
    else if (status == DebugAdapterRunningStatus)
    {
        setStartingEnabled(false);
        setStoppingEnabled(true);
        setSteppingEnabled(false);
        m_actionPause->setEnabled(true);
        m_actionResume->setEnabled(false);
    }
    else
    {
        setStartingEnabled(false);
        setStoppingEnabled(true);
        setSteppingEnabled(true);
        m_actionPause->setEnabled(false);
        m_actionResume->setEnabled(true);
    }
}