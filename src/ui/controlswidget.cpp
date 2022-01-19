#include "controlswidget.h"
#include "adaptersettings.h"
#include <QtGui/QPixmap>
#include <QtCore/QCoreApplication>
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
                        [this](){ performLaunch(); });
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
    m_controller->RemoveEventCallback(m_eventCallback);
}


void DebugControlsWidget::performLaunch()
{
    std::thread([&](){
        m_controller->Launch();
    }).detach();
}


void DebugControlsWidget::performRestart()
{
    std::thread([&](){
        m_controller->Restart();
    }).detach();
}


void DebugControlsWidget::performQuit()
{
    std::thread([&](){
        m_controller->Quit();
    }).detach();
}


void DebugControlsWidget::performAttach()
{
    std::thread([&](){
        m_controller->Attach();
    }).detach();
}


void DebugControlsWidget::performDetach()
{
    std::thread([&](){
        m_controller->Detach();
    }).detach();
}


void DebugControlsWidget::performSettings()
{
    AdapterSettingsDialog* dialog = new AdapterSettingsDialog(this, m_controller);
    dialog->show();
    QObject::connect(dialog, &QDialog::finished, [this](){
        updateButtons();
    });
}


void DebugControlsWidget::performPause()
{
    m_controller->Pause();
//    Don't update state here-- one of the other thread is running in a thread and updating for us
}


void DebugControlsWidget::performResume()
{
	std::thread([&](){
    	m_controller->Go();
	}).detach();
}


void DebugControlsWidget::performStepInto()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

    std::thread([&, graphType](){
        m_controller->StepInto(graphType);
    }).detach();
}


void DebugControlsWidget::performStepOver()
{
    BNFunctionGraphType graphType = NormalFunctionGraph;
    UIContext* context = UIContext::contextForWidget(this);
    if (context && context->getCurrentView())
        graphType = context->getCurrentView()->getILViewType();

    std::thread([&, graphType](){
        m_controller->StepOver(graphType);
    }).detach();
}


void DebugControlsWidget::performStepReturn()
{
    std::thread([&](){
        m_controller->StepReturn();
    }).detach();
}


bool DebugControlsWidget::canExec()
{
	auto currentAdapter = m_controller->GetState()->GetAdapterType();
	if (currentAdapter == "")
		return false;
    auto adapter = DebugAdapterType::GetByName(currentAdapter);
	if (!adapter)
		return false;
	return adapter->CanExecute(m_controller->GetData());
}


bool DebugControlsWidget::canConnect()
{
	auto currentAdapter = m_controller->GetState()->GetAdapterType();
	if (currentAdapter == "")
		return false;
	auto adapter = DebugAdapterType::GetByName(currentAdapter);
	if (!adapter)
		return false;
    return adapter->CanConnect(m_controller->GetData());
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


void DebugControlsWidget::uiEventHandler(const DebuggerEvent &event)
{
    ExecuteOnMainThreadAndWait([&](){
        updateButtons();
    });

    switch (event.type)
    {
		case DetachedEventType:
		case QuitDebuggingEventType:
		case TargetExitedEventType:
		{
			std::thread([=](){
				ExecuteOnMainThreadAndWait([=]()
				{
					UIContext* context = UIContext::contextForWidget(this);
					ViewFrame* frame = context->getCurrentViewFrame();
					FileContext* fileContext = frame->getFileContext();
					fileContext->refreshDataViewCache();
					ViewFrame* newFrame = context->openFileContext(fileContext);
					QCoreApplication::processEvents();

					if (newFrame)
					{
						newFrame->navigate(m_controller->GetData(), m_controller->GetData()->GetEntryPoint(), true, true);
						context->closeTab(context->getTabForFile(fileContext));
						QCoreApplication::processEvents();
					}
					else
					{
						LogWarn("fail to navigate to the original view");
					}
				});
			}).detach();
			break;
		}

        case InitialViewRebasedEventType:
        {
			uint64_t address = m_controller->GetState()->IP();
			// If there is no function at the current address, define one. This might be a little aggressive,
			// but given that we are lacking the ability to "show as code", this feels like an OK workaround.
			auto functions = m_controller->GetLiveView()->GetAnalysisFunctionsContainingAddress(address);
			if (functions.size() == 0)
				m_controller->GetLiveView()->CreateUserFunction(m_controller->GetLiveView()->GetDefaultPlatform(), address);

			std::thread([=](){
				ExecuteOnMainThreadAndWait([=]()
				{
					UIContext* context = UIContext::contextForWidget(this);
					ViewFrame* frame = context->getCurrentViewFrame();
					FileContext* fileContext = frame->getFileContext();
					fileContext->refreshDataViewCache();
					ViewFrame* newFrame = context->openFileContext(fileContext);
					QCoreApplication::processEvents();

					if (newFrame)
					{
						newFrame->navigate(m_controller->GetLiveView(), address, true, true);
						context->closeTab(context->getTabForFile(fileContext));
						QCoreApplication::processEvents();
					}
					else
					{
						LogWarn("fail to navigate to the debugger view");
					}
				});
			}).detach();
			break;
        }
        case TargetStoppedEventType:
        {
			if (event.data.targetStoppedData.reason == DebugStopReason::ProcessExited)
			{
				return;
			}

            uint64_t address = m_controller->GetState()->IP();
			// If there is no function at the current address, define one. This might be a little aggressive,
			// but given that we are lacking the ability to "show as code", this feels like an OK workaround.
            BinaryViewRef liveView = m_controller->GetLiveView();
            if (!liveView)
                break;

			auto functions = liveView->GetAnalysisFunctionsContainingAddress(address);
			if (functions.size() == 0)
				m_controller->GetLiveView()->CreateUserFunction(m_controller->GetLiveView()->GetDefaultPlatform(), address);

            // This works, but it seems not natural to me
            std::thread([=](){
                ExecuteOnMainThreadAndWait([this, address]()
                {
                    UIContext* context = UIContext::contextForWidget(this);
                    ViewFrame* frame = context->getCurrentViewFrame();
					frame->navigate(m_controller->GetLiveView(), address, true, true);
                });
            }).detach();

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
                    if (tag->GetType() != m_controller->getPCTagType(data))
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
                    if (tag->GetType() == m_controller->getPCTagType(data))
                    {
                        tagFound = true;
                        break;
                    }
                }

                if (!tagFound)
                {
                    func->SetAutoInstructionHighlight(data->GetDefaultArchitecture(), address, BlueHighlightColor);
                    func->CreateUserAddressTag(data->GetDefaultArchitecture(), address, m_controller->getPCTagType(data),
                                               "program counter");
                }
            }
            break;
        }
        default:
            break;
    }
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
