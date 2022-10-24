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

#include "launchdialog.h"
#include "uicontext.h"
#include "QVBoxLayout"
#include "QPushButton"
#include "QMessageBox"
#include "QTimer"
#include "fmt/format.h"

using namespace BinaryNinjaDebuggerAPI;
using namespace BinaryNinja;
using namespace std;

DebuggerLaunchDialog::DebuggerLaunchDialog(QWidget* parent, DebuggerControllerRef controller,
										   const enum DebuggerLaunchOperation operation):
	QDialog(), m_controller(controller)
{
	QString title;
	switch (operation)
	{
	case LaunchOperation:
		title = "Launching";
		break;
	case ConnectOperation:
		title = "Connecting";
	case AttachOperation:
		title = "Attaching";
	default:
//		ConnectToDebugServerOperation is not used for now
		break;
	}

    setWindowTitle(title);
    setMinimumSize(UIContext::getScaledWindowSize(400, 130));
    setAttribute(Qt::WA_DeleteOnClose);

    setModal(true);
    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);

	m_text = new QLabel("");
	m_text->setWordWrap(true);

	QString operationString;
	switch (operation)
	{
	case LaunchOperation:
		operationString = "launching";
		break;
	case ConnectOperation:
		operationString = "connecting to";
	case AttachOperation:
		operationString = "attaching to";
	default:
//		ConnectToDebugServerOperation is not used for now
		break;
	}

	QString text = QString("The debugger is %1 the target and preparing the debugger binary view. \n"
									 "This might take a while. \n\n"
									 "It is highly recommended that you wait for this dialog to dismiss before you \n"
									 "further interact with Binary Ninja or the running target.").arg(operationString);
	m_text->setText(text);

	// The code below are commented out because pressing the "Cancel" button does not cancel the launch -- it just
	// closes the dialog. To avoid confusion, it is better not to show the button at all, for now.
	// The dialog can still be closed by clicking the "X" button on its top -- if anything goes wrong and the dialog
	// does not dismiss automatically.

//    QHBoxLayout* buttonLayout = new QHBoxLayout;
//    buttonLayout->setContentsMargins(0, 0, 0, 0);
//
//    QPushButton* cancelButton = new QPushButton("Cancel");
//    connect(cancelButton, &QPushButton::clicked, [&](){ reject(); });
//    cancelButton->setDefault(true);
//
//    buttonLayout->addStretch(1);
//    buttonLayout->addWidget(cancelButton);

    layout->addStretch(1);
	layout->addWidget(m_text);
    layout->addSpacing(10);
//    layout->addLayout(buttonLayout);
    setLayout(layout);

	m_callbackIndex = m_controller->RegisterEventCallback([&](const DebuggerEvent& event){
		switch (event.type)
		{
		case TargetStoppedEventType:
			// The target has stopped. The launch procedure is considered, dismiss the dialog and allow user interaction
			accept();
			break;
		case TargetExitedEventType:
		{
			// The target exited without hitting any breakpoint. Show a message box
			uint8_t exitCode = event.data.exitData.exitCode;
			auto message = QString::fromStdString(fmt::format("The target has exited with code {}", exitCode));
			QMessageBox::information(this, "Exited", message);
			reject();
			break;
		}

		case ErrorEventType:
		{
			// an error occurred during the launch
			QString message;
			if (!event.data.errorData.error.empty())
				message = QString::fromStdString(event.data.errorData.error);
			else if (!event.data.errorData.shortError.empty())
				message = QString::fromStdString(event.data.errorData.shortError);
			else
				message = "An error occurred";

			QMessageBox::critical(this, "Error", message);
			reject();
			break;
		}

		default:
			break;
		}
	}, "LaunchDialog");

	// Only show the dialog after one second
	QTimer::singleShot(1000, this, &DebuggerLaunchDialog::show);
}


DebuggerLaunchDialog::~DebuggerLaunchDialog()
{
	if (m_controller && (m_callbackIndex != -1))
		m_controller->RemoveEventCallback(m_callbackIndex);

	m_callbackIndex = -1;
}
