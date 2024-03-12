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

#include "inttypes.h"
#include "uinotification.h"
#include "filecontext.h"
#include "viewframe.h"
#include <QMessageBox>
#include <QFileInfo>
#include <QPushButton>
#include <QObject>
#include <QCheckBox>
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

	auto settings = Settings::Instance();
	if (controller->GetLiveView() && settings->Get<bool>("debugger.ui.warnDebuggerBinaryViewLost"))
	{
		QMessageBox* msgBox = new QMessageBox(mainWindow);
		msgBox->setAttribute(Qt::WA_DeleteOnClose, false);
		msgBox->setIcon(QMessageBox::Question);
		msgBox->setText(QObject::tr("The debugger binary view for ") + file->getShortFileName(mainWindow)
			+ QObject::tr(" cannot be saved into the database. Changes in it will be permanently lost after closing. \n\n"
						  "If you wish to save them, please manually copy the changes to the ")
						  + QString::fromStdString(controller->GetData()->GetTypeName()) +
						  QObject::tr(" view.\n\n"
						  "Would you like to close the file?"));

		msgBox->setWindowTitle(QObject::tr("Debugger Binary View"));
		msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
		msgBox->setDefaultButton(QMessageBox::Cancel);
		msgBox->setAttribute(Qt::WA_KeyboardFocusChange);

		QCheckBox* checkBox = new QCheckBox(QObject::tr("Do not ask again"));
		msgBox->setCheckBox(checkBox);

		int result = msgBox->exec();
		auto state = checkBox->checkState();
		delete msgBox;

		if (result == QMessageBox::Cancel)
		{
			return false;
		}
		else if (state == Qt::Checked)
		{
			settings->Set("debugger.ui.warnDebuggerBinaryViewLost", false);
		}
	}

	if (controller->IsConnected())
	{
		QMessageBox* msgBox = new QMessageBox(mainWindow);
		msgBox->setAttribute(Qt::WA_DeleteOnClose);
		msgBox->setIcon(QMessageBox::Question);
		msgBox->setText(QObject::tr("The debugger file ") + file->getShortFileName(mainWindow)
			+ QObject::tr(" is active. Do you want to stop it before closing?"));
		msgBox->setWindowTitle(QObject::tr("Debugger Active"));
		msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
		msgBox->setDefaultButton(QMessageBox::Cancel);
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
