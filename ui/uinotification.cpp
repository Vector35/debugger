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

#include "inttypes.h"
#include "uinotification.h"
#include "filecontext.h"
#include "viewframe.h"
#include <QMessageBox>
#include <QFileInfo>
#include <QPushButton>
#include <QObject>
#include "ui.h"

using namespace BinaryNinja;

NotificationListener* NotificationListener::m_instance = nullptr;

void NotificationListener::init()
{
	m_instance = new NotificationListener;
	UIContext::registerNotification(m_instance);
}


void NotificationListener::OnContextOpen(UIContext* context)
{
	GlobalDebuggerUI* ui = GlobalDebuggerUI::CreateForContext(context);
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


void NotificationListener::OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
}


bool NotificationListener::OnBeforeSaveFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	return true;
}


void NotificationListener::OnAfterSaveFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
}


bool NotificationListener::OnBeforeCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	auto currentTab = context->getCurrentTab();
	auto mainWindow = context->mainWindow();
	auto tabs = context->getTabs();
	bool tabRemaining = false;
	for (auto tab: tabs)
	{
		if (tab == currentTab)
			continue;

		auto viewFrame = context->getViewFrameForTab(tab);
		if (viewFrame && (viewFrame->getFileContext() == file))
		{
			tabRemaining = true;
			break;
		}
	}

	// This is the last tab of the file being closed. Check whether the debugger is connected
	if (!tabRemaining)
	{
		auto viewFrame = context->getCurrentViewFrame();
		if (!viewFrame)
			return true;
		auto data = viewFrame->getCurrentBinaryView();
		if (!data)
			return true;
		auto controller = DebuggerController::GetController(data);
		if (controller && controller->IsConnected())
		{
			QMessageBox* msgBox = new QMessageBox(mainWindow);
			msgBox->setAttribute(Qt::WA_DeleteOnClose);
			msgBox->setIcon(QMessageBox::Question);
			msgBox->setText(QObject::tr("The debugger file ") + file->getShortFileName(mainWindow) + QObject::tr(" is active. Do you want to stop it before closing?"));
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
				controller->Quit();
				return true;
			}
		}
	}
	return true;
}


void NotificationListener::OnAfterCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
}


void NotificationListener::OnViewChange(UIContext* context, ViewFrame* frame, const QString& type)
{
	GlobalDebuggerUI::GetForContext(context)->SetActiveFrame(frame);
}


void NotificationListener::OnAddressChange(UIContext* context, ViewFrame* frame, View* view, const ViewLocation& location)
{
}


bool NotificationListener::GetNameForFile(UIContext* context, FileContext* file, QString& name)
{
	name = file->getFilename();
	return true;
}


bool NotificationListener::GetNameForPath(UIContext* context, const QString& path, QString& name)
{
	name = path;
	return true;
}
