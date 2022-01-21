#include "inttypes.h"
#include "uinotification.h"
#include "filecontext.h"
#include "viewframe.h"
#include <QtWidgets/QMessageBox>
#include <QtCore/QFileInfo>
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
	LogInfo("OnContextOpen");
}


void NotificationListener::OnContextClose(UIContext* context)
{
	LogInfo("OnContextClose");
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
	return true;
}


void NotificationListener::OnAfterCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
}


void NotificationListener::OnViewChange(UIContext* context, ViewFrame* frame, const QString& type)
{
//	LogInfo("OnViewChange");
	DebuggerUI* ui = DebuggerUI::CreateForViewFrame(frame);
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
	QFileInfo info(path);
	name = info.baseName();
	return true;
}
