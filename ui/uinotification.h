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

#pragma once

#include "uicontext.h"

class NotificationListener : UIContextNotification
{
	static NotificationListener* m_instance;

public:
	virtual void OnContextOpen(UIContext* context) override;
	virtual void OnContextClose(UIContext* context) override;
	virtual bool OnBeforeOpenDatabase(UIContext* context, FileMetadataRef metadata) override;
	virtual bool OnAfterOpenDatabase(UIContext* context, FileMetadataRef metadata, BinaryViewRef data) override;
	virtual bool OnBeforeOpenFile(UIContext* context, FileContext* file) override;
	virtual void OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual bool OnBeforeSaveFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual void OnAfterSaveFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual bool OnBeforeCloseFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual void OnAfterCloseFile(UIContext* context, FileContext* file, ViewFrame* frame) override;
	virtual void OnViewChange(UIContext* context, ViewFrame* frame, const QString& type) override;
	virtual void OnAddressChange(
		UIContext* context, ViewFrame* frame, View* view, const ViewLocation& location) override;
	virtual bool GetNameForFile(UIContext* context, FileContext* file, QString& name) override;
	virtual bool GetNameForPath(UIContext* context, const QString& path, QString& name) override;

	static void init();
};