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

#include <QPainter>
#include <QHeaderView>
#include <QGuiApplication>
#include <QMimeData>
#include <QClipboard>
#include "ui.h"
#include "debuggerinfowidget.h"

using namespace BinaryNinja;
using namespace std;


DebugInfoSidebarWidget::DebugInfoSidebarWidget(BinaryViewRef data): SidebarWidget("Debugger Info"), m_data(data)
{
	m_debugger = DebuggerController::GetController(data);
	m_label = new QLabel("nothing");
	auto* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(m_label);
	setLayout(layout);
}


void DebugInfoSidebarWidget::notifyViewLocationChanged(View* view, const ViewLocation& location)
{
	auto info = QString::asprintf("View type: %s, offset: 0x%llx, il: %d", location.getViewType().toStdString().c_str(), location.getOffset(), location.getILViewType());
	m_label->setText(info);
}


DebugInfoSidebarWidget::~DebugInfoSidebarWidget()
{

}


DebugInfoWidgetType::DebugInfoWidgetType():
	SidebarWidgetType(QIcon(":/icons/images/history.png").pixmap(QSize(64, 64)).toImage(), "Debugger Info")
{
}


SidebarWidget* DebugInfoWidgetType::createWidget(ViewFrame*, BinaryViewRef data)
{
	return new DebugInfoSidebarWidget(data);
}
