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

#pragma once

#include <QAbstractItemModel>
#include <QItemSelectionModel>
#include <QModelIndex>
#include <QTableView>
#include <QStyledItemDelegate>
#include <QTabWidget>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "expandablegroup.h"
#include "stackwidget.h"
#include "breakpointswidget.h"
#include "registerswidget.h"
#include "moduleswidget.h"
#include "controlswidget.h"
#include "ui.h"
#include "debuggerapi.h"

class DebuggerUI;

class DebuggerWidget: public SidebarWidget
{
    Q_OBJECT;

    ViewFrame* m_view;
    DbgRef<DebuggerController> m_controller;

    QSplitter *m_splitter;
	QTabWidget* m_tabs;

    DebugControlsWidget* m_controlsWidget;
	DebugRegistersContainer* m_registersWidget;
	DebugBreakpointsWidget* m_breakpointsWidget;

	DebuggerUI* m_ui;

    // void shouldBeVisible()

    virtual void notifyFontChanged() override;

private slots:
	void uiEventHandler(const DebuggerEvent &event);

public:
    DebuggerWidget(const QString& name, ViewFrame* view, BinaryViewRef data);
    ~DebuggerWidget();

	void updateContent();
};


class DebuggerWidgetType : public SidebarWidgetType {
public:
    DebuggerWidgetType(const QImage& icon, const QString& name) : SidebarWidgetType(icon, name) { }

    bool isInReferenceArea() const override { return false; }

    SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override {
        return new DebuggerWidget("Debugger", frame, data);
    }
};
