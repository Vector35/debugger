#pragma once

#include <QAbstractItemModel>
#include <QItemSelectionModel>
#include <QModelIndex>
#include <QTableView>
#include <QStyledItemDelegate>
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
#include "threadswidget.h"
#include "controlswidget.h"
#include "ui.h"
#include "debuggerapi.h"

class DebuggerUI;

class DebuggerWidget: public SidebarWidget
{
    Q_OBJECT;

    ViewFrame* m_view;
    BinaryViewRef m_data;
    DebuggerController* m_controller;

    UIActionHandler* M_actionHandler;
    QSplitter *m_splitter;

    DebugControlsWidget* m_controlsWidget;
    DebugRegistersWidget* m_registersWidget;
    DebugBreakpointsWidget* m_breakpointsWidget;
    DebugModulesWidget* m_modulesWidget;

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
        return new DebuggerWidget("Native Debugger", frame, data);
    }
};
