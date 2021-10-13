#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QModelIndex>
#include <QtWidgets/QTableView>
#include <QtWidgets/QStyledItemDelegate>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "../debuggerstate.h"
#include "expandablegroup.h"
#include "stackwidget.h"
#include "breakpointswidget.h"
#include "registerswidget.h"
#include "moduleswidget.h"
#include "threadswidget.h"
#include "controlswidget.h"
#include "../debuggercontroller.h"

class DebuggerController;
class DebugRegistersWidget;

class DebuggerWidget: public SidebarWidget
{
    Q_OBJECT;

    ViewFrame* m_view;
    BinaryViewRef m_data;
    DebuggerController* m_controller;

    UIActionHandler* M_actionHandler;
    ExpandableGroup *m_registersGroup, *m_breakpointsGroup, *m_stackGroup, *m_threadsGroup, *m_modulesGroup;
    QSplitter *m_splitter;

    DebugControlsWidget* m_controlsWidget;
    DebugRegistersWidget* m_registersWidget;
    DebugBreakpointsWidget* m_breakpointsWidget;
    DebugModulesWidget* m_modulesWidget;
    DebugThreadsWidget* m_threadsWidget;
    DebugStackWidget* m_stackWidget;

    DebuggerState* m_state;
    DebuggerUI* m_ui;

    size_t m_eventCallback;

    // void shouldBeVisible()

    virtual void notifyFontChanged() override;


public:
    DebuggerWidget(const QString& name, ViewFrame* view, BinaryViewRef data);
    ~DebuggerWidget();

    DebugBreakpointsWidget* getBreakpointsWidget() const { return m_breakpointsWidget; }
    DebugModulesWidget* getModulesWidget() const { return m_modulesWidget; }
    DebugThreadsWidget* getThreadsWidget() const { return m_threadsWidget; }
    DebugStackWidget* getStackWidget() const { return m_stackWidget; }

    void uiEventHandler(const DebuggerEvent& event);

private slots:
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
