#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QModelIndex>
#include <QtWidgets/QTableView>
#include <QtWidgets/QStyledItemDelegate>
#include "inttypes.h"
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "../debuggerstate.h"
#include "expandablegroup.h"
#include "stackwidget.h"
#include "breakpointswidget.h"
#include "moduleswidget.h"
#include "threadswidget.h"

class DebuggerWidget: public SidebarWidget
{
    Q_OBJECT;

    ViewFrame* m_view;
    BinaryViewRef m_data;

    UIActionHandler* M_actionHandler;
    ExpandableGroup *m_breakpointsGroup, *m_stackGroup, *m_threadsGroup, *m_modulesGroup;
    QSplitter *m_splitter;

    DebugBreakpointsWidget* m_breakpointsWidget;
    DebugModulesWidget* m_modulesWidget;
    DebugThreadsWidget* m_threadsWidget;
    DebugStackWidget* m_stackWidget;

    DebuggerState* m_state;
    DebuggerUI* m_ui;

    // void shouldBeVisible()

    virtual void notifyFontChanged() override;


public:
    DebuggerWidget(const QString& name, ViewFrame* view, BinaryViewRef data);
    ~DebuggerWidget();

    DebugBreakpointsWidget* getBreakpointsWidget() const { return m_breakpointsWidget; }
    DebugModulesWidget* getModulesWidget() const { return m_modulesWidget; }
    DebugThreadsWidget* getThreadsWidget() const { return m_threadsWidget; }
    DebugStackWidget* getStackWidget() const { return m_stackWidget; }

private slots:
    void updateContext();
};


class DebuggerWidgetType : public SidebarWidgetType {
public:
    DebuggerWidgetType(const QImage& icon, const QString& name) : SidebarWidgetType(icon, name) { }

    bool isInReferenceArea() const override { return false; }

    SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override {
        return new DebuggerWidget("Native Debugger", frame, data);
    }
};
