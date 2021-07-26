#pragma once

#include "binaryninjaapi.h"
#include <QtWidgets/QToolBar>
#include <QtWidgets/QMenu>
#include <QtWidgets/QToolButton>
#include <QtGui/QIcon>
#include <QtWidgets/QLineEdit>
#include "uicontext.h"

struct BinaryViewAndWidgets
{
    BinaryViewRef data;
    std::unordered_map<QString, QWidget*> widgets;
};


class Widget
{
    // Widget() is just a collection of data and helper functions; it cannot be instantiated.
    Widget() = delete;

public:
    static std::vector<BinaryViewAndWidgets> g_debugDockWidgets;
    static QWidget* createWidgdet(const std::function<QWidget*(ViewFrame*, const QString&, BinaryViewRef)>& widgetClass,
            const QString& name, ViewFrame* parent, BinaryViewRef data);

    static void destroyWidget(QObject* destroyed, QWidget* old, BinaryViewRef data, const QString& name);
    static void registerDockWidget(const std::function<QWidget*(ViewFrame*, const QString&, BinaryViewRef)>& widgetClass,
        const std::string& name, Qt::DockWidgetArea area, Qt::Orientation orientation, bool defaultVisibility);
    static QWidget* getDockWidget(BinaryViewRef data, const std::string& name);
};
