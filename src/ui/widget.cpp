#include "widget.h"
#include "dockhandler.h"

using namespace BinaryNinja;

std::vector<BinaryViewAndWidgets> Widget::g_debugDockWidgets;

QWidget* Widget::createWidgdet(const std::function<QWidget*(ViewFrame*, const QString&, BinaryViewRef)>& widgetClass,
        const QString& name, ViewFrame* parent, BinaryViewRef data)
{
    QWidget* widget = widgetClass(parent, name, data);
    if (!widget)
        return nullptr;

    bool found = false;
    for (BinaryViewAndWidgets bvAndWidget: g_debugDockWidgets)
    {
        if (bvAndWidget.data == data)
        {
            bvAndWidget.widgets[name] = widget;
            found = true;
            break;            
        }
    }

    if (!found)
    {
        BinaryViewAndWidgets bvAndWidget;
        bvAndWidget.data = data;
        bvAndWidget.widgets[name] = widget;
        g_debugDockWidgets.push_back(bvAndWidget);
    }

    QObject::connect(widget, &QWidget::destroyed, [&](QObject* destroyed){
        destroyWidget(destroyed, widget, data, name);
    });

    return widget;
}


void Widget::destroyWidget(QObject* destroyed, QWidget* old, BinaryViewRef data, const QString& name)
{
    for (BinaryViewAndWidgets bvAndWidget: g_debugDockWidgets)
    {
        if (bvAndWidget.data == data)
        {
            auto iter = bvAndWidget.widgets.find(name);
            if (iter != bvAndWidget.widgets.end())
            {
                bvAndWidget.widgets.erase(iter);
            }
        }
    } 
}


void Widget::registerDockWidget(const std::function<QWidget*(ViewFrame*, const QString&, BinaryViewRef)>& widgetClass,
    const std::string& name, Qt::DockWidgetArea area, Qt::Orientation orientation, bool defaultVisibility)
{
    DockHandler* activeDocks = DockHandler::getActiveDockHandler();
	activeDocks->addDockWidget(QString::fromStdString(name),
        [&](const QString& name, ViewFrame* frame, BinaryViewRef data) -> QWidget* { 
            return Widget::createWidgdet(widgetClass, name, frame, data); 
        },
        area, orientation, defaultVisibility);
}


QWidget* Widget::getDockWidget(BinaryViewRef data, const std::string& name)
{
    for (const BinaryViewAndWidgets bvAndWidget: g_debugDockWidgets)
    {
        if (bvAndWidget.data == data)
        {
            auto iter = bvAndWidget.widgets.find(QString::fromStdString(name));
            if (iter != bvAndWidget.widgets.end())
            {
                return iter->second;
            }
            else
            {
                return nullptr;
            }
            
        }
    }
    return nullptr;
}
