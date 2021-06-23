#include "registerwidget.h"

using namespace BinaryNinja;
using namespace std;

DebugRegisterWidget::DebugRegisterWidget(ViewFrame* view, const std::string& name, BinaryViewRef data):
    QWidget(view), DockContextHandler(this, name), m_view(view), m_data(data)
{

}
