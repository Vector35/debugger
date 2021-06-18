#include <QtWidgets/QGroupBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QSplitter>
#include "fontsettings.h"
#include "debugview.h"


DebugView::DebugView(QWidget* parent, BinaryViewRef data): QWidget(parent)
{
	m_data = data;
    m_state = new DebuggerState(data);
    m_controls = new DebugControlsWidget(parent, "Controls", data, m_state);
    QVBoxLayout* layout = new QVBoxLayout;
    layout->addWidget(m_controls);
    setLayout(layout);
}


BinaryViewRef DebugView::getData()
{
	return m_data;
}


uint64_t DebugView::getCurrentOffset()
{
	// if (m_byteView)
	// 	return m_byteView->getCurrentOffset();
	return m_currentOffset;
}


BNAddressRange DebugView::getSelectionOffsets()
{
	// if (m_byteView)
	// 	return m_byteView->getSelectionOffsets();
	return { m_currentOffset, m_currentOffset };
}

void DebugView::setSelectionOffsets(BNAddressRange range)
{
	// for subclass of View who does not have a meaningful setSelectionOffsets() behavior,
	// we navigate to the start of the selection range
	navigate(range.start);
}

void DebugView::setCurrentOffset(uint64_t offset)
{
	m_currentOffset = offset;
	UIContext::updateStatus(true);
}


QFont DebugView::getFont()
{
	return getMonospaceFont(this);
}


bool DebugView::navigate(uint64_t addr)
{
	// if (m_byteView)
	// 	return m_byteView->navigate(addr);
	return false;
}


void DebugView::focusInEvent(QFocusEvent*)
{
	// if (m_byteView)
	// 	m_byteView->setFocus(Qt::OtherFocusReason);
}


DebugViewType::DebugViewType(): ViewType("Native Debugger", "Native Debugger")
{
}


int DebugViewType::getPriority(BinaryViewRef data, const QString&)
{
	return 1;
}


QWidget* DebugViewType::create(BinaryViewRef data, ViewFrame* frame)
{
	return new DebugView(frame, data);
}
