#include <QtWidgets/QGroupBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QSplitter>
#include <QtGui/QFont>
#include "fontsettings.h"
#include "debugview.h"


DebugView::DebugView(QWidget* parent, BinaryViewRef data): QWidget(parent)
{
    // setBinaryDataNavigable(true);
    setupView(this);

	m_data = data;
    m_state = new DebuggerState(data);
    m_controls = new DebugControlsWidget(parent, "Controls", data, m_state);

    m_splitter = new QSplitter(Qt::Horizontal, this);
    ViewFrame* frame = ViewFrame::viewFrameForWidget(this);

    DebugProcessView* memoryView = m_state->getMemoryView();

    m_memoryEditor = new LinearView(memoryView, frame);
    m_binaryEditor = new DisassemblyContainer(frame, data, frame);
    m_binaryText = new TokenizedTextView(this, memoryView);

    m_isRawDisassembly = false;
    m_rawAddress = 0;

    m_isNavigatingHistory = false;
    m_memoryHistoryAddress = 0;

    // TODO: bind navigation actions

    QFont smallFont = QFont();
    smallFont.setPointSize(11);

    QVBoxLayout* m_binaryViewLayout = new QVBoxLayout;
    m_binaryViewLayout->setSpacing(0);
    m_binaryViewLayout->setContentsMargins(0, 0, 0, 0);

    m_bianryViewLabel = new QLabel("Loaded File");
    m_bianryViewLabel->setFont(smallFont);
    m_binaryViewLayout->addWidget(m_bianryViewLabel);
    m_binaryViewLayout->addWidget(m_binaryEditor);

    QWidget* m_binaryViewWidget = new QWidget;
    m_binaryViewWidget->setLayout(m_binaryViewLayout);


    QVBoxLayout* m_disassemblyLayout = new QVBoxLayout;
    m_disassemblyLayout->setSpacing(0);
    m_disassemblyLayout->setContentsMargins(0, 0, 0, 0);

    m_disassemblyLabel = new QLabel("Raw Disassembly at PC");
    m_disassemblyLabel->setFont(smallFont);
    m_disassemblyLayout->addWidget(m_disassemblyLabel);
    m_disassemblyLayout->addWidget(m_binaryText);

    QWidget* m_disassemblyWidget = new QWidget;
    m_disassemblyWidget->setLayout(m_disassemblyLayout);


    QVBoxLayout* m_memoryLayout = new QVBoxLayout;
    m_memoryLayout->setSpacing(0);
    m_memoryLayout->setContentsMargins(0, 0, 0, 0);

    m_memoryLabel = new QLabel("Debugged Process");
    m_memoryLabel->setFont(smallFont);
    m_memoryLayout->addWidget(m_memoryLabel);
    m_memoryLayout->addWidget(m_memoryEditor);

    QWidget* m_memoryWidget = new QWidget;
    m_memoryWidget->setLayout(m_memoryLayout);


    m_splitter->addWidget(m_binaryViewWidget);
    m_splitter->addWidget(m_memoryWidget);
    m_splitter->setSizes(QList<int>(2, 0x7fffffff));

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_controls);
    layout->addWidget(m_splitter, 100);
    setLayout(layout);

    m_needsUpdate = true;
    m_updateTimer = new QTimer(this);
    m_updateTimer->setInterval(200);
    m_updateTimer->setSingleShot(false);
    connect(m_updateTimer, &QTimer::timeout, this, &DebugView::updateTimerEvent);
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


void DebugView::updateTimerEvent()
{
    if (m_needsUpdate)
    {
        // TODO: we probably need to /ALWAYS/ refresh the memory, since the memory could have
        // been updated even if no events happen
        m_needsUpdate = false;
        m_memoryEditor->navigate(0);
    }
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
