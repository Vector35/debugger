#include <QtWidgets/QGroupBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QSplitter>
#include <QtGui/QFont>
#include "fontsettings.h"
#include "debugview.h"
#include "ui.h"

DebugView::DebugView(QWidget* parent, BinaryViewRef data): QWidget(parent)
{
    // setBinaryDataNavigable(true);
    setupView(this);

	m_data = data;
    m_state = DebuggerState::GetState(data);
    m_state->GetDebuggerUI()->SetDebugView(this);
    m_controls = new DebugControlsWidget(parent, "Controls", data, m_state);

    m_splitter = new QSplitter(Qt::Horizontal, this);
    ViewFrame* frame = ViewFrame::viewFrameForWidget(this);

    DebugProcessView* memoryView = m_state->GetMemoryView();

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

    // TODO: we should add an option whether to add a breakpoint at program entry
    uint64_t entryPoint = data->GetEntryPoint();
    uint64_t localEntryOffset = entryPoint - data->GetStart();
    ModuleNameAndOffset address(data->GetFile()->GetOriginalFilename(), localEntryOffset);
    if (!m_state->GetBreakpoints()->ContainsOffset(address))
    {
        m_state->GetBreakpoints()->AddOffset(address);
        LogWarn("added breakpoint at offset 0x%" PRIx64, localEntryOffset);
        if (m_state->GetDebuggerUI())
        {
            m_state->GetDebuggerUI()->AddBreakpointTag(m_state->GetData()->GetEntryPoint());
            m_state->GetDebuggerUI()->UpdateBreakpoints();
        }
    }
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
    if (!m_state->IsConnected())
    {
        return navigateLive(addr);
    }

    BinaryViewRef data = m_state->GetData();
    if (!data)
        return navigateRaw(addr);

    char temp;
    if (m_state->IsLocalAddress(addr))
    {
        uint64_t localAddr = m_state->RemoteAddressToLocal(addr);
        if (data->Read(&temp, localAddr, 1) && data->GetAnalysisFunctionsContainingAddress(localAddr).size() > 0)
            return navigateLive(localAddr);  
    }

    if (data->Read(&temp, addr, 1) && data->GetAnalysisFunctionsContainingAddress(addr).size() > 0)
        return navigateLive(addr);        

    return navigateRaw(addr);
}


void DebugView::focusInEvent(QFocusEvent*)
{
	// if (m_byteView)
	// 	m_byteView->setFocus(Qt::OtherFocusReason);
}


bool DebugView::navigateLive(uint64_t addr)
{
    showRawAssembly(false);
    return m_binaryEditor->getDisassembly()->navigate(addr);
}


bool DebugView::navigateRaw(uint64_t addr)
{
    if (!m_state->IsConnected())
        return false;

    m_rawAddress = addr;
    showRawAssembly(true);
    loadRawDisassembly(addr);
    return true;
}


void DebugView::showRawAssembly(bool raw)
{
    if (raw != m_isRawDisassembly)
    {
        if (raw)
        {
            LogWarn("m_splitter count: %d", m_splitter->count());
            // if (m_splitter && m_disassemblyWidget)
            //     m_splitter->replaceWidget(0, m_disassemblyWidget);
            // else
            //     LogWarn("something invalid");
        }
        else
        {
            if (m_splitter && m_binaryViewWidget)
                m_splitter->replaceWidget(0, m_binaryViewWidget);
        }
    }
    m_isRawDisassembly = raw;
}


void DebugView::loadRawDisassembly(uint64_t addr)
{
    LogWarn("Showing raw disassembly at 0x%" PRIx64, addr);
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
