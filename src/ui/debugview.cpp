#include <QtWidgets/QGroupBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QSplitter>
#include <QtGui/QFont>
#include "fontsettings.h"
#include "debugview.h"
#include "ui.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;

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

    m_binaryEditor = new DisassemblyContainer(frame, data, frame);
    m_binaryText = new TokenizedTextView(this, memoryView);

    m_isRawDisassembly = false;
    m_rawAddress = 0;

    m_isNavigatingHistory = false;
    m_memoryHistoryAddress = 0;

    QFont smallFont = QFont();
    smallFont.setPointSize(11);

    m_binaryViewLayout = new QVBoxLayout;
    m_binaryViewLayout->setSpacing(0);
    m_binaryViewLayout->setContentsMargins(0, 0, 0, 0);

    m_bianryViewLabel = new QLabel("Loaded File");
    m_bianryViewLabel->setFont(smallFont);
    m_binaryViewLayout->addWidget(m_bianryViewLabel);
    m_binaryViewLayout->addWidget(m_binaryEditor);

    m_binaryViewWidget = new QWidget;
    m_binaryViewWidget->setLayout(m_binaryViewLayout);


    m_disassemblyLayout = new QVBoxLayout;
    m_disassemblyLayout->setSpacing(0);
    m_disassemblyLayout->setContentsMargins(0, 0, 0, 0);

    m_disassemblyLabel = new QLabel("Raw Disassembly at PC");
    m_disassemblyLabel->setFont(smallFont);
    m_disassemblyLayout->addWidget(m_disassemblyLabel);
    m_disassemblyLayout->addWidget(m_binaryText);

    m_disassemblyWidget = new QWidget;
    m_disassemblyWidget->setLayout(m_disassemblyLayout);

    m_memoryTabs = new QTabWidget(this);
    for (size_t i = 0; i < m_numMemoryTabs; i++)
    {
        LinearView* memoryEditor = new LinearView(memoryView, frame);
        m_memoryTabs->addTab(memoryEditor, QString::asprintf("Memory %ld", i));
    }

    m_splitter->addWidget(m_binaryViewWidget);
    m_splitter->addWidget(m_memoryTabs);
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

    // TODO: Handle these and change views accordingly
    // Currently they are just disabled as the DisassemblyContainer gets confused
    // about where to go and just shows a bad view
    m_binaryEditor->getDisassembly()->actionHandler()->bindAction("View in Hex Editor", UIAction());
    m_binaryEditor->getDisassembly()->actionHandler()->bindAction("View in Linear Disassembly", UIAction());
    m_binaryEditor->getDisassembly()->actionHandler()->bindAction("View in Types View", UIAction());

    for (size_t i = 0; i < m_numMemoryTabs; i++)
    {
        LinearView* view = dynamic_cast<LinearView*>(m_memoryTabs->widget(i));
        if (!view)
            continue;

        view->actionHandler()->bindAction("View in Hex Editor", UIAction());
        view->actionHandler()->bindAction("View in Linear Disassembly", UIAction());
        view->actionHandler()->bindAction("View in Types View", UIAction());
    }

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
    if (!m_isRawDisassembly)
        return m_binaryEditor->getDisassembly()->getCurrentOffset();

    return m_rawAddress;
}


BNAddressRange DebugView::getSelectionOffsets()
{
    if (!m_isRawDisassembly)
        return m_binaryEditor->getDisassembly()->getSelectionOffsets();

    return { m_rawAddress, m_rawAddress };
}


FunctionRef DebugView::getCurrentFunction()
{
    if (!m_isRawDisassembly)
        return m_binaryEditor->getDisassembly()->getCurrentFunction();

    return nullptr;
}


BasicBlockRef DebugView::getCurrentBasicBlock()
{
    if (!m_isRawDisassembly)
        return m_binaryEditor->getDisassembly()->getCurrentBasicBlock();

    return nullptr;
}


ArchitectureRef DebugView::getCurrentArchitecture()
{
    if (!m_isRawDisassembly)
        return m_binaryEditor->getDisassembly()->getCurrentArchitecture();

    return nullptr;
}


LowLevelILFunctionRef DebugView::getCurrentLowLevelILFunction()
{
    if (!m_isRawDisassembly)
        return m_binaryEditor->getDisassembly()->getCurrentLowLevelILFunction();

    return nullptr;
}


MediumLevelILFunctionRef DebugView::getCurrentMediumLevelILFunction()
{
    if (!m_isRawDisassembly)
        return m_binaryEditor->getDisassembly()->getCurrentMediumLevelILFunction();

    return nullptr;
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
	//UIContext::updateStatus();
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
            if (m_splitter && m_disassemblyWidget)
                m_splitter->replaceWidget(0, m_disassemblyWidget);
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

    size_t instCount = 50;
    ArchitectureRef arch = m_state->GetRemoteArchitecture();
    uint64_t rip = m_state->IP();
    size_t readLength = arch->GetMaxInstructionLength() * instCount;

    std::vector<LinearDisassemblyLine> result;
    std::vector<InstructionTextToken> tokens =
        { InstructionTextToken(TextToken, "(Code not backed by loaded file, showing only raw disassembly)") };
    DisassemblyTextLine contents;
    contents.addr = addr;
    contents.tokens = tokens;
    LinearDisassemblyLine line;
    line.type = BasicLineType;
    line.contents = contents;
    result.push_back(line);

    BinaryReader* reader = new BinaryReader(m_state->GetMemoryView());
    if (!reader)
    {
        m_binaryText->setLines(result);
        return;
    }

    reader->Seek(addr);
    uint8_t* buffer = (uint8_t*)malloc(readLength);
    bool ok = reader->TryRead(buffer, readLength);
    if (!ok)
    {
        m_binaryText->setLines(result);
        return;
    }

    size_t totalRead = 0;
    for (size_t i = 0; i < instCount; i++)
    {
        uint64_t lineAddr = addr + totalRead;
        size_t length = readLength - totalRead;
        std::vector<InstructionTextToken> insnTokens;
        ok = arch->GetInstructionText(buffer + totalRead, lineAddr, length, insnTokens);
        if ((!ok) || (insnTokens.size() == 0))
        {
            insnTokens = { InstructionTextToken(TextToken, "??") };
            length = arch->GetInstructionAlignment();
            if (length == 0)
                length = 1;
        }

        tokens.clear();
        BNHighlightStandardColor color = NoHighlightColor;
        std::string breakpointIcon = m_state->GetDebuggerUI()->GetBreakpointTagType()->GetIcon();
        std::string pcIcon = m_state->GetDebuggerUI()->GetPCTagType()->GetIcon();
        // size_t maxWidth = breakpointIcon.size() + pcIcon.size();

        if (lineAddr == rip)
        {
            if (m_state->GetBreakpoints()->ContainsAbsolute(lineAddr))
            {
                // Breakpoint & pc
                tokens.push_back(InstructionTextToken(TagToken, breakpointIcon));
                tokens.push_back(InstructionTextToken(TagToken, pcIcon));
                color = RedHighlightColor;
            }
            else
            {
                // PC
                tokens.push_back(InstructionTextToken(TagToken, pcIcon));
                color = BlueHighlightColor;
            }
        }
        else
        {
            if (m_state->GetBreakpoints()->ContainsAbsolute(lineAddr))
            {
                // Breakpoint
                tokens.push_back(InstructionTextToken(TagToken, breakpointIcon));
                color = RedHighlightColor;
            }
            else
            {
                // Regular line
                tokens.push_back(InstructionTextToken(TextToken, "    "));
            }    
        }

        tokens.push_back(InstructionTextToken(AddressDisplayToken, fmt::format("{:x}", lineAddr), lineAddr));
        tokens.push_back(InstructionTextToken(TextToken, "  "));
        tokens.insert(tokens.end(), insnTokens.begin(), insnTokens.end());
    
        contents.addr = lineAddr;
        contents.tokens = tokens;

        BNHighlightColor hc;
        hc.style = StandardHighlightColor;
        hc.color = color;
        hc.mixColor = NoHighlightColor;
        hc.mix = 0;
        hc.r = 0;
        hc.g = 0;
        hc.b = 0;
        hc.alpha = 0;
        contents.highlight = hc;

        line.type = CodeDisassemblyLineType;
        line.contents = contents;

        result.push_back(line);
        totalRead += length;
    }

    free(buffer);
    m_binaryText->setLines(result);
}


void DebugView::refreshRawDisassembly()
{
    if (!m_state->IsConnected())
        return;

    if (m_isRawDisassembly)
        loadRawDisassembly(getCurrentOffset());
}


void DebugView::updateTimerEvent()
{
    if (m_needsUpdate)
    {
        // TODO: we probably need to /ALWAYS/ refresh the memory, since the memory could have
        // been updated even if no events happen
        m_needsUpdate = false;
//        m_memoryEditor->navigate(0);
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
