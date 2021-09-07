#include <QtWidgets/QGroupBox>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStatusBar>
#include <QtGui/QFont>
#include "fontsettings.h"
#include "debugview.h"
#include "ui.h"
#include "binaryninjaapi.h"
#include "hexeditor.h"
#include "inttypes.h"

using namespace BinaryNinja;

DebugView::DebugView(QWidget* parent, BinaryViewRef data): QWidget(parent)
{
    setupView(this);
    setBinaryDataNavigable(true);

	m_data = data;
	m_controller = DebuggerController::GetController(m_data);
	m_state = m_controller->GetState();

//    m_state = DebuggerState::GetState(data);
//    m_state->GetDebuggerUI()->SetDebugView(this);
    m_controller = DebuggerController::GetController(data);
    m_controller->GetUI()->SetDebugView(this);

    UIContext* context = UIContext::contextForWidget(this);
    if (context)
    {
        QMainWindow* mainWindow = context->mainWindow();
        if (mainWindow)
        {
            // TODO: This should not be in the DebugView class, it should better be moved to DebuggerUI
            m_debuggerStatus = new QLabel("INACTIVE");
            mainWindow->statusBar()->insertWidget(0, m_debuggerStatus);
        }
    }

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
    m_memoryTabs->setMovable(true);
    m_memoryTabs->setTabsClosable(true);
    m_memoryTabs->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_memoryTabs, &QTabWidget::tabCloseRequested, [&](int i){ m_memoryTabs->removeTab(i); });

    for (size_t i = 0; i < m_numMemoryTabs; i++)
    {
        LinearView* memoryEditor = new LinearView(memoryView, frame);
        m_memoryTabs->addTab(memoryEditor, QString::asprintf("Memory %ld", i));
    }

    HexEditor* hexEditor = new HexEditor(memoryView, frame);
    m_memoryTabs->addTab(hexEditor, "Hex");
    m_oldFileLockStatus = frame->areFileContentsLocked(false);
    if (m_oldFileLockStatus)
        frame->setFileContentsLocked(false);

//    This is not the correct way to do it. We should subclass QTabBar and call QTabWidget::setTabBar().
//    m_tabMenu = new QMenu;
//    connect(m_memoryTabs, &QTabWidget::tabBarClicked, [&](int tabIndex){ m_tabMenu->popup(QCursor::pos()); });
//    connect(m_memoryTabs, &QTabWidget::customContextMenuRequested, [&](const QPoint& pos){
//        LogWarn("Context menu requested");
//        m_tabMenu->popup(pos);
//    });

    m_splitter->addWidget(m_binaryViewWidget);
    m_splitter->addWidget(m_memoryTabs);
    m_splitter->setSizes(QList<int>(2, 0x7fffffff));

    QVBoxLayout* layout = new QVBoxLayout;
    layout->setSpacing(0);
    layout->setContentsMargins(0, 0, 0, 0);
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

    CreateBreakpointTagType();
    CreateProgramCounterTagType();

    connect(m_controller, &DebuggerController::IPChanged, [this](uint64_t address){
        UpdateIP(address);
    });

    connect(m_controller, &DebuggerController::relativeBreakpointDeleted, [this](const ModuleNameAndOffset& address){
        DeleteRelativeBreakpointTag(address);
    });

    connect(m_controller, &DebuggerController::absoluteBreakpointDeleted, [this](uint64_t address){
        DeleteAbsoluteBreakpointTag(address);
    });

    connect(m_controller, &DebuggerController::relativeBreakpointAdded, [this](const ModuleNameAndOffset& address) {
        AddRelativeBreakpointTag(address);
    });

    connect(m_controller, &DebuggerController::absoluteBreakpointAdded, [this](uint64_t address){
        AddAbsoluteBreakpointTag(address);
    });
}


DebugView::~DebugView()
{
//    This does not work, the DebugView is not destructed immediately after the user switches to a different tab
//    ViewFrame* frame = ViewFrame::viewFrameForWidget(this);
//    if (!frame)
//        return;
//
//    frame->setFileContentsLocked(m_oldFileLockStatus);
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


bool DebugView::navigateToFunction(FunctionRef func, uint64_t offset)
{
    return navigate(offset);
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


Ref<HistoryEntry> DebugView::getHistoryEntry()
{
    if (m_isNavigatingHistory)
        return nullptr;

    uint64_t memoryAddr = dynamic_cast<LinearView*>(m_memoryTabs->widget(0))->getCurrentOffset();
    if (memoryAddr != m_memoryHistoryAddress)
        m_memoryHistoryAddress = memoryAddr;

    if (m_isRawDisassembly && m_state->IsConnected())
    {
        ModuleNameAndOffset relAddr = m_state->GetModules()->AbsoluteAddressToRelative(m_rawAddress);
        return new DebugViewHistoryEntry(memoryAddr, relAddr, true);
    }
    else
    {
        uint64_t address = m_binaryEditor->getDisassembly()->getCurrentOffset();
        return new DebugViewHistoryEntry(memoryAddr, address, false);
    }
}


void DebugView::navigateToHistoryEntry(BinaryNinja::Ref<HistoryEntry> entry)
{
    DebugViewHistoryEntry* data = dynamic_cast<DebugViewHistoryEntry*>(entry.GetPtr());
    if (!data)
        return;

    LinearView* view = dynamic_cast<LinearView*>(m_memoryTabs->widget(0));
    if (!view)
        return;

    m_isNavigatingHistory = true;
    view->navigate(data->getMemoryAddr());
    if (data->getIsRaw())
    {
        if (m_state->IsConnected())
        {
            uint64_t address = m_state->GetModules()->RelativeAddressToAbsolute(data->getRelAddress());
            navigateRaw(address);
        }
    }
    else
    {
        navigateLive(data->getAddress());
    }

    View::navigateToHistoryEntry(entry);
    m_isNavigatingHistory = false;
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
        std::string breakpointIcon = GetBreakpointTagType()->GetIcon();
        std::string pcIcon = GetPCTagType()->GetIcon();
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


void DebugView::setDebuggerStatus(const std::string &status)
{
    m_debuggerStatus->setText(QString::fromStdString(status));
}



void DebugView::CreateBreakpointTagType()
{
    TagTypeRef type = m_data->GetTagType("Breakpoints");
    if (type)
    {
        m_breakpointTagType = type;
        return;
    }

    m_breakpointTagType = new TagType(m_data, "Breakpoints", "🛑");
    m_data->AddTagType(m_breakpointTagType);
}


void DebugView::CreateProgramCounterTagType()
{
    TagTypeRef type = m_data->GetTagType("Program Counter");
    if (type)
    {
        m_pcTagType = type;
        return;
    }

    m_pcTagType = new TagType(m_data, "Program Counter", "==>");
    m_data->AddTagType(m_pcTagType);
}


void DebugView::DeleteAbsoluteBreakpointTag(uint64_t address)
{
    refreshRawDisassembly();
}


void DebugView::DeleteRelativeBreakpointTag(const ModuleNameAndOffset& address)
{
    for (FunctionRef func: m_data->GetAnalysisFunctionsContainingAddress(address.offset))
    {
        func->SetAutoInstructionHighlight(m_data->GetDefaultArchitecture(), address.offset, NoHighlightColor);
        for (TagRef tag: func->GetAddressTags(m_data->GetDefaultArchitecture(), address.offset))
        {
            if (tag->GetType() != GetBreakpointTagType())
                continue;

            func->RemoveUserAddressTag(m_data->GetDefaultArchitecture(), address.offset, tag);
        }
    }
}


void DebugView::AddAbsoluteBreakpointTag(uint64_t address)
{
    refreshRawDisassembly();
}


void DebugView::AddRelativeBreakpointTag(const ModuleNameAndOffset& address)
{
    for (FunctionRef func: m_data->GetAnalysisFunctionsContainingAddress(address.offset))
    {
        if (!func)
            continue;

        bool tagFound = false;
        for (TagRef tag: func->GetAddressTags(m_controller->GetState()->GetData()->GetDefaultArchitecture(),
                                              address.offset))
        {
            if (tag->GetType() == GetBreakpointTagType())
            {
                tagFound = true;
                break;
            }
        }

        if (!tagFound)
        {
            func->SetAutoInstructionHighlight(m_controller->GetState()->GetData()->GetDefaultArchitecture(), address.offset,
                                              RedHighlightColor);
            func->CreateUserAddressTag(m_controller->GetState()->GetData()->GetDefaultArchitecture(), address.offset,
                                       GetBreakpointTagType(), "breakpoint");
        }
    }
}


void DebugView::UpdateIP(uint64_t address)
{
    uint64_t localIP = m_controller->GetState()->LocalIP();
    navigate(localIP);

    for (FunctionRef func: m_controller->GetState()->GetData()->GetAnalysisFunctionsContainingAddress(m_lastIP))
    {
        ModuleNameAndOffset addr;
        addr.module = m_data->GetFile()->GetOriginalFilename();
        addr.offset = m_lastIP - m_data->GetStart();

        BNHighlightStandardColor oldColor = NoHighlightColor;
        if (m_controller->GetState()->GetBreakpoints()->ContainsOffset(addr))
            oldColor = RedHighlightColor;

        func->SetAutoInstructionHighlight(m_data->GetDefaultArchitecture(), m_lastIP, oldColor);
        for (TagRef tag: func->GetAddressTags(m_data->GetDefaultArchitecture(), m_lastIP))
        {
            if (tag->GetType() != GetPCTagType())
                continue;

            func->RemoveUserAddressTag(m_data->GetDefaultArchitecture(), m_lastIP, tag);
        }
    }

    m_lastIP = localIP;

    for (FunctionRef func: m_controller->GetState()->GetData()->GetAnalysisFunctionsContainingAddress(localIP))
    {
        func->SetAutoInstructionHighlight(m_data->GetDefaultArchitecture(), localIP, BlueHighlightColor);
        func->CreateUserAddressTag(m_data->GetDefaultArchitecture(), localIP, GetPCTagType(), "program counter");
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
