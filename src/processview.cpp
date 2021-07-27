#include "processview.h"
#include "debuggerstate.h"

using namespace BinaryNinja;

static DebugMemoryViewType* g_debugMemoryViewType = nullptr;
static DebugProcessViewType* g_debugProcessViewType = nullptr;


DebugProcessView::DebugProcessView(BinaryView* parent):
    BinaryView("Debugged Process", parent->GetFile(), new DebugMemoryView(parent))
{
    m_memory = new DebugMemoryView(parent);
    m_localView = parent;
    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();

    // TODO: Read segments from debugger
    uint64_t length = PerformGetLength();
    AddAutoSegment(0, length, 0, length, SegmentReadable | SegmentWritable | SegmentExecutable);
    AddAutoSection("Memory", 0, length);
}


size_t DebugProcessView::PerformGetAddressSize() const
{
    return m_memory->PerformGetAddressSize();
}


uint64_t DebugProcessView::PerformGetLength() const
{
    return m_memory->PerformGetLength();
}


void DebugProcessView::MarkDirty()
{
    m_memory->MarkDirty();
}


void DebugProcessView::ClearModuleBases()
{
    m_moduleBases.clear();
}


/*
Get the base address of the binary in the debugged process
*/
uint64_t DebugProcessView::GetRemoteBase(BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    auto file = relativeView->GetFile();
    if (!file)
        return 0;
    
    std::string moduleName = file->GetOriginalFilename();
    auto iter = m_moduleBases.find(moduleName);
    if (iter == m_moduleBases.end())
    {
        DebuggerState* state = DebuggerState::GetState(m_localView);
        DebuggerModules* modulesCache = state->GetModules();
        if (!modulesCache)
            // TODO: should return false, and return the address by reference
            return 0;
        uint64_t address = modulesCache->GetModuleBase(moduleName);
        m_moduleBases[moduleName] = address;
        return address;
    }
    else
    {
        return iter->second;
    }
}


/*
Determine if the debugged process is using ASLR for its code segment
(eg in a PIE binary)
*/
bool DebugProcessView::IsCodeASLR(BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    return GetRemoteBase(relativeView) != relativeView->GetStart();
}

/*
Given a local address (relative to the analysis binaryview),
find its remote address (relative to the debugged process) after ASLR
If the address is not within our view, it will be unchanged
*/
uint64_t DebugProcessView::LocalAddressToRemote(uint64_t localAddr, BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    uint64_t localBase = relativeView->GetStart();
    uint64_t remoteBase = GetRemoteBase(relativeView);
    if ((localAddr < localBase) || (localAddr >= localBase + relativeView->GetLength()))
        // Not within our local binary, return original
        return localAddr;

    return localAddr - localBase + remoteBase;
}


/*
Given a remote address (relative to the debugged process) after ASLR,
find its local address (relative to the analysis binaryview)
If the address is not within our view, it will be unchanged
*/
uint64_t DebugProcessView::RemoteAddressToLocal(uint64_t remoteAddr, BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    // TODO: Make sure the addr is within the loaded segments for our binary
	// Else return the original
    uint64_t localBase = relativeView->GetStart();
    uint64_t remoteBase = GetRemoteBase(relativeView);
    uint64_t localAddr = remoteAddr - remoteBase + localBase;
    if ((localAddr < localBase) || (localAddr >= localBase + relativeView->GetLength()))
        // Not within our local binary, return original
        return remoteAddr;

    return localAddr;
}

/*
Determine if a remote address is within the loaded BinaryView
*/
bool DebugProcessView::IsLocalAddress(uint64_t remoteAddr, BinaryViewRef relativeView)
{
    if (!relativeView)
        relativeView = m_localView;

    uint64_t localBase = relativeView->GetStart();
    uint64_t remoteBase = GetRemoteBase(relativeView);
    uint64_t localAddr = remoteAddr - remoteBase + localBase;
    return (localAddr >= localBase) && (localAddr < localBase + relativeView->GetLength());
}


DebugProcessViewType::DebugProcessViewType():
    BinaryViewType("Debugged Process", "Debugged Process")
{
}


BinaryView* DebugProcessViewType::Create(BinaryView* data)
{
	try
	{
		return new DebugProcessView(data);
	}
	catch (std::exception& e)
	{
		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


BinaryView* DebugProcessViewType::Parse(BinaryView* data)
{
	try
	{
		return new DebugProcessView(data);
	}
	catch (std::exception& e)
	{
		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


void InitDebugProcessViewType()
{
    static DebugProcessViewType type;
    BinaryViewType::Register(&type);
	g_debugProcessViewType = &type;
}


DebugMemoryViewType::DebugMemoryViewType():
    BinaryViewType("Debugged Process Memory", "Debugged Process Memory")
{
}


BinaryView* DebugMemoryViewType::Create(BinaryView* data)
{
	try
	{
		return new DebugMemoryView(data);
	}
	catch (std::exception& e)
	{
		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


BinaryView* DebugMemoryViewType::Parse(BinaryView* data)
{
	try
	{
		return new DebugMemoryView(data);
	}
	catch (std::exception& e)
	{
		LogError("%s<BinaryViewType> failed to create view! '%s'", GetName().c_str(), e.what());
		return nullptr;
	}
}


void InitDebugMemoryViewType()
{
    static DebugMemoryViewType type;
    BinaryViewType::Register(&type);
	g_debugMemoryViewType = &type;
}


DebugMemoryView::DebugMemoryView(BinaryView* parent):
    BinaryView("Debugged Process Memory", parent->GetFile(), parent)
{
    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();
    m_valueCache.clear();
    m_errorCache.clear();
}


size_t DebugMemoryView::PerformGetAddressSize() const
{
    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 8;

    Ref<Architecture> parentArch = parentView->GetDefaultArchitecture();
    if (!parentArch)
        return 8;

    return parentArch->GetAddressSize();
}


uint64_t DebugMemoryView::PerformGetLength() const
{
    size_t addressSize = PerformGetAddressSize();
    const size_t bitsPerByte = 8;
    size_t bits = addressSize * bitsPerByte;
    if (bits >= 64)
        return UINT64_MAX;
    
    return (1UL << bits) - 1;
}


size_t DebugMemoryView::PerformRead(void* dest, uint64_t offset, size_t len)
{
    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerState* state = DebuggerState::GetState(parentView);
    if (!state)
        return 0;

    DebugAdapter* adapter = state->GetAdapter();
    if (!adapter)
        return 0;

    std::vector<uint8_t> result;

    // ProcessView implements read caching in a manner inspired by CPU cache:
    // Reads are aligned on 256-byte boundaries and 256 bytes long

    // Cache read start: round down addr to nearest 256 byte boundary
    size_t cacheStart = offset & (~0xffLL);
    // Cache read end: round up addr+length to nearest 256 byte boundary
    size_t cacheEnd = (offset + len + 0xFF) & (~0xffLL);
    // List of 256-byte block addresses to read into the cache to fully cover this region
    for (uint64_t block = cacheStart; block < cacheEnd; block += 0x100)
    {
        // If any block cannot be read, then return false
        if (m_errorCache.find(block) != m_errorCache.end())
        {
            return 0;
        }

        auto iter = m_valueCache.find(block);
        if (iter == m_valueCache.end())
        {
            std::vector<uint8_t> buffer;
            buffer.resize(0x100);
            // The ReadMemory() function should return the number of bytes read
            bool ok = adapter->ReadMemory(block, buffer.data(), 0x100);
            if (ok)
            {
                // Treating ok as 0x100 bytes have been read
                m_valueCache[block] = buffer;
            }
            else
            {
                m_errorCache.insert(block);
                return 0;
            }
        }

        std::vector<uint8_t> cached = m_valueCache[block];
        if (offset + len < block + cached.size())
        {
            // Last block
            cached = std::vector<uint8_t>(cached.begin(), cached.begin() + (offset + len - block));
        }
        if (offset > block)
        {
            // First block
            cached = std::vector<uint8_t>(cached.begin() + offset - block, cached.end());
        }
        result.insert(result.end(), cached.begin(), cached.end());
    }

    if (result.size() == len)
    {
        memcpy(dest, result.data(), result.size());
        return len;
    }
    return 0;
}


size_t DebugMemoryView::PerformWrite(uint64_t offset, const void* data, size_t len)
{
    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerState* state = DebuggerState::GetState(parentView);
    if (!state)
        return 0;

    DebugAdapter* adapter = state->GetAdapter();
    if (!adapter)
        return 0;

    // Assume any memory change invalidates all of memory (suboptimal, may not be necessary)
    MarkDirty();

    if (adapter->WriteMemory(offset, data, len))
        return len;

    return 0;
}


void DebugMemoryView::MarkDirty()
{
    m_valueCache.clear();
    m_errorCache.clear();
}
