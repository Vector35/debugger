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
    uint64_t length = m_memory->GetLength();
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


void DebugProcessView::markDirty()
{
    m_memory->markDirty();
}


void DebugProcessView::clearModuleBases()
{
    m_moduleBases.clear();
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
    if (bits > 64)
        return UINT64_MAX;
    
    return (1UL << bits) - 1;
}


size_t DebugMemoryView::PerformRead(void* dest, uint64_t offset, size_t len)
{
    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerState* state = DebuggerState::getState(parentView);
    if (!state)
        return 0;
    
    // Since DebugAdapter backend is not yet merged into this branch, there is no way
    // to acutally implement it. For now, just fill the buffer with 0x90
    memset(dest, 0x90, len);
    return len;

    // ProcessView implements read caching in a manner inspired by CPU cache:
    // Reads are aligned on 256-byte boundaries and 256 bytes long

    // Cache read start: round down addr to nearest 256 byte boundary
    size_t cacheStart = offset & (~0xffLL);
    // Cache read end: round up addr+length to nearest 256 byte boundary
    size_t cacheEnd = (offset + len + 0xFF) & (~0xffLL);
    // List of 256-byte block addresses to read into the cache to fully cover this region
    for (uint64_t block = cacheStart; block < cacheEnd; block += 0x100)
    {
        if (m_errorCache.find(block) != m_errorCache.end())
            return 0;

        auto iter = m_valueCache.find(block);
        if (iter == m_valueCache.end())
        {
            
        }
    }
    return 0;
}


size_t DebugMemoryView::PerformWrite(uint64_t offset, const void* data, size_t len)
{
    markDirty();
    // Since DebugAdapter backend is not yet merged into this branch, there is no way
    // to acutally implement it. For now, just pretend it is all written.
    return len;
}


void DebugMemoryView::markDirty()
{
    m_valueCache.clear();
    m_errorCache.clear();
}
