#include "processview.h"
#include "debuggerstate.h"
#include "debuggercontroller.h"

using namespace BinaryNinja;

static DebugProcessViewType* g_debugProcessViewType = nullptr;


DebugProcessView::DebugProcessView(BinaryView* parent):
    BinaryView("Debugged Process", parent->GetFile(), parent)
{
    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();
    m_addressSize = parent->GetAddressSize();
    m_entryPoints.push_back(parent->GetEntryPoint());

    // TODO: Read segments from debugger
    uint64_t length = PerformGetLength();
    AddAutoSegment(0, length, 0, length, SegmentReadable | SegmentWritable | SegmentExecutable);
    AddAutoSection("Memory", 0, length);
}


DebugProcessView::~DebugProcessView()
{
}


bool DebugProcessView::Init()
{
    return true;
}


uint64_t DebugProcessView::PerformGetEntryPoint() const
{
    if (m_entryPoints.size() == 0)
        return 0;

    return m_entryPoints[0];
}


BNEndianness DebugProcessView::PerformGetDefaultEndianness() const
{
    return m_endian;
}


size_t DebugProcessView::PerformGetAddressSize() const
{
    return m_addressSize;
}


uint64_t DebugProcessView::PerformGetLength() const
{
    size_t addressSize = PerformGetAddressSize();
    const size_t bitsPerByte = 8;
    size_t bits = addressSize * bitsPerByte;
    if (bits >= 64)
        return UINT64_MAX;

    return (1UL << bits) - 1;
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


size_t DebugProcessView::PerformRead(void* dest, uint64_t offset, size_t len)
{
//    LogWarn("DebugProcessView::PerformRead, 0x%lx", offset);
    std::unique_lock<std::mutex> memoryLock(m_memoryMutex);

    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerController* controller = DebuggerController::GetController(parentView);
    DebugAdapter* adapter = controller->GetState()->GetAdapter();

    if (!adapter)
        return 0;

    std::vector<uint8_t> result;
    std::vector<uint8_t> buffer;

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
            buffer.clear();
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
                LogWarn("Failed to read at address 0x%lx", offset);
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


size_t DebugProcessView::PerformWrite(uint64_t offset, const void* data, size_t len)
{
    std::unique_lock<std::mutex> memoryLock(m_memoryMutex);

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


void DebugProcessView::MarkDirty()
{
    m_valueCache.clear();
    m_errorCache.clear();
}
