#include "processview.h"
#include "debuggerstate.h"
#include "debuggercontroller.h"

using namespace BinaryNinja;

static DebugProcessViewType* g_debugProcessViewType = nullptr;


DebugProcessView::DebugProcessView(BinaryView* parent):
    // This used to be called "Debugged Process", but it conflicts with the Python debugger, so I changed the view
    // name to "Debugger"
    BinaryView("Debugger", parent->GetFile(), parent)
{
	// quick and dirty way to deal with the construction by BN
	// a better way to deal with is to somehow tell BN to not construct this object, even if its validForData()
	// returns true
	if (parent->GetTypeName() == "Raw")
		throw std::runtime_error("unexpected construction");

    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();
    m_addressSize = parent->GetAddressSize();
    m_entryPoints.push_back(parent->GetEntryPoint());

    // TODO: Read segments from debugger
    uint64_t length = PerformGetLength();
    AddAutoSegment(0, length, 0, length, SegmentReadable | SegmentWritable | SegmentExecutable);
    AddAutoSection("Memory", 0, length);

    m_controller = DebuggerController::GetController(parent);
	m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
		eventHandler(event);
	});
}


DebugProcessView::~DebugProcessView()
{
	m_controller->RemoveEventCallback(m_eventCallback);
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
    BinaryViewType("Debugger", "Debugger")
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
    std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);

    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerController* controller = DebuggerController::GetController(parentView);
    DebugAdapter* adapter = controller->GetState()->GetAdapter();

    if (!adapter)
        return 0;

    DataBuffer result;

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
            // The ReadMemory() function should return the number of bytes read
            DataBuffer buffer = adapter->ReadMemory(block, 0x100);
            // TODO: what if the buffer's size is smaller than 0x100
            if (buffer.GetLength() > 0)
            {
                m_valueCache[block] = buffer;
            }
            else
            {
                m_errorCache.insert(block);
                return 0;
            }
        }

        DataBuffer cached = m_valueCache[block];
        if (offset + len < block + cached.GetLength())
        {
            // Last block
            cached = cached.GetSlice(0, offset + len - block);
        }
        // Note a block can be both the fist and the last block, so we should not put an else here
        if (offset > block)
        {
            // First block
            cached = cached.GetSlice(offset - block, cached.GetLength() - (offset - block));
        }
        result.Append(cached);
    }

    if (result.GetLength() == len)
    {
        memcpy(dest, result.GetData(), result.GetLength());
        return len;
    }
    return 0;
}


size_t DebugProcessView::PerformWrite(uint64_t offset, const void* data, size_t len)
{
    std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);

    Ref<BinaryView> parentView = GetParentView();
    if (!parentView)
        return 0;

    DebuggerController* controller = DebuggerController::GetController(parentView);
    DebugAdapter* adapter = controller->GetState()->GetAdapter();
    if (!adapter)
        return 0;

    // TODO: Assume any memory change invalidates memory cache (suboptimal, may not be necessary)
    MarkDirty();

    if (adapter->WriteMemory(offset, DataBuffer(data, len)))
        return len;

    return 0;
}


void DebugProcessView::MarkDirty()
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);

    m_valueCache.clear();
    m_errorCache.clear();
}


void DebugProcessView::eventHandler(const DebuggerEvent &event)
{
	switch (event.type)
	{
	case TargetStoppedEventType:
	case TargetExitedEventType:
	case DetachedEventType:
	case QuitDebuggingEventType:
	case BackEndDisconnectedEventType:
		MarkDirty();
		break;
	default:
		break;
	}
}
