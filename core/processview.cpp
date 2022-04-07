#include "processview.h"
#include "debuggerstate.h"
#include "debuggercontroller.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

static DebugProcessViewType* g_debugProcessViewType = nullptr;


DebugProcessView::DebugProcessView(BinaryView* parent):
    BinaryView("Debugger", parent->GetFile(), parent)
{
    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();
    m_addressSize = parent->GetAddressSize();
    m_entryPoints.push_back(parent->GetEntryPoint());
	m_endian = parent->GetDefaultEndianness();

    // TODO: Read segments from debugger
    uint64_t length = PerformGetLength();
    AddAutoSegment(0, length, 0, length, SegmentReadable | SegmentWritable | SegmentExecutable);
    AddAutoSection("Memory", 0, length);

	// quick and dirty way to deal with the construction by BN
	// a better way to deal with is to somehow tell BN to not construct this object, even if its validForData()
	// returns true
	if (parent->GetTypeName() == "Raw")
		return;

    m_controller = DebuggerController::GetController(parent);
	m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
		eventHandler(event);
	});
}


DebugProcessView::~DebugProcessView()
{
	if (m_controller)
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

    return (1ULL << bits) - 1;
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


void BinaryNinjaDebugger::InitDebugProcessViewType()
{
    static DebugProcessViewType type;
    BinaryViewType::Register(&type);
	g_debugProcessViewType = &type;
}


size_t DebugProcessView::PerformRead(void* dest, uint64_t offset, size_t len)
{
	DataBuffer buffer = m_controller->ReadMemory(offset, len);
	memcpy(dest, buffer.GetData(), buffer.GetLength());

	return buffer.GetLength();
}


size_t DebugProcessView::PerformWrite(uint64_t offset, const void* data, size_t len)
{
	if (m_controller->WriteMemory(offset, DataBuffer(data, len)))
	{
		BinaryView::NotifyDataWritten(offset, len);
		return len;
	}

	return 0;
}


void DebugProcessView::MarkDirty()
{
	// This hack will let the views (linear/graph) update its display
	ExecuteOnMainThread([this](){
		BinaryView::NotifyDataWritten(0, 1);
	});
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
