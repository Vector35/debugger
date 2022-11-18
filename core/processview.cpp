/*
Copyright 2020-2022 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "processview.h"
#include "debuggerstate.h"
#include "debuggercontroller.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

static DebugProcessViewType* g_debugProcessViewType = nullptr;


DebugProcessView::DebugProcessView(DebugProcessMemoryView* memory, BinaryView* parent):
    BinaryView("Debugger", memory->GetFile(), memory)
{
    m_arch = parent->GetDefaultArchitecture();
    m_platform = parent->GetDefaultPlatform();
    m_addressSize = parent->GetAddressSize();
	auto bits = m_addressSize * 8;
	if (bits >= 64)
		m_length = UINT64_MAX;
	else
		m_length = (1ULL << bits) - 1;

    m_entryPoints.push_back(parent->GetEntryPoint());
	m_endian = parent->GetDefaultEndianness();

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
	return m_length;
}


DebugProcessViewType::DebugProcessViewType():
    BinaryViewType("Debugger", "Debugger")
{
}


BinaryView* DebugProcessViewType::Create(BinaryView* data)
{
	try
	{
		// memory must be ref-counted, otherwise there will be a memory leak
		Ref<DebugProcessMemoryView> memory = new DebugProcessMemoryView(data);
		return new DebugProcessView(memory, data);
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
		// memory must be ref-counted, otherwise there will be a memory leak
		Ref<DebugProcessMemoryView> memory = new DebugProcessMemoryView(data);
		return new DebugProcessView(memory, data);
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



DebugProcessMemoryView::DebugProcessMemoryView(BinaryView* parent):
    BinaryView("Debugger memory", parent->GetFile(), parent)
{
	auto bits = parent->GetAddressSize() * 8;
	if (bits >= 64)
		m_length = UINT64_MAX;
	else
		m_length = (1ULL << bits) - 1;

    m_controller = DebuggerController::GetController(parent);
	m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
		eventHandler(event);
	}, "Debug Memory View");
}


DebugProcessMemoryView::~DebugProcessMemoryView()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_eventCallback);
}


uint64_t DebugProcessMemoryView::PerformGetLength() const
{
	return m_length;
}


bool DebugProcessMemoryView::PerformIsOffsetBackedByFile(uint64_t offset)
{
    return offset <= m_length;
}


size_t DebugProcessMemoryView::PerformRead(void* dest, uint64_t offset, size_t len)
{
	DataBuffer buffer = m_controller->ReadMemory(offset, len);
	memcpy(dest, buffer.GetData(), buffer.GetLength());

	return buffer.GetLength();
}


size_t DebugProcessMemoryView::PerformWrite(uint64_t offset, const void* data, size_t len)
{
	if (m_controller->WriteMemory(offset, DataBuffer(data, len)))
	{
		BinaryView::NotifyDataWritten(offset, len);
		return len;
	}

	return 0;
}


void DebugProcessMemoryView::MarkDirty()
{
	// This hack will let the views (linear/graph) update its display
	ExecuteOnMainThread([this](){
		BinaryView::NotifyDataWritten(0, 1);
	});
}


void DebugProcessMemoryView::eventHandler(const DebuggerEvent &event)
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
