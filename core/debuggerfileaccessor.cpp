/*
Copyright 2020-2024 Vector 35 Inc.

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

#include "debuggerfileaccessor.h"
#include "debuggercontroller.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

DebuggerFileAccessor::DebuggerFileAccessor(BinaryView* parent)
{
	auto addressSize = parent->GetAddressSize();
	auto bits = addressSize * 8;
	if (bits >= 64)
		m_length = UINT64_MAX;
	else
		m_length = (1ULL << bits) - 1;

	m_controller = DebuggerController::GetController(parent);
	m_eventCallback = m_controller->RegisterEventCallback([this](const DebuggerEvent& event){
		eventHandler(event);
	}, "Process View");
}


DebuggerFileAccessor::~DebuggerFileAccessor()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_eventCallback);
}


uint64_t DebuggerFileAccessor::GetLength() const
{
	return m_length;
}


size_t DebuggerFileAccessor::Read(void *dest, uint64_t offset, size_t len)
{
	DataBuffer buffer = m_controller->ReadMemory(offset, len);
	memcpy(dest, buffer.GetData(), buffer.GetLength());

	return buffer.GetLength();
}


size_t DebuggerFileAccessor::Write(uint64_t offset, const void *src, size_t len)
{
	if (m_controller->WriteMemory(offset, DataBuffer(src, len)))
	{
		m_controller->GetData()->NotifyDataWritten(offset, len);
		return len;
	}

	return 0;
}



void DebuggerFileAccessor::MarkDirty()
{
	// This hack will let the views (linear/graph) update its display
	if (m_aggressiveAnalysisUpdate)
	{
		m_controller->GetData()->NotifyDataWritten(0, GetLength());
	}
	else
	{
		// This ensures or the BinaryDataListener, e.g, the linear view, refreshes its display. But it avoids any
		// functions get marked as update required
		m_controller->GetData()->NotifyDataWritten(0xdeadbeefdeadbeef, 0);
	}
}


void DebuggerFileAccessor::ForceMemoryCacheUpdate()
{
	m_controller->GetData()->NotifyDataWritten(0, GetLength());
}


void DebuggerFileAccessor::eventHandler(const DebuggerEvent &event)
{
	switch (event.type)
	{
	case TargetStoppedEventType:
	// We should not call MarkDirty() in case of a TargetExitedEvent, since the debugger binary view is about to be
	// deleted. And it can cause a crash in certain cases.
		MarkDirty();
		break;
	case ForceMemoryCacheUpdateEvent:
		ForceMemoryCacheUpdate();
		break;
	default:
		break;
	}
}
