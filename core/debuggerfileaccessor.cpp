/*
Copyright 2020-2026 Vector 35 Inc.

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

#include <thread>

#include "debuggercontroller.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

DebuggerFileAccessor::DebuggerFileAccessor(BinaryView* parent, uint64_t length) : m_length(length)
{
	m_controller = DebuggerController::GetController(parent);
}


DebuggerFileAccessor::~DebuggerFileAccessor()
{
	// The memory map deletes us on whichever thread releases the last snapshot holding the region, which can be the
	// debugger worker (e.g. removing the regions in FinalizeTargetGoneCleanup). If ours is the last reference to the
	// controller, releasing it there would run ~DebuggerController, which joins the worker and so deadlocks. Release it
	// on a detached thread instead.
	if (m_controller)
		std::thread([controller = std::move(m_controller)]() mutable { controller = nullptr; }).detach();
}


uint64_t DebuggerFileAccessor::GetLength() const
{
	return m_length;
}


size_t DebuggerFileAccessor::Read(void* dest, uint64_t offset, size_t len, BNMemoryReadStatus& status)
{
	return m_controller->ReadMemorySpan(dest, offset, len, status);
}


size_t DebuggerFileAccessor::Write(uint64_t offset, const void* src, size_t len)
{
	if (m_controller->WriteMemory(offset, DataBuffer(src, len)))
	{
		m_controller->GetData()->NotifyDataWritten(offset, len);
		return len;
	}

	return 0;
}
