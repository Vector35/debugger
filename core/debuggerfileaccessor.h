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

#pragma once

#include "binaryninjaapi.h"
#include "debuggerevent.h"
#include "refcountobject.h"

using namespace BinaryNinja;

namespace BinaryNinjaDebugger
{
	class DebuggerController;

	class DebuggerFileAccessor: public FileAccessor
	{
		uint64_t m_length;

		DbgRef<DebuggerController> m_controller;
		// The stop-event subscription that refreshes the views. Only the "primary" accessor (the one
		// covering the whole address space) registers it; the per-region accessors leave it as
		// DEBUGGER_NO_EVENT_CALLBACK so we do not fire N redundant view refreshes on every stop.
		size_t m_eventCallback;

		bool m_aggressiveAnalysisUpdate;

		static constexpr size_t DEBUGGER_NO_EVENT_CALLBACK = (size_t)-1;

	public:
		// Primary accessor: spans the whole address space and owns the view-refresh subscription. Used
		// as the blanket overlay when the backend does not report a memory map.
		DebuggerFileAccessor(BinaryView* parent);
		// Bounded accessor: backs a single memory-map region [base, base + length). Reads still resolve
		// absolute addresses (the region is created in absolute-address mode), so this only differs from
		// the primary accessor in its reported length and in not owning an event subscription.
		DebuggerFileAccessor(BinaryView* parent, uint64_t base, uint64_t length);
		~DebuggerFileAccessor();
		bool IsValid() const override { return true; }
		uint64_t GetLength() const override;
		size_t Read(void* dest, uint64_t offset, size_t len) override;
		size_t Write(uint64_t offset, const void* src, size_t len) override;

		void MarkDirty();
		void ForceMemoryCacheUpdate();
		void eventHandler(const DebuggerEvent& event);
	};
}
