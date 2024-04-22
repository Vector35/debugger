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
		size_t m_eventCallback;

		bool m_aggressiveAnalysisUpdate;

	public:
		DebuggerFileAccessor(BinaryView* parent);
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
