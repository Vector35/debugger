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

#pragma once

#include "binaryninjaapi.h"
#include "debuggerevent.h"
#include "refcountobject.h"

using namespace BinaryNinja;

namespace BinaryNinjaDebugger {
	class DebuggerController;
	class DebugProcessMemoryView;

	class DebugProcessView : public BinaryView
	{
		std::vector<uint64_t> m_entryPoints;
		size_t m_addressSize;
		uint64_t m_length;
		BNEndianness m_endian;
		Ref<Architecture> m_arch;
		Ref<Platform> m_platform;

		DbgRef<DebuggerController> m_controller;
		size_t m_eventCallback;

		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override { return true; };
		virtual size_t PerformGetAddressSize() const override;
		virtual bool PerformIsValidOffset(uint64_t addr) override { return true; }
		virtual uint64_t PerformGetLength() const override;

	public:
		DebugProcessView(DebugProcessMemoryView* memory, BinaryView* data);
		virtual ~DebugProcessView();
		virtual bool Init() override;
	};


	class DebugProcessViewType : public BinaryViewType
	{
	public:
		DebugProcessViewType();
		virtual BinaryView* Create(BinaryView* data) override;
		virtual BinaryView* Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override { return true; }
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override { return nullptr; }
		// Here we abuse (smartly use) the IsDeprecated() API to achieve our goal of stopping BN to construct
		// the DebugProcessView for any data. We can still construct it manually, as done within the debugger.
		// Any alternative way to do is to have IsTypeValidForData() return false. However, it does not work well,
		// because the DataTypeList widget will refuse to list the Debugger view.
		// TODO: we should probably create a different API, or rename the IsDeprecated() API.
		virtual bool IsDeprecated() override { return true; };
	};

	class DebugProcessMemoryView : public BinaryView
	{
		uint64_t m_length;
		DbgRef<DebuggerController> m_controller;
		size_t m_eventCallback;

		virtual uint64_t PerformGetLength() const override;
		bool PerformIsOffsetBackedByFile(uint64_t offset) override;

		virtual size_t PerformRead(void* dest, uint64_t offset, size_t len) override;
		virtual size_t PerformWrite(uint64_t offset, const void* data, size_t len) override;

	public:
		DebugProcessMemoryView(BinaryView* data);
		virtual ~DebugProcessMemoryView();

		void MarkDirty();
		void eventHandler(const DebuggerEvent& event);
	};

	void InitDebugProcessViewType();
};  // namespace BinaryNinjaDebugger
