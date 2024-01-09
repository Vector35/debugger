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
#include "debugadapter.h"
#include "../api/ffi.h"
#include "ffi_global.h"

DECLARE_DEBUGGER_API_OBJECT(BNDebugAdapterType, DebugAdapterType);

namespace BinaryNinjaDebugger {
	class DebugAdapter;

	class DebugAdapterType
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNDebugAdapterType);

	private:
		std::string m_name;
		inline static std::vector<DebugAdapterType*> m_types;

	public:
		DebugAdapterType(const std::string& name);

		static void Register(DebugAdapterType* type);

		virtual DebugAdapter* Create(BinaryNinja::BinaryView* data) = 0;

		virtual bool IsValidForData(BinaryNinja::BinaryView* data) = 0;

		virtual bool CanExecute(BinaryNinja::BinaryView* data) = 0;

		virtual bool CanConnect(BinaryNinja::BinaryView* data) = 0;

		std::string GetName() const { return m_name; }

		static DebugAdapterType* GetByName(const std::string& name);

		// Returns a list of usable DebugAdapters on the current system
		static std::vector<std::string> GetAvailableAdapters(BinaryNinja::BinaryView* data);

		static std::string GetBestAdapterForCurrentSystem(BinaryNinja::BinaryView* data);
	};
};  // namespace BinaryNinjaDebugger