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

#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;


DebugAdapterType* DebugAdapterType::GetByName(const std::string& name)
{
	BNDebugAdapterType* adapter = BNGetDebugAdapterTypeByName(name.c_str());
	if (!adapter)
		return nullptr;

	return new DebugAdapterType(adapter);
}


DebugAdapterType::DebugAdapterType(BNDebugAdapterType* controller)
{
	m_object = controller;
}


bool DebugAdapterType::CanConnect(Ref<BinaryView> data)
{
	return BNDebugAdapterTypeCanConnect(m_object, data->GetObject());
}


bool DebugAdapterType::CanExecute(Ref<BinaryView> data)
{
	return BNDebugAdapterTypeCanExecute(m_object, data->GetObject());
}


std::vector<std::string> DebugAdapterType::GetAvailableAdapters(Ref<BinaryView> data)
{
	size_t count;
	char** adapters = BNGetAvailableDebugAdapterTypes(data->GetObject(), &count);

	std::vector<std::string> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(adapters[i]);
	}

	BNDebuggerFreeStringList(adapters, count);
	return result;
}