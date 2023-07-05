/*
Copyright 2020-2023 Vector 35 Inc.

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

	return new DbgCoreDebugAdapterType(adapter);
}


DebugAdapterType::DebugAdapterType(BNDebugAdapterType* type)
{
	m_object = type;
}


DebugAdapterType::DebugAdapterType(const std::string &name): m_nameForRegister(name)
{
	m_object = nullptr;
}


void DebugAdapterType::Register(BinaryNinjaDebuggerAPI::DebugAdapterType *type)
{
	BNDebuggerCustomDebugAdapterType callback;
	callback.context = type;
	callback.create = CreateCallback;
	callback.isValidForData = IsvalidForDataCallback;
	callback.canExecute = CanExecuteCallback;
	callback.canConnect = CanConnectCallback;
	type->AddRefForRegistration();
	type->m_object = BNDebuggerRegisterDebugAdapterType(type->m_nameForRegister.c_str(), &callback);
}


BNDebugAdapter* DebugAdapterType::CreateCallback(void *ctxt, BNBinaryView *data)
{
	DebugAdapterType* type = (DebugAdapterType*)ctxt;
	Ref<BinaryView> view = new BinaryView(BNNewViewReference(data));
	DbgRef<DebugAdapter> result = type->Create(view);
	if (!result)
		return nullptr;

	return BNDebuggerNewDebugAdapterReference(result->GetObject());
}


bool DebugAdapterType::IsvalidForDataCallback(void *ctxt, BNBinaryView *data)
{
	DebugAdapterType* type = (DebugAdapterType*)ctxt;
	return type->IsValidForData(new BinaryView(data));
}


bool DebugAdapterType::CanExecuteCallback(void *ctxt, BNBinaryView *data)
{
	DebugAdapterType* type = (DebugAdapterType*)ctxt;
	return type->CanExecute(new BinaryView(data));

}


bool DebugAdapterType::CanConnectCallback(void *ctxt, BNBinaryView *data)
{
	DebugAdapterType* type = (DebugAdapterType*)ctxt;
	return type->CanConnect(new BinaryView(data));
}


DbgCoreDebugAdapterType::DbgCoreDebugAdapterType(BNDebugAdapterType *type): DebugAdapterType(type)
{

}


bool DbgCoreDebugAdapterType::IsValidForData(Ref<BinaryNinja::BinaryView> data)
{
	return BNDebugAdapterTypeIsValidForData(m_object, data->GetObject());
}


bool DbgCoreDebugAdapterType::CanConnect(Ref<BinaryView> data)
{
	return BNDebugAdapterTypeCanConnect(m_object, data->GetObject());
}


bool DbgCoreDebugAdapterType::CanExecute(Ref<BinaryView> data)
{
	return BNDebugAdapterTypeCanExecute(m_object, data->GetObject());
}


DbgRef<DebugAdapter> DbgCoreDebugAdapterType::Create(BinaryNinja::BinaryView *data)
{
	BNDebugAdapter* adapter = BNDebugCreateDebugAdapterOfType(m_object, data->GetObject());
	if (!adapter)
		return nullptr;

	return new DebugAdapter(adapter);
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
