#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;
using namespace std;


DebugAdapterType* DebugAdapterType::GetByName(const std::string &name)
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
	return BNDebugAdapterTypeCanConnect(m_object, data);
}


bool DebugAdapterType::CanExecute(Ref<BinaryView> data)
{
	return BNDebugAdapterTypeCanExecute(m_object, data);
}


std::vector<std::string> DebugAdapterType::GetAvailableAdapters(Ref<BinaryView> data)
{
	size_t count;
	char** adapters = BNGetAvailableDebugAdapterTypes(data, &count);

	std::vector<std::string> result;
	result.reserve(count);
	for(size_t i = 0; i < count; i++)
	{
		result.push_back(adapters[i]);
	}

	BNFreeStringList(adapters, count);
	return result;
}