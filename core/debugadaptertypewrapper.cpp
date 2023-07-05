#include "debugadaptertypewrapper.h"

using namespace BinaryNinjaDebugger;
using namespace BinaryNinja;
using namespace std;


DebugAdapterTypeWrapper::DebugAdapterTypeWrapper(const std::string &name, BNDebuggerCustomDebugAdapterType *type):
	DebugAdapterType(name), m_type(*type)
{

}


DebugAdapter* DebugAdapterTypeWrapper::Create(BinaryNinja::BinaryView *data)
{
	if (!m_type.create)
		return nullptr;
	BNDebugAdapter* adapter = m_type.create(m_type.context, data->GetObject());
	if (!adapter)
	{
		LogError("Failed to create DebugAdapter for: '%s'\n", GetName().c_str());
		return nullptr;
	}
	DbgRef<DebugAdapter> result = adapter->object;
	BNDebuggerFreeDebugAdapter(adapter);
	return result;
}


bool DebugAdapterTypeWrapper::IsValidForData(BinaryNinja::BinaryView *data)
{
	if (!m_type.isValidForData)
		return false;
	return m_type.isValidForData(m_type.context, data->GetObject());
}


bool DebugAdapterTypeWrapper::CanExecute(BinaryNinja::BinaryView *data)
{
	if (!m_type.canExecute)
		return false;
	return m_type.canExecute(m_type.context, data->GetObject());
}


bool DebugAdapterTypeWrapper::CanConnect(BinaryNinja::BinaryView *data)
{
	if (!m_type.canConnect)
		return false;
	return m_type.canConnect(m_type.context, data->GetObject());
}
