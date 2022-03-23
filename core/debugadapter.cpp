#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>
#ifndef WIN32
#include "libgen.h"
#endif
#include "debugadapter.h"

using namespace BinaryNinjaDebugger;


DebugAdapter::DebugAdapter(BinaryView* data): m_data(data)
{
	INIT_DEBUGGER_API_OBJECT();
}


void DebugAdapter::PostDebuggerEvent(const DebuggerEvent &event)
{
	if (m_eventCallback)
		m_eventCallback(event);
}


std::string DebugModule::GetPathBaseName(const std::string& path)
{
#ifdef WIN32
    // TODO: someone please write it on Windows!
    char baseName[MAX_PATH];
    _splitpath(path.c_str(), NULL, NULL, baseName, NULL);
    return std::string(baseName);
#else
    return basename(strdup(path.c_str()));
#endif
}


bool DebugModule::IsSameBaseModule(const DebugModule& other) const
{
    return ((m_name == other.m_name) ||
        (m_short_name == other.m_short_name) ||
        (GetPathBaseName(m_name) == GetPathBaseName(other.m_name)) ||
        (GetPathBaseName(m_short_name) == GetPathBaseName(other.m_short_name)));
}


bool DebugModule::IsSameBaseModule(const std::string& name) const
{
    return ((m_name == name) ||
        (m_short_name == name) ||
        (GetPathBaseName(m_name) == GetPathBaseName(name)) ||
        (GetPathBaseName(m_short_name) == GetPathBaseName(name)));
}


bool DebugModule::IsSameBaseModule(const std::string& module1, const std::string& module2)
{
    return ((module1 == module2) ||
        (GetPathBaseName(module1) == GetPathBaseName(module2)));
}


DebugStopReason DebugAdapter::StepReturn()
{
	return OperationNotSupported;
}


uint64_t DebugAdapter::GetStackPointer()
{
	return 0;
}


void DebugAdapter::WriteStdin(const std::string &msg)
{
	LogWarn("WriteStdin operation not supported");
}


std::vector<DebugFrame> DebugAdapter::GetFramesOfThread(std::uint32_t tid)
{
	return {};
}
