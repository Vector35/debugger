#include "debugadapter.h"
#include <binaryninjacore.h>
#include <binaryninjaapi.h>
#include <lowlevelilinstruction.h>
#include <mediumlevelilinstruction.h>
#include <highlevelilinstruction.h>
#ifndef WIN32
#include "libgen.h"
#endif

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
