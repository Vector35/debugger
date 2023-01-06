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


DebugAdapter::DebugAdapter(BinaryView* data)
{
	INIT_DEBUGGER_API_OBJECT();

	// These are just a workaround to avoid holding a reference to the data. Note, when DebugAdapter is constructed,
	// the binary view passed in is the one *before* rebasing. After the debugger launches the target and rebases the
	// binary view, the un-rebased binary view is released by the core and the debugger becomes the only place where
	// we hold a reference to it.
	// Though, a better approach would be to add a function SetData() to the DebugAdapter class and update the binary
	// view after the launch, similar to what we do for the DebuggerController. However, we will need to add new APIs
	// to get the original image base of the binary view, because LLDB requires the breakpoint address be relative to
	// the original image base, and it does not work with a rebased one.
	m_entryPoint = data->GetEntryPoint();
	m_start = data->GetStart();
	if (data->GetDefaultArchitecture())
		m_defaultArchitecture = data->GetDefaultArchitecture()->GetName();

	m_originalFileName = data->GetFile()->GetOriginalFilename();
}


void DebugAdapter::PostDebuggerEvent(const DebuggerEvent& event)
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
	return ((m_name == other.m_name) || (m_short_name == other.m_short_name)
		|| (GetPathBaseName(m_name) == GetPathBaseName(other.m_name))
		|| (GetPathBaseName(m_short_name) == GetPathBaseName(other.m_short_name)));
}


bool DebugModule::IsSameBaseModule(const std::string& name) const
{
	return ((m_name == name) || (m_short_name == name) || (GetPathBaseName(m_name) == GetPathBaseName(name))
		|| (GetPathBaseName(m_short_name) == GetPathBaseName(name)));
}


bool DebugModule::IsSameBaseModule(const std::string& module1, const std::string& module2)
{
	return ((module1 == module2) || (GetPathBaseName(module1) == GetPathBaseName(module2)));
}


DebugStopReason DebugAdapter::StepReturn()
{
	return OperationNotSupported;
}


uint64_t DebugAdapter::GetStackPointer()
{
	return 0;
}


void DebugAdapter::WriteStdin(const std::string& msg)
{
	LogWarn("WriteStdin operation not supported");
}


std::vector<DebugFrame> DebugAdapter::GetFramesOfThread(std::uint32_t tid)
{
	return {};
}


bool DebugAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port)
{
	return false;
}


bool DebugAdapter::DisconnectDebugServer()
{
	return true;
}


Ref<Metadata> DebugAdapter::GetProperty(const std::string& name)
{
	return nullptr;
}


bool DebugAdapter::SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value)
{
	return false;
}
