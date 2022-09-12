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

#include "debugadapterscriptingprovider.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

static DebugAdapterScriptingProvider* g_debugAdapterScriptingProvider = nullptr;

DebugAdapterScriptingProvider::DebugAdapterScriptingProvider():
	ScriptingProvider("Debugger", "debugger")
{

}


Ref<ScriptingInstance> DebugAdapterScriptingProvider::CreateNewInstance()
{
	return new DebugAdapterScriptingInstance(this);
}


bool DebugAdapterScriptingProvider::LoadModule(const std::string& repository, const std::string& module, bool force)
{
	return false;
}


bool DebugAdapterScriptingProvider::InstallModules(const std::string& modules)
{
	return false;
}


DebugAdapterScriptingInstance::DebugAdapterScriptingInstance(ScriptingProvider* provider):
	ScriptingInstance(provider)
{
	m_readyStatus = NotReadyForInput;
}


DebugAdapterScriptingInstance::~DebugAdapterScriptingInstance()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_debuggerEventCallback);
}


void DebugAdapterScriptingInstance::SetCurrentBinaryView(BinaryNinja::BinaryView* view)
{
	if (m_data.operator!=(view))
	{
		m_data = view;
		if (m_data)
		{
			if (m_controller)
				m_controller->RemoveEventCallback(m_debuggerEventCallback);

			m_controller = DebuggerController::GetController(view);
			if (m_controller)
			{
				m_debuggerEventCallback = m_controller->RegisterEventCallback(
					[&](const DebuggerEvent& event) {
						if (event.type == BackendMessageEventType)
						{
							const std::string message = event.data.messageData.message;
							Output(message);
						}
					},
					"Debugger Console");
			}
		}
		else
		{
			if (m_controller)
			{
				m_controller->RemoveEventCallback(m_debuggerEventCallback);
				m_controller = nullptr;
				m_debuggerEventCallback = -1;
			}
		}
	}

	BNScriptingProviderInputReadyState newReadyStatus = NotReadyForInput;
	if (m_data && m_controller)
		newReadyStatus = ReadyForScriptExecution;
	else
		newReadyStatus = NotReadyForInput;

	if (newReadyStatus != m_readyStatus)
	{
		m_readyStatus = newReadyStatus;
		InputReadyStateChanged(m_readyStatus);
	}
}


BNScriptingProviderExecuteResult DebugAdapterScriptingInstance::ExecuteScriptInput(const std::string& input)
{
	if (m_controller)
	{
		// The UI component adds a trailing '\n' to the input, which must be removed before we send it to the backend
		auto trimmedInput = input;
		trimmedInput.erase(trimmedInput.find_last_not_of('\n') + 1);
		auto ret = m_controller->InvokeBackendCommand(trimmedInput);
		Output(ret);
		return SuccessfulScriptExecution;
	}
	return InvalidScriptInput;
}


BNScriptingProviderExecuteResult DebugAdapterScriptingInstance::ExecuteScriptInputFromFilename(const std::string& filename)
{
	return SuccessfulScriptExecution;
}


void RegisterDebugAdapterScriptingProvider()
{
	static DebugAdapterScriptingProvider provider;
	ScriptingProvider::Register(&provider);
	g_debugAdapterScriptingProvider = &provider;
}
