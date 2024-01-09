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

#include "targetscriptingprovier.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

static TargetScriptingProvider* g_targetScriptingProvider = nullptr;

TargetScriptingProvider::TargetScriptingProvider() : ScriptingProvider("Target", "target") {}


Ref<ScriptingInstance> TargetScriptingProvider::CreateNewInstance()
{
	return new TargetScriptingInstance(this);
}


bool TargetScriptingProvider::LoadModule(const std::string& repository, const std::string& module, bool force)
{
	return false;
}


bool TargetScriptingProvider::InstallModules(const std::string& modules)
{
	return false;
}


TargetScriptingInstance::TargetScriptingInstance(ScriptingProvider* provider) : ScriptingInstance(provider)
{
	m_readyStatus = NotReadyForInput;
}


TargetScriptingInstance::~TargetScriptingInstance()
{
	if (m_controller)
		m_controller->RemoveEventCallback(m_debuggerEventCallback);
}


void TargetScriptingInstance::SetCurrentBinaryView(BinaryNinja::BinaryView* view)
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
						if (event.type == StdoutMessageEventType)
						{
							const std::string message = event.data.messageData.message;
							Output(message);
						}
					},
					"Target Console");
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


BNScriptingProviderExecuteResult TargetScriptingInstance::ExecuteScriptInput(const std::string& input)
{
	if (m_controller)
	{
		m_controller->WriteStdin(input);
		return SuccessfulScriptExecution;
	}
	return InvalidScriptInput;
}


BNScriptingProviderExecuteResult TargetScriptingInstance::ExecuteScriptInputFromFilename(const std::string& filename)
{
	return SuccessfulScriptExecution;
}


void RegisterTargetScriptingProvider()
{
	static TargetScriptingProvider provider;
	ScriptingProvider::Register(&provider);
	g_targetScriptingProvider = &provider;
}
