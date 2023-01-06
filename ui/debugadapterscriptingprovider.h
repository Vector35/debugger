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

#pragma once

#include "binaryninjaapi.h"
#include "debuggerapi.h"
#include "uitypes.h"

class DebugAdapterScriptingInstance : public ScriptingInstance
{
private:
	Ref<BinaryView> m_data;
	DebuggerControllerRef m_controller = nullptr;
	size_t m_debuggerEventCallback = -1;
	BNScriptingProviderInputReadyState m_readyStatus;

public:
	DebugAdapterScriptingInstance(ScriptingProvider* provider);
	~DebugAdapterScriptingInstance();

	virtual BNScriptingProviderExecuteResult ExecuteScriptInput(const std::string& input);
	virtual BNScriptingProviderExecuteResult ExecuteScriptInputFromFilename(const std::string& filename);

	virtual void SetCurrentBinaryView(BinaryView* view);
};


class DebugAdapterScriptingProvider : public ScriptingProvider
{
public:
	DebugAdapterScriptingProvider();

	virtual Ref<ScriptingInstance> CreateNewInstance();
	virtual bool LoadModule(const std::string& repository, const std::string& module, bool force);
	virtual bool InstallModules(const std::string& modules);
};


void RegisterDebugAdapterScriptingProvider();
