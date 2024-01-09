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

#include <inttypes.h>
#include "processview.h"
#include "adapters/lldbadapter.h"
#ifdef WIN32
	#include "adapters/dbgengadapter.h"
	#include "adapters/dbgengttdadapter.h"
#endif

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

void InitDebugAdapterTypes()
{
#ifdef WIN32
    InitDbgEngAdapterType();
    InitDbgEngTTDAdapterType();
#endif

	// Disable these adapters because they are not tested, and will get replaced later
	//InitGdbAdapterType();
	//InitLldbRspAdapterType();
	InitLldbAdapterType();
}


static void RegisterSettings()
{
	Ref<Settings> settings = Settings::Instance();
	settings->RegisterGroup("debugger", "Debugger");
	/*

	Removed blockPython -- we can re-add it once this debugger is enabled by
	default

	Leaving this function for migration of the settings popup.

	*/

	settings->RegisterSetting("debugger.stopAtSystemEntryPoint",
		R"({
			"title" : "Stop At System Entry Point",
			"type" : "boolean",
			"default" : false,
			"description" : "Stop the target at system entry point",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	settings->RegisterSetting("debugger.stopAtEntryPoint",
		R"({
			"title" : "Stop At Entry Point",
			"type" : "boolean",
			"default" : true,
			"description" : "Stop the target at program entry point",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

#ifdef WIN32
	settings->RegisterSetting("debugger.x64dbgEngPath",
		R"({
			"title" : "x64 DbgEng Installation Path",
			"type" : "string",
			"default" : "",
			"description" : "Path of the x64 DbgEng Installation. This folder should contain an x64 dbgeng.dll.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");
	settings->RegisterSetting("debugger.x86dbgEngPath",
		R"({
			"title" : "x86 DbgEng Installation Path",
			"type" : "string",
			"default" : "",
			"description" : "Path of the x86 DbgEng Installation. This folder should contain an x86 dbgeng.dll.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");
#endif

	settings->RegisterSetting("debugger.stackVariableAnnotations",
		R"({
			"title" : "Stack Variable Annotations",
			"type" : "boolean",
			"default" : true,
			"description" : "Add stack variable annotations",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	settings->RegisterSetting("debugger.aggressiveAnalysisUpdate",
		R"({
			"title" : "Update the analysis aggressively",
			"type" : "boolean",
			"default" : false,
			"description" : "Whether to aggressively update the memory cache and analysis. If the target has self-modifying code, turning this on makes sure every function is re-analyzed every time the target stops, which gives the most accurate analysis. However, for large binaries with lots of functions, this may cause performance issues.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	settings->RegisterSetting("debugger.safeMode",
		R"({
			"title" : "Safe Mode",
			"type" : "boolean",
			"default" : false,
			"description" : "When enabled, this prevents the debugger from launching any file.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	settings->RegisterSetting("debugger.confirmFirstLaunch",
		R"({
			"title" : "Confirm on first launch",
			"type" : "boolean",
			"default" : true,
			"description" : "Asks the user to confirm the operation when the target is launched for the first time.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");

	settings->RegisterSetting("debugger.dbgEngOutputStateOnStop",
		R"({
			"title" : "Output current state when the DbgEng engine stops",
			"type" : "boolean",
			"default" : true,
			"description" : "Output the current state (e.g., register values, next instruction) in the debugger console when the target stops.",
			"ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
			})");
}

extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

#ifndef DEMO_VERSION
	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		SetCurrentPluginLoadOrder(LatePluginLoadOrder);
	}
#endif

#ifdef DEMO_VERSION
	bool DebuggerPluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		LogDebug("Native debugger loaded!");
		RegisterSettings();
		InitDebugAdapterTypes();
		InitDebugProcessViewType();
		return true;
	}
}
