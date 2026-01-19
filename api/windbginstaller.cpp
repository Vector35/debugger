/*
Copyright 2020-2026 Vector 35 Inc.

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

using namespace BinaryNinjaDebuggerAPI;


InstallResult BinaryNinjaDebuggerAPI::InstallWinDbg(const std::string& installPath, bool isUpdate)
{
	BNDebuggerInstallResult ffiResult = BNDebuggerInstallWinDbg(installPath.empty() ? nullptr : installPath.c_str(), isUpdate);

	InstallResult result;
	result.success = ffiResult.success;
	if (ffiResult.errorMessage)
	{
		result.errorMessage = ffiResult.errorMessage;
	}

	BNDebuggerFreeInstallResult(&ffiResult);
	return result;
}


bool BinaryNinjaDebuggerAPI::IsWinDbgInstalled(const std::string& installPath)
{
	return BNDebuggerIsWinDbgInstalled(installPath.empty() ? nullptr : installPath.c_str());
}


std::string BinaryNinjaDebuggerAPI::GetWinDbgInstallerPath()
{
	char* path = BNDebuggerGetWinDbgInstallerPath();
	std::string result = path ? path : "";
	BNDebuggerFreeString(path);
	return result;
}


std::string BinaryNinjaDebuggerAPI::GetWinDbgInstalledVersion(const std::string& installPath)
{
	char* version = BNDebuggerGetWinDbgInstalledVersion(installPath.empty() ? nullptr : installPath.c_str());
	std::string result = version ? version : "";
	BNDebuggerFreeString(version);
	return result;
}


std::string BinaryNinjaDebuggerAPI::GetWinDbgLatestVersion()
{
	char* version = BNDebuggerGetWinDbgLatestVersion();
	std::string result = version ? version : "";
	BNDebuggerFreeString(version);
	return result;
}
