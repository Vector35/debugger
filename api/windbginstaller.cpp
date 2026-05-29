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
#include "pathhelpers.h"

using namespace BinaryNinjaDebuggerAPI;


InstallResult BinaryNinjaDebuggerAPI::InstallWinDbg(const std::filesystem::path& installPath, bool isUpdate)
{
	Path::ScopedCorePath corePath(installPath);
	BNDebuggerInstallResult ffiResult = BNDebuggerInstallWinDbg(installPath.empty() ? nullptr : corePath.get(), isUpdate);

	InstallResult result;
	result.success = ffiResult.success;
	if (ffiResult.errorMessage)
	{
		result.errorMessage = ffiResult.errorMessage;
	}

	BNDebuggerFreeInstallResult(&ffiResult);
	return result;
}


bool BinaryNinjaDebuggerAPI::IsWinDbgInstalled(const std::filesystem::path& installPath)
{
	Path::ScopedCorePath corePath(installPath);
	return BNDebuggerIsWinDbgInstalled(installPath.empty() ? nullptr : corePath.get());
}


std::filesystem::path BinaryNinjaDebuggerAPI::GetWinDbgInstallerPath()
{
	BNPath* path = BNDebuggerGetWinDbgInstallerPath();
	if (!path)
		return {};
	return Path::PathFromCore(path);
}


std::string BinaryNinjaDebuggerAPI::GetWinDbgInstalledVersion(const std::filesystem::path& installPath)
{
	Path::ScopedCorePath corePath(installPath);
	char* version = BNDebuggerGetWinDbgInstalledVersion(installPath.empty() ? nullptr : corePath.get());
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
