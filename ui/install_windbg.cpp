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

#ifdef WIN32

#include "install_windbg.h"
#include "../api/debuggerapi.h"

using namespace BinaryNinjaDebuggerAPI;

namespace BinaryNinjaDebugger
{
	bool CheckInstallOk(const std::string& path)
	{
		return IsWinDbgInstalled(path);
	}

	InstallResult InstallWinDbg(const std::string& installPath, bool isUpdate)
	{
		BinaryNinjaDebuggerAPI::InstallResult apiResult = BinaryNinjaDebuggerAPI::InstallWinDbg(installPath, isUpdate);

		InstallResult result;
		result.success = apiResult.success;
		result.errorMessage = apiResult.errorMessage;
		return result;
	}

	std::string GetInstalledVersion(const std::string& installPath)
	{
		return BinaryNinjaDebuggerAPI::GetWinDbgInstalledVersion(installPath);
	}

	std::string GetLatestVersion()
	{
		return BinaryNinjaDebuggerAPI::GetWinDbgLatestVersion();
	}
}

#endif // WIN32
