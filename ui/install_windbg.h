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

#pragma once

#ifdef WIN32

#include <string>

namespace BinaryNinjaDebugger
{
	/// Result of WinDbg installation
	struct InstallResult
	{
		bool success;
		std::string errorMessage;  // Empty if success, otherwise describes the error

		InstallResult() : success(false) {}
		InstallResult(bool s, const std::string& err = "") : success(s), errorMessage(err) {}
	};

	/// Install WinDbg/TTD by launching the installer CLI
	/// @param installPath Custom install path (empty = default)
	/// @param isUpdate If true, CLI will wait for Binary Ninja to exit first
	/// @return InstallResult with success status and error message if failed
	InstallResult InstallWinDbg(const std::string& installPath = "", bool isUpdate = false);

	/// Check if WinDbg/TTD installation is valid at the given path
	/// @param path Path to check for required WinDbg/TTD files
	/// @return true if all required files are present, false otherwise
	bool CheckInstallOk(const std::string& path);

	/// Get the version of installed WinDbg
	/// @param installPath Path to check (empty = default)
	/// @return Version string (e.g., "1.2404.24002.0"), or empty if not installed
	std::string GetInstalledVersion(const std::string& installPath = "");

	/// Get the latest available WinDbg version from Microsoft
	/// @return Version string, or empty on error
	std::string GetLatestVersion();
}

#endif // WIN32