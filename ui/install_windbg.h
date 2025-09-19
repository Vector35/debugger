/*
Copyright 2020-2025 Vector 35 Inc.

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
#include <functional>

namespace BinaryNinjaDebugger
{
	/// Progress callback function type for installation progress updates
	/// @param step Current step description (e.g., "Downloading...", "Extracting...")
	/// @param progress Progress percentage (0-100), or -1 for indeterminate
	using InstallProgressCallback = std::function<void(const std::string& step, int progress)>;

	/// Install WinDbg/TTD by downloading and extracting the MSIX package
	/// @param progressCallback Optional callback for progress updates
	/// @return true if installation was successful, false otherwise
	bool InstallWinDbg(InstallProgressCallback progressCallback = nullptr);

	/// Check if WinDbg/TTD installation is valid at the given path
	/// @param path Path to check for required WinDbg/TTD files
	/// @return true if all required files are present, false otherwise
	bool CheckInstallOk(const std::string& path);
}

#endif // WIN32