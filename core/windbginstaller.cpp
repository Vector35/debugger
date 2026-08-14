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

#include "windbginstaller.h"
#include <binaryninjaapi.h>
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>

using namespace BinaryNinja;
namespace fs = std::filesystem;

namespace BinaryNinjaDebugger {

std::string GetInstallerPath() {
    std::string pluginRoot;
    if (getenv("BN_STANDALONE_DEBUGGER") != nullptr)
        pluginRoot = GetUserPluginDirectory();
    else
        pluginRoot = GetBundledPluginDirectory();

    if (!pluginRoot.empty()) {
        fs::path path = fs::path(pluginRoot) / "windbg-installer.exe";
        if (fs::exists(path)) {
            return fs::canonical(path).string();
        }
    }

    return "";
}

bool IsWinDbgInstalled(const std::string& installPath) {
    std::string path = installPath;
    if (path.empty()) {
        /* Use default path */
        char appData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData))) {
            path = std::string(appData) + "\\Binary Ninja\\windbg";
        }
    }

    if (path.empty()) {
        return false;
    }

    /* Check for required DLLs */
    return fs::exists(path + "\\amd64\\dbgeng.dll") &&
           fs::exists(path + "\\amd64\\dbghelp.dll");
}

InstallResult InstallWinDbg(const std::string& installPath, bool isUpdate) {
    std::string installerPath = GetInstallerPath();
    if (installerPath.empty()) {
        LogError("Could not find windbg-installer.exe");
        return InstallResult(false, "Could not find windbg-installer.exe");
    }

    /* Determine install path for result file */
    std::string targetPath = installPath;
    if (targetPath.empty()) {
        char appData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData))) {
            targetPath = std::string(appData) + "\\Binary Ninja\\windbg";
        }
    }

    /* Build command line */
    std::string cmdLine = "\"" + installerPath + "\" install";
    if (isUpdate) {
        cmdLine += " --update";
    }
    if (!installPath.empty()) {
        cmdLine += " --path \"" + installPath + "\"";
    }
    /* Install the version the user has configured, rather than the installer's built-in default */
    std::string version = Settings::Instance()->Get<std::string>("debugger.windbgVersion");
    if (!version.empty()) {
        cmdLine += " --windbg-version \"" + version + "\"";
    }

    LogInfo("Running: %s", cmdLine.c_str());

    /* Create process with visible console window */
    STARTUPINFOA si = {};
    si.cb = sizeof(si);

    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(
            nullptr,
            const_cast<char*>(cmdLine.c_str()),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi)) {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, sizeof(errorMsg), "Failed to start installer process (error code: %lu)", error);
        LogError("%s", errorMsg);
        return InstallResult(false, errorMsg);
    }

    /* Wait for process to finish */
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode == 0) {
        return InstallResult(true);
    } else {
        /* Read error message from result file written by installer CLI */
        std::string errorMessage = "Installation failed";

        std::string resultPath = targetPath + "\\install_result.json";
        std::ifstream resultFile(resultPath);
        if (resultFile.is_open()) {
            std::string line;
            std::string json;
            while (std::getline(resultFile, line)) {
                json += line;
            }
            resultFile.close();

            /* Parse JSON to extract error message */
            /* Look for "error":"message" */
            size_t errorPos = json.find("\"error\":\"");
            if (errorPos != std::string::npos) {
                errorPos += 9;  /* Skip past "error":" */
                size_t errorEnd = json.find("\"", errorPos);
                if (errorEnd != std::string::npos) {
                    errorMessage = json.substr(errorPos, errorEnd - errorPos);
                }
            }

            /* Clean up result file */
            fs::remove(resultPath);
        }

        LogError("Installation failed: %s", errorMessage.c_str());
        return InstallResult(false, errorMessage);
    }
}

std::string GetInstalledVersion(const std::string& installPath) {
    /* Read version directly from marker file (fast, no CLI call needed) */
    std::string path = installPath;
    if (path.empty()) {
        /* Use default path */
        char appData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData))) {
            path = std::string(appData) + "\\Binary Ninja\\windbg";
        }
    }

    if (path.empty()) {
        return "";
    }

    /* Read from version marker file */
    std::string versionFilePath = path + "\\installed_version.txt";
    std::ifstream versionFile(versionFilePath);
    if (versionFile.is_open()) {
        std::string version;
        std::getline(versionFile, version);
        versionFile.close();
        if (!version.empty()) {
            return version;
        }
    }

    /* Version file not found - installation may be from older version or corrupted */
    /* Return empty string rather than calling CLI to keep UI responsive */
    return "";
}

} // namespace BinaryNinjaDebugger

#endif // WIN32
