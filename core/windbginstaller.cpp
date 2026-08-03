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
        std::error_code ec;
        fs::path path = fs::path(pluginRoot) / "windbg-installer.exe";
        if (fs::exists(path, ec)) {
            fs::path canonicalPath = fs::canonical(path, ec);
            return ec ? path.string() : canonicalPath.string();
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
    std::error_code ec;
    return fs::exists(path + "\\amd64\\dbgeng.dll", ec) &&
           fs::exists(path + "\\amd64\\dbghelp.dll", ec);
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
            std::error_code ec;
            fs::remove(resultPath, ec);
        }

        LogError("Installation failed: %s", errorMessage.c_str());
        return InstallResult(false, errorMessage);
    }
}

/* Helper function to run installer CLI and capture JSON output */
static std::string RunInstallerCommand(const std::string& command, const std::string& extraArgs = "") {
    std::string installerPath = GetInstallerPath();
    if (installerPath.empty()) {
        return "";
    }

    std::string cmdLine = "\"" + installerPath + "\" " + command + " --json";
    if (!extraArgs.empty()) {
        cmdLine += " " + extraArgs;
    }

    /* Create pipes for stdout */
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return "";
    }

    /* Ensure read handle is not inherited */
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(
            nullptr,
            const_cast<char*>(cmdLine.c_str()),
            nullptr,
            nullptr,
            TRUE,  /* Inherit handles */
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "";
    }

    /* Close write end in parent */
    CloseHandle(hWritePipe);

    /* Read output */
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }

    CloseHandle(hReadPipe);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output;
}

/* Simple JSON value extractor - finds "key":"value" pattern */
static std::string ExtractJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) {
        return "";
    }
    pos += searchKey.length();
    size_t endPos = json.find("\"", pos);
    if (endPos == std::string::npos) {
        return "";
    }
    return json.substr(pos, endPos - pos);
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

std::string GetLatestVersion() {
    std::string output = RunInstallerCommand("check-update");
    return ExtractJsonValue(output, "latest");
}

} // namespace BinaryNinjaDebugger

#endif // WIN32
