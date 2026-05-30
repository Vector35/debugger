/*
 * WinDbg/TTD Installer Library Implementation
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "windbg_installer.h"
#include "http_downloader.h"
#include "zip_extractor.h"
#include "../vendor/pugixml/pugixml.hpp"
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <sstream>
#include <system_error>

#pragma comment(lib, "version.lib")

namespace fs = std::filesystem;

namespace WinDbgInstaller {

namespace {

/* URL for WinDbg appinstaller file */
const char* kWinDbgDownloadUrl = "https://aka.ms/windbg/download";

/* Files required for valid installation */
const std::vector<std::string> kRequiredFiles = {
    "amd64\\dbgeng.dll",
    "amd64\\dbghelp.dll",
    "amd64\\dbgmodel.dll",
    "amd64\\dbgcore.dll",
    "amd64\\ttd\\TTD.exe",
    "amd64\\ttd\\TTDRecord.dll"
};

/* Inner MSIX file to extract from bundle */
const char* kInnerMsixName = "windbg_win-x64.msix";

void Log(LogCallback logCallback, int level, const std::string& message) {
    if (logCallback) {
        logCallback(level, message);
    }
}

void ReportProgress(ProgressCallback progressCallback, const std::string& step, int percent,
                    int64_t bytesDownloaded = 0, int64_t totalBytes = -1, double bytesPerSecond = 0.0) {
    if (progressCallback) {
        ProgressInfo info;
        info.step = step;
        info.overallPercent = percent;
        info.bytesDownloaded = bytesDownloaded;
        info.totalBytes = totalBytes;
        info.bytesPerSecond = bytesPerSecond;
        progressCallback(info);
    }
}

/* Get Binary Ninja user directory */
std::string GetUserDirectory() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        return std::string(path) + "\\Binary Ninja";
    }
    return "";
}

/* Generate a unique temporary file path */
std::string GetTempFilePath(const std::string& extension) {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    /* Generate a unique filename using GUID */
    GUID guid;
    CoCreateGuid(&guid);
    char guidStr[40];
    sprintf_s(guidStr, sizeof(guidStr), "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

    return std::string(tempPath) + "windbg_" + guidStr + extension;
}

/* Parse appinstaller XML to get MSIX bundle URL */
std::string ParseAppInstallerXml(const std::string& appInstallerPath, LogCallback logCallback) {
    Log(logCallback, LOG_INFO, "Parsing appinstaller XML: " + appInstallerPath);

    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file(appInstallerPath.c_str());

    if (!result) {
        Log(logCallback, LOG_ERROR, "Failed to parse XML: " + std::string(result.description()));
        return "";
    }

    /* Look for MainBundle element with Uri attribute */
    pugi::xml_node mainBundle = doc.child("AppInstaller").child("MainBundle");
    if (!mainBundle) {
        Log(logCallback, LOG_ERROR, "MainBundle element not found in XML");
        return "";
    }

    pugi::xml_attribute uriAttr = mainBundle.attribute("Uri");
    if (!uriAttr) {
        Log(logCallback, LOG_ERROR, "Uri attribute not found in MainBundle element");
        return "";
    }

    std::string msixUrl = uriAttr.value();
    Log(logCallback, LOG_INFO, "Found MSIX bundle URL: " + msixUrl);
    return msixUrl;
}

/* Print info about Binary Ninja settings (settings are configured by UI after install) */
void PrintSettingsInfo(const std::string& dbgEngPath, LogCallback logCallback) {
    Log(logCallback, LOG_INFO, "DbgEng path: " + dbgEngPath);
    Log(logCallback, LOG_INFO, "Binary Ninja will configure settings automatically when launched.");
}

/* Cleanup temporary files */
void CleanupTempFiles(const std::vector<std::string>& files, LogCallback logCallback) {
    for (const auto& file : files) {
        std::error_code ec;
        if (fs::is_directory(file, ec)) {
            fs::remove_all(file, ec);
        } else {
            fs::remove(file, ec);
        }
        if (!ec) {
            Log(logCallback, LOG_DEBUG, "Cleaned up: " + file);
        }
    }
}

} // anonymous namespace

std::string GetDefaultInstallPath() {
    std::string userDir = GetUserDirectory();
    if (userDir.empty()) {
        return "";
    }
    return userDir + "\\windbg";
}

bool CheckInstallation(const std::string& path) {
    for (const auto& file : kRequiredFiles) {
        fs::path fullPath = fs::path(path) / file;
        std::error_code ec;
        if (!fs::exists(fullPath, ec)) {
            return false;
        }
    }
    return true;
}

bool CheckInstallOk(const std::string& path) {
    return CheckInstallation(path);
}

InstallResult Install(const InstallConfig& config) {
    LogCallback logCallback = config.onLog;
    ProgressCallback progressCallback = config.onProgress;
    std::vector<std::string> tempFiles;

    try {
        Log(logCallback, LOG_INFO, "Starting WinDbg/TTD installation");

        ReportProgress(progressCallback, "Initializing installation...", 0);

        /* Determine install path */
        std::string installTarget = config.installPath;
        if (installTarget.empty()) {
            installTarget = GetDefaultInstallPath();
            if (installTarget.empty()) {
                std::string error = "Could not determine installation path";
                Log(logCallback, LOG_ERROR, error);
                return InstallResult(false, error);
            }
        }
        Log(logCallback, LOG_INFO, "Installation target: " + installTarget);

        /* Step 1: Download appinstaller file (small, no progress needed) */
        ReportProgress(progressCallback, "Downloading WinDbg package information from:", 0);
        ReportProgress(progressCallback, std::string(kWinDbgDownloadUrl), 0);

        std::string appInstallerPath = GetTempFilePath(".appinstaller");
        tempFiles.push_back(appInstallerPath);

        if (!DownloadFileWithProgress(kWinDbgDownloadUrl, appInstallerPath, nullptr, logCallback)) {
            std::string error = "Failed to download appinstaller file";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 2: Parse XML to get MSIX bundle URL */
        ReportProgress(progressCallback, "Parsing package information...", 0);

        std::string msixUrl = ParseAppInstallerXml(appInstallerPath, logCallback);
        if (msixUrl.empty()) {
            std::string error = "Failed to parse appinstaller XML";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 3: Download MSIX bundle (this is the main download that shows progress) */
        ReportProgress(progressCallback, "Downloading WinDbg/TTD package from:", 0);
        ReportProgress(progressCallback, msixUrl, 0);

        std::string msixPath = GetTempFilePath(".msixbundle.zip");
        tempFiles.push_back(msixPath);

        auto msixDownloadProgressCb = [&](const DownloadProgress& dp) {
            /* Report download percentage (0-100%) directly - this is the only step that needs progress display */
            int percent = 0;
            if (dp.totalBytes > 0) {
                percent = (int)(100 * dp.bytesDownloaded / dp.totalBytes);
            }
            ReportProgress(progressCallback, "Downloading...", percent,
                          dp.bytesDownloaded, dp.totalBytes, dp.bytesPerSecond);
        };

        if (!DownloadFileWithProgress(msixUrl, msixPath, msixDownloadProgressCb, logCallback)) {
            std::string error = "Failed to download MSIX bundle";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 4: Extract inner MSIX file from bundle */
        ReportProgress(progressCallback, "Extracting package contents...", 0);

        std::string tempExtractDir = GetTempFilePath("_extract");
        tempFiles.push_back(tempExtractDir);

        std::string innerMsixPath = ExtractFileFromZipArchive(msixPath, kInnerMsixName, tempExtractDir, logCallback);
        if (innerMsixPath.empty()) {
            std::string error = "Failed to extract inner MSIX file";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 5: Extract WinDbg contents to installation directory */
        ReportProgress(progressCallback, "Installing WinDbg/TTD files...", 0);

        if (!ExtractZipArchive(innerMsixPath, installTarget, nullptr, logCallback)) {
            std::string error = "Failed to extract WinDbg contents";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 6: Verify installation */
        ReportProgress(progressCallback, "Verifying installation...", 0);

        if (!CheckInstallation(installTarget)) {
            std::string error = "Installation verification failed - required files missing";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        Log(logCallback, LOG_INFO, "WinDbg/TTD installed to: " + installTarget);

        /* Step 6b: Write version marker file */
        /* Re-parse appinstaller to get version (file is still on disk) */
        std::string installedVersion;
        {
            pugi::xml_document doc;
            if (doc.load_file(appInstallerPath.c_str())) {
                pugi::xml_node appInstaller = doc.child("AppInstaller");
                if (appInstaller) {
                    pugi::xml_attribute versionAttr = appInstaller.attribute("Version");
                    if (versionAttr) {
                        installedVersion = versionAttr.value();
                    }
                }
            }
        }

        if (!installedVersion.empty()) {
            std::string versionFilePath = installTarget + "\\installed_version.txt";
            std::ofstream versionFile(versionFilePath);
            if (versionFile.is_open()) {
                versionFile << installedVersion;
                versionFile.close();
                Log(logCallback, LOG_INFO, "Wrote version marker: " + installedVersion);
            } else {
                Log(logCallback, LOG_WARN, "Could not write version marker file");
            }
        }

        /* Step 7: Print settings info (actual settings configuration is done by UI) */
        if (config.updateSettings) {
            std::string x64dbgEngPath = installTarget + "\\amd64";
            PrintSettingsInfo(x64dbgEngPath, logCallback);
        }

        /* Cleanup */
        CleanupTempFiles(tempFiles, logCallback);

        ReportProgress(progressCallback, "Installation completed successfully!", 0);
        Log(logCallback, LOG_INFO, "Please restart Binary Ninja to use WinDbg/TTD.");

        return InstallResult(true);
    }
    catch (const std::exception& e) {
        std::string error = "Exception during installation: " + std::string(e.what());
        Log(logCallback, LOG_ERROR, error);
        CleanupTempFiles(tempFiles, logCallback);
        return InstallResult(false, error);
    }
}

bool InstallWinDbg(LegacyProgressCallback progressCallback) {
    InstallConfig config;
    config.updateSettings = true;

    /* Wrap legacy callback */
    if (progressCallback) {
        config.onProgress = [progressCallback](const ProgressInfo& info) {
            progressCallback(info.step, info.overallPercent);
        };
    }

    InstallResult result = Install(config);
    return result.success;
}

/* ============================================================================
 * Version Functions
 * ============================================================================ */

VersionInfo GetInstalledVersion(const std::string& installPath) {
    VersionInfo info;

    std::string path = installPath.empty() ? GetDefaultInstallPath() : installPath;
    if (path.empty()) {
        return info;  /* isInstalled = false, version = "" */
    }

    /* Store the path for reference */
    info.installPath = path;

    /* Check if installation exists */
    std::string dllPath = path + "\\amd64\\dbgeng.dll";
    std::error_code ec;
    if (!fs::exists(dllPath, ec)) {
        return info;  /* isInstalled = false, version = "" */
    }

    /* Installation exists */
    info.isInstalled = true;

    /* Read version from marker file (written during installation) */
    std::string versionFilePath = path + "\\installed_version.txt";
    std::ifstream versionFile(versionFilePath);
    if (versionFile.is_open()) {
        std::getline(versionFile, info.version);
        versionFile.close();
        if (!info.version.empty()) {
            info.displayName = "WinDbg " + info.version;
        }
    }

    /* If no version file, installation is from older version - mark as unknown */
    if (info.version.empty()) {
        info.displayName = "WinDbg (unknown version)";
    }

    return info;
}

VersionInfo GetLatestVersion(LogCallback logCallback) {
    VersionInfo info;

    /* Download appinstaller file to temp location */
    std::string tempPath = GetTempFilePath(".appinstaller");

    if (!DownloadFileWithProgress(kWinDbgDownloadUrl, tempPath, nullptr, logCallback)) {
        Log(logCallback, LOG_ERROR, "Failed to download appinstaller for version check");
        return info;
    }

    /* Parse XML to get version */
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_file(tempPath.c_str());

    if (!result) {
        Log(logCallback, LOG_ERROR, "Failed to parse appinstaller XML: " + std::string(result.description()));
        std::error_code ec;
        fs::remove(tempPath, ec);
        return info;
    }

    /* Get version from AppInstaller element */
    pugi::xml_node appInstaller = doc.child("AppInstaller");
    if (appInstaller) {
        pugi::xml_attribute versionAttr = appInstaller.attribute("Version");
        if (versionAttr) {
            info.version = versionAttr.value();
            info.displayName = "WinDbg " + info.version;
        }

        /* Get download URL from MainBundle */
        pugi::xml_node mainBundle = appInstaller.child("MainBundle");
        if (mainBundle) {
            pugi::xml_attribute uriAttr = mainBundle.attribute("Uri");
            if (uriAttr) {
                info.downloadUrl = uriAttr.value();
            }
        }
    }

    /* Cleanup */
    std::error_code ec;
    fs::remove(tempPath, ec);

    return info;
}

int CompareVersions(const std::string& v1, const std::string& v2) {
    /* Parse version strings like "1.2404.24002.0" */
    auto parseVersion = [](const std::string& v) -> std::vector<int> {
        std::vector<int> parts;
        std::istringstream iss(v);
        std::string part;
        while (std::getline(iss, part, '.')) {
            try {
                parts.push_back(std::stoi(part));
            } catch (...) {
                parts.push_back(0);
            }
        }
        return parts;
    };

    std::vector<int> parts1 = parseVersion(v1);
    std::vector<int> parts2 = parseVersion(v2);

    /* Pad with zeros to make them equal length */
    size_t maxLen = (std::max)(parts1.size(), parts2.size());
    parts1.resize(maxLen, 0);
    parts2.resize(maxLen, 0);

    /* Compare part by part */
    for (size_t i = 0; i < maxLen; i++) {
        if (parts1[i] < parts2[i]) return -1;
        if (parts1[i] > parts2[i]) return 1;
    }

    return 0;
}

bool IsVersionUpToDate(const VersionInfo& installed, const VersionInfo& latest) {
    /* If either version is invalid, assume up to date (can't determine) */
    if (!installed.IsValid() || !latest.IsValid()) {
        return true;
    }

    /* Installed >= Latest means up to date */
    return CompareVersions(installed.version, latest.version) >= 0;
}

} // namespace WinDbgInstaller

#endif // _WIN32
