/*
 * WinDbg/TTD Installer Library Implementation
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "windbg_installer.h"
#include "windbg_version.h"
#include "http_downloader.h"
#include "zip_extractor.h"
#include "signature_verifier.h"
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <vector>

#pragma comment(lib, "version.lib")

namespace fs = std::filesystem;

namespace WinDbgInstaller {

namespace {

/* Base URL that serves the MSIX bundle of every WinDbg release */
const char* kMsixBundleBaseUrl = "https://windbg.download.prss.microsoft.com/dbazure/prod";

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

/* Build the MSIX bundle URL for a specific WinDbg version.
 * Microsoft hosts every release at a predictable path where the dots of the version are
 * replaced with dashes, e.g. version "1.2603.20001.0" lives at
 * "https://windbg.download.prss.microsoft.com/dbazure/prod/1-2603-20001-0/windbg.msixbundle" */
std::string BuildMsixBundleUrl(const std::string& version) {
    std::string pathVersion = version;
    std::replace(pathVersion.begin(), pathVersion.end(), '.', '-');
    return std::string(kMsixBundleBaseUrl) + "/" + pathVersion + "/windbg.msixbundle";
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
        if (fs::is_directory(file)) {
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
        if (!fs::exists(fullPath)) {
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

        /* Step 1: Determine which version to install and where to download it from.
         * We install a specific version rather than whatever is newest, see windbg_version.h */
        std::string version = config.version.empty() ? kDefaultVersion : config.version;
        std::string msixUrl = BuildMsixBundleUrl(version);
        Log(logCallback, LOG_INFO, "Installing WinDbg/TTD version " + version);

        /* Step 2: Download MSIX bundle (this is the main download that shows progress) */
        ReportProgress(progressCallback, "Downloading WinDbg/TTD package from:", 0);
        ReportProgress(progressCallback, msixUrl, 0);

        /* Note: the extension must be a recognized MSIX/APPX extension (not .zip) so that
         * WinVerifyTrust engages the AppX signature provider during Step 2.5 verification. */
        std::string msixPath = GetTempFilePath(".msixbundle");
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

        /* Step 2.5: Verify the downloaded bundle is genuinely signed by Microsoft.
         * This must happen before we extract or trust any of its contents so that a
         * tampered or substituted package (supply-chain attack) is rejected. */
        ReportProgress(progressCallback, "Verifying package signature...", 0);

        SignatureResult sigResult = VerifyMicrosoftSignature(msixPath, logCallback);
        if (!sigResult.valid) {
            std::string error = sigResult.errorMessage.empty()
                ? "MSIX bundle signature verification failed"
                : sigResult.errorMessage;
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 3: Extract inner MSIX file from bundle */
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

        /* Step 4: Extract WinDbg contents to installation directory */
        ReportProgress(progressCallback, "Installing WinDbg/TTD files...", 0);

        if (!ExtractZipArchive(innerMsixPath, installTarget, nullptr, logCallback)) {
            std::string error = "Failed to extract WinDbg contents";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 5: Verify installation */
        ReportProgress(progressCallback, "Verifying installation...", 0);

        if (!CheckInstallation(installTarget)) {
            std::string error = "Installation verification failed - required files missing";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        Log(logCallback, LOG_INFO, "WinDbg/TTD installed to: " + installTarget);

        /* Step 5b: Write version marker file */
        {
            std::string versionFilePath = installTarget + "\\installed_version.txt";
            std::ofstream versionFile(versionFilePath);
            if (versionFile.is_open()) {
                versionFile << version;
                versionFile.close();
                Log(logCallback, LOG_INFO, "Wrote version marker: " + version);
            } else {
                Log(logCallback, LOG_WARN, "Could not write version marker file");
            }
        }

        /* Step 6: Print settings info (actual settings configuration is done by UI) */
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
    if (!fs::exists(dllPath)) {
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

} // namespace WinDbgInstaller

#endif // _WIN32
