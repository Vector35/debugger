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
#include "msix_extractor.h"
#include "signature_verifier.h"
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
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
fs::path GetUserDirectory() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        return fs::path(path) / "Binary Ninja";
    }
    return {};
}

/* Generate a unique temporary file path */
fs::path GetTempBundlePath() {
    wchar_t tempPath[MAX_PATH];
    const DWORD length = GetTempPathW(MAX_PATH, tempPath);
    if (length == 0 || length >= MAX_PATH) {
        throw std::runtime_error("Could not determine the temporary directory");
    }

    /* Generate a unique filename using GUID */
    GUID guid;
    if (FAILED(CoCreateGuid(&guid))) {
        throw std::runtime_error("Could not generate a temporary bundle filename");
    }
    char guidStr[40];
    sprintf_s(guidStr, sizeof(guidStr), "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

    return fs::path(tempPath) / (std::string("windbg_") + guidStr + ".msixbundle");
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
void CleanupTempFiles(const std::vector<fs::path>& files, LogCallback logCallback) {
    for (const auto& file : files) {
        std::error_code ec;
        if (fs::is_directory(file)) {
            fs::remove_all(file, ec);
        } else {
            fs::remove(file, ec);
        }
        if (!ec) {
            Log(logCallback, LOG_DEBUG, "Cleaned up temporary bundle");
        }
    }
}

bool HasRequiredFiles(const fs::path& path) {
    for (const auto& file : kRequiredFiles) {
        if (!fs::exists(path / file)) {
            return false;
        }
    }
    return true;
}

} // anonymous namespace

std::string GetDefaultInstallPath() {
    const fs::path userDir = GetUserDirectory();
    if (userDir.empty()) {
        return "";
    }
    return (userDir / "windbg").string();
}

bool CheckInstallation(const std::string& path) {
    return HasRequiredFiles(fs::path(path));
}

bool CheckInstallOk(const std::string& path) {
    return CheckInstallation(path);
}

InstallResult Install(const InstallConfig& config) {
    LogCallback logCallback = config.onLog;
    ProgressCallback progressCallback = config.onProgress;
    std::vector<fs::path> tempFiles;

    try {
        Log(logCallback, LOG_INFO, "Starting WinDbg/TTD installation");

        ReportProgress(progressCallback, "Initializing installation...", 0);

        /* Determine install path */
        const std::string installPath = config.installPath.empty() ? GetDefaultInstallPath() : config.installPath;
        if (installPath.empty()) {
            std::string error = "Could not determine installation path";
            Log(logCallback, LOG_ERROR, error);
            return InstallResult(false, error);
        }
        const fs::path installTarget(installPath);
        Log(logCallback, LOG_INFO, "Installation target: " + installPath);

        /* Step 1: Determine which version to install and where to download it from.
         * We install a specific version rather than whatever is newest, see windbg_version.h */
        std::string version = config.version.empty() ? kDefaultVersion : config.version;
        Log(logCallback, LOG_INFO, "Installing WinDbg/TTD version " + version);

        /* Step 2: Download MSIX bundle (this is the main download that shows progress) */
        std::string msixUrl = BuildMsixBundleUrl(version);
        ReportProgress(progressCallback, "Downloading WinDbg/TTD package from:", 0);
        ReportProgress(progressCallback, msixUrl, 0);

        /* Note: the extension must be a recognized MSIX/APPX extension (not .zip) so that
         * WinVerifyTrust engages the AppX signature provider during Step 2.5 verification. */
        const fs::path msixPath = GetTempBundlePath();
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

        /* Extract the inner package's contents straight to the install dir.
         * The App Packaging API exposes it as a stream, so no large temporary
         * inner MSIX is written. */
        ReportProgress(progressCallback, "Installing WinDbg/TTD files...", 0);

        if (!ExtractInnerPackageToDir(msixPath, kInnerMsixName, installTarget, nullptr, logCallback)) {
            std::string error = "Failed to extract WinDbg contents from package";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        /* Step 5: Verify installation */
        ReportProgress(progressCallback, "Verifying installation...", 0);

        if (!HasRequiredFiles(installTarget)) {
            std::string error = "Installation verification failed - required files missing";
            Log(logCallback, LOG_ERROR, error);
            CleanupTempFiles(tempFiles, logCallback);
            return InstallResult(false, error);
        }

        Log(logCallback, LOG_INFO, "WinDbg/TTD installed to: " + installPath);

        /* Step 5b: Write version marker file */
        {
            std::ofstream versionFile(installTarget / "installed_version.txt");
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
            PrintSettingsInfo((installTarget / "amd64").string(), logCallback);
        }

        /* Cleanup */
        ReportProgress(progressCallback, "Cleaning up temporary files...", 0);
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

    const std::string target = installPath.empty() ? GetDefaultInstallPath() : installPath;
    if (target.empty()) {
        return info;  /* isInstalled = false, version = "" */
    }

    /* Store the path for reference */
    info.installPath = target;
    const fs::path path(target);

    /* Check if installation exists */
    if (!fs::exists(path / "amd64" / "dbgeng.dll")) {
        return info;  /* isInstalled = false, version = "" */
    }

    /* Installation exists */
    info.isInstalled = true;

    /* Read version from marker file (written during installation) */
    std::ifstream versionFile(path / "installed_version.txt");
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
