/*
 * WinDbg/TTD Installer Library
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#pragma once

#ifdef _WIN32

#include <string>
#include <functional>
#include <cstdint>

namespace WinDbgInstaller {

/* Progress information */
struct ProgressInfo {
    std::string step;           /* Current step description */
    int overallPercent;         /* Overall progress 0-100 */
    int64_t bytesDownloaded;    /* Bytes downloaded so far (for download steps) */
    int64_t totalBytes;         /* Total bytes to download (-1 if unknown) */
    double bytesPerSecond;      /* Current download speed in bytes/second */
};

/* Callback function types */
using ProgressCallback = std::function<void(const ProgressInfo& info)>;
using LogCallback = std::function<void(int level, const std::string& message)>;

/* Log levels */
enum LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

/* Installation configuration */
struct InstallConfig {
    std::string installPath;     /* Override default install path (empty = use default) */
    std::string version;         /* WinDbg version to install (empty = kDefaultVersion) */
    bool updateSettings;         /* Whether to update Binary Ninja settings (default: true) */
    ProgressCallback onProgress; /* Progress callback */
    LogCallback onLog;           /* Logging callback */

    InstallConfig() : updateSettings(true) {}
};

/* Installation result */
struct InstallResult {
	bool success;
	std::string errorMessage;  // Empty if success, otherwise describes error

	InstallResult() : success(false) {}
	InstallResult(bool s, const std::string& err = "") : success(s), errorMessage(err) {}
};

/*
 * Install WinDbg/TTD
 *
 * @param config Installation configuration
 * @return InstallResult with success status and error message if failed
 */
InstallResult Install(const InstallConfig& config);

/*
 * Check if installation is valid at path
 *
 * @param path Path to check
 * @return true if all required files are present
 */
bool CheckInstallation(const std::string& path);

/*
 * Get default installation path
 *
 * @return Default path where WinDbg will be installed
 */
std::string GetDefaultInstallPath();

/* ============================================================================
 * Version Information
 * ============================================================================ */

/* Version information structure */
struct VersionInfo {
    std::string version;        /* Version string (e.g., "1.2404.24002.0"), empty if unknown */
    std::string displayName;    /* Display name (e.g., "WinDbg 1.2404.24002.0") */
    std::string installPath;    /* Path where this version is installed */
    bool isInstalled;           /* True if WinDbg is installed (even if version unknown) */

    VersionInfo() : isInstalled(false) {}
};

/*
 * Get version of installed WinDbg
 *
 * @param installPath Path to WinDbg installation (empty = use default)
 * @return Version info, or empty VersionInfo if not installed
 */
VersionInfo GetInstalledVersion(const std::string& installPath = "");

/* ============================================================================
 * Legacy API for backward compatibility with existing UI code
 * ============================================================================ */

/* Legacy progress callback type (from ui/install_windbg.h) */
using LegacyProgressCallback = std::function<void(const std::string& step, int progress)>;

/*
 * Install WinDbg/TTD (legacy API)
 *
 * This function maintains backward compatibility with the existing UI code.
 *
 * @param progressCallback Optional legacy progress callback
 * @return true if installation was successful, false otherwise
 */
bool InstallWinDbg(LegacyProgressCallback progressCallback = nullptr);

/*
 * Check installation (legacy API)
 *
 * @param path Path to check
 * @return true if all required files are present
 */
bool CheckInstallOk(const std::string& path);

} // namespace WinDbgInstaller

#endif // _WIN32
