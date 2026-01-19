/*
 * HTTP Downloader with progress callback using WinHTTP
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

/* Download progress information */
struct DownloadProgress {
    int64_t bytesDownloaded;  /* Bytes downloaded so far */
    int64_t totalBytes;       /* Total bytes to download, -1 if unknown */
    double bytesPerSecond;    /* Current download speed in bytes/second */
};

/* Callback function type for download progress */
using DownloadProgressCallback = std::function<void(const DownloadProgress& progress)>;

/* Callback function type for logging */
using LogCallback = std::function<void(int level, const std::string& message)>;

/*
 * Download a file from URL with progress callback
 *
 * @param url URL to download from (http:// or https://)
 * @param localPath Path where to save the downloaded file
 * @param progressCallback Optional callback for progress updates
 * @param logCallback Optional callback for log messages
 * @return true if download was successful, false otherwise
 */
bool DownloadFileWithProgress(
    const std::string& url,
    const std::string& localPath,
    DownloadProgressCallback progressCallback = nullptr,
    LogCallback logCallback = nullptr
);

} // namespace WinDbgInstaller

#endif // _WIN32
