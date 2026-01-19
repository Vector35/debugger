/*
 * ZIP Extractor using minizip-ng library
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#pragma once

#ifdef _WIN32

#include <string>
#include <functional>

namespace WinDbgInstaller {

/* Extraction progress information */
struct ExtractionProgress {
    std::string currentFile;    /* File currently being extracted */
    int filesExtracted;         /* Number of files extracted so far */
    int totalFiles;             /* Total number of files to extract */
};

/* Callback function type for extraction progress */
using ExtractionProgressCallback = std::function<void(const ExtractionProgress& progress)>;

/* Callback function type for logging */
using LogCallback = std::function<void(int level, const std::string& message)>;

/*
 * Extract all files from a ZIP archive
 *
 * @param zipPath Path to the ZIP file
 * @param extractPath Directory where to extract contents
 * @param progressCallback Optional callback for progress updates
 * @param logCallback Optional callback for log messages
 * @return true if extraction was successful, false otherwise
 */
bool ExtractZipArchive(
    const std::string& zipPath,
    const std::string& extractPath,
    ExtractionProgressCallback progressCallback = nullptr,
    LogCallback logCallback = nullptr
);

/*
 * Extract a single file from a ZIP archive
 *
 * @param zipPath Path to the ZIP file
 * @param fileName Name of file to extract (case-insensitive)
 * @param extractDir Directory where to extract the file
 * @param logCallback Optional callback for log messages
 * @return Path to extracted file, or empty string if extraction failed
 */
std::string ExtractFileFromZipArchive(
    const std::string& zipPath,
    const std::string& fileName,
    const std::string& extractDir,
    LogCallback logCallback = nullptr
);

} // namespace WinDbgInstaller

#endif // _WIN32
