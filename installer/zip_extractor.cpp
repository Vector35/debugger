/*
 * ZIP Extractor using minizip-ng library
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "zip_extractor.h"
#include "../vendor/minizip-ng/mz_zip.h"
#include <filesystem>

namespace fs = std::filesystem;

namespace WinDbgInstaller {

namespace {

/* Log levels */
enum LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

void Log(LogCallback logCallback, int level, const std::string& message) {
    if (logCallback) {
        logCallback(level, message);
    }
}

} // anonymous namespace

bool ExtractZipArchive(
    const std::string& zipPath,
    const std::string& extractPath,
    ExtractionProgressCallback progressCallback,
    LogCallback logCallback)
{
    Log(logCallback, LOG_INFO, "Extracting " + zipPath + " to " + extractPath);

    mz::ZipReader reader;
    int result = reader.Open(zipPath);
    if (result != MZ_OK) {
        Log(logCallback, LOG_ERROR, "Failed to open ZIP file: " + zipPath + " (error: " + std::to_string(result) + ")");
        return false;
    }

    /* Create destination directory */
    std::error_code ec;
    fs::create_directories(extractPath, ec);
    if (ec) {
        Log(logCallback, LOG_ERROR, "Failed to create extract directory: " + extractPath);
        reader.Close();
        return false;
    }

    /* Wrapper callback to convert from mz:: format to our format */
    auto mzProgressCallback = [&](const std::string& filename, int filesExtracted, int totalFiles) {
        if (progressCallback) {
            ExtractionProgress progress;
            progress.currentFile = filename;
            progress.filesExtracted = filesExtracted;
            progress.totalFiles = totalFiles;
            progressCallback(progress);
        }
        if (!filename.empty()) {
            Log(logCallback, LOG_DEBUG, "Extracting: " + filename);
        }
    };

    result = reader.ExtractAll(extractPath, mzProgressCallback);
    reader.Close();

    if (result != MZ_OK) {
        Log(logCallback, LOG_ERROR, "Failed to extract ZIP file (error: " + std::to_string(result) + ")");
        return false;
    }

    Log(logCallback, LOG_INFO, "Successfully extracted " + std::to_string(reader.GetEntryCount()) + " entries");
    return true;
}

std::string ExtractFileFromZipArchive(
    const std::string& zipPath,
    const std::string& fileName,
    const std::string& extractDir,
    LogCallback logCallback)
{
    Log(logCallback, LOG_INFO, "Extracting " + fileName + " from " + zipPath);

    mz::ZipReader reader;
    int result = reader.Open(zipPath);
    if (result != MZ_OK) {
        Log(logCallback, LOG_ERROR, "Failed to open ZIP file: " + zipPath + " (error: " + std::to_string(result) + ")");
        return "";
    }

    /* Find the entry */
    const mz::ZipEntry* entry = reader.FindEntry(fileName);
    if (!entry) {
        Log(logCallback, LOG_ERROR, "File not found in ZIP: " + fileName);

        /* List available files for debugging */
        Log(logCallback, LOG_DEBUG, "Available files in ZIP:");
        for (const auto& e : reader.GetEntries()) {
            Log(logCallback, LOG_DEBUG, "  " + e.filename);
        }

        reader.Close();
        return "";
    }

    /* Create destination directory */
    std::error_code ec;
    fs::create_directories(extractDir, ec);
    if (ec) {
        Log(logCallback, LOG_ERROR, "Failed to create extract directory: " + extractDir);
        reader.Close();
        return "";
    }

    /* Build output path using the entry's actual filename */
    fs::path outputPath = fs::path(extractDir) / entry->filename;

    /* Extract the file */
    result = reader.ExtractFileTo(entry->filename, outputPath.string());
    reader.Close();

    if (result != MZ_OK) {
        Log(logCallback, LOG_ERROR, "Failed to extract file (error: " + std::to_string(result) + ")");
        return "";
    }

    /* Verify the file exists */
    if (!fs::exists(outputPath)) {
        Log(logCallback, LOG_ERROR, "Extracted file does not exist: " + outputPath.string());
        return "";
    }

    Log(logCallback, LOG_INFO, "Successfully extracted to: " + outputPath.string());
    return outputPath.string();
}

} // namespace WinDbgInstaller

#endif // _WIN32
