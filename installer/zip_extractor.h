/*
 * MSIX package extraction (miniz-backed)
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
 * Extract the payload contents of the inner package (innerName, e.g.
 * "windbg_win-x64.msix") contained in an MSIX bundle directly into destDir.
 *
 * The inner package is read from memory - it is never written to a temporary
 * file - so the payload files go straight to destDir with no large intermediate
 * file to later delete. Backed by the vendored miniz library.
 *
 * @param bundlePath      Path to the .msixbundle
 * @param innerName       Name of the inner package inside the bundle to extract
 * @param destDir         Directory to extract payload files into
 * @param progressCallback Optional callback for progress updates
 * @param logCallback     Optional callback for log messages
 * @return true if extraction was successful, false otherwise
 */
bool ExtractInnerPackageToDir(
    const std::string& bundlePath,
    const std::string& innerName,
    const std::string& destDir,
    ExtractionProgressCallback progressCallback = nullptr,
    LogCallback logCallback = nullptr
);

} // namespace WinDbgInstaller

#endif // _WIN32
