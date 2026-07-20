/*
 * MSIX package extraction (miniz-backed)
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "zip_extractor.h"
#include "windbg_installer.h"  /* for LogLevel */
#include "../vendor/miniz/miniz.h"
#include <filesystem>
#include <cstring>

namespace fs = std::filesystem;

namespace WinDbgInstaller {

namespace {

void Log(LogCallback logCallback, int level, const std::string& message) {
    if (logCallback) {
        logCallback(level, message);
    }
}

/* Find the inner package to extract. Prefer an exact (case-insensitive) name match;
 * otherwise fall back to the first entry that looks like an x64 package. Returns the
 * entry index, or -1 if none was found. */
int LocateInnerPackage(mz_zip_archive& outer, const std::string& innerName, LogCallback logCallback) {
    int idx = mz_zip_reader_locate_file(&outer, innerName.c_str(), nullptr, 0);
    if (idx >= 0) {
        return idx;
    }

    /* Fallback: scan for a *.msix entry whose name contains "x64" */
    mz_uint count = mz_zip_reader_get_num_files(&outer);
    for (mz_uint i = 0; i < count; i++) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&outer, i, &st)) {
            continue;
        }
        std::string name = st.m_filename;
        std::string lower = name;
        for (auto& c : lower) c = (char)tolower((unsigned char)c);
        if (lower.find("x64") != std::string::npos &&
            lower.size() >= 5 && lower.compare(lower.size() - 5, 5, ".msix") == 0) {
            Log(logCallback, LOG_WARN, "Inner package '" + innerName +
                "' not found by name; falling back to '" + name + "'");
            return (int)i;
        }
    }
    return -1;
}

} // anonymous namespace

bool ExtractInnerPackageToDir(
    const std::string& bundlePath,
    const std::string& innerName,
    const std::string& destDir,
    ExtractionProgressCallback progressCallback,
    LogCallback logCallback)
{
    Log(logCallback, LOG_INFO, "Extracting '" + innerName + "' contents from " + bundlePath);

    /* Open the outer bundle */
    mz_zip_archive outer;
    memset(&outer, 0, sizeof(outer));
    if (!mz_zip_reader_init_file(&outer, bundlePath.c_str(), 0)) {
        Log(logCallback, LOG_ERROR, "Failed to open bundle archive: " + bundlePath);
        return false;
    }

    int innerIdx = LocateInnerPackage(outer, innerName, logCallback);
    if (innerIdx < 0) {
        Log(logCallback, LOG_ERROR, "Inner package not found in bundle: " + innerName);
        mz_zip_reader_end(&outer);
        return false;
    }

    /* Read the inner package into memory (no temporary file on disk) */
    size_t innerSize = 0;
    void* innerBuf = mz_zip_reader_extract_to_heap(&outer, (mz_uint)innerIdx, &innerSize, 0);
    mz_zip_reader_end(&outer);
    if (!innerBuf) {
        Log(logCallback, LOG_ERROR, "Failed to read inner package from bundle");
        return false;
    }

    /* Open the inner package straight from that memory buffer */
    mz_zip_archive inner;
    memset(&inner, 0, sizeof(inner));
    if (!mz_zip_reader_init_mem(&inner, innerBuf, innerSize, 0)) {
        Log(logCallback, LOG_ERROR, "Failed to open inner package");
        mz_free(innerBuf);
        return false;
    }

    std::error_code ec;
    fs::create_directories(fs::path(destDir), ec);

    mz_uint total = mz_zip_reader_get_num_files(&inner);
    bool ok = true;
    int extracted = 0;

    for (mz_uint i = 0; i < total; i++) {
        if (mz_zip_reader_is_file_a_directory(&inner, i)) {
            continue;
        }

        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&inner, i, &st)) {
            Log(logCallback, LOG_ERROR, "Failed to read file info in inner package");
            ok = false;
            break;
        }

        /* m_filename uses '/' separators; fs::path handles those on Windows */
        fs::path outPath = fs::path(destDir) / fs::path(st.m_filename);
        fs::create_directories(outPath.parent_path(), ec);

        if (!mz_zip_reader_extract_to_file(&inner, i, outPath.string().c_str(), 0)) {
            Log(logCallback, LOG_ERROR, "Failed to extract: " + std::string(st.m_filename));
            ok = false;
            break;
        }

        extracted++;
        if (progressCallback) {
            ExtractionProgress progress;
            progress.currentFile = st.m_filename;
            progress.filesExtracted = extracted;
            progress.totalFiles = (int)total;
            progressCallback(progress);
        }
        Log(logCallback, LOG_DEBUG, std::string("Extracted: ") + st.m_filename);
    }

    mz_zip_reader_end(&inner);
    mz_free(innerBuf);

    if (ok) {
        Log(logCallback, LOG_INFO, "Successfully extracted " + std::to_string(extracted) +
            " files to " + destDir);
    }
    return ok;
}

} // namespace WinDbgInstaller

#endif // _WIN32
