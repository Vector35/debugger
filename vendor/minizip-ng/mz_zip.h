/*
 * Minimal ZIP library - ZIP file handling
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifndef MZ_ZIP_H
#define MZ_ZIP_H

#include "mz.h"
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace mz {

/* ZIP entry information */
struct ZipEntry {
    std::string filename;
    uint64_t compressedSize;
    uint64_t uncompressedSize;
    uint32_t crc32;
    uint16_t compressionMethod;
    uint64_t localHeaderOffset;
    bool isDirectory;
};

/* Progress callback for extraction */
using ExtractProgressCallback = std::function<void(const std::string& filename, int filesExtracted, int totalFiles)>;

/* ZIP reader class */
class ZipReader {
public:
    ZipReader();
    ~ZipReader();

    /* Open a ZIP file for reading */
    int Open(const std::string& path);

    /* Close the ZIP file */
    int Close();

    /* Get list of entries in the ZIP */
    const std::vector<ZipEntry>& GetEntries() const;

    /* Get number of entries */
    size_t GetEntryCount() const;

    /* Find entry by filename (case-insensitive) */
    const ZipEntry* FindEntry(const std::string& filename) const;

    /* Extract all files to a directory */
    int ExtractAll(const std::string& destPath, ExtractProgressCallback progressCallback = nullptr);

    /* Extract a single file to a directory */
    int ExtractFile(const std::string& filename, const std::string& destPath);

    /* Extract a single file to a specific output path */
    int ExtractFileTo(const std::string& filename, const std::string& outputPath);

private:
    int ReadCentralDirectory();
    int ReadLocalFileHeader(uint64_t offset, uint16_t& headerSize);
    int DecompressStore(const uint8_t* input, uint64_t inputSize, uint8_t* output, uint64_t outputSize);
    int DecompressDeflate(const uint8_t* input, uint64_t inputSize, uint8_t* output, uint64_t outputSize);

    void* m_file;
    std::string m_path;
    std::vector<ZipEntry> m_entries;
    bool m_isOpen;
};

} // namespace mz

#endif /* MZ_ZIP_H */
