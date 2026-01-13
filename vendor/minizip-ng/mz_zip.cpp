/*
 * Minimal ZIP library - ZIP file handling implementation
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#include "mz_zip.h"
#include "mz_inflate.h"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace mz {

namespace {

#pragma pack(push, 1)
struct LocalFileHeader {
    uint32_t signature;
    uint16_t versionNeeded;
    uint16_t flags;
    uint16_t compressionMethod;
    uint16_t lastModTime;
    uint16_t lastModDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t filenameLength;
    uint16_t extraFieldLength;
};

struct CentralDirHeader {
    uint32_t signature;
    uint16_t versionMade;
    uint16_t versionNeeded;
    uint16_t flags;
    uint16_t compressionMethod;
    uint16_t lastModTime;
    uint16_t lastModDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t filenameLength;
    uint16_t extraFieldLength;
    uint16_t commentLength;
    uint16_t diskStart;
    uint16_t internalAttr;
    uint32_t externalAttr;
    uint32_t localHeaderOffset;
};

struct EndOfCentralDir {
    uint32_t signature;
    uint16_t diskNumber;
    uint16_t diskWithCentralDir;
    uint16_t entriesOnDisk;
    uint16_t totalEntries;
    uint32_t centralDirSize;
    uint32_t centralDirOffset;
    uint16_t commentLength;
};

struct Zip64EndOfCentralDir {
    uint32_t signature;
    uint64_t recordSize;
    uint16_t versionMade;
    uint16_t versionNeeded;
    uint32_t diskNumber;
    uint32_t diskWithCentralDir;
    uint64_t entriesOnDisk;
    uint64_t totalEntries;
    uint64_t centralDirSize;
    uint64_t centralDirOffset;
};

struct Zip64Locator {
    uint32_t signature;
    uint32_t diskWithZip64End;
    uint64_t zip64EndOffset;
    uint32_t totalDisks;
};
#pragma pack(pop)

bool CaseInsensitiveCompare(const std::string& a, const std::string& b) {
#ifdef _WIN32
    return _stricmp(a.c_str(), b.c_str()) == 0;
#else
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (tolower(a[i]) != tolower(b[i])) return false;
    }
    return true;
#endif
}

} // anonymous namespace

ZipReader::ZipReader()
    : m_file(nullptr), m_isOpen(false) {
}

ZipReader::~ZipReader() {
    Close();
}

int ZipReader::Open(const std::string& path) {
    if (m_isOpen) {
        Close();
    }

    FILE* fp = nullptr;
#ifdef _WIN32
    fopen_s(&fp, path.c_str(), "rb");
#else
    fp = fopen(path.c_str(), "rb");
#endif

    if (!fp) {
        return MZ_OPEN_ERROR;
    }

    m_file = fp;
    m_path = path;
    m_isOpen = true;

    int result = ReadCentralDirectory();
    if (result != MZ_OK) {
        Close();
        return result;
    }

    return MZ_OK;
}

int ZipReader::Close() {
    if (m_file) {
        fclose((FILE*)m_file);
        m_file = nullptr;
    }
    m_entries.clear();
    m_path.clear();
    m_isOpen = false;
    return MZ_OK;
}

const std::vector<ZipEntry>& ZipReader::GetEntries() const {
    return m_entries;
}

size_t ZipReader::GetEntryCount() const {
    return m_entries.size();
}

const ZipEntry* ZipReader::FindEntry(const std::string& filename) const {
    for (const auto& entry : m_entries) {
        if (CaseInsensitiveCompare(entry.filename, filename)) {
            return &entry;
        }
        /* Also try without extension for Windows "hide extensions" compatibility */
        size_t dotPos = filename.rfind('.');
        if (dotPos != std::string::npos) {
            std::string nameWithoutExt = filename.substr(0, dotPos);
            if (CaseInsensitiveCompare(entry.filename, nameWithoutExt)) {
                return &entry;
            }
        }
    }
    return nullptr;
}

int ZipReader::ReadCentralDirectory() {
    FILE* fp = (FILE*)m_file;

    /* Find end of central directory */
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);

    if (fileSize < (long)sizeof(EndOfCentralDir)) {
        return MZ_DATA_ERROR;
    }

    /* Search for EOCD signature from end of file */
    int searchLen = (int)std::min((long)65535 + 22, fileSize);
    std::vector<uint8_t> buffer(searchLen);

    fseek(fp, fileSize - searchLen, SEEK_SET);
    if (fread(buffer.data(), 1, searchLen, fp) != (size_t)searchLen) {
        return MZ_DATA_ERROR;
    }

    int eocdOffset = -1;
    for (int i = searchLen - (int)sizeof(EndOfCentralDir); i >= 0; i--) {
        if (*(uint32_t*)(buffer.data() + i) == MZ_ZIP_SIGNATURE_ENDOFCENTRALDIR) {
            eocdOffset = fileSize - searchLen + i;
            break;
        }
    }

    if (eocdOffset < 0) {
        return MZ_DATA_ERROR;
    }

    /* Read EOCD */
    fseek(fp, eocdOffset, SEEK_SET);
    EndOfCentralDir eocd;
    if (fread(&eocd, sizeof(eocd), 1, fp) != 1) {
        return MZ_DATA_ERROR;
    }

    uint64_t centralDirOffset = eocd.centralDirOffset;
    uint64_t totalEntries = eocd.totalEntries;

    /* Check for ZIP64 */
    if (eocd.centralDirOffset == 0xFFFFFFFF || eocd.totalEntries == 0xFFFF) {
        /* Look for ZIP64 locator */
        if (eocdOffset >= (int)sizeof(Zip64Locator)) {
            fseek(fp, eocdOffset - sizeof(Zip64Locator), SEEK_SET);
            Zip64Locator locator;
            if (fread(&locator, sizeof(locator), 1, fp) == 1 &&
                locator.signature == 0x07064b50) {
                /* Read ZIP64 EOCD */
                fseek(fp, (long)locator.zip64EndOffset, SEEK_SET);
                Zip64EndOfCentralDir zip64Eocd;
                if (fread(&zip64Eocd, sizeof(zip64Eocd), 1, fp) == 1 &&
                    zip64Eocd.signature == 0x06064b50) {
                    centralDirOffset = zip64Eocd.centralDirOffset;
                    totalEntries = zip64Eocd.totalEntries;
                }
            }
        }
    }

    /* Read central directory entries */
    fseek(fp, (long)centralDirOffset, SEEK_SET);
    m_entries.reserve((size_t)totalEntries);

    for (uint64_t i = 0; i < totalEntries; i++) {
        CentralDirHeader header;
        if (fread(&header, sizeof(header), 1, fp) != 1) {
            return MZ_DATA_ERROR;
        }

        if (header.signature != MZ_ZIP_SIGNATURE_CENTRALDIR) {
            return MZ_DATA_ERROR;
        }

        /* Read filename */
        std::string filename(header.filenameLength, '\0');
        if (fread(&filename[0], 1, header.filenameLength, fp) != header.filenameLength) {
            return MZ_DATA_ERROR;
        }

        /* Skip extra field and comment */
        fseek(fp, header.extraFieldLength + header.commentLength, SEEK_CUR);

        /* Handle ZIP64 extended info if needed */
        uint64_t uncompressedSize = header.uncompressedSize;
        uint64_t compressedSize = header.compressedSize;
        uint64_t localHeaderOffset = header.localHeaderOffset;

        if (header.uncompressedSize == 0xFFFFFFFF ||
            header.compressedSize == 0xFFFFFFFF ||
            header.localHeaderOffset == 0xFFFFFFFF) {
            /* Need to read ZIP64 extra field - for now use 32-bit values */
            /* TODO: Properly parse ZIP64 extra field */
        }

        ZipEntry entry;
        entry.filename = filename;
        entry.compressedSize = compressedSize;
        entry.uncompressedSize = uncompressedSize;
        entry.crc32 = header.crc32;
        entry.compressionMethod = header.compressionMethod;
        entry.localHeaderOffset = localHeaderOffset;
        entry.isDirectory = !filename.empty() && (filename.back() == '/' || filename.back() == '\\');

        m_entries.push_back(entry);
    }

    return MZ_OK;
}

int ZipReader::ReadLocalFileHeader(uint64_t offset, uint16_t& headerSize) {
    FILE* fp = (FILE*)m_file;

    fseek(fp, (long)offset, SEEK_SET);
    LocalFileHeader header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        return MZ_DATA_ERROR;
    }

    if (header.signature != MZ_ZIP_SIGNATURE_LOCALHEADER) {
        return MZ_DATA_ERROR;
    }

    headerSize = sizeof(LocalFileHeader) + header.filenameLength + header.extraFieldLength;
    return MZ_OK;
}

int ZipReader::DecompressStore(const uint8_t* input, uint64_t inputSize,
                               uint8_t* output, uint64_t outputSize) {
    if (inputSize != outputSize) {
        return MZ_DATA_ERROR;
    }
    memcpy(output, input, (size_t)inputSize);
    return MZ_OK;
}

int ZipReader::DecompressDeflate(const uint8_t* input, uint64_t inputSize,
                                 uint8_t* output, uint64_t outputSize) {
    size_t bytesWritten = 0;
    int result = Inflate(input, (size_t)inputSize, output, (size_t)outputSize, &bytesWritten);
    if (result != MZ_OK) {
        return result;
    }
    if (bytesWritten != outputSize) {
        return MZ_DATA_ERROR;
    }
    return MZ_OK;
}

int ZipReader::ExtractAll(const std::string& destPath, ExtractProgressCallback progressCallback) {
    if (!m_isOpen) {
        return MZ_OPEN_ERROR;
    }

    /* Create destination directory */
    std::error_code ec;
    fs::create_directories(destPath, ec);
    if (ec) {
        return MZ_OPEN_ERROR;
    }

    int totalFiles = (int)m_entries.size();
    int filesExtracted = 0;

    for (const auto& entry : m_entries) {
        if (progressCallback) {
            progressCallback(entry.filename, filesExtracted, totalFiles);
        }

        if (entry.isDirectory) {
            /* Create directory */
            fs::path dirPath = fs::path(destPath) / entry.filename;
            fs::create_directories(dirPath, ec);
        } else {
            /* Extract file */
            fs::path filePath = fs::path(destPath) / entry.filename;

            /* Create parent directories */
            fs::create_directories(filePath.parent_path(), ec);

            int result = ExtractFileTo(entry.filename, filePath.string());
            if (result != MZ_OK) {
                return result;
            }
        }

        filesExtracted++;
    }

    if (progressCallback) {
        progressCallback("", filesExtracted, totalFiles);
    }

    return MZ_OK;
}

int ZipReader::ExtractFile(const std::string& filename, const std::string& destPath) {
    const ZipEntry* entry = FindEntry(filename);
    if (!entry) {
        return MZ_EXIST_ERROR;
    }

    fs::path outputPath = fs::path(destPath) / entry->filename;

    /* Create parent directories */
    std::error_code ec;
    fs::create_directories(outputPath.parent_path(), ec);

    return ExtractFileTo(filename, outputPath.string());
}

int ZipReader::ExtractFileTo(const std::string& filename, const std::string& outputPath) {
    if (!m_isOpen) {
        return MZ_OPEN_ERROR;
    }

    const ZipEntry* entry = FindEntry(filename);
    if (!entry) {
        return MZ_EXIST_ERROR;
    }

    if (entry->isDirectory) {
        /* Just create the directory */
        std::error_code ec;
        fs::create_directories(outputPath, ec);
        return MZ_OK;
    }

    FILE* fp = (FILE*)m_file;

    /* Read local file header to get actual data offset */
    uint16_t headerSize = 0;
    int result = ReadLocalFileHeader(entry->localHeaderOffset, headerSize);
    if (result != MZ_OK) {
        return result;
    }

    /* Seek to compressed data */
    uint64_t dataOffset = entry->localHeaderOffset + headerSize;
    fseek(fp, (long)dataOffset, SEEK_SET);

    /* Read compressed data */
    std::vector<uint8_t> compressedData((size_t)entry->compressedSize);
    if (entry->compressedSize > 0) {
        if (fread(compressedData.data(), 1, (size_t)entry->compressedSize, fp) != (size_t)entry->compressedSize) {
            return MZ_DATA_ERROR;
        }
    }

    /* Decompress */
    std::vector<uint8_t> uncompressedData((size_t)entry->uncompressedSize);
    if (entry->uncompressedSize > 0) {
        if (entry->compressionMethod == MZ_COMPRESS_METHOD_STORE) {
            result = DecompressStore(compressedData.data(), entry->compressedSize,
                                     uncompressedData.data(), entry->uncompressedSize);
        } else if (entry->compressionMethod == MZ_COMPRESS_METHOD_DEFLATE) {
            result = DecompressDeflate(compressedData.data(), entry->compressedSize,
                                       uncompressedData.data(), entry->uncompressedSize);
        } else {
            return MZ_DATA_ERROR; /* Unsupported compression method */
        }

        if (result != MZ_OK) {
            return result;
        }
    }

    /* Write to output file */
    FILE* outFp = nullptr;
#ifdef _WIN32
    fopen_s(&outFp, outputPath.c_str(), "wb");
#else
    outFp = fopen(outputPath.c_str(), "wb");
#endif

    if (!outFp) {
        return MZ_OPEN_ERROR;
    }

    if (entry->uncompressedSize > 0) {
        if (fwrite(uncompressedData.data(), 1, (size_t)entry->uncompressedSize, outFp) != (size_t)entry->uncompressedSize) {
            fclose(outFp);
            return MZ_DATA_ERROR;
        }
    }

    fclose(outFp);
    return MZ_OK;
}

} // namespace mz
