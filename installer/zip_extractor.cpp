/*
 * MSIX package extraction using the Windows App Packaging API
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "zip_extractor.h"
#include "windbg_installer.h"
#include <windows.h>
#include <shlwapi.h>
#include <appxpackaging.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace WinDbgInstaller {

namespace {

void Log(LogCallback logCallback, int level, const std::string& message) {
    if (logCallback) {
        logCallback(level, message);
    }
}

template <typename T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { Reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : m_ptr(other.m_ptr) {
        other.m_ptr = nullptr;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            Reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    T* operator->() const { return m_ptr; }
    T* Get() const { return m_ptr; }

    T** Put() {
        Reset();
        return &m_ptr;
    }

private:
    void Reset() {
        if (m_ptr) {
            m_ptr->Release();
            m_ptr = nullptr;
        }
    }

    T* m_ptr = nullptr;
};

class ComInitialization {
public:
    ComInitialization() {
        m_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        m_shouldUninitialize = SUCCEEDED(m_result);
    }

    ~ComInitialization() {
        if (m_shouldUninitialize) {
            CoUninitialize();
        }
    }

    bool Available() const {
        return SUCCEEDED(m_result) || m_result == RPC_E_CHANGED_MODE;
    }

    HRESULT Result() const { return m_result; }

private:
    HRESULT m_result = E_FAIL;
    bool m_shouldUninitialize = false;
};

std::string FormatHResult(HRESULT result) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase
           << std::setw(8) << std::setfill('0')
           << static_cast<unsigned long>(result);
    return stream.str();
}

bool Utf8ToWide(const std::string& input, std::wstring& output) {
    if (input.empty()) {
        output.clear();
        return true;
    }

    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (length <= 0) {
        return false;
    }

    output.resize(static_cast<size_t>(length));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), output.data(), length) == length;
}

bool WideToUtf8(const std::wstring& input, std::string& output) {
    if (input.empty()) {
        output.clear();
        return true;
    }

    int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return false;
    }

    output.resize(static_cast<size_t>(length));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), output.data(), length,
        nullptr, nullptr) == length;
}

bool IsSafeRelativePath(const fs::path& path) {
    if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory()) {
        return false;
    }

    for (const auto& component : path) {
        if (component == L"." || component == L".." ||
            component.native().find(L':') != std::wstring::npos) {
            return false;
        }
    }
    return true;
}

bool WritePayloadFile(IAppxFile* file, const fs::path& destinationRoot,
    std::string& extractedName, LogCallback logCallback) {
    LPWSTR allocatedName = nullptr;
    HRESULT result = file->GetName(&allocatedName);
    if (FAILED(result) || !allocatedName) {
        Log(logCallback, LOG_ERROR, "Failed to read package payload name: " + FormatHResult(result));
        CoTaskMemFree(allocatedName);
        return false;
    }

    std::wstring wideName(allocatedName);
    CoTaskMemFree(allocatedName);

    fs::path relativePath(wideName);
    if (!IsSafeRelativePath(relativePath)) {
        Log(logCallback, LOG_ERROR, "Refusing unsafe package payload path");
        return false;
    }

    if (!WideToUtf8(wideName, extractedName)) {
        Log(logCallback, LOG_ERROR, "Package payload name is not valid Unicode");
        return false;
    }

    fs::path outputPath = destinationRoot / relativePath;
    std::error_code error;
    fs::create_directories(outputPath.parent_path(), error);
    if (error) {
        Log(logCallback, LOG_ERROR, "Failed to create directory for: " + extractedName);
        return false;
    }

    ComPtr<IStream> input;
    result = file->GetStream(input.Put());
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to open payload stream for " + extractedName +
            ": " + FormatHResult(result));
        return false;
    }

    std::ofstream output(outputPath, std::ios::binary | std::ios::trunc);
    if (!output) {
        Log(logCallback, LOG_ERROR, "Failed to create output file: " + extractedName);
        return false;
    }

    char buffer[64 * 1024];
    while (true) {
        ULONG bytesRead = 0;
        result = input->Read(buffer, static_cast<ULONG>(sizeof(buffer)), &bytesRead);
        if (FAILED(result)) {
            output.close();
            fs::remove(outputPath, error);
            Log(logCallback, LOG_ERROR, "Failed while reading payload " + extractedName +
                ": " + FormatHResult(result));
            return false;
        }
        if (bytesRead == 0) {
            break;
        }
        output.write(buffer, static_cast<std::streamsize>(bytesRead));
        if (!output) {
            output.close();
            fs::remove(outputPath, error);
            Log(logCallback, LOG_ERROR, "Failed while writing payload: " + extractedName);
            return false;
        }
    }

    output.close();
    if (!output) {
        fs::remove(outputPath, error);
        Log(logCallback, LOG_ERROR, "Failed to finish writing payload: " + extractedName);
        return false;
    }
    return true;
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

    std::wstring wideBundlePath;
    std::wstring wideInnerName;
    if (!Utf8ToWide(bundlePath, wideBundlePath) || !Utf8ToWide(innerName, wideInnerName)) {
        Log(logCallback, LOG_ERROR, "Bundle path or inner package name is not valid UTF-8");
        return false;
    }

    ComInitialization com;
    if (!com.Available()) {
        Log(logCallback, LOG_ERROR, "Failed to initialize COM: " + FormatHResult(com.Result()));
        return false;
    }

    ComPtr<IStream> bundleStream;
    HRESULT result = SHCreateStreamOnFileEx(
        wideBundlePath.c_str(), STGM_READ | STGM_SHARE_DENY_WRITE,
        FILE_ATTRIBUTE_NORMAL, FALSE, nullptr, bundleStream.Put());
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to open bundle: " + FormatHResult(result));
        return false;
    }

    ComPtr<IAppxBundleFactory> bundleFactory;
    result = CoCreateInstance(__uuidof(AppxBundleFactory), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IAppxBundleFactory), reinterpret_cast<void**>(bundleFactory.Put()));
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to create AppX bundle factory: " + FormatHResult(result));
        return false;
    }

    ComPtr<IAppxBundleReader> bundleReader;
    result = bundleFactory->CreateBundleReader(bundleStream.Get(), bundleReader.Put());
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to read MSIX bundle: " + FormatHResult(result));
        return false;
    }

    ComPtr<IAppxFile> innerPackage;
    result = bundleReader->GetPayloadPackage(wideInnerName.c_str(), innerPackage.Put());
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Inner package not found in bundle: " + innerName +
            " (" + FormatHResult(result) + ")");
        return false;
    }

    ComPtr<IStream> innerStream;
    result = innerPackage->GetStream(innerStream.Put());
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to open inner package stream: " + FormatHResult(result));
        return false;
    }

    ComPtr<IAppxFactory> packageFactory;
    result = CoCreateInstance(__uuidof(AppxFactory), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IAppxFactory), reinterpret_cast<void**>(packageFactory.Put()));
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to create AppX package factory: " + FormatHResult(result));
        return false;
    }

    ComPtr<IAppxPackageReader> packageReader;
    result = packageFactory->CreatePackageReader(innerStream.Get(), packageReader.Put());
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to read inner MSIX package: " + FormatHResult(result));
        return false;
    }

    ComPtr<IAppxFilesEnumerator> enumerator;
    result = packageReader->GetPayloadFiles(enumerator.Put());
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed to enumerate package payloads: " + FormatHResult(result));
        return false;
    }

    std::vector<ComPtr<IAppxFile>> payloads;
    BOOL hasCurrent = FALSE;
    result = enumerator->GetHasCurrent(&hasCurrent);
    while (SUCCEEDED(result) && hasCurrent) {
        ComPtr<IAppxFile> payload;
        result = enumerator->GetCurrent(payload.Put());
        if (FAILED(result)) {
            break;
        }
        payloads.push_back(std::move(payload));
        result = enumerator->MoveNext(&hasCurrent);
    }
    if (FAILED(result)) {
        Log(logCallback, LOG_ERROR, "Failed while enumerating package payloads: " + FormatHResult(result));
        return false;
    }

    fs::path destinationRoot(destDir);
    std::error_code error;
    fs::create_directories(destinationRoot, error);
    if (error) {
        Log(logCallback, LOG_ERROR, "Failed to create installation directory: " + destDir);
        return false;
    }

    int extracted = 0;
    for (auto& payload : payloads) {
        std::string name;
        if (!WritePayloadFile(payload.Get(), destinationRoot, name, logCallback)) {
            return false;
        }

        extracted++;
        if (progressCallback) {
            ExtractionProgress progress;
            progress.currentFile = name;
            progress.filesExtracted = extracted;
            progress.totalFiles = static_cast<int>(payloads.size());
            progressCallback(progress);
        }
        Log(logCallback, LOG_DEBUG, "Extracted: " + name);
    }

    Log(logCallback, LOG_INFO, "Successfully extracted " + std::to_string(extracted) +
        " files to " + destDir);
    return true;
}

} // namespace WinDbgInstaller

#endif // _WIN32
