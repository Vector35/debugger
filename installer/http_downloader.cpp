/*
 * HTTP Downloader with progress callback using WinHTTP
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "http_downloader.h"
#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <chrono>

#pragma comment(lib, "winhttp.lib")

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

/* Parse URL into components */
struct UrlComponents {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port;
    bool isHttps;
};

bool ParseUrl(const std::string& url, UrlComponents& components) {
    /* Convert to wide string */
    std::wstring wUrl(url.begin(), url.end());

    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);

    wchar_t hostName[256] = {0};
    wchar_t urlPath[2048] = {0};

    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName) / sizeof(wchar_t);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(wchar_t);

    if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
        return false;
    }

    components.host = hostName;
    components.path = urlPath;
    components.port = urlComp.nPort;
    components.isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    return true;
}

/* Convert wide string to narrow string */
std::string WideToNarrow(const std::wstring& wide) {
    if (wide.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.length(), nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.length(), &result[0], size, nullptr, nullptr);
    return result;
}

} // anonymous namespace

bool DownloadFileWithProgress(
    const std::string& url,
    const std::string& localPath,
    DownloadProgressCallback progressCallback,
    LogCallback logCallback)
{
    Log(logCallback, LOG_INFO, "Downloading from: " + url);

    UrlComponents urlComp;
    if (!ParseUrl(url, urlComp)) {
        Log(logCallback, LOG_ERROR, "Failed to parse URL: " + url);
        return false;
    }

    /* Open WinHTTP session */
    HINTERNET hSession = WinHttpOpen(
        L"BinaryNinja-Debugger/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) {
        Log(logCallback, LOG_ERROR, "WinHttpOpen failed: " + std::to_string(GetLastError()));
        return false;
    }

    /* Connect to server */
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        urlComp.host.c_str(),
        urlComp.port,
        0);

    if (!hConnect) {
        Log(logCallback, LOG_ERROR, "WinHttpConnect failed: " + std::to_string(GetLastError()));
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Create request */
    DWORD flags = urlComp.isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        urlComp.path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!hRequest) {
        Log(logCallback, LOG_ERROR, "WinHttpOpenRequest failed: " + std::to_string(GetLastError()));
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Send request */
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        Log(logCallback, LOG_ERROR, "WinHttpSendRequest failed: " + std::to_string(GetLastError()));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Receive response */
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        Log(logCallback, LOG_ERROR, "WinHttpReceiveResponse failed: " + std::to_string(GetLastError()));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Check for redirect */
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusCodeSize,
        WINHTTP_NO_HEADER_INDEX);

    if (statusCode >= 300 && statusCode < 400) {
        /* Handle redirect - get Location header */
        wchar_t redirectUrl[2048] = {0};
        DWORD redirectUrlSize = sizeof(redirectUrl);
        if (WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_LOCATION,
            WINHTTP_HEADER_NAME_BY_INDEX,
            redirectUrl,
            &redirectUrlSize,
            WINHTTP_NO_HEADER_INDEX)) {

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            std::string newUrl = WideToNarrow(redirectUrl);
            Log(logCallback, LOG_INFO, "Redirecting to: " + newUrl);
            return DownloadFileWithProgress(newUrl, localPath, progressCallback, logCallback);
        }
    }

    if (statusCode != 200) {
        Log(logCallback, LOG_ERROR, "HTTP error: " + std::to_string(statusCode));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Get content length */
    int64_t contentLength = -1;
    wchar_t contentLengthStr[32] = {0};
    DWORD contentLengthStrSize = sizeof(contentLengthStr);
    if (WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH,
        WINHTTP_HEADER_NAME_BY_INDEX,
        contentLengthStr,
        &contentLengthStrSize,
        WINHTTP_NO_HEADER_INDEX)) {
        contentLength = _wtoi64(contentLengthStr);
    }

    if (contentLength > 0) {
        Log(logCallback, LOG_INFO, "Content length: " + std::to_string(contentLength) + " bytes");
    }

    /* Open output file */
    std::ofstream outFile(localPath, std::ios::binary);
    if (!outFile) {
        Log(logCallback, LOG_ERROR, "Failed to create output file: " + localPath);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    /* Read data with progress */
    std::vector<char> buffer(8192);
    DWORD bytesRead = 0;
    int64_t totalRead = 0;

    /* Speed calculation */
    auto startTime = std::chrono::steady_clock::now();
    auto lastSpeedUpdate = startTime;
    int64_t bytesAtLastUpdate = 0;
    double currentSpeed = 0.0;

    while (true) {
        if (!WinHttpReadData(hRequest, buffer.data(), (DWORD)buffer.size(), &bytesRead)) {
            Log(logCallback, LOG_ERROR, "WinHttpReadData failed: " + std::to_string(GetLastError()));
            outFile.close();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        if (bytesRead == 0) {
            break; /* End of data */
        }

        outFile.write(buffer.data(), bytesRead);
        totalRead += bytesRead;

        if (progressCallback) {
            /* Update speed calculation every 500ms for smoother display */
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastSpeedUpdate).count();
            if (elapsed >= 500) {
                int64_t bytesDelta = totalRead - bytesAtLastUpdate;
                currentSpeed = (bytesDelta * 1000.0) / elapsed;
                bytesAtLastUpdate = totalRead;
                lastSpeedUpdate = now;
            }

            DownloadProgress progress;
            progress.bytesDownloaded = totalRead;
            progress.totalBytes = contentLength;
            progress.bytesPerSecond = currentSpeed;
            progressCallback(progress);
        }
    }

    outFile.close();

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    Log(logCallback, LOG_INFO, "Downloaded " + std::to_string(totalRead) + " bytes to: " + localPath);

    return true;
}

} // namespace WinDbgInstaller

#endif // _WIN32
