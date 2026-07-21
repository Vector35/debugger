/*
 * WinDbg/TTD Installer CLI
 *
 * A command-line utility for installing and updating WinDbg/TTD.
 * Can be invoked directly by users or spawned by Binary Ninja API.
 *
 * Usage:
 *   windbg-installer install [--path <dir>] [--quiet] [--json]
 *   windbg-installer check-update [--path <dir>] [--json]
 *   windbg-installer version [--path <dir>] [--json]
 *   windbg-installer --help
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "windbg_installer.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>

using namespace WinDbgInstaller;

namespace {

/* Output mode */
enum class OutputMode {
    Human,  /* Human-readable with progress bar */
    Quiet,  /* Minimal output */
    Json    /* Machine-readable JSON */
};

/* Console colors */
enum ConsoleColor {
    COLOR_DEFAULT = 7,
    COLOR_GREEN = 10,
    COLOR_YELLOW = 14,
    COLOR_RED = 12,
    COLOR_CYAN = 11
};

void SetConsoleColor(ConsoleColor color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void ResetConsoleColor() {
    SetConsoleColor(COLOR_DEFAULT);
}

/* Find all processes with a given name */
std::vector<DWORD> FindProcessesByName(const std::string& processName) {
    std::vector<DWORD> pids;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName.c_str()) == 0) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pids;
}

/* Wait for all instances of a process to exit */
bool WaitForProcessesToExit(const std::string& processName, OutputMode mode) {
    auto pids = FindProcessesByName(processName);
    if (pids.empty()) {
        return true;
    }

    if (mode == OutputMode::Human) {
        SetConsoleColor(COLOR_YELLOW);
        std::cout << "  Waiting for " << processName << " to exit...\n";
        ResetConsoleColor();
        std::cout << "  Found " << pids.size() << " instance(s) running.\n";
    } else if (mode == OutputMode::Json) {
        std::cout << "{\"type\":\"status\",\"message\":\"Waiting for " << processName << " to exit\",\"count\":" << pids.size() << "}" << std::endl;
    }

    /* Open handles to all processes */
    std::vector<HANDLE> handles;
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pid);
        if (hProcess != nullptr) {
            handles.push_back(hProcess);
        }
    }

    if (handles.empty()) {
        return true;
    }

    /* Wait for all processes to exit (timeout: 5 minutes) */
    DWORD result = WaitForMultipleObjects((DWORD)handles.size(), handles.data(), TRUE, 300000);

    /* Close all handles */
    for (HANDLE h : handles) {
        CloseHandle(h);
    }

    if (result == WAIT_TIMEOUT) {
        if (mode == OutputMode::Human) {
            SetConsoleColor(COLOR_RED);
            std::cout << "  Timeout waiting for " << processName << " to exit.\n";
            ResetConsoleColor();
        }
        return false;
    }

    if (mode == OutputMode::Human) {
        SetConsoleColor(COLOR_GREEN);
        std::cout << "  " << processName << " has exited.\n\n";
        ResetConsoleColor();
    }

    return true;
}

/* Format seconds as human-readable time (e.g., "1m 23s" or "45s") */
std::string FormatETA(int64_t seconds) {
    if (seconds < 0) return "";
    if (seconds < 60) {
        return std::to_string(seconds) + "s";
    } else if (seconds < 3600) {
        int mins = (int)(seconds / 60);
        int secs = (int)(seconds % 60);
        return std::to_string(mins) + "m " + std::to_string(secs) + "s";
    } else {
        int hours = (int)(seconds / 3600);
        int mins = (int)((seconds % 3600) / 60);
        return std::to_string(hours) + "h " + std::to_string(mins) + "m";
    }
}

/* Print a progress bar (human mode) */
void PrintProgressBar(int percent, int64_t downloaded = -1, int64_t total = -1, double bytesPerSecond = 0.0) {
    const int barWidth = 40;
    int pos = barWidth * percent / 100;

    std::cout << "\r  [";
    SetConsoleColor(COLOR_GREEN);
    for (int i = 0; i < barWidth; i++) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    ResetConsoleColor();
    std::cout << "] " << std::setw(3) << percent << "%";

    if (downloaded >= 0 && total > 0) {
        double downloadedMB = downloaded / (1024.0 * 1024.0);
        double totalMB = total / (1024.0 * 1024.0);
        std::cout << " (" << std::fixed << std::setprecision(1)
                  << downloadedMB << "/" << totalMB << " MB";
        if (bytesPerSecond > 0) {
            double speedMBps = bytesPerSecond / (1024.0 * 1024.0);
            std::cout << ", " << std::setprecision(1) << speedMBps << " MB/s";
            /* Calculate and show ETA */
            int64_t remaining = total - downloaded;
            int64_t etaSeconds = (int64_t)(remaining / bytesPerSecond);
            std::cout << ", ETA " << FormatETA(etaSeconds);
        }
        std::cout << ")";
    } else if (downloaded >= 0) {
        double downloadedMB = downloaded / (1024.0 * 1024.0);
        std::cout << " (" << std::fixed << std::setprecision(1)
                  << downloadedMB << " MB";
        if (bytesPerSecond > 0) {
            double speedMBps = bytesPerSecond / (1024.0 * 1024.0);
            std::cout << ", " << std::setprecision(1) << speedMBps << " MB/s";
        }
        std::cout << ")";
    }

    std::cout << "        " << std::flush;
}

/* Print JSON progress (json mode) */
void PrintJsonProgress(const std::string& step, int percent, int64_t downloaded = -1, int64_t total = -1, double bytesPerSecond = 0.0) {
    std::cout << "{\"type\":\"progress\",\"step\":\"" << step
              << "\",\"percent\":" << percent;
    if (downloaded >= 0) {
        std::cout << ",\"bytesDownloaded\":" << downloaded;
    }
    if (total >= 0) {
        std::cout << ",\"totalBytes\":" << total;
    }
    if (bytesPerSecond > 0) {
        std::cout << ",\"bytesPerSecond\":" << std::fixed << std::setprecision(1) << bytesPerSecond;
    }
    std::cout << "}" << std::endl;
}

/* Print JSON result */
void PrintJsonResult(bool success, const std::string& message, const std::string& extra = "") {
    std::cout << "{\"type\":\"result\",\"success\":" << (success ? "true" : "false")
              << ",\"message\":\"" << message << "\"";
    if (!extra.empty()) {
        std::cout << "," << extra;
    }
    std::cout << "}" << std::endl;
}

/* Print JSON version info */
void PrintJsonVersion(const std::string& installed, const std::string& latest, bool updateAvailable) {
    std::cout << "{\"type\":\"version\",\"installed\":\"" << installed
              << "\",\"latest\":\"" << latest
              << "\",\"updateAvailable\":" << (updateAvailable ? "true" : "false")
              << "}" << std::endl;
}

void PrintUsage(const char* programName) {
    std::cout << "WinDbg/TTD Installer for Binary Ninja Debugger\n"
              << "\n"
              << "Usage:\n"
              << "  " << programName << " <command> [options]\n"
              << "\n"
              << "Commands:\n"
              << "  install       Install or update WinDbg/TTD\n"
              << "  version       Show installed version (local only, no network)\n"
              << "  check-update  Check for updates (compares local vs latest online)\n"
              << "\n"
              << "Options:\n"
              << "  --path <dir>     Specify installation directory\n"
              << "                   (default: %APPDATA%\\Binary Ninja\\windbg)\n"
              << "  --bundle <file>  Install from an already-downloaded .msixbundle instead\n"
              << "                   of downloading it (for testing; the file is kept)\n"
              << "  --update         Update mode: wait for Binary Ninja to exit first\n"
              << "                   (use this when WinDbg DLLs may be loaded)\n"
              << "  --quiet          Suppress progress output (exit code only)\n"
              << "  --json           Output in JSON format (for API integration)\n"
              << "  --verbose, -v    Show info-level logs, including timing measurements\n"
              << "  --help           Show this help message\n"
              << "\n"
              << "Examples:\n"
              << "  " << programName << " version\n"
              << "  " << programName << " check-update\n"
              << "  " << programName << " install\n"
              << "  " << programName << " install --update\n"
              << "  " << programName << " install --path C:\\Tools\\WinDbg\n"
              << "\n"
              << "Exit codes:\n"
              << "  0  Success / up to date\n"
              << "  1  Not installed / error\n"
              << "  2  Update available (for check-update)\n"
              << "\n";
}

void PrintBanner() {
    SetConsoleColor(COLOR_CYAN);
    std::cout << "\n";
    std::cout << "  ============================================\n";
    std::cout << "   Binary Ninja Debugger - WinDbg/TTD Installer\n";
    std::cout << "  ============================================\n";
    ResetConsoleColor();
    std::cout << "\n";
}

/* Command: install */
int CmdInstall(const std::string& installPath, OutputMode mode, bool isUpdate,
               const std::string& bundlePath, bool verbose) {
    /* Determine and print install path */
    std::string targetPath = installPath.empty() ? GetDefaultInstallPath() : installPath;

    if (mode == OutputMode::Human) {
        std::cout << "  Install path: " << targetPath << "\n\n";
    } else if (mode == OutputMode::Json) {
        std::cout << "{\"type\":\"info\",\"installPath\":\"" << targetPath << "\"}" << std::endl;
    }

    /* Only wait for Binary Ninja to exit when updating */
    /* Fresh installs don't need to wait since DLLs aren't loaded yet */
    if (isUpdate) {
        if (mode == OutputMode::Human) {
            std::cout << "  Update mode: checking for running Binary Ninja instances...\n";
        }
        if (!WaitForProcessesToExit("binaryninja.exe", mode)) {
            if (mode == OutputMode::Json) {
                std::cout << "{\"type\":\"error\",\"message\":\"Timeout waiting for Binary Ninja to exit\"}" << std::endl;
            }
            return 1;
        }
    }

    InstallConfig config;
    config.installPath = targetPath;
    config.updateSettings = true;
    config.localBundlePath = bundlePath;

    if (!bundlePath.empty()) {
        if (mode == OutputMode::Human) {
            std::cout << "  Using local bundle (skipping download): " << bundlePath << "\n\n";
        } else if (mode == OutputMode::Json) {
            std::cout << "{\"type\":\"info\",\"localBundle\":\"" << bundlePath << "\"}" << std::endl;
        }
    }

    std::string lastStep;

    /* Setup callbacks based on output mode */
    if (mode == OutputMode::Human) {
        config.onProgress = [&lastStep](const ProgressInfo& info) {
            if (info.step != lastStep) {
                if (!lastStep.empty()) {
                    std::cout << "\n";
                }
                SetConsoleColor(COLOR_CYAN);
                std::cout << "  " << info.step;
                ResetConsoleColor();
                /* Only print newline for non-download steps */
                if (info.totalBytes <= 0) {
                    std::cout << "\n";
                }
                lastStep = info.step;
            }
            /* Only show progress bar for the TTD download (when we have byte info) */
            if (info.totalBytes > 0) {
                PrintProgressBar(info.overallPercent, info.bytesDownloaded, info.totalBytes, info.bytesPerSecond);
            }
        };

        int logThreshold = verbose ? LOG_INFO : LOG_WARN;
        config.onLog = [logThreshold](int level, const std::string& message) {
            if (level >= logThreshold) {
                ConsoleColor color = COLOR_DEFAULT;
                if (level == LOG_ERROR) color = COLOR_RED;
                else if (level == LOG_WARN) color = COLOR_YELLOW;
                SetConsoleColor(color);
                std::cout << "\n  " << message;
                ResetConsoleColor();
            }
        };
    } else if (mode == OutputMode::Json) {
        config.onProgress = [](const ProgressInfo& info) {
            PrintJsonProgress(info.step, info.overallPercent, info.bytesDownloaded, info.totalBytes, info.bytesPerSecond);
        };

        config.onLog = [](int level, const std::string& message) {
            const char* levelStr = "debug";
            if (level == LOG_INFO) levelStr = "info";
            else if (level == LOG_WARN) levelStr = "warn";
            else if (level == LOG_ERROR) levelStr = "error";
            std::cout << "{\"type\":\"log\",\"level\":\"" << levelStr
                      << "\",\"message\":\"" << message << "\"}" << std::endl;
        };
    }
    /* Quiet mode: no callbacks */

    InstallResult result = Install(config);

    /* Write result to a file so UI can read it */
    {
        std::string resultPath = targetPath + "\\install_result.json";
        std::ofstream resultFile(resultPath);
        if (resultFile.is_open()) {
            resultFile << "{\"success\":" << (result.success ? "true" : "false");
            if (!result.errorMessage.empty()) {
                resultFile << ",\"error\":\"" << result.errorMessage << "\"";
            }
            resultFile << "}" << std::endl;
            resultFile.close();
        }
    }

    if (mode == OutputMode::Human) {
        std::cout << "\n\n";
        if (result.success) {
            SetConsoleColor(COLOR_GREEN);
            std::cout << "  Installation completed successfully!\n";
            ResetConsoleColor();
            std::cout << "  Please restart Binary Ninja to use WinDbg/TTD.\n";
        } else {
            SetConsoleColor(COLOR_RED);
            std::cout << "  Installation failed";
            if (!result.errorMessage.empty()) {
                std::cout << ": " << result.errorMessage;
            }
            std::cout << "\n";
            ResetConsoleColor();
        }
        std::cout << "\n";
    } else if (mode == OutputMode::Json) {
        std::string message = result.success ? "Installation completed successfully" : result.errorMessage;
        if (!result.success && result.errorMessage.empty()) {
            message = "Installation failed";
        }
        PrintJsonResult(result.success, message);
    }

    return result.success ? 0 : 1;
}

/* Command: version (local only, no network) */
int CmdVersion(const std::string& installPath, OutputMode mode) {
    std::string path = installPath.empty() ? GetDefaultInstallPath() : installPath;

    VersionInfo installed = GetInstalledVersion(path);

    if (mode == OutputMode::Json) {
        std::cout << "{\"type\":\"version\",\"isInstalled\":" << (installed.isInstalled ? "true" : "false")
                  << ",\"installed\":\"" << installed.version
                  << "\",\"installPath\":\"" << path << "\"}" << std::endl;
    } else if (mode == OutputMode::Human) {
        std::cout << "\n";
        std::cout << "  Install path: " << path << "\n";
        std::cout << "  Installed:    ";
        if (!installed.isInstalled) {
            SetConsoleColor(COLOR_YELLOW);
            std::cout << "(not installed)";
        } else if (installed.version.empty()) {
            SetConsoleColor(COLOR_YELLOW);
            std::cout << "(installed, version unknown)";
        } else {
            std::cout << installed.version;
        }
        ResetConsoleColor();
        std::cout << "\n\n";
    }

    return installed.isInstalled ? 0 : 1;
}

/* Command: check-update */
int CmdCheckUpdate(const std::string& installPath, OutputMode mode) {
    std::string path = installPath.empty() ? GetDefaultInstallPath() : installPath;

    /* Get installed version first (local, fast) */
    VersionInfo installed = GetInstalledVersion(path);

    if (mode == OutputMode::Human) {
        std::cout << "Install path: " << path << "\n";
        std::cout << "Installed:    ";
        if (!installed.isInstalled) {
            SetConsoleColor(COLOR_YELLOW);
            std::cout << "(not installed)";
            ResetConsoleColor();
            std::cout << "\n";
            return 1;  /* Exit early, no need to check latest */
        } else if (installed.version.empty()) {
            SetConsoleColor(COLOR_YELLOW);
            std::cout << "(installed, version unknown)";
            ResetConsoleColor();
            std::cout << "\n";
        } else {
            std::cout << installed.version << "\n";
        }

        std::cout << "Latest:       ";
        std::cout << std::flush;  /* Flush before network request */
    }

    /* Fetch latest version (network request, may take time) */
    VersionInfo latest = GetLatestVersion(nullptr);
    bool updateAvailable = !IsVersionUpToDate(installed, latest);

    if (mode == OutputMode::Json) {
        /* Include path and isInstalled in JSON output */
        std::cout << "{\"type\":\"version\",\"isInstalled\":" << (installed.isInstalled ? "true" : "false")
                  << ",\"installed\":\"" << installed.version
                  << "\",\"latest\":\"" << latest.version
                  << "\",\"updateAvailable\":" << (updateAvailable ? "true" : "false")
                  << ",\"installPath\":\"" << path << "\"}" << std::endl;
    } else if (mode == OutputMode::Human) {
        if (latest.version.empty()) {
            SetConsoleColor(COLOR_YELLOW);
            std::cout << "(unable to check)";
        } else {
            std::cout << latest.version;
        }
        ResetConsoleColor();
        std::cout << "\n";

        if (installed.version.empty()) {
            std::cout << "Recommend reinstalling with 'install --update' for version tracking.\n";
        } else if (updateAvailable) {
            SetConsoleColor(COLOR_GREEN);
            std::cout << "Update available!\n";
            ResetConsoleColor();
        } else {
            std::cout << "No update available.\n";
        }
    }

    /* Exit code 2 means update available, 1 means not installed */
    if (!installed.isInstalled) {
        return 1;
    }
    return updateAvailable ? 2 : 0;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    /* Parse command line arguments */
    std::string command;
    std::string installPath;
    std::string bundlePath;
    OutputMode mode = OutputMode::Human;
    bool isUpdate = false;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--path") == 0) {
            if (i + 1 < argc) {
                installPath = argv[++i];
            } else {
                std::cerr << "Error: --path requires a directory argument\n";
                return 1;
            }
        } else if (strcmp(argv[i], "--bundle") == 0) {
            if (i + 1 < argc) {
                bundlePath = argv[++i];
            } else {
                std::cerr << "Error: --bundle requires a file path argument\n";
                return 1;
            }
        } else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) {
            mode = OutputMode::Quiet;
        } else if (strcmp(argv[i], "--json") == 0) {
            mode = OutputMode::Json;
        } else if (strcmp(argv[i], "--update") == 0) {
            isUpdate = true;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (argv[i][0] != '-') {
            if (command.empty()) {
                command = argv[i];
            } else {
                std::cerr << "Error: Unexpected argument: " << argv[i] << "\n";
                return 1;
            }
        } else {
            std::cerr << "Error: Unknown option: " << argv[i] << "\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }

    /* No command = show help */
    if (command.empty()) {
        PrintUsage(argv[0]);
        return 0;
    }

    /* Print banner for human mode */
    if (mode == OutputMode::Human) {
        PrintBanner();
    }

    /* Execute command */
    if (command == "install") {
        return CmdInstall(installPath, mode, isUpdate, bundlePath, verbose);
    } else if (command == "version") {
        return CmdVersion(installPath, mode);
    } else if (command == "check-update") {
        return CmdCheckUpdate(installPath, mode);
    } else {
        std::cerr << "Error: Unknown command: " << command << "\n";
        PrintUsage(argv[0]);
        return 1;
    }
}

#else

/* Non-Windows stub */
#include <iostream>

int main() {
    std::cerr << "This installer is only available on Windows.\n";
    return 1;
}

#endif // _WIN32
