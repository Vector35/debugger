/*
 * Authenticode signature verification for downloaded packages
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

/* Callback function type for logging (matches the one in windbg_installer.h) */
using LogCallback = std::function<void(int level, const std::string& message)>;

/* Result of a signature verification */
struct SignatureResult {
    bool valid;                /* True only if the signature is trusted AND signed by Microsoft */
    std::string signerName;    /* Subject name of the signing certificate (if available) */
    std::string errorMessage;  /* Empty on success, otherwise describes why verification failed */

    SignatureResult() : valid(false) {}
};

/*
 * Verify that a file carries a valid Authenticode signature that chains to a
 * trusted root and is signed by Microsoft.
 *
 * This guards against supply-chain attacks: even if the download endpoint is
 * compromised or the traffic is tampered with, an attacker cannot substitute a
 * malicious package without a valid Microsoft code-signing certificate.
 *
 * @param filePath Path to the file to verify (e.g. the downloaded MSIX bundle)
 * @param logCallback Optional callback for log messages
 * @return SignatureResult; check .valid before trusting the file
 */
SignatureResult VerifyMicrosoftSignature(const std::string& filePath, LogCallback logCallback = nullptr);

} // namespace WinDbgInstaller

#endif // _WIN32
