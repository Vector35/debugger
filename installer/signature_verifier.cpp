/*
 * Authenticode signature verification for downloaded packages
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#ifdef _WIN32

#include "signature_verifier.h"
#include "windbg_installer.h"  /* for LogLevel */
#include <windows.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <vector>
#include <cstdio>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace WinDbgInstaller {

namespace {

void Log(LogCallback logCallback, int level, const std::string& message) {
    if (logCallback) {
        logCallback(level, message);
    }
}

/* Convert an ANSI (CP_ACP) path - as produced by the GetTempPathA-based helpers - to UTF-16 */
std::wstring ToWide(const std::string& s) {
    if (s.empty()) {
        return std::wstring();
    }
    int len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (len <= 0) {
        return std::wstring();
    }
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}

/* Format a Win32/WinVerifyTrust status code as a short hex string */
std::string StatusToHex(LONG status) {
    char buf[16];
    sprintf_s(buf, sizeof(buf), "0x%08lX", (unsigned long)status);
    return std::string(buf);
}

/*
 * Step 1: Verify the embedded Authenticode signature is present, intact, and
 * chains to a trusted root certificate. Revocation of the whole chain is
 * checked as well (the network is available immediately after download).
 */
bool VerifyTrust(const std::wstring& path, std::string& err) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.pPolicyCallbackData = nullptr;
    trustData.pSIPClientData = nullptr;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = nullptr;
    trustData.pwszURLReference = nullptr;
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | WTD_SAFER_FLAG;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    /* Always release the state data, regardless of the verification result */
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    if (status != ERROR_SUCCESS) {
        switch (status) {
        case TRUST_E_NOSIGNATURE:
            err = "the file is not signed or has an invalid signature (" + StatusToHex(status) + ")";
            break;
        case TRUST_E_BAD_DIGEST:
            err = "the file has been tampered with (digest mismatch, " + StatusToHex(status) + ")";
            break;
        case TRUST_E_EXPLICIT_DISTRUST:
        case CERT_E_UNTRUSTEDROOT:
            err = "the signing certificate is not trusted (" + StatusToHex(status) + ")";
            break;
        case CRYPT_E_REVOKED:
            err = "the signing certificate has been revoked (" + StatusToHex(status) + ")";
            break;
        default:
            err = "signature verification failed (" + StatusToHex(status) + ")";
            break;
        }
        return false;
    }

    return true;
}

/*
 * Step 2: Confirm the signer is Microsoft. WinVerifyTrust only proves the file
 * is signed by *someone* who chains to a trusted root; we additionally require
 * the signer's subject name to be Microsoft so a valid-but-unrelated
 * certificate cannot be used to smuggle in a malicious package.
 */
bool VerifySignerIsMicrosoft(const std::wstring& path, std::string& signerName, std::string& err) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;
    bool result = false;
    PCCERT_CONTEXT certContext = nullptr;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &contentType, &formatType,
            &hStore, &hMsg, nullptr)) {
        err = "could not read signature data (" + StatusToHex((LONG)GetLastError()) + ")";
        return false;
    }

    /* Pull the signer information out of the PKCS#7 message */
    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize) || signerInfoSize == 0) {
        err = "could not read signer info (" + StatusToHex((LONG)GetLastError()) + ")";
        goto cleanup;
    }

    {
        std::vector<BYTE> signerInfoBuf(signerInfoSize);
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuf.data(), &signerInfoSize)) {
            err = "could not read signer info (" + StatusToHex((LONG)GetLastError()) + ")";
            goto cleanup;
        }

        CMSG_SIGNER_INFO* signerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(signerInfoBuf.data());

        /* Locate the signer's certificate in the store using its issuer + serial */
        CERT_INFO certId = {};
        certId.Issuer = signerInfo->Issuer;
        certId.SerialNumber = signerInfo->SerialNumber;

        certContext = CertFindCertificateInStore(hStore, encoding, 0,
            CERT_FIND_SUBJECT_CERT, &certId, nullptr);
        if (!certContext) {
            err = "signer certificate not found in package (" + StatusToHex((LONG)GetLastError()) + ")";
            goto cleanup;
        }

        /* Read the simple display name (the certificate subject's common name) */
        DWORD nameLen = CertGetNameStringA(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
        if (nameLen > 1) {
            std::vector<char> nameBuf(nameLen);
            CertGetNameStringA(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nameBuf.data(), nameLen);
            signerName.assign(nameBuf.data());
        }

        /*
         * The public WinDbg packages are published under "Microsoft Corporation".
         * Require the signer common name to be exactly that so that neither an
         * unrelated Microsoft-adjacent certificate nor a look-alike passes.
         */
        if (signerName == "Microsoft Corporation") {
            result = true;
        } else {
            err = "the package is not signed by Microsoft (signer: \"" +
                  (signerName.empty() ? std::string("<unknown>") : signerName) + "\")";
        }
    }

cleanup:
    if (certContext) {
        CertFreeCertificateContext(certContext);
    }
    if (hStore) {
        CertCloseStore(hStore, 0);
    }
    if (hMsg) {
        CryptMsgClose(hMsg);
    }
    return result;
}

} // anonymous namespace

SignatureResult VerifyMicrosoftSignature(const std::string& filePath, LogCallback logCallback) {
    SignatureResult result;

    std::wstring widePath = ToWide(filePath);
    if (widePath.empty()) {
        result.errorMessage = "invalid file path for signature verification";
        Log(logCallback, LOG_ERROR, result.errorMessage);
        return result;
    }

    Log(logCallback, LOG_INFO, "Verifying digital signature of: " + filePath);

    /* Step 1: signature is present, intact, and chains to a trusted root */
    std::string trustErr;
    if (!VerifyTrust(widePath, trustErr)) {
        result.errorMessage = "Signature verification failed - " + trustErr;
        Log(logCallback, LOG_ERROR, result.errorMessage);
        return result;
    }

    /* Step 2: signer is Microsoft */
    std::string signerErr;
    if (!VerifySignerIsMicrosoft(widePath, result.signerName, signerErr)) {
        result.errorMessage = "Signature verification failed - " + signerErr;
        Log(logCallback, LOG_ERROR, result.errorMessage);
        return result;
    }

    result.valid = true;
    Log(logCallback, LOG_INFO, "Signature verified - signed by: " + result.signerName);
    return result;
}

} // namespace WinDbgInstaller

#endif // _WIN32
