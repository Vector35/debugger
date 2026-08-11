/*
 * Pinned WinDbg/TTD version
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#pragma once

namespace WinDbgInstaller {

/* The WinDbg version we install and support.
 *
 * We deliberately install a known-good, pinned version instead of always pulling the
 * absolute latest, because a freshly released WinDbg occasionally ships regressions that
 * break the debugger's DbgEng/TTD adapter (see issues #1129 and #1130). When Microsoft
 * releases a new version we can validate it and bump this constant.
 *
 * This header is the single source of truth: the installer downloads this version, and the
 * UI shows it as the version we support. */
constexpr const char* kPinnedVersion = "1.2603.20001.0";

} // namespace WinDbgInstaller
