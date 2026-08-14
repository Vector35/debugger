/*
 * Default WinDbg/TTD version
 *
 * Copyright 2020-2026 Vector 35 Inc.
 * Licensed under the Apache License, Version 2.0
 */

#pragma once

namespace WinDbgInstaller {

/* The WinDbg version that the debugger installs by default.
 *
 * We install a known-good version instead of the newest release, because a freshly
 * released WinDbg occasionally ships regressions that break the DbgEng/TTD adapter (see
 * issues #1129 and #1130). Bump this once a newer release has been validated.
 *
 * It is only the default: the "debugger.windbgVersion" setting overrides it, which allows
 * installing any released version without a new build. */
constexpr const char* kDefaultVersion = "1.2603.20001.0";

} // namespace WinDbgInstaller
