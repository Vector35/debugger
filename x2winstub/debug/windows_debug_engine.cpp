/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "windows_debug_engine.h"
#include <cstdio>
#include <cstdarg>

namespace x2win {
	void LogWarn(const char* fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		fprintf(stderr, "[Windows Remote][WARN] ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
		// MSVC's CRT fully-buffers stderr (unlike glibc, which leaves it unbuffered) once it's
		// redirected to a file/pipe rather than a console -- e.g. exactly how the test harness's
		// subprocess.Popen(..., stderr=subprocess.STDOUT) runs this binary. Without an explicit
		// flush, a warning/error can sit in that buffer indefinitely and never reach whoever is
		// tailing the log, especially if the process is later force-killed rather than exiting
		// cleanly (which would never flush it at all).
		fflush(stderr);
	}

	void LogError(const char* fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		fprintf(stderr, "[Windows Remote][ERROR] ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
		fflush(stderr);
	}

}  // namespace x2win
