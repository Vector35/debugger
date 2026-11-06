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


#pragma once
#include <optional>
#include <string>
#include <vector>

namespace BinaryNinjaDebugger {
	// Splits a command line the way a POSIX shell does before it expands anything: words are separated by blanks (space, tab,
	// newline); single quotes keep everything literally; inside double quotes a backslash only escapes $, `, ", \ and a
	// newline, and is an ordinary character before anything else; outside quotes a backslash escapes the next character, and a
	// backslash followed by a newline vanishes. Nothing is expanded: no variables, globs, redirections or operators.
	// Returns nothing if a quote or a trailing backslash is left open.
	std::optional<std::vector<std::string>> ParseCommandLineArguments(const std::string& commandLine);
}  // namespace BinaryNinjaDebugger
