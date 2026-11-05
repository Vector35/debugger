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

namespace BinaryNinjaDebugger {
	// Registers the debugger_* tools with Binary Ninja's native MCP server (see mcp.h /
	// mcpserver.h in the API). Unlike api/python/mcp_tools.py, this runs as part of the core
	// plugin, so the tools are available under every license tier, including Free -- which has
	// no Python/API access at all and therefore never loads api/python/mcp_tools.py. Call once
	// from CorePluginInit/DebuggerPluginInit.
	void RegisterDebuggerMcpTools();
};  // namespace BinaryNinjaDebugger
