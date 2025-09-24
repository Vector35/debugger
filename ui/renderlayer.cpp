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

#include "renderlayer.h"
#include "ttdcoveragerenderlayer.h"
#include "debuggerapi.h"
#include <map>

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

DebuggerRenderLayer::DebuggerRenderLayer(): RenderLayer("Debugger")
{

}


void DebuggerRenderLayer::ApplyToBlock(Ref<BasicBlock> block, std::vector<DisassemblyTextLine>& lines)
{
	Ref<BinaryView> bv = block->GetFunction()->GetView();
	DbgRef<DebuggerController> controller = DebuggerController::GetController(bv);
	if (!controller)
		return;

	uint64_t ipAddr = controller->IP();
	bool paused = controller->GetTargetStatus() == DebugAdapterPausedStatus;

	// Get all breakpoints with their enabled state and type
	std::vector<DebugBreakpoint> breakpoints = controller->GetBreakpoints();
	std::map<uint64_t, bool> breakpointEnabledMap;
	std::map<uint64_t, DebugBreakpointType> breakpointTypeMap;
	for (const auto& bp : breakpoints)
	{
		breakpointEnabledMap[bp.address] = bp.enabled;
		breakpointTypeMap[bp.address] = bp.type;
	}

	for (auto& line : lines)
	{
		// Do not draw the tags on an empty line, e.g., those separating the basic blocks in the linear view
		if (line.tokens.empty() || (line.tokens[0].type == CommentToken))
			continue;

		bool hasPC = (line.addr == ipAddr) && paused;
		bool hasEnabledBreakpoint = false;
		bool hasDisabledBreakpoint = false;
		bool isHardwareBreakpoint = false;

		if (breakpointEnabledMap.count(line.addr) > 0)
		{
			// Check if it's a hardware breakpoint
			if (breakpointTypeMap.count(line.addr) > 0)
			{
				DebugBreakpointType type = breakpointTypeMap[line.addr];
				isHardwareBreakpoint = (type != SoftwareBreakpoint);
			}

			if (breakpointEnabledMap[line.addr])
				hasEnabledBreakpoint = true;
			else
				hasDisabledBreakpoint = true;
		}

		if (hasPC && hasEnabledBreakpoint)
		{
			// Use different icons for software vs hardware breakpoints
			std::string icon = isHardwareBreakpoint ? "🔶➞" : "🛑➞";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = icon;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = MagentaHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasPC && hasDisabledBreakpoint)
		{
			// PC at a disabled breakpoint - show both indicators using different icons for software vs hardware
			std::string icon = isHardwareBreakpoint ? "◇➞" : "⭕➞";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = icon;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = BlueHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasPC)
		{
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = "…➞";
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, "➞");
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = BlueHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasEnabledBreakpoint)
		{
			// Use different icons for software vs hardware breakpoints
			std::string icon = isHardwareBreakpoint ? "🔶" : "🛑";
			std::string iconWithEllipsis = isHardwareBreakpoint ? "…🔶" : "…🛑";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = iconWithEllipsis;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = RedHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasDisabledBreakpoint)
		{
			// Disabled breakpoint - use different icons for software vs hardware, no line highlighting
			std::string icon = isHardwareBreakpoint ? "◇" : "⭕";
			std::string iconWithEllipsis = isHardwareBreakpoint ? "…◇" : "…⭕";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = iconWithEllipsis;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}
			// No line highlighting for disabled breakpoints
		}
	}
}


void DebuggerRenderLayer::ApplyToHighLevelILBody(Ref<Function> function, std::vector<LinearDisassemblyLine>& lines)
{
	Ref<BinaryView> bv = function->GetView();
	DbgRef<DebuggerController> controller = DebuggerController::GetController(bv);
	if (!controller)
		return;

	uint64_t ipAddr = controller->IP();
	bool paused = controller->GetTargetStatus() == DebugAdapterPausedStatus;

	// Get all breakpoints with their enabled state and type
	std::vector<DebugBreakpoint> breakpoints = controller->GetBreakpoints();
	std::map<uint64_t, bool> breakpointEnabledMap;
	std::map<uint64_t, DebugBreakpointType> breakpointTypeMap;
	for (const auto& bp : breakpoints)
	{
		breakpointEnabledMap[bp.address] = bp.enabled;
		breakpointTypeMap[bp.address] = bp.type;
	}

	for (auto& linearLine : lines)
	{
		DisassemblyTextLine& line = linearLine.contents;
		bool hasPC = (line.addr == ipAddr) && paused;
		bool hasEnabledBreakpoint = false;
		bool hasDisabledBreakpoint = false;
		bool isHardwareBreakpoint = false;

		if (breakpointEnabledMap.count(line.addr) > 0)
		{
			// Check if it's a hardware breakpoint
			if (breakpointTypeMap.count(line.addr) > 0)
			{
				DebugBreakpointType type = breakpointTypeMap[line.addr];
				isHardwareBreakpoint = (type != SoftwareBreakpoint);
			}

			if (breakpointEnabledMap[line.addr])
				hasEnabledBreakpoint = true;
			else
				hasDisabledBreakpoint = true;
		}

		if (hasPC && hasEnabledBreakpoint)
		{
			// Use different icons for software vs hardware breakpoints
			std::string icon = isHardwareBreakpoint ? "🔶➞" : "🛑➞";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = icon;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = MagentaHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasPC && hasDisabledBreakpoint)
		{
			// PC at a disabled breakpoint - show both indicators using different icons for software vs hardware
			std::string icon = isHardwareBreakpoint ? "◇➞" : "⭕➞";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = icon;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = BlueHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasPC)
		{
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = "…➞";
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, "➞");
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = BlueHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasEnabledBreakpoint)
		{
			// Use different icons for software vs hardware breakpoints
			std::string icon = isHardwareBreakpoint ? "🔶" : "🛑";
			std::string iconWithEllipsis = isHardwareBreakpoint ? "…🔶" : "…🛑";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = iconWithEllipsis;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}

			line.highlight.style = StandardHighlightColor;
			line.highlight.color = RedHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;
		}
		else if (hasDisabledBreakpoint)
		{
			// Disabled breakpoint - use different icons for software vs hardware, no line highlighting
			std::string icon = isHardwareBreakpoint ? "◇" : "⭕";
			std::string iconWithEllipsis = isHardwareBreakpoint ? "…◇" : "…⭕";
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = iconWithEllipsis;
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, icon);
				line.tokens.insert(line.tokens.begin(), indicator);
			}
			// No line highlighting for disabled breakpoints
		}
	}
}


void RegisterRenderLayers()
{
	static DebuggerRenderLayer* g_debuggerRenderLayer = new DebuggerRenderLayer();
	static TTDCoverageRenderLayer* g_ttdCoverageRenderLayer = new TTDCoverageRenderLayer();

	RenderLayer::Register(g_debuggerRenderLayer, BNRenderLayerDefaultEnableState::AlwaysEnabledRenderLayerDefaultEnableState);
	RenderLayer::Register(g_ttdCoverageRenderLayer, BNRenderLayerDefaultEnableState::DisabledByDefaultRenderLayerDefaultEnableState);
}