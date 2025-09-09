/*
Copyright 2020-2025 Vector 35 Inc.

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

	for (auto& line : lines)
	{
		// Do not draw the tags on an empty line, e.g., those separating the basic blocks in the linear view
		if (line.tokens.empty() || (line.tokens[0].type == CommentToken))
			continue;

		bool hasPC = (line.addr == ipAddr) && paused;
		bool hasBreakpoint = controller->ContainsBreakpoint(line.addr);

		if (hasPC && hasBreakpoint)
		{
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = "🛑➞";
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, "🛑➞");
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
		else if (hasBreakpoint)
		{
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = "…🛑";
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, "🛑");
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

	for (auto& linearLine : lines)
	{
		DisassemblyTextLine& line = linearLine.contents;
		bool hasPC = (line.addr == ipAddr) && paused;
		bool hasBreakpoint = controller->ContainsBreakpoint(line.addr);

		if (hasPC && hasBreakpoint)
		{
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = "🛑➞";
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, "🛑➞");
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
		else if (hasBreakpoint)
		{
			bool appliedTag = false;
			for (size_t i = 0; i < line.tokens.size(); i++)
			{
				if (line.tokens[i].type == TagToken)
				{
					line.tokens[i].text = "…🛑";
					appliedTag = true;
					break;
				}
			}
			if (!appliedTag)
			{
				InstructionTextToken indicator(BNInstructionTextTokenType::TagToken, "🛑");
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
	}
}


void RegisterRenderLayers()
{
	static DebuggerRenderLayer* g_debuggerRenderLayer = new DebuggerRenderLayer();
	static TTDCoverageRenderLayer* g_ttdCoverageRenderLayer = new TTDCoverageRenderLayer();

	RenderLayer::Register(g_debuggerRenderLayer, BNRenderLayerDefaultEnableState::AlwaysEnabledRenderLayerDefaultEnableState);
	RenderLayer::Register(g_ttdCoverageRenderLayer, BNRenderLayerDefaultEnableState::DisabledByDefaultRenderLayerDefaultEnableState);
}