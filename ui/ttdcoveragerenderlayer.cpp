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

#include "ttdcoveragerenderlayer.h"
#include "debuggerapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebuggerAPI;

TTDCoverageRenderLayer::TTDCoverageRenderLayer(): RenderLayer("TTD Coverage")
{

}


void TTDCoverageRenderLayer::ApplyToBlock(Ref<BasicBlock> block, std::vector<DisassemblyTextLine>& lines)
{
	Ref<BinaryView> bv = block->GetFunction()->GetView();
	DbgRef<DebuggerController> controller = DebuggerController::GetController(bv);
	if (!controller)
		return;

	// Only apply TTD coverage highlighting if this is a TTD session
	if (!controller->IsTTD())
		return;

	for (auto& line : lines)
	{
		// Do not highlight empty lines or comments
		if (line.tokens.empty() || (line.tokens[0].type == CommentToken))
			continue;

		// Check if this instruction was executed during the TTD trace
		bool isExecuted = controller->IsInstructionExecuted(line.addr);

		if (isExecuted)
		{
			// Highlight executed instructions with a green color
			line.highlight.style = StandardHighlightColor;
			line.highlight.color = RedHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 64; // Light highlight
		}
	}
}


void TTDCoverageRenderLayer::ApplyToHighLevelILBody(Ref<Function> function, std::vector<LinearDisassemblyLine>& lines)
{
	Ref<BinaryView> bv = function->GetView();
	DbgRef<DebuggerController> controller = DebuggerController::GetController(bv);
	if (!controller)
		return;

	// Only apply TTD coverage highlighting if this is a TTD session
	if (!controller->IsTTD())
		return;

	for (auto& linearLine : lines)
	{
		DisassemblyTextLine& line = linearLine.contents;

		// Do not highlight empty lines or comments
		if (line.tokens.empty() || (line.tokens[0].type == CommentToken))
			continue;

		// Check if this instruction was executed during the TTD trace
		bool isExecuted = controller->IsInstructionExecuted(line.addr);

		if (isExecuted)
		{
			// Highlight executed instructions with a green color
			line.highlight.style = StandardHighlightColor;
			line.highlight.color = GreenHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 64; // Light highlight
		}
	}
}