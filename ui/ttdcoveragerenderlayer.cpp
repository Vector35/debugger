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

	// Quick check: if no coverage data has been loaded, return immediately
	if (controller->GetExecutedInstructionCount() == 0)
		return;

	for (auto& line : lines)
	{
		// Do not highlight empty lines or comments
		if (line.tokens.empty() || (line.tokens[0].type == CommentToken))
			continue;

		// Check if this instruction was executed during the TTD trace (single lookup optimization)
		uint64_t executionCount = controller->GetInstructionExecutionCount(line.addr);

		if (executionCount > 0)
		{
			// Highlight executed instructions with a red color
			line.highlight.style = StandardHighlightColor;
			line.highlight.color = RedHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;

			InstructionTextToken execCountToken = InstructionTextToken(AnnotationToken, " [" + std::to_string(executionCount) + "]", line.addr);
			line.tokens.push_back(execCountToken);
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

	// Quick check: if no coverage data has been loaded, return immediately
	if (controller->GetExecutedInstructionCount() == 0)
		return;

	for (auto& linearLine : lines)
	{
		DisassemblyTextLine& line = linearLine.contents;

		// Do not highlight empty lines or comments
		if (line.tokens.empty() || (line.tokens[0].type == CommentToken))
			continue;

		// Check if this instruction was executed during the TTD trace (single lookup optimization)
		uint64_t executionCount = controller->GetInstructionExecutionCount(line.addr);

		if (executionCount > 0)
		{
			// Highlight executed instructions with a red color
			line.highlight.style = StandardHighlightColor;
			line.highlight.color = RedHighlightColor;
			line.highlight.mixColor = NoHighlightColor;
			line.highlight.mix = 0;
			line.highlight.r = 0;
			line.highlight.g = 0;
			line.highlight.b = 0;
			line.highlight.alpha = 255;

			//only add execution count if the line has tokens and is not only indentation
			if (!line.tokens.empty() && std::prev(line.tokens.end())->type != IndentationToken)
			{
				InstructionTextToken execCountToken = InstructionTextToken(
					AnnotationToken, " [" + std::to_string(executionCount) + "]", line.addr);
				line.tokens.push_back(execCountToken);
			}
		}
	}
}