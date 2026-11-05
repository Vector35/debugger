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
#include <cstdint>
#include <functional>
#include <mutex>
#include <set>
#include <vector>
#include "ptraceengine.h"

namespace BinaryNinjaDebugger {
	// Steps over a call and out of a function. Both let the target run until it reaches an address of ours, and a stop
	// there only counts if it is the same thread in the same frame: other threads run through the same code, and a
	// recursive function comes back to the same address from deeper frames. Any other stop ends the step and is
	// left to the caller to report.
	class PtraceStepper
	{
		enum class Mode
		{
			None,
			// Run to an address that the function returns to
			ReturnAddress,
			// Run to the instructions that return from the function, and then step once more to do the return
			ReturnSites,
			FinalStep
		};

		using BreakpointFunction = std::function<bool(uint64_t)>;

		PtraceEngine& m_engine;
		BreakpointFunction m_acquire;
		BreakpointFunction m_release;

		std::mutex m_mutex;
		Mode m_mode = Mode::None;
		uint32_t m_tid = 0;
		uint64_t m_minSp = 0;
		std::set<uint64_t> m_addresses;

		void ReleaseAll();

	public:
		enum class Result
		{
			// No step is going on, or it has been called off. The stop is for the caller to deal with.
			Ignored,
			// The stop was part of the step, which goes on
			Consumed,
			// The step is done, and this stop is where it ended
			Finished
		};

		// `acquire` and `release` place and remove the breakpoints of a step. They may be shared with other users of
		// the same address, and are called once per address.
		PtraceStepper(PtraceEngine& engine, BreakpointFunction acquire, BreakpointFunction release);

		// Runs the call at `pc` to its end. `callLength` is zero if the instruction is not a call, and that is
		// only a single step.
		bool StepOver(uint32_t tid, uint64_t pc, uint64_t sp, size_t callLength, size_t wordSize);

		// Runs until the function that the thread is in returns. `returnSites` are the instructions that do it, and a
		// stop at one only counts if the stack pointer is at least `minSp`, which is what tells the function apart from
		// the calls that it makes to itself. What a return leaves the stack pointer at depends on the ABI, so the
		// caller works it out. If there are no return sites, `returnAddress` is where the function returns to, and
		// `returnSp` the stack pointer that the caller has once it is back.
		bool StepReturn(uint32_t tid, uint64_t pc, uint64_t minSp, const std::vector<uint64_t>& returnSites,
			uint64_t returnAddress, uint64_t returnSp);

		// Call for every stop of the target. `userBreakpoint` tells whether there is a breakpoint of the user at `pc`.
		Result OnStop(const PtraceEngine::Event& event, uint64_t pc, uint64_t sp, bool userBreakpoint);

		bool IsActive();
		void Cancel();
	};
}  // namespace BinaryNinjaDebugger
