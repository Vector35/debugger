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

#include "ptracestep.h"
#include <algorithm>

namespace BinaryNinjaDebugger {

	PtraceStepper::PtraceStepper(PtraceEngine& engine, BreakpointFunction acquire, BreakpointFunction release) :
		m_engine(engine), m_acquire(std::move(acquire)), m_release(std::move(release))
	{}


	void PtraceStepper::ReleaseAll()
	{
		for (uint64_t address : m_addresses)
			m_release(address);
		m_addresses.clear();
		m_mode = Mode::None;
	}


	bool PtraceStepper::IsActive()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_mode != Mode::None;
	}


	void PtraceStepper::Cancel()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		ReleaseAll();
	}


	bool PtraceStepper::StepOver(uint32_t tid, uint64_t pc, uint64_t sp, size_t callLength, size_t wordSize)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		ReleaseAll();
		if (callLength == 0)
			return m_engine.Resume(true, tid);

		uint64_t address = pc + callLength;
		if (!m_acquire(address))
			return false;

		m_addresses.insert(address);
		m_mode = Mode::ReturnAddress;
		m_tid = tid;
		// A call that goes to the next instruction leaves its return address on the stack, so allow for it
		m_minSp = sp - wordSize;
		if (m_engine.Resume(false, 0))
			return true;

		ReleaseAll();
		return false;
	}


	bool PtraceStepper::StepReturn(uint32_t tid, uint64_t pc, uint64_t minSp, const std::vector<uint64_t>& returnSites,
		uint64_t returnAddress, uint64_t returnSp)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		ReleaseAll();

		// Already at the instruction that returns, so the return is the next step
		if (std::find(returnSites.begin(), returnSites.end(), pc) != returnSites.end())
		{
			m_mode = Mode::FinalStep;
			m_tid = tid;
			if (m_engine.Resume(true, tid))
				return true;

			m_mode = Mode::None;
			return false;
		}

		for (uint64_t site : returnSites)
		{
			if (!m_addresses.count(site) && m_acquire(site))
				m_addresses.insert(site);
		}

		if (!m_addresses.empty())
		{
			m_mode = Mode::ReturnSites;
			m_minSp = minSp;
		}
		else if (returnAddress != 0 && m_acquire(returnAddress))
		{
			m_addresses.insert(returnAddress);
			m_mode = Mode::ReturnAddress;
			m_minSp = returnSp;
		}
		else
		{
			return false;
		}

		m_tid = tid;
		if (m_engine.Resume(false, 0))
			return true;

		ReleaseAll();
		return false;
	}


	PtraceStepper::Result PtraceStepper::OnStop(
		const PtraceEngine::Event& event, uint64_t pc, uint64_t sp, bool userBreakpoint)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_mode == Mode::None)
			return Result::Ignored;

		if (m_mode == Mode::FinalStep)
		{
			bool stepped = event.tid == m_tid && event.singleStep && !event.breakpoint;
			m_mode = Mode::None;
			return stepped ? Result::Finished : Result::Ignored;
		}

		// Whatever else stops the target ends the step. That includes a breakpoint of the user, even at one of our
		// addresses.
		bool atOurs = event.breakpoint && m_addresses.count(pc);
		if (!atOurs || userBreakpoint)
		{
			ReleaseAll();
			return Result::Ignored;
		}

		if (event.tid != m_tid || sp < m_minSp)
		{
			// Another thread, or a deeper frame. It is not ours, so it goes on.
			if (m_engine.Resume(false, 0))
				return Result::Consumed;

			ReleaseAll();
			return Result::Ignored;
		}

		if (m_mode == Mode::ReturnAddress)
		{
			ReleaseAll();
			return Result::Finished;
		}

		// At an instruction that returns: it takes one step to be out
		ReleaseAll();
		m_mode = Mode::FinalStep;
		if (m_engine.Resume(true, m_tid))
			return Result::Consumed;

		m_mode = Mode::None;
		return Result::Ignored;
	}

}  // namespace BinaryNinjaDebugger
