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
#include <sys/types.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include "ptracearch.h"

namespace BinaryNinjaDebugger {
	// Owns a single ptrace session. Linux only requires that every ptrace request and wait comes from the thread that
	// started tracing, so all of them run on one tracer thread and the public methods only marshal onto it.
	// Events are delivered from a separate thread, so a handler is free to call back into the engine.
	class PtraceEngine
	{
	public:
		enum class TrapOrigin
		{
			None,
			SoftwareBreakpoint,
			HardwareBreakpoint,
			SingleStep,
			SignalHandler,
			Target,
			Internal
		};

		enum EventType
		{
			StoppedEvent,
			ExitedEvent,
			DetachedEvent,
			OutputEvent,
			// Not from the target. See PostTask.
			TaskEvent
		};

		struct Event
		{
			EventType type {};
			uint32_t tid = 0;
			// StoppedEvent: the signal that stopped the thread. ExitedEvent: the terminating signal, if any.
			int signal = 0;
			int exitCode = 0;
			bool singleStep = false;
			bool interrupted = false;
			bool breakpoint = false;
			bool hardware = false;
			// SIGTRAP is shared by ptrace, debugger breakpoints and the target. This records which of those produced it.
			TrapOrigin trapOrigin = TrapOrigin::None;
			// The target has started another program. The engine has started over with it: the breakpoints, the memory
			// and the threads are all new.
			bool exec = false;
			// The signal that was delivered to the thread, whose handler the thread is now stopped at the start of
			int signalHandler = 0;
			std::string data;
			std::function<void()> task;
		};

		struct MapEntry
		{
			uint64_t start = 0;
			uint64_t end = 0;
			bool read = false;
			bool write = false;
			bool execute = false;
			bool shared = false;
			uint64_t offset = 0;
			std::string path;
		};

		// What the target's file descriptor `fd` is set to before the target starts
		struct FdRedirect
		{
			enum Kind
			{
				OpenFile,
				Duplicate,
				Close
			};

			Kind kind = OpenFile;
			int fd = 0;
			// OpenFile
			std::string path;
			int flags = 0;
			// Duplicate: the descriptor of the target that `fd` becomes a copy of
			int source = 0;
		};

		struct LaunchOptions
		{
			std::string path;
			std::vector<std::string> args;
			std::string workingDir;
			bool disableAslr = true;
			bool usePty = true;
			// The size of the terminal
			unsigned short rows = 24;
			unsigned short columns = 80;
			// Applied in order, after the terminal is set up, so 1 and 2 can be sent elsewhere and later ones can refer
			// to earlier ones. A relative path is relative to the working directory.
			std::vector<FdRedirect> redirects;
			// Overrides the architecture that is detected from the target
			const PtraceArch* arch = nullptr;
		};

		using EventHandler = std::function<void(const Event&)>;

		// Where the exit of a target that was let go of is picked up, since it is still our child
		struct DetachedExit
		{
			std::mutex mutex;
			std::condition_variable cv;
			bool done = false;
			int status = 0;
		};

	private:
		struct ThreadInfo
		{
			bool stopped = false;
			bool stepping = false;
			bool awaitingInitialStop = false;
			// SIGSTOPs we sent that have not been consumed yet
			int expectedStops = 0;
			int pendingSignal = 0;
			// The signal that the thread was resumed with in order to stop at its handler
			int handlerSignal = 0;
			// SIGTRAP delivered into a SIGTRAP handler can retain its original si_code. A changed PC distinguishes that
			// handler-entry stop from the original signal-delivery stop.
			uint64_t handlerResumePc = 0;
			bool handlerResumePcValid = false;
			// Set for the thread whose stop was reported, so that resuming it steps over a breakpoint at its PC
			bool atReportedStop = false;
			uint64_t reportedPc = 0;
			// The breakpoint that is lifted while the thread steps over it
			bool guardSoftware = false;
			std::vector<size_t> guardSlots;
			uint64_t guardAddress = 0;
			bool hardwareBeforeAccess = false;
		};

		struct Breakpoint
		{
			std::vector<uint8_t> original;
			bool inserted = false;
			// Taken out while a child that shares the memory of the target runs, and put back after it
			bool suspended = false;
		};

		struct HardwareSlot
		{
			bool used = false;
			uint64_t address = 0;
			PtraceHwType type = PtraceHwType::Execute;
			size_t size = 0;
		};

		enum class StopKind
		{
			Gone,
			Internal,
			Report
		};

		struct Classified
		{
			StopKind kind = StopKind::Internal;
			int signal = 0;
			bool interrupted = false;
			bool breakpoint = false;
			bool hardware = false;
			bool stepTrap = false;
			bool exec = false;
			int signalHandler = 0;
			TrapOrigin trapOrigin = TrapOrigin::None;
			// The thread that the stop is for, if it is not the one that it was found on
			pid_t tid = 0;
		};

		EventHandler m_handler;
		LaunchOptions m_options;
		std::promise<std::string> m_launchResult;

		std::thread m_tracerThread;
		std::thread m_eventThread;
		std::thread m_ioThread;

		std::mutex m_taskMutex;
		std::condition_variable m_taskCv;
		std::deque<std::function<void()>> m_tasks;
		bool m_tracerStop = false;
		bool m_shutdown = false;

		std::mutex m_eventMutex;
		std::condition_variable m_eventCv;
		std::deque<Event> m_events;
		bool m_eventStop = false;

		// Only touched by the tracer thread
		std::map<pid_t, ThreadInfo> m_threads;
		bool m_running = false;
		bool m_continueMode = false;
		bool m_done = false;
		std::vector<HardwareSlot> m_hardwareSlots;
		std::set<uint64_t> m_recentlyRemoved;
		std::vector<pid_t> m_stepOverQueue;
		pid_t m_stepOverTid = -1;
		int m_vforkPending = 0;

		const PtraceArch* m_arch = nullptr;
		std::mutex m_breakpointMutex;
		std::map<uint64_t, Breakpoint> m_breakpoints;

		mutable std::mutex m_infoMutex;
		std::shared_ptr<DetachedExit> m_detachedExit;
		std::vector<uint32_t> m_publishedThreads;
		std::atomic<bool> m_publishedRunning {false};
		// An interrupt is a SIGSTOP that we send. It can be asked for again before the first one has been seen, so the
		// signals that are on their way are counted, and whether a pause is still wanted is kept apart from that.
		std::atomic<bool> m_interruptWanted {false};
		std::atomic<int> m_interruptInFlight {0};
		std::atomic<bool> m_debugSignalHandlers {false};

		pid_t m_pid = -1;
		pid_t m_attachPid = -1;
		// The target was running before we came to it, so we let go of it rather than kill it when we are done
		bool m_attached = false;
		int m_masterFd = -1;
		int m_memFd = -1;
		std::atomic<bool> m_finished {false};
		std::atomic<bool> m_ioStop {false};
		std::mutex m_inputMutex;
		std::deque<std::string> m_inputQueue;
		size_t m_inputOffset = 0;
		size_t m_pendingInputBytes = 0;

		void TracerMain();
		void EventMain();
		void IoMain();

		std::string Spawn();
		std::string AttachToProcess();
		std::string AdoptTarget();
		bool RunOnTracer(std::function<bool()> function);
		void PushEvent(const Event& event);
		void Publish();
		void StopIo();

		bool PollThreads();
		void HandleStatus(pid_t tid, int status);
		Classified Classify(pid_t tid, int status);
		bool ResumeThread(pid_t tid);
		bool HasSignalHandler(int signal);
		bool ClassifyTrap(pid_t tid, ThreadInfo& info, Classified& result);
		bool RawGetRegisterSet(pid_t tid, int regset, std::vector<uint8_t>& data);
		bool RawSetRegisterSet(pid_t tid, int regset, const std::vector<uint8_t>& data);
		bool ReadPc(pid_t tid, uint64_t& pc);
		bool WritePc(pid_t tid, uint64_t pc);
		bool RawReadMemory(uint64_t address, void* buffer, size_t size);
		bool RawWriteMemory(uint64_t address, const void* buffer, size_t size);
		bool HasBreakpointAt(uint64_t address);
		bool NeedsStepOver(pid_t tid, const ThreadInfo& info);
		bool BeginGuard(pid_t tid, uint64_t address);
		bool EndGuard(pid_t tid, bool threadAlive);
		bool StartNextStepOver();
		bool ResumeAll();
		void ApplyHardwareToThread(pid_t tid);
		void HandleFork(pid_t child, bool sharedMemory);
		Classified HandleExec(pid_t tid);
		void ResumeBreakpointsAfterVfork();
		bool RemoveAllBreakpoints();
		void StopAll();
		void FinishStop(pid_t tid, const Classified& stop);
		void FinishExit(int status);

		bool DoResume(bool step, pid_t tid);
		bool DoKill();
		bool DoDetach();
		bool DoAddBreakpoint(uint64_t address);
		bool DoRemoveBreakpoint(uint64_t address);
		bool DoDiscardBreakpoint(uint64_t address);
		bool DoAddHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size);
		bool DoRemoveHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size);

	public:
		explicit PtraceEngine(EventHandler handler);
		~PtraceEngine();

		bool Launch(const LaunchOptions& options, std::string& error);
		// Starts tracing a process that is already running, and stops all of its threads. The target keeps its own
		// terminal, so there is no output and no input.
		// `arch` overrides the architecture that is detected from the target.
		bool Attach(uint32_t pid, std::string& error, const PtraceArch* arch = nullptr);

		// With step set, only `tid` runs, for one instruction. Otherwise every thread runs.
		bool Resume(bool step, uint32_t tid);
		bool Interrupt();
		bool Kill();
		bool Detach();
		bool WriteInput(const std::string& data);

		// Runs a function on the thread that delivers the events, after everything that was posted before it. That
		// thread is not tied up by the caller, so it is the place for work that must not run under the caller's locks.
		void PostTask(std::function<void()> task);

		// A signal that the target has a handler for is normally delivered and the handler runs on its own. With this
		// set, the thread stops at the first instruction of the handler instead.
		void SetDebugSignalHandlers(bool enable) { m_debugSignalHandlers = enable; }

		// Raw register sets, as PTRACE_GETREGSET and PTRACE_SETREGSET see them. The thread must be stopped.
		bool GetRegisterSet(uint32_t tid, int regset, std::vector<uint8_t>& data);
		bool SetRegisterSet(uint32_t tid, int regset, const std::vector<uint8_t>& data);

		// Software breakpoints are inserted straight into the target. ReadMemory and WriteMemory hide them.
		bool AddBreakpoint(uint64_t address);
		bool RemoveBreakpoint(uint64_t address);
		// For a mapping that has been removed or replaced. Drops bookkeeping without writing the saved bytes into a
		// different mapping that now occupies the address.
		bool DiscardBreakpoint(uint64_t address);
		// The target must be stopped
		bool AddHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size);
		bool RemoveHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size);

		const PtraceArch* GetArch() const { return m_arch; }
		std::vector<MapEntry> GetMaps() const;

		// All or nothing
		bool ReadMemory(uint64_t address, void* buffer, size_t size);
		bool WriteMemory(uint64_t address, const void* buffer, size_t size);

		uint32_t GetPid() const { return m_pid > 0 ? m_pid : 0; }
		std::vector<uint32_t> GetThreads() const;
		bool IsRunning() const { return m_publishedRunning; }

		// After Detach, waits for the target to exit and gives its wait status. A launched target is our child, so a
		// thread reaps it when it exits, and this is the only way to see its status.
		bool WaitForDetachedExit(int& status, std::chrono::milliseconds timeout);
	};

	// Reads a redirect the way a shell writes one: `N<path` (read), `N>path` (write, truncating), `N>>path` (append),
	// `N<>path` (read and write), `N>&M` (a copy of the descriptor M of the target) and `N>&-` (close). Without N it is
	// 0 for `<` and 1 for the others.
	bool ParseFdRedirect(const std::string& text, PtraceEngine::FdRedirect& redirect, std::string& error);
}  // namespace BinaryNinjaDebugger
