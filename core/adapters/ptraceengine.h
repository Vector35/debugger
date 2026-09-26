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
			Internal,
			Syscall
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
			// The thread is stopped at a system call, because it was resumed to one. See ResumeToSyscall.
			bool syscall = false;
			// Threads that did not answer within the wait timeout, and that the engine went on without: they did not stop
			// when they were asked to, or they did not die when they were killed. See SetWaitTimeout.
			std::vector<uint32_t> unresponsive;
			// Things that the engine handled that the owner should know of, one line each. They come with the next stop, exit
			// or detach.
			std::vector<std::string> notes;
			// Things that went wrong that the engine cannot put right, and that leave what it says about the target in doubt:
			// a breakpoint that could not be put back, a PC that could not be moved. The engine goes on, and says so.
			std::vector<std::string> errors;
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

		// A stop at a system call, as PTRACE_GET_SYSCALL_INFO tells it
		struct SyscallInfo
		{
			enum Op
			{
				None,
				Entry,
				Exit,
				Seccomp
			};

			Op op = None;
			// The AUDIT_ARCH_* value, which tells the table that the number belongs to
			uint32_t arch = 0;
			uint64_t instructionPointer = 0;
			uint64_t stackPointer = 0;
			// Entry and Seccomp
			uint64_t number = 0;
			uint64_t args[6] = {};
			// Exit
			int64_t returnValue = 0;
			// The return value is -errno
			bool isError = false;
			// Seccomp: the SECCOMP_RET_DATA of the filter
			uint32_t seccompData = 0;
		};

		// Which stops at system calls a resume asks for
		enum class SyscallMode
		{
			None,
			// Stop at the entry and at the exit of the next system call, which is executed
			Trace,
			// Stop at the entry of the next system call, which is not executed: the debugger stands in for the kernel
			Emulate
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
			// It did not stop within the wait timeout. It is not waited for again, and is looked at when it may have
			// stopped, until it does.
			bool unresponsive = false;
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
			bool syscall = false;
			// The thread that the stop is for, if it is not the one that it was found on
			pid_t tid = 0;
		};

		// What the event thread works on. The thread owns a share of it, and touches nothing else of the engine, so that it
		// can outlive the engine: a handler that is still running when the engine is destroyed (because it destroyed the
		// engine itself, or because it waits for whoever destroys it) is left to finish on its own.
		struct EventCore
		{
			std::mutex mutex;
			std::condition_variable cv;
			std::deque<Event> events;
			bool stop = false;
			bool done = false;
			std::condition_variable doneCv;
			std::shared_ptr<const EventHandler> handler;
			// The bytes of output that are queued for the handler. The pty is not read while there are too many, so a target
			// that writes faster than the handler takes it up is slowed down by its terminal filling, and memory stays bounded.
			std::atomic<size_t> pendingOutput {0};
			std::mutex outputMutex;
			std::condition_variable outputCv;
		};

		std::shared_ptr<EventCore> m_core;
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

		std::atomic<size_t> m_outputLimit {1024 * 1024};
		// How long the destructor waits for a handler that is still running
		std::atomic<int> m_teardownWaitMs {2000};

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
		SyscallMode m_syscallMode = SyscallMode::None;

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
		// How long a wait for a thread lasts before it is given up on, in milliseconds
		std::atomic<int> m_waitTimeoutMs {5000};
		// Tasks that were given up on and are not in m_threads: a child of a fork that did not stop, and the threads that
		// did not die when the target was killed
		std::vector<uint32_t> m_lingering;
		std::vector<std::string> m_notes;
		std::vector<std::string> m_errors;

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
		static void EventLoop(std::shared_ptr<EventCore> core);
		void IoMain();

		std::string Spawn();
		std::string AttachToProcess();
		std::string AdoptTarget();
		bool RunOnTracer(std::function<bool()> function);
		void PushEvent(const Event& event);
		void Publish();
		void StopIo();
		void DrainOutput(char* buffer, size_t size);

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
		bool ApplyHardwareToThread(pid_t tid);
		void HandleFork(pid_t child, bool sharedMemory);
		Classified HandleExec(pid_t tid);
		void ResumeBreakpointsAfterVfork();
		bool RemoveAllBreakpoints();
		void StopAll();
		enum class WaitResult
		{
			Status,
			Timeout,
			Gone
		};

		// Waits for a status of `tid` for at most `timeout`. A wait that has no deadline hangs the tracer thread, and
		// with it everything that calls into the engine, for as long as a thread is stuck in uninterruptible sleep.
		WaitResult WaitForThread(pid_t tid, int& status, std::chrono::milliseconds timeout);
		std::chrono::milliseconds WaitTimeout() const { return std::chrono::milliseconds(m_waitTimeoutMs.load()); }
		void KillAndReap(pid_t pid);
		std::vector<uint32_t> TakeUnresponsive();
		void Note(const std::string& note) { m_notes.push_back(note); }
		void Error(const std::string& error) { m_errors.push_back(error); }
		std::vector<std::string> TakeErrors()
		{
			std::vector<std::string> result;
			result.swap(m_errors);
			return result;
		}
		void FinishGuard(pid_t tid, bool threadAlive);
		std::vector<std::string> TakeNotes()
		{
			std::vector<std::string> result;
			result.swap(m_notes);
			return result;
		}
		pid_t ThreadGroupOf(pid_t tid);
		void FinishStop(pid_t tid, const Classified& stop);
		void FinishExit(int status);

		bool DoResume(bool step, pid_t tid, SyscallMode mode = SyscallMode::None);
		bool DoGetSyscallInfo(pid_t tid, SyscallInfo& info);
		bool DoSetSyscallInfo(pid_t tid, const SyscallInfo& info);
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
		// Resumes every thread, and stops when one of them is at a system call. The other threads are stopped where they
		// are, so they may be at one too. Emulate needs an architecture with PTRACE_SYSEMU (see PtraceArch::sysemu).
		// A thread that is resumed after an Emulate stop does not execute the system call that it stopped at, whatever
		// it is resumed with, so it goes on with the registers as they are: the return value is what the debugger left
		// in the register for it.
		bool ResumeToSyscall(SyscallMode mode);
		bool Interrupt();
		bool Kill();
		bool Detach();
		bool WriteInput(const std::string& data);

		// Runs a function on the thread that delivers the events, after everything that was posted before it. That
		// thread is not tied up by the caller, so it is the place for work that must not run under the caller's locks.
		void PostTask(std::function<void()> task);

		// How long the engine waits for a thread to stop after it was asked to, to die after it was killed, and so on,
		// before it goes on without it. A thread in uninterruptible sleep, on NFS or FUSE for example, does neither until
		// its I/O is done. The events that follow tell which threads were given up on.
		void SetWaitTimeout(std::chrono::milliseconds timeout) { m_waitTimeoutMs = (int)timeout.count(); }

		// How much output can be queued for the handler before the target's terminal is left to fill up. The output that is
		// queued is joined into events of up to 64 KB, so a handler that is slow sees fewer and larger ones.
		void SetOutputLimit(size_t bytes) { m_outputLimit = bytes; }
		size_t PendingOutputBytes() const { return m_core->pendingOutput; }

		// The engine can be destroyed from its own handler: nothing waits for the handler that is running. It can be
		// destroyed while a handler waits for the caller (an event that is posted to the controller is waited for, and the
		// controller may be what destroys the engine): the destructor waits this long for the handler, and then goes on. In
		// both cases the handler is not called again, and it finishes without the engine. What it does to whatever else it
		// captured is its own matter.
		void SetTeardownWait(std::chrono::milliseconds wait) { m_teardownWaitMs = (int)wait.count(); }

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

		// PTRACE_GET_SYSCALL_INFO and PTRACE_SET_SYSCALL_INFO for a thread that is stopped. They need Linux 5.3 and 6.16.
		// Setting takes the number and the arguments at an entry, and the return value at an exit.
		bool GetSyscallInfo(uint32_t tid, SyscallInfo& info);
		bool SetSyscallInfo(uint32_t tid, const SyscallInfo& info);

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
