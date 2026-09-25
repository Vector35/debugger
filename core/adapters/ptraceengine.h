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
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace BinaryNinjaDebugger {
	// Owns a single ptrace session. Linux only requires that every ptrace request and wait comes from the thread that
	// started tracing, so all of them run on one tracer thread and the public methods only marshal onto it.
	// Events are delivered from a separate thread, so a handler is free to call back into the engine.
	class PtraceEngine
	{
	public:
		enum EventType
		{
			StoppedEvent,
			ExitedEvent,
			DetachedEvent,
			OutputEvent
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
			std::string data;
		};

		struct LaunchOptions
		{
			std::string path;
			std::vector<std::string> args;
			std::string workingDir;
			bool disableAslr = true;
			bool usePty = true;
		};

		using EventHandler = std::function<void(const Event&)>;

	private:
		struct ThreadInfo
		{
			bool stopped = false;
			bool stepping = false;
			bool awaitingInitialStop = false;
			// SIGSTOPs we sent that have not been consumed yet
			int expectedStops = 0;
			int pendingSignal = 0;
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

		mutable std::mutex m_infoMutex;
		std::vector<uint32_t> m_publishedThreads;
		std::atomic<bool> m_publishedRunning {false};
		std::atomic<bool> m_interruptRequested {false};

		pid_t m_pid = -1;
		int m_masterFd = -1;
		std::atomic<bool> m_ioStop {false};

		void TracerMain();
		void EventMain();
		void IoMain();

		std::string Spawn();
		bool RunOnTracer(std::function<bool()> function);
		void PushEvent(const Event& event);
		void Publish();
		void StopIo();

		bool PollThreads();
		void HandleStatus(pid_t tid, int status);
		Classified Classify(pid_t tid, int status);
		bool ResumeThread(pid_t tid);
		void StopAll();
		void FinishStop(pid_t tid, const Classified& stop);
		void FinishExit(int status);

		bool DoResume(bool step, pid_t tid);
		bool DoKill();
		bool DoDetach();

	public:
		explicit PtraceEngine(EventHandler handler);
		~PtraceEngine();

		bool Launch(const LaunchOptions& options, std::string& error);

		// With step set, only `tid` runs, for one instruction. Otherwise every thread runs.
		bool Resume(bool step, uint32_t tid);
		bool Interrupt();
		bool Kill();
		bool Detach();
		bool WriteInput(const std::string& data);

		uint32_t GetPid() const { return m_pid > 0 ? m_pid : 0; }
		std::vector<uint32_t> GetThreads() const;
		bool IsRunning() const { return m_publishedRunning; }
	};
}  // namespace BinaryNinjaDebugger
