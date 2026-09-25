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

#include "ptraceengine.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace BinaryNinjaDebugger {

	static bool IsSilentSignal(int signal)
	{
		switch (signal)
		{
		case SIGCHLD:
		case SIGALRM:
		case SIGURG:
		case SIGVTALRM:
		case SIGPROF:
		case SIGWINCH:
		case SIGIO:
			return true;
		default:
			return false;
		}
	}


	[[noreturn]] static void ChildFail(int fd)
	{
		int error = errno;
		[[maybe_unused]] auto ignored = write(fd, &error, sizeof(error));
		_exit(127);
	}


	PtraceEngine::PtraceEngine(EventHandler handler) : m_handler(std::move(handler)) {}


	PtraceEngine::~PtraceEngine()
	{
		if (m_tracerThread.joinable())
		{
			RunOnTracer([this] { return DoKill(); });
			{
				std::lock_guard<std::mutex> lock(m_taskMutex);
				m_shutdown = true;
			}
			m_taskCv.notify_all();
			m_tracerThread.join();
		}

		if (m_ioThread.joinable())
		{
			m_ioStop = true;
			m_ioThread.join();
		}

		if (m_eventThread.joinable())
		{
			{
				std::lock_guard<std::mutex> lock(m_eventMutex);
				m_eventStop = true;
			}
			m_eventCv.notify_all();
			m_eventThread.join();
		}

		if (m_masterFd >= 0)
			close(m_masterFd);
	}


	bool PtraceEngine::Launch(const LaunchOptions& options, std::string& error)
	{
		m_options = options;
		auto result = m_launchResult.get_future();
		m_eventThread = std::thread(&PtraceEngine::EventMain, this);
		m_tracerThread = std::thread(&PtraceEngine::TracerMain, this);
		error = result.get();
		return error.empty();
	}


	bool PtraceEngine::RunOnTracer(std::function<bool()> function)
	{
		auto task = std::make_shared<std::packaged_task<bool()>>(std::move(function));
		auto result = task->get_future();
		{
			std::lock_guard<std::mutex> lock(m_taskMutex);
			if (m_tracerStop)
				return false;
			m_tasks.push_back([task] { (*task)(); });
		}
		m_taskCv.notify_all();

		// Only the queue may keep the task alive, so that discarding it breaks the promise
		task.reset();
		try
		{
			return result.get();
		}
		catch (const std::future_error&)
		{
			return false;
		}
	}


	bool PtraceEngine::Resume(bool step, uint32_t tid)
	{
		return RunOnTracer([this, step, tid] { return DoResume(step, tid); });
	}


	bool PtraceEngine::Kill()
	{
		return RunOnTracer([this] { return DoKill(); });
	}


	bool PtraceEngine::Detach()
	{
		return RunOnTracer([this] { return DoDetach(); });
	}


	bool PtraceEngine::Interrupt()
	{
		if (!m_publishedRunning)
			return false;

		m_interruptRequested = true;
		return kill(m_pid, SIGSTOP) == 0;
	}


	bool PtraceEngine::WriteInput(const std::string& data)
	{
		if (m_masterFd < 0)
			return false;

		size_t written = 0;
		while (written < data.size())
		{
			auto count = write(m_masterFd, data.data() + written, data.size() - written);
			if (count < 0)
			{
				if (errno == EINTR || errno == EAGAIN)
					continue;
				return false;
			}
			written += count;
		}
		return true;
	}


	std::vector<uint32_t> PtraceEngine::GetThreads() const
	{
		std::lock_guard<std::mutex> lock(m_infoMutex);
		return m_publishedThreads;
	}


	void PtraceEngine::PushEvent(const Event& event)
	{
		{
			std::lock_guard<std::mutex> lock(m_eventMutex);
			m_events.push_back(event);
		}
		m_eventCv.notify_one();
	}


	void PtraceEngine::Publish()
	{
		std::lock_guard<std::mutex> lock(m_infoMutex);
		m_publishedThreads.clear();
		for (const auto& [tid, info] : m_threads)
			m_publishedThreads.push_back(tid);
		m_publishedRunning = m_running;
	}


	void PtraceEngine::StopIo()
	{
		if (!m_ioThread.joinable())
			return;

		m_ioStop = true;
		m_ioThread.join();
	}


	void PtraceEngine::EventMain()
	{
		while (true)
		{
			Event event;
			{
				std::unique_lock<std::mutex> lock(m_eventMutex);
				m_eventCv.wait(lock, [this] { return m_eventStop || !m_events.empty(); });
				if (m_eventStop)
					return;

				event = std::move(m_events.front());
				m_events.pop_front();
			}
			m_handler(event);
		}
	}


	void PtraceEngine::IoMain()
	{
		char buffer[4096];
		while (true)
		{
			pollfd fd {m_masterFd, POLLIN, 0};
			int ready = poll(&fd, 1, 50);
			if (ready == 0)
			{
				if (m_ioStop)
					return;
				continue;
			}
			if (ready < 0)
			{
				if (errno == EINTR)
					continue;
				return;
			}

			auto count = read(m_masterFd, buffer, sizeof(buffer));
			if (count > 0)
			{
				Event event;
				event.type = OutputEvent;
				event.data.assign(buffer, count);
				PushEvent(event);
			}
			else if (count == 0 || (errno != EINTR && errno != EAGAIN))
			{
				return;
			}
		}
	}


	std::string PtraceEngine::Spawn()
	{
		std::vector<std::string> argStorage;
		argStorage.push_back(m_options.path);
		argStorage.insert(argStorage.end(), m_options.args.begin(), m_options.args.end());
		std::vector<char*> argv;
		for (auto& arg : argStorage)
			argv.push_back(arg.data());
		argv.push_back(nullptr);

		const char* path = m_options.path.c_str();
		const char* workingDir = m_options.workingDir.empty() ? nullptr : m_options.workingDir.c_str();

		char slaveName[256] = {};
		if (m_options.usePty)
		{
			m_masterFd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
			if (m_masterFd < 0 || grantpt(m_masterFd) != 0 || unlockpt(m_masterFd) != 0
				|| ptsname_r(m_masterFd, slaveName, sizeof(slaveName)) != 0)
				return std::string("failed to open a pseudo terminal: ") + strerror(errno);
		}

		int errorPipe[2];
		if (pipe2(errorPipe, O_CLOEXEC) != 0)
			return std::string("failed to create a pipe: ") + strerror(errno);

		pid_t pid = fork();
		if (pid < 0)
		{
			int error = errno;
			close(errorPipe[0]);
			close(errorPipe[1]);
			return std::string("failed to fork: ") + strerror(error);
		}

		if (pid == 0)
		{
			sigset_t noSignals;
			sigemptyset(&noSignals);
			sigprocmask(SIG_SETMASK, &noSignals, nullptr);

			if (slaveName[0])
			{
				setsid();
				int slave = open(slaveName, O_RDWR);
				if (slave < 0)
					ChildFail(errorPipe[1]);
				ioctl(slave, TIOCSCTTY, 0);
				dup2(slave, 0);
				dup2(slave, 1);
				dup2(slave, 2);
				if (slave > 2)
					close(slave);
			}

			if (workingDir && chdir(workingDir) != 0)
				ChildFail(errorPipe[1]);
			if (m_options.disableAslr)
				personality(personality(0xffffffff) | ADDR_NO_RANDOMIZE);
			if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0)
				ChildFail(errorPipe[1]);

			execv(path, argv.data());
			ChildFail(errorPipe[1]);
		}

		close(errorPipe[1]);
		int childError = 0;
		ssize_t count;
		do
		{
			count = read(errorPipe[0], &childError, sizeof(childError));
		} while (count < 0 && errno == EINTR);
		close(errorPipe[0]);

		if (count == (ssize_t)sizeof(childError))
		{
			waitpid(pid, nullptr, __WALL);
			return std::string("failed to execute ") + m_options.path + ": " + strerror(childError);
		}

		int status = 0;
		if (waitpid(pid, &status, __WALL) < 0 || !WIFSTOPPED(status))
			return "the target exited before it could be traced";

		ptrace(PTRACE_SETOPTIONS, pid, nullptr, (void*)(uintptr_t)(PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE));

		m_pid = pid;
		ThreadInfo info;
		info.stopped = true;
		m_threads[pid] = info;
		Publish();

		if (m_masterFd >= 0)
		{
			fcntl(m_masterFd, F_SETFL, fcntl(m_masterFd, F_GETFL) | O_NONBLOCK);
			m_ioThread = std::thread(&PtraceEngine::IoMain, this);
		}

		Event event;
		event.type = StoppedEvent;
		event.tid = pid;
		event.signal = WSTOPSIG(status);
		PushEvent(event);
		return "";
	}


	void PtraceEngine::TracerMain()
	{
		std::string error = Spawn();
		m_launchResult.set_value(error);

		int idle = 0;
		while (error.empty() && !m_done)
		{
			std::deque<std::function<void()>> tasks;
			{
				std::unique_lock<std::mutex> lock(m_taskMutex);
				if (!m_running)
				{
					m_taskCv.wait(lock, [this] { return m_shutdown || !m_tasks.empty(); });
				}
				else if (m_tasks.empty() && idle >= 20)
				{
					auto delay = std::chrono::microseconds(50 << std::min(idle - 20, 6));
					m_taskCv.wait_for(lock, delay, [this] { return m_shutdown || !m_tasks.empty(); });
				}
				if (m_shutdown)
					break;
				tasks.swap(m_tasks);
			}

			for (auto& task : tasks)
				task();
			if (m_done)
				break;

			if (m_running)
			{
				if (PollThreads())
					idle = 0;
				else if (++idle < 20)
					sched_yield();
			}
		}

		std::lock_guard<std::mutex> lock(m_taskMutex);
		m_tracerStop = true;
		m_tasks.clear();
	}


	bool PtraceEngine::PollThreads()
	{
		std::vector<pid_t> tids;
		for (const auto& [tid, info] : m_threads)
		{
			if (!info.stopped)
				tids.push_back(tid);
		}

		bool progressed = false;
		for (pid_t tid : tids)
		{
			if (!m_running || m_done)
				break;
			if (m_threads.find(tid) == m_threads.end())
				continue;

			int status = 0;
			pid_t result = waitpid(tid, &status, __WALL | WNOHANG);
			if (result == 0)
				continue;

			progressed = true;
			if (result < 0)
			{
				if (errno == EINTR)
					continue;
				// The thread is gone without a status we can read
				status = 0;
			}
			HandleStatus(tid, status);
		}
		return progressed;
	}


	PtraceEngine::Classified PtraceEngine::Classify(pid_t tid, int status)
	{
		Classified result;
		if (!WIFSTOPPED(status))
		{
			m_threads.erase(tid);
			Publish();
			result.kind = StopKind::Gone;
			if (tid == m_pid)
				FinishExit(status);
			return result;
		}

		auto& info = m_threads[tid];
		info.stopped = true;
		int signal = WSTOPSIG(status);
		int event = status >> 16;

		if (event == PTRACE_EVENT_CLONE)
		{
			unsigned long newTid = 0;
			ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &newTid);
			ThreadInfo created;
			created.awaitingInitialStop = true;
			m_threads[(pid_t)newTid] = created;
			Publish();
			return result;
		}
		if (event != 0)
			return result;

		if (signal == SIGSTOP)
		{
			if (info.awaitingInitialStop)
			{
				info.awaitingInitialStop = false;
				return result;
			}
			if (info.expectedStops > 0)
			{
				info.expectedStops--;
				return result;
			}
			if (m_interruptRequested.exchange(false))
			{
				result.kind = StopKind::Report;
				result.interrupted = true;
				return result;
			}
		}

		if (IsSilentSignal(signal))
		{
			info.pendingSignal = signal;
			return result;
		}

		if (signal != SIGTRAP)
			info.pendingSignal = signal;
		result.kind = StopKind::Report;
		result.signal = signal;
		return result;
	}


	bool PtraceEngine::ResumeThread(pid_t tid)
	{
		auto& info = m_threads[tid];
		int signal = info.pendingSignal;
		info.pendingSignal = 0;
		info.stopped = false;
		auto request = info.stepping ? PTRACE_SINGLESTEP : PTRACE_CONT;
		return ptrace(request, tid, nullptr, (void*)(intptr_t)signal) == 0 || errno == ESRCH;
	}


	void PtraceEngine::HandleStatus(pid_t tid, int status)
	{
		auto stop = Classify(tid, status);
		switch (stop.kind)
		{
		case StopKind::Gone:
			break;
		case StopKind::Internal:
		{
			auto it = m_threads.find(tid);
			if (it != m_threads.end() && it->second.stopped && (m_continueMode || it->second.stepping))
				ResumeThread(tid);
			break;
		}
		case StopKind::Report:
			StopAll();
			if (!m_done)
				FinishStop(tid, stop);
			break;
		}
	}


	// Stops every thread that is still running, and waits for the new threads that have not reported yet.
	void PtraceEngine::StopAll()
	{
		while (!m_done)
		{
			pid_t next = -1;
			for (const auto& [tid, info] : m_threads)
			{
				if (!info.stopped)
				{
					next = tid;
					break;
				}
			}
			if (next < 0)
				return;

			auto& info = m_threads[next];
			if (!info.awaitingInitialStop && info.expectedStops == 0)
			{
				syscall(SYS_tgkill, m_pid, next, SIGSTOP);
				info.expectedStops++;
			}

			int status = 0;
			if (waitpid(next, &status, __WALL) < 0)
			{
				if (errno == EINTR)
					continue;
				status = 0;
			}
			Classify(next, status);
		}
	}


	void PtraceEngine::FinishStop(pid_t tid, const Classified& stop)
	{
		Event event;
		event.type = StoppedEvent;
		event.tid = tid;
		event.signal = stop.signal;
		event.interrupted = stop.interrupted;
		event.singleStep = m_threads[tid].stepping;

		for (auto& [id, info] : m_threads)
			info.stepping = false;
		m_running = false;
		Publish();
		PushEvent(event);
	}


	void PtraceEngine::FinishExit(int status)
	{
		m_done = true;
		m_running = false;
		Publish();
		StopIo();

		Event event;
		event.type = ExitedEvent;
		event.tid = m_pid;
		if (WIFEXITED(status))
			event.exitCode = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			event.signal = WTERMSIG(status);
		PushEvent(event);
	}


	bool PtraceEngine::DoResume(bool step, pid_t tid)
	{
		if (m_done || m_running)
			return false;
		if (step && m_threads.find(tid) == m_threads.end())
			return false;

		m_continueMode = !step;
		bool resumed = false;
		for (auto& [id, info] : m_threads)
		{
			if (!info.stopped || (step && id != tid))
				continue;

			info.stepping = step;
			resumed |= ResumeThread(id);
		}

		m_running = resumed;
		Publish();
		return resumed;
	}


	bool PtraceEngine::DoKill()
	{
		if (m_done)
			return false;

		kill(m_pid, SIGKILL);

		std::vector<pid_t> tids;
		for (const auto& [tid, info] : m_threads)
		{
			if (tid != m_pid)
				tids.push_back(tid);
		}
		tids.push_back(m_pid);

		int status = SIGKILL;
		for (pid_t tid : tids)
		{
			while (true)
			{
				int threadStatus = 0;
				if (waitpid(tid, &threadStatus, __WALL) < 0)
				{
					if (errno == EINTR)
						continue;
					break;
				}
				if (WIFEXITED(threadStatus) || WIFSIGNALED(threadStatus))
				{
					if (tid == m_pid)
						status = threadStatus;
					break;
				}
			}
		}

		m_threads.clear();
		FinishExit(status);
		return true;
	}


	bool PtraceEngine::DoDetach()
	{
		if (m_done)
			return false;

		StopAll();
		if (m_done)
			return false;

		// A SIGSTOP we sent that was never consumed would stop the target for good once we let go of it
		for (int attempt = 0; attempt < 8; attempt++)
		{
			pid_t pending = -1;
			for (const auto& [tid, info] : m_threads)
			{
				if (info.expectedStops > 0)
				{
					pending = tid;
					break;
				}
			}
			if (pending < 0)
				break;

			m_threads[pending].stepping = false;
			ResumeThread(pending);
			int status = 0;
			if (waitpid(pending, &status, __WALL) < 0)
				break;
			Classify(pending, status);
			if (m_done)
				return false;
		}

		for (const auto& [tid, info] : m_threads)
			ptrace(PTRACE_DETACH, tid, nullptr, (void*)(intptr_t)info.pendingSignal);

		m_threads.clear();
		m_done = true;
		m_running = false;
		Publish();
		StopIo();

		Event event;
		event.type = DetachedEvent;
		PushEvent(event);
		return true;
	}

}  // namespace BinaryNinjaDebugger
