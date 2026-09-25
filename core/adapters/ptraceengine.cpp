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
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <poll.h>
#include <sched.h>
#include <sys/uio.h>
#include <cstdio>
#include <sstream>
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
			RunOnTracer([this] { return m_attached ? DoDetach() : DoKill(); });
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
		if (m_memFd >= 0)
			close(m_memFd);
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


	bool PtraceEngine::Attach(uint32_t pid, std::string& error, const PtraceArch* arch)
	{
		m_options.arch = arch;
		m_attachPid = pid;
		m_attached = true;
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

		m_interruptWanted = true;

		// One signal on its way is enough, because the stop that it causes is the one that is wanted
		if (m_interruptInFlight++ > 0)
		{
			m_interruptInFlight--;
			return true;
		}
		if (kill(m_pid, SIGSTOP) != 0)
		{
			m_interruptInFlight--;
			return false;
		}
		return true;
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


	bool PtraceEngine::GetRegisterSet(uint32_t tid, int regset, std::vector<uint8_t>& data)
	{
		return RunOnTracer([this, tid, regset, &data] {
			auto it = m_threads.find(tid);
			if (m_done || m_running || it == m_threads.end() || !it->second.stopped)
				return false;

			return RawGetRegisterSet(tid, regset, data);
		});
	}


	bool PtraceEngine::SetRegisterSet(uint32_t tid, int regset, const std::vector<uint8_t>& data)
	{
		return RunOnTracer([this, tid, regset, &data] {
			auto it = m_threads.find(tid);
			if (m_done || m_running || it == m_threads.end() || !it->second.stopped)
				return false;

			return RawSetRegisterSet(tid, regset, data);
		});
	}


	bool PtraceEngine::RawReadMemory(uint64_t address, void* buffer, size_t size)
	{
		if (m_memFd < 0 || m_finished || address > INT64_MAX || size > INT64_MAX - address)
			return false;

		size_t done = 0;
		while (done < size)
		{
			auto count = pread(m_memFd, (char*)buffer + done, size - done, address + done);
			if (count < 0 && errno == EINTR)
				continue;
			if (count <= 0)
				return false;
			done += count;
		}
		return true;
	}


	bool PtraceEngine::RawWriteMemory(uint64_t address, const void* buffer, size_t size)
	{
		if (m_memFd < 0 || m_finished || address > INT64_MAX || size > INT64_MAX - address)
			return false;

		size_t done = 0;
		while (done < size)
		{
			auto count = pwrite(m_memFd, (const char*)buffer + done, size - done, address + done);
			if (count < 0 && errno == EINTR)
				continue;
			if (count <= 0)
				return false;
			done += count;
		}
		return true;
	}


	bool PtraceEngine::ReadMemory(uint64_t address, void* buffer, size_t size)
	{
		std::lock_guard<std::mutex> lock(m_breakpointMutex);
		if (!RawReadMemory(address, buffer, size))
			return false;

		for (const auto& [breakpointAddress, breakpoint] : m_breakpoints)
		{
			if (!breakpoint.inserted)
				continue;

			// Show the original bytes wherever the read overlaps a breakpoint
			for (size_t i = 0; i < breakpoint.original.size(); i++)
			{
				uint64_t byteAddress = breakpointAddress + i;
				if (byteAddress >= address && byteAddress - address < size)
					((uint8_t*)buffer)[byteAddress - address] = breakpoint.original[i];
			}
		}
		return true;
	}


	bool PtraceEngine::WriteMemory(uint64_t address, const void* buffer, size_t size)
	{
		std::lock_guard<std::mutex> lock(m_breakpointMutex);
		std::vector<uint8_t> data((const uint8_t*)buffer, (const uint8_t*)buffer + size);

		// The breakpoint bytes stay in place, and what was written becomes the bytes underneath them
		for (auto& [breakpointAddress, breakpoint] : m_breakpoints)
		{
			if (!breakpoint.inserted)
				continue;

			for (size_t i = 0; i < breakpoint.original.size(); i++)
			{
				uint64_t byteAddress = breakpointAddress + i;
				if (byteAddress >= address && byteAddress - address < size)
				{
					breakpoint.original[i] = data[byteAddress - address];
					data[byteAddress - address] = m_arch->breakpointInstruction[i];
				}
			}
		}
		return RawWriteMemory(address, data.data(), size);
	}


	std::vector<PtraceEngine::MapEntry> PtraceEngine::GetMaps() const
	{
		std::vector<MapEntry> maps;
		std::ifstream file("/proc/" + std::to_string(m_pid) + "/maps");
		std::string line;
		while (std::getline(file, line))
		{
			unsigned long long start, end, offset;
			char permissions[8] = {};
			int consumed = 0;
			if (sscanf(line.c_str(), "%llx-%llx %7s %llx %*s %*s %n", &start, &end, permissions, &offset, &consumed)
				< 4)
				continue;

			MapEntry entry;
			entry.start = start;
			entry.end = end;
			entry.offset = offset;
			entry.read = permissions[0] == 'r';
			entry.write = permissions[1] == 'w';
			entry.execute = permissions[2] == 'x';
			entry.shared = permissions[3] == 's';
			if (consumed > 0 && (size_t)consumed < line.size())
				entry.path = line.substr(consumed);
			maps.push_back(entry);
		}
		return maps;
	}


	bool PtraceEngine::RawGetRegisterSet(pid_t tid, int regset, std::vector<uint8_t>& data)
	{
		// The largest register set, the extended state, can be a few kilobytes
		std::vector<uint8_t> buffer(16384);
		iovec vec {buffer.data(), buffer.size()};
		if (ptrace(PTRACE_GETREGSET, tid, (void*)(uintptr_t)regset, &vec) != 0)
			return false;

		buffer.resize(vec.iov_len);
		data = std::move(buffer);
		return true;
	}


	bool PtraceEngine::RawSetRegisterSet(pid_t tid, int regset, const std::vector<uint8_t>& data)
	{
		iovec vec {const_cast<uint8_t*>(data.data()), data.size()};
		return ptrace(PTRACE_SETREGSET, tid, (void*)(uintptr_t)regset, &vec) == 0;
	}


	bool PtraceEngine::ReadPc(pid_t tid, uint64_t& pc)
	{
		auto reg = m_arch ? m_arch->Find(m_arch->pc) : nullptr;
		std::vector<uint8_t> data;
		if (!reg || !RawGetRegisterSet(tid, reg->regset, data) || reg->offset + reg->size > data.size())
			return false;

		pc = 0;
		memcpy(&pc, data.data() + reg->offset, std::min(reg->size, sizeof(pc)));
		return true;
	}


	bool PtraceEngine::WritePc(pid_t tid, uint64_t pc)
	{
		auto reg = m_arch ? m_arch->Find(m_arch->pc) : nullptr;
		std::vector<uint8_t> data;
		if (!reg || !RawGetRegisterSet(tid, reg->regset, data) || reg->offset + reg->size > data.size())
			return false;

		memcpy(data.data() + reg->offset, &pc, std::min(reg->size, sizeof(pc)));
		return RawSetRegisterSet(tid, reg->regset, data);
	}


	bool PtraceEngine::AddBreakpoint(uint64_t address)
	{
		return RunOnTracer([this, address] { return DoAddBreakpoint(address); });
	}


	bool PtraceEngine::RemoveBreakpoint(uint64_t address)
	{
		return RunOnTracer([this, address] { return DoRemoveBreakpoint(address); });
	}


	bool PtraceEngine::AddHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size)
	{
		return RunOnTracer([this, address, type, size] { return DoAddHardwareBreakpoint(address, type, size); });
	}


	bool PtraceEngine::RemoveHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size)
	{
		return RunOnTracer([this, address, type, size] { return DoRemoveHardwareBreakpoint(address, type, size); });
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


	void PtraceEngine::PostTask(std::function<void()> task)
	{
		Event event;
		event.type = TaskEvent;
		event.task = std::move(task);
		PushEvent(event);
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
			if (event.type == TaskEvent)
				event.task();
			else
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

		// The descriptors that we keep for ourselves are kept above every one that the redirects name, so that setting
		// those up cannot get in their way
		int firstFreeFd = 10;
		for (const auto& redirect : m_options.redirects)
		{
			firstFreeFd = std::max(firstFreeFd, redirect.fd + 1);
			if (redirect.kind == FdRedirect::Duplicate)
				firstFreeFd = std::max(firstFreeFd, redirect.source + 1);
		}

		std::vector<int> redirectFds(m_options.redirects.size(), -1);
		auto closeRedirectFds = [&redirectFds]() {
			for (int fd : redirectFds)
			{
				if (fd >= 0)
					close(fd);
			}
		};

		for (size_t i = 0; i < m_options.redirects.size(); i++)
		{
			const auto& redirect = m_options.redirects[i];
			if (redirect.kind != FdRedirect::OpenFile)
				continue;

			std::string redirectPath = redirect.path;
			if (workingDir && !redirectPath.empty() && redirectPath[0] != '/')
				redirectPath = std::string(workingDir) + "/" + redirectPath;

			int fd = open(redirectPath.c_str(), redirect.flags | O_CLOEXEC, 0666);
			int moved = fd >= 0 ? fcntl(fd, F_DUPFD_CLOEXEC, firstFreeFd) : -1;
			int error = errno;
			if (fd >= 0)
				close(fd);
			if (moved < 0)
			{
				closeRedirectFds();
				return "failed to open " + redirectPath + " for file descriptor " + std::to_string(redirect.fd) + ": "
					+ strerror(error);
			}
			redirectFds[i] = moved;
		}

		int errorPipe[2];
		if (pipe2(errorPipe, O_CLOEXEC) != 0)
		{
			closeRedirectFds();
			return std::string("failed to create a pipe: ") + strerror(errno);
		}
		int movedPipe = fcntl(errorPipe[1], F_DUPFD_CLOEXEC, firstFreeFd);
		if (movedPipe < 0)
		{
			int error = errno;
			close(errorPipe[0]);
			close(errorPipe[1]);
			closeRedirectFds();
			return std::string("failed to create a pipe: ") + strerror(error);
		}
		close(errorPipe[1]);
		errorPipe[1] = movedPipe;

		pid_t pid = fork();
		if (pid < 0)
		{
			int error = errno;
			close(errorPipe[0]);
			close(errorPipe[1]);
			closeRedirectFds();
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

			for (size_t i = 0; i < m_options.redirects.size(); i++)
			{
				const auto& redirect = m_options.redirects[i];
				switch (redirect.kind)
				{
				case FdRedirect::OpenFile:
					if (dup2(redirectFds[i], redirect.fd) < 0)
						ChildFail(errorPipe[1]);
					break;
				case FdRedirect::Duplicate:
					if (dup2(redirect.source, redirect.fd) < 0)
						ChildFail(errorPipe[1]);
					break;
				case FdRedirect::Close:
					close(redirect.fd);
					break;
				}
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
		closeRedirectFds();
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

		ptrace(PTRACE_SETOPTIONS, pid, nullptr,
			(void*)(uintptr_t)(PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
				| PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXEC));

		m_pid = pid;
		AdoptTarget();
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


	void PtraceEngine::AdoptTarget()
	{
		m_memFd = open(("/proc/" + std::to_string(m_pid) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
		m_arch = m_options.arch ? m_options.arch : DetectPtraceArch(m_pid);
		if (m_arch && m_arch->hwDebug)
			m_hardwareSlots.resize(m_arch->hwDebug->SlotCount());
	}


	static std::string AttachErrorMessage(pid_t pid, int error)
	{
		std::string message = "failed to attach to process " + std::to_string(pid) + ": " + strerror(error);
		if (error == ESRCH)
			return message;

		std::string line;
		std::ifstream status("/proc/" + std::to_string(pid) + "/status");
		while (std::getline(status, line))
		{
			if (line.rfind("TracerPid:", 0) == 0 && atoi(line.c_str() + 10) > 0)
				return message + " (it is already being traced by process " + std::to_string(atoi(line.c_str() + 10)) + ")";
		}

		if (error == EPERM || error == EACCES)
		{
			std::ifstream yama("/proc/sys/kernel/yama/ptrace_scope");
			int scope = 0;
			if (yama >> scope && scope > 0)
				message += " (kernel.yama.ptrace_scope is " + std::to_string(scope)
					+ ", so only descendants of the debugger can be traced without extra privileges)";
		}
		return message;
	}


	std::string PtraceEngine::AttachToProcess()
	{
		pid_t pid = m_attachPid;
		auto listThreads = [pid]() {
			std::vector<pid_t> tids;
			std::error_code error;
			for (const auto& entry : std::filesystem::directory_iterator("/proc/" + std::to_string(pid) + "/task", error))
			{
				pid_t tid = atoi(entry.path().filename().c_str());
				if (tid > 0)
					tids.push_back(tid);
			}
			return tids;
		};

		if (listThreads().empty())
			return "failed to attach to process " + std::to_string(pid) + ": there is no such process";

		std::vector<pid_t> attached;
		auto detachAll = [&attached]() {
			for (pid_t tid : attached)
				ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
		};

		// A thread can be created while the others are being stopped, so go over the list until nothing is new
		bool foundNew = true;
		for (int round = 0; foundNew && round < 32; round++)
		{
			foundNew = false;
			for (pid_t tid : listThreads())
			{
				if (std::find(attached.begin(), attached.end(), tid) != attached.end())
					continue;
				foundNew = true;

				if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != 0)
				{
					int error = errno;
					if (tid != pid && error == ESRCH)
						continue;
					detachAll();
					return AttachErrorMessage(pid, error);
				}

				// A signal can reach the thread before the SIGSTOP that attaching sends. It is passed on, and the
				// SIGSTOP comes after it.
				bool stopped = false;
				bool gone = false;
				for (int attempt = 0; attempt < 16 && !stopped && !gone; attempt++)
				{
					int status = 0;
					if (waitpid(tid, &status, __WALL) < 0)
					{
						if (errno == EINTR)
							continue;
						gone = true;
					}
					else if (WIFEXITED(status) || WIFSIGNALED(status))
					{
						gone = true;
					}
					else if (WIFSTOPPED(status))
					{
						int signal = WSTOPSIG(status);
						if (signal == SIGSTOP)
							stopped = true;
						else
							ptrace(PTRACE_CONT, tid, nullptr, (void*)(intptr_t)(signal == SIGTRAP ? 0 : signal));
					}
				}

				if (!stopped)
				{
					if (!gone)
					{
						attached.push_back(tid);
						detachAll();
						return "failed to attach to process " + std::to_string(pid) + ": thread " + std::to_string(tid)
							+ " did not stop";
					}
					if (tid == pid)
					{
						detachAll();
						return "failed to attach to process " + std::to_string(pid) + ": it exited";
					}
					continue;
				}
				attached.push_back(tid);
			}
		}

		for (pid_t tid : attached)
			ptrace(PTRACE_SETOPTIONS, tid, nullptr,
				(void*)(uintptr_t)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
					| PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXEC));

		m_pid = pid;
		AdoptTarget();
		for (pid_t tid : attached)
		{
			ThreadInfo info;
			info.stopped = true;
			m_threads[tid] = info;
		}
		auto& leader = m_threads[pid];
		leader.atReportedStop = ReadPc(pid, leader.reportedPc);
		Publish();

		Event event;
		event.type = StoppedEvent;
		event.tid = pid;
		event.signal = SIGSTOP;
		PushEvent(event);
		return "";
	}


	void PtraceEngine::TracerMain()
	{
		std::string error = m_attached ? AttachToProcess() : Spawn();
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


	bool PtraceEngine::HasBreakpointAt(uint64_t address)
	{
		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			auto it = m_breakpoints.find(address);
			if (it != m_breakpoints.end() && it->second.inserted)
				return true;
		}

		for (const auto& slot : m_hardwareSlots)
		{
			if (slot.used && slot.type == PtraceHwType::Execute && slot.address == address)
				return true;
		}
		return false;
	}


	// Works out why a thread stopped with SIGTRAP. Returns false if the stop is not worth reporting.
	bool PtraceEngine::ClassifyTrap(pid_t tid, ThreadInfo& info, Classified& result)
	{
		siginfo_t signalInfo {};
		bool haveInfo = ptrace(PTRACE_GETSIGINFO, tid, nullptr, &signalInfo) == 0;
		int code = haveInfo ? signalInfo.si_code : 0;

		if (code == TRAP_HWBKPT)
		{
			if (m_arch && m_arch->hwDebug)
				m_arch->hwDebug->OnTrap(tid);
			result.hardware = true;
			return true;
		}

		if (code == TRAP_TRACE)
		{
			result.stepTrap = true;
			return true;
		}

		uint64_t pc = 0;
		if (m_arch && !m_arch->breakpointInstruction.empty() && ReadPc(tid, pc))
		{
			uint64_t address = pc - m_arch->breakpointPcAdjust;
			bool ours;
			{
				std::lock_guard<std::mutex> lock(m_breakpointMutex);
				auto it = m_breakpoints.find(address);
				ours = it != m_breakpoints.end() && it->second.inserted;
			}
			bool removed = !ours && m_recentlyRemoved.count(address);

			if (ours || removed)
			{
				if (m_arch->breakpointPcAdjust)
					WritePc(tid, address);
				// A thread that trapped on a breakpoint that has just been removed only needs to run again
				if (removed)
					return false;

				result.breakpoint = true;
				return true;
			}
		}

		// Stepping over a system call traps like a breakpoint on x86, so this is a step if we asked for one
		if (info.stepping)
			result.stepTrap = true;
		return true;
	}


	PtraceEngine::Classified PtraceEngine::Classify(pid_t tid, int status)
	{
		Classified result;

		// The breakpoint that a thread is stepping over goes back once the thread reports a stop, but not while it is
		// only passing through an internal one
		auto endGuard = [this, tid](bool threadAlive) {
			auto it = m_threads.find(tid);
			if (it != m_threads.end() && (it->second.guardSoftware || !it->second.guardSlots.empty()))
				EndGuard(tid, threadAlive);
		};

		if (!WIFSTOPPED(status))
		{
			endGuard(false);
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
		int handlerSignal = info.handlerSignal;
		info.handlerSignal = 0;

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
		if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK)
		{
			unsigned long child = 0;
			ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &child);
			HandleFork((pid_t)child, event == PTRACE_EVENT_VFORK);
			return result;
		}
		if (event == PTRACE_EVENT_EXEC)
			return HandleExec(tid);
		if (event == PTRACE_EVENT_VFORK_DONE)
		{
			if (m_vforkPending > 0 && --m_vforkPending == 0)
				ResumeBreakpointsAfterVfork();
			return result;
		}
		if (event != 0)
			return result;

		// The thread has been resumed into the handler of a signal, and this is where it has got to
		if (handlerSignal && signal == SIGTRAP)
		{
			endGuard(true);
			result.kind = StopKind::Report;
			result.signal = SIGTRAP;
			result.signalHandler = handlerSignal;
			return result;
		}

		if (signal == SIGSTOP)
		{
			if (info.awaitingInitialStop)
			{
				info.awaitingInitialStop = false;
				ApplyHardwareToThread(tid);
				return result;
			}
			if (info.expectedStops > 0)
			{
				info.expectedStops--;
				return result;
			}
			if (m_interruptInFlight > 0)
			{
				m_interruptInFlight--;
				// The pause may have been given by another stop since, and then this signal is only left over
				if (m_interruptWanted.exchange(false))
				{
					endGuard(true);
					result.kind = StopKind::Report;
					result.interrupted = true;
				}
				return result;
			}
		}

		if (IsSilentSignal(signal))
		{
			info.pendingSignal = signal;
			return result;
		}

		if (signal == SIGTRAP)
		{
			if (!ClassifyTrap(tid, info, result))
				return result;
		}
		else
		{
			info.pendingSignal = signal;
		}

		endGuard(true);
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
		bool step = info.stepping;

		// Resuming with a single step and a signal delivers the signal and stops at the first instruction of its
		// handler
		info.handlerSignal = 0;
		if (signal && !step && m_debugSignalHandlers && HasSignalHandler(signal))
		{
			step = true;
			info.handlerSignal = signal;
		}

		auto request = step ? PTRACE_SINGLESTEP : PTRACE_CONT;
		return ptrace(request, tid, nullptr, (void*)(intptr_t)signal) == 0 || errno == ESRCH;
	}


	// The signals that the target has a handler for are the ones that /proc lists as caught
	bool PtraceEngine::HasSignalHandler(int signal)
	{
		std::ifstream file("/proc/" + std::to_string(m_pid) + "/status");
		std::string line;
		while (std::getline(file, line))
		{
			if (line.rfind("SigCgt:", 0) != 0)
				continue;

			uint64_t caught = strtoull(line.c_str() + strlen("SigCgt:"), nullptr, 16);
			return signal >= 1 && signal <= 64 && (caught >> (signal - 1)) & 1;
		}
		return false;
	}


	bool PtraceEngine::NeedsStepOver(pid_t tid, const ThreadInfo& info)
	{
		uint64_t pc;
		return info.atReportedStop && ReadPc(tid, pc) && pc == info.reportedPc
			&& (info.hardwareBeforeAccess || HasBreakpointAt(pc));
	}


	// Lifts the breakpoints at an address, so that a thread can execute the instruction there
	void PtraceEngine::BeginGuard(pid_t tid, uint64_t address)
	{
		auto& info = m_threads[tid];
		info.guardAddress = address;

		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			auto it = m_breakpoints.find(address);
			if (it != m_breakpoints.end() && it->second.inserted)
			{
				RawWriteMemory(address, it->second.original.data(), it->second.original.size());
				it->second.inserted = false;
				info.guardSoftware = true;
			}
		}

		// A watchpoint that reports before the access has to be lifted altogether, since we do not know which one it
		// was
		for (size_t i = 0; i < m_hardwareSlots.size(); i++)
		{
			const auto& slot = m_hardwareSlots[i];
			if (slot.used
				&& (info.hardwareBeforeAccess || (slot.type == PtraceHwType::Execute && slot.address == address)))
			{
				m_arch->hwDebug->Clear(tid, i);
				info.guardSlots.push_back(i);
			}
		}
	}


	void PtraceEngine::EndGuard(pid_t tid, bool threadAlive)
	{
		auto& info = m_threads[tid];
		if (info.guardSoftware)
		{
			info.guardSoftware = false;
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			auto it = m_breakpoints.find(info.guardAddress);
			if (it != m_breakpoints.end() && !it->second.inserted && !it->second.suspended)
			{
				RawWriteMemory(
					info.guardAddress, m_arch->breakpointInstruction.data(), m_arch->breakpointInstruction.size());
				it->second.inserted = true;
			}
		}

		info.hardwareBeforeAccess = false;
		auto slots = std::move(info.guardSlots);
		info.guardSlots.clear();
		for (size_t index : slots)
		{
			const auto& slot = m_hardwareSlots[index];
			if (threadAlive && slot.used)
				m_arch->hwDebug->Set(tid, index, slot.address, slot.type, slot.size);
		}
	}


	bool PtraceEngine::ResumeAll()
	{
		bool resumed = false;
		for (auto& [id, info] : m_threads)
		{
			if (!info.stopped)
				continue;

			info.stepping = false;
			resumed |= ResumeThread(id);
		}
		return resumed;
	}


	// Runs one thread past a breakpoint while all the others stay stopped, and then lets everything run
	bool PtraceEngine::StartNextStepOver()
	{
		while (!m_stepOverQueue.empty())
		{
			pid_t tid = m_stepOverQueue.front();
			m_stepOverQueue.erase(m_stepOverQueue.begin());

			auto it = m_threads.find(tid);
			uint64_t pc;
			if (it == m_threads.end() || !it->second.stopped || !ReadPc(tid, pc))
				continue;

			BeginGuard(tid, pc);
			it->second.stepping = true;
			m_stepOverTid = tid;
			return ResumeThread(tid);
		}

		m_stepOverTid = -1;
		return ResumeAll();
	}


	// A child of the target starts out as a copy of it, breakpoints included, and it is not ours to debug. So the
	// breakpoints come out of it, and it is let go.
	void PtraceEngine::HandleFork(pid_t child, bool sharedMemory)
	{
		// It is stopped from the start, and has to be seen to before it can be let go
		int status = 0;
		pid_t result;
		do
		{
			result = waitpid(child, &status, __WALL);
		} while (result < 0 && errno == EINTR);
		if (result < 0 || !WIFSTOPPED(status))
			return;

		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			if (sharedMemory)
			{
				// There is only one memory, so the breakpoints are out of the target for as long as the child uses it
				for (auto& [address, breakpoint] : m_breakpoints)
				{
					if (!breakpoint.inserted)
						continue;

					RawWriteMemory(address, breakpoint.original.data(), breakpoint.original.size());
					breakpoint.inserted = false;
					breakpoint.suspended = true;
				}
				m_vforkPending++;
			}
			else
			{
				int fd = open(("/proc/" + std::to_string(child) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
				if (fd >= 0)
				{
					for (const auto& [address, breakpoint] : m_breakpoints)
					{
						{
							if (!breakpoint.inserted)
								continue;

							// Best effort: a child that cannot be written to is simply let go
							[[maybe_unused]] auto written =
								pwrite(fd, breakpoint.original.data(), breakpoint.original.size(), address);
						}
					}
					close(fd);
				}
			}
		}

		ptrace(PTRACE_DETACH, child, nullptr, nullptr);
	}


	// The target has started another program. Nothing of the old one is left: not its threads, its memory, its
	// breakpoints or its debug registers. So this starts over, and the stop is reported so that the owner can set the
	// new program up before it runs.
	PtraceEngine::Classified PtraceEngine::HandleExec(pid_t tid)
	{
		// Every thread but one is gone, and that one is the leader from now on, whichever thread it was before
		std::vector<pid_t> gone;
		bool stepping = false;
		int expectedStops = 0;
		for (const auto& [id, info] : m_threads)
		{
			if (id != m_pid)
				gone.push_back(id);
			if (id == tid)
				stepping = info.stepping;
			if (id == m_pid)
				expectedStops = info.expectedStops;
		}

		ThreadInfo leader;
		leader.stopped = true;
		leader.stepping = stepping;
		leader.expectedStops = expectedStops;
		m_threads.clear();
		m_threads[m_pid] = leader;

		// Whatever is left of the threads that were killed
		for (pid_t id : gone)
		{
			int status;
			waitpid(id, &status, __WALL | WNOHANG);
		}

		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			int fd = open(("/proc/" + std::to_string(m_pid) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
			if (m_memFd >= 0)
				close(m_memFd);
			m_memFd = fd;
			m_breakpoints.clear();
			m_arch = m_options.arch ? m_options.arch : DetectPtraceArch(m_pid);
		}

		m_recentlyRemoved.clear();
		m_stepOverQueue.clear();
		m_stepOverTid = -1;
		m_vforkPending = 0;
		m_hardwareSlots.assign(m_arch && m_arch->hwDebug ? m_arch->hwDebug->SlotCount() : 0, HardwareSlot());
		Publish();

		Classified result;
		result.kind = StopKind::Report;
		result.signal = SIGTRAP;
		result.exec = true;
		result.tid = m_pid;
		return result;
	}


	void PtraceEngine::ResumeBreakpointsAfterVfork()
	{
		std::lock_guard<std::mutex> lock(m_breakpointMutex);
		const auto& instruction = m_arch->breakpointInstruction;
		for (auto& [address, breakpoint] : m_breakpoints)
		{
			if (!breakpoint.suspended)
				continue;

			// The child may have changed what is there
			breakpoint.suspended = false;
			if (RawReadMemory(address, breakpoint.original.data(), instruction.size())
				&& RawWriteMemory(address, instruction.data(), instruction.size()))
				breakpoint.inserted = true;
		}
	}


	void PtraceEngine::ApplyHardwareToThread(pid_t tid)
	{
		for (size_t i = 0; i < m_hardwareSlots.size(); i++)
		{
			const auto& slot = m_hardwareSlots[i];
			if (slot.used)
				m_arch->hwDebug->Set(tid, i, slot.address, slot.type, slot.size);
		}
	}


	void PtraceEngine::HandleStatus(pid_t tid, int status)
	{
		auto stop = Classify(tid, status);
		bool steppingOver = tid == m_stepOverTid;
		switch (stop.kind)
		{
		case StopKind::Gone:
			if (steppingOver && !m_done)
			{
				m_stepOverTid = -1;
				StartNextStepOver();
			}
			break;
		case StopKind::Internal:
		{
			auto it = m_threads.find(tid);
			if (it != m_threads.end() && it->second.stopped
				&& ((m_continueMode && m_stepOverTid < 0) || it->second.stepping))
				ResumeThread(tid);
			break;
		}
		case StopKind::Report:
			if (steppingOver && stop.stepTrap)
			{
				m_threads[tid].stepping = false;
				m_stepOverTid = -1;
				StartNextStepOver();
				break;
			}
			if (steppingOver)
			{
				m_stepOverTid = -1;
				m_stepOverQueue.clear();
			}
			StopAll();
			if (!m_done)
				FinishStop(stop.tid ? stop.tid : tid, stop);
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
		event.breakpoint = stop.breakpoint;
		event.hardware = stop.hardware;
		event.exec = stop.exec;
		event.signalHandler = stop.signalHandler;
		event.singleStep = m_threads[tid].stepping;

		for (auto& [id, info] : m_threads)
			info.stepping = false;

		// Once everything is stopped, no thread can still trap on a breakpoint that was removed
		m_recentlyRemoved.clear();
		// Any stop is a pause, so a request for one that has not been seen yet is answered
		m_interruptWanted = false;

		auto& info = m_threads[tid];
		info.atReportedStop = ReadPc(tid, info.reportedPc);
		info.hardwareBeforeAccess =
			stop.hardware && m_arch && m_arch->hwDebug && m_arch->hwDebug->DataTrapsBeforeAccess();
		// The first instruction of a program is where a breakpoint of the new program may be, and it has not run yet
		if (stop.exec)
			info.atReportedStop = false;

		m_running = false;
		Publish();
		PushEvent(event);
	}


	void PtraceEngine::FinishExit(int status)
	{
		m_done = true;
		m_finished = true;
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

		auto stepping = m_threads.find(tid);
		if (step && (stepping == m_threads.end() || !stepping->second.stopped))
			return false;

		m_continueMode = !step;
		std::vector<pid_t> stepOver;
		for (auto& [id, info] : m_threads)
		{
			if (!info.stopped || (step && id != tid))
				continue;

			if (NeedsStepOver(id, info))
				stepOver.push_back(id);
			info.atReportedStop = false;
		}

		bool resumed;
		if (step)
		{
			uint64_t pc;
			if (!stepOver.empty() && ReadPc(tid, pc))
				BeginGuard(tid, pc);

			stepping->second.stepping = true;
			resumed = ResumeThread(tid);
		}
		else if (!stepOver.empty())
		{
			m_stepOverQueue = stepOver;
			resumed = StartNextStepOver();
		}
		else
		{
			resumed = ResumeAll();
		}

		m_running = resumed;
		Publish();
		return resumed;
	}


	bool PtraceEngine::DoAddBreakpoint(uint64_t address)
	{
		if (m_done || !m_arch || m_arch->breakpointInstruction.empty())
			return false;

		std::lock_guard<std::mutex> lock(m_breakpointMutex);
		if (m_breakpoints.count(address))
			return true;

		const auto& instruction = m_arch->breakpointInstruction;
		Breakpoint breakpoint;
		breakpoint.original.resize(instruction.size());
		if (!RawReadMemory(address, breakpoint.original.data(), instruction.size()))
			return false;

		// While a child shares the memory it must not run into a new breakpoint either
		if (m_vforkPending > 0)
		{
			breakpoint.suspended = true;
		}
		else
		{
			if (!RawWriteMemory(address, instruction.data(), instruction.size()))
				return false;
			breakpoint.inserted = true;
		}
		m_breakpoints[address] = std::move(breakpoint);
		return true;
	}


	bool PtraceEngine::DoRemoveBreakpoint(uint64_t address)
	{
		std::lock_guard<std::mutex> lock(m_breakpointMutex);
		auto it = m_breakpoints.find(address);
		if (it == m_breakpoints.end())
			return false;

		if (it->second.inserted && !m_done)
			RawWriteMemory(address, it->second.original.data(), it->second.original.size());
		m_breakpoints.erase(it);

		// A thread that is running may just have trapped on it
		if (m_running)
			m_recentlyRemoved.insert(address);
		return true;
	}


	bool PtraceEngine::DoAddHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size)
	{
		if (m_done || m_running || !m_arch || !m_arch->hwDebug)
			return false;

		for (const auto& slot : m_hardwareSlots)
		{
			if (slot.used && slot.address == address && slot.type == type && slot.size == size)
				return true;
		}

		size_t index = 0;
		while (index < m_hardwareSlots.size()
			&& (m_hardwareSlots[index].used || !m_arch->hwDebug->SlotSupports(index, type)))
			index++;
		if (index == m_hardwareSlots.size())
			return false;

		std::vector<pid_t> programmed;
		for (const auto& [tid, info] : m_threads)
		{
			if (!info.stopped)
				continue;
			if (!m_arch->hwDebug->Set(tid, index, address, type, size))
			{
				for (pid_t done : programmed)
					m_arch->hwDebug->Clear(done, index);
				return false;
			}
			programmed.push_back(tid);
		}

		m_hardwareSlots[index] = {true, address, type, size};
		return true;
	}


	bool PtraceEngine::DoRemoveHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size)
	{
		if (m_done || m_running || !m_arch || !m_arch->hwDebug)
			return false;

		for (size_t index = 0; index < m_hardwareSlots.size(); index++)
		{
			auto& slot = m_hardwareSlots[index];
			if (!slot.used || slot.address != address || slot.type != type || slot.size != size)
				continue;

			for (const auto& [tid, info] : m_threads)
			{
				if (info.stopped)
					m_arch->hwDebug->Clear(tid, index);
			}
			slot.used = false;
			return true;
		}
		return false;
	}


	// Puts the target back the way it was before we let go of it
	void PtraceEngine::RemoveAllBreakpoints()
	{
		for (auto& [tid, info] : m_threads)
		{
			if (info.guardSoftware || !info.guardSlots.empty())
				EndGuard(tid, true);
		}

		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			for (auto& [address, breakpoint] : m_breakpoints)
			{
				if (breakpoint.inserted)
					RawWriteMemory(address, breakpoint.original.data(), breakpoint.original.size());
			}
			m_breakpoints.clear();
		}

		for (size_t index = 0; index < m_hardwareSlots.size(); index++)
		{
			if (!m_hardwareSlots[index].used)
				continue;

			for (const auto& [tid, info] : m_threads)
				m_arch->hwDebug->Clear(tid, index);
			m_hardwareSlots[index].used = false;
		}
		m_stepOverQueue.clear();
		m_stepOverTid = -1;
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

		RemoveAllBreakpoints();
		for (const auto& [tid, info] : m_threads)
			ptrace(PTRACE_DETACH, tid, nullptr, (void*)(intptr_t)info.pendingSignal);

		m_threads.clear();
		m_done = true;
		m_finished = true;
		m_running = false;
		Publish();
		StopIo();

		Event event;
		event.type = DetachedEvent;
		PushEvent(event);
		return true;
	}


	bool ParseFdRedirect(const std::string& text, PtraceEngine::FdRedirect& redirect, std::string& error)
	{
		using Redirect = PtraceEngine::FdRedirect;
		redirect = Redirect();

		size_t i = 0;
		auto skipSpace = [&]() {
			while (i < text.size() && isspace((unsigned char)text[i]))
				i++;
		};
		auto readNumber = [&](int& value) {
			size_t start = i;
			long result = 0;
			while (i < text.size() && isdigit((unsigned char)text[i]))
			{
				result = result * 10 + (text[i] - '0');
				if (result > 1000000)
					return false;
				i++;
			}
			value = (int)result;
			return i > start;
		};

		skipSpace();
		int fd = -1;
		if (i < text.size() && isdigit((unsigned char)text[i]) && !readNumber(fd))
		{
			error = "the file descriptor is too large: " + text;
			return false;
		}
		if (i >= text.size() || (text[i] != '<' && text[i] != '>'))
		{
			error = "expected < or > after the file descriptor: " + text;
			return false;
		}

		bool input = text[i++] == '<';
		if (fd < 0)
			fd = input ? 0 : 1;
		redirect.fd = fd;

		if (i < text.size() && text[i] == '&')
		{
			i++;
			skipSpace();
			if (i < text.size() && text[i] == '-')
			{
				i++;
				redirect.kind = Redirect::Close;
			}
			else
			{
				redirect.kind = Redirect::Duplicate;
				if (!readNumber(redirect.source))
				{
					error = "expected a file descriptor or - after &: " + text;
					return false;
				}
			}
			skipSpace();
			if (i != text.size())
			{
				error = "unexpected text after the file descriptor: " + text;
				return false;
			}
			return true;
		}

		if (input)
		{
			if (i < text.size() && text[i] == '>')
			{
				i++;
				redirect.flags = O_RDWR | O_CREAT;
			}
			else
			{
				redirect.flags = O_RDONLY;
			}
		}
		else if (i < text.size() && text[i] == '>')
		{
			i++;
			redirect.flags = O_WRONLY | O_CREAT | O_APPEND;
		}
		else
		{
			redirect.flags = O_WRONLY | O_CREAT | O_TRUNC;
		}

		skipSpace();
		redirect.kind = Redirect::OpenFile;
		redirect.path = text.substr(i);
		while (!redirect.path.empty() && isspace((unsigned char)redirect.path.back()))
			redirect.path.pop_back();
		if (redirect.path.empty())
		{
			error = "expected a path: " + text;
			return false;
		}
		return true;
	}

}  // namespace BinaryNinjaDebugger
