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
#include <cinttypes>
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
#include <cstddef>
#include <cstdio>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// Older headers do not have these
#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef PTRACE_SET_SYSCALL_INFO
#define PTRACE_SET_SYSCALL_INFO 0x4212
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif

namespace BinaryNinjaDebugger {

	// struct ptrace_syscall_info of the kernel
	struct KernelSyscallInfo
	{
		uint8_t op;
		uint8_t reserved;
		uint16_t flags;
		uint32_t arch;
		uint64_t instructionPointer;
		uint64_t stackPointer;
		union
		{
			struct
			{
				uint64_t number;
				uint64_t args[6];
			} entry;
			struct
			{
				int64_t returnValue;
				uint8_t isError;
			} exit;
			struct
			{
				uint64_t number;
				uint64_t args[6];
				uint32_t data;
			} seccomp;
		};
	};

	static_assert(sizeof(KernelSyscallInfo) == 88, "struct ptrace_syscall_info");

	enum : uint8_t
	{
		KernelSyscallInfoNone = 0,
		KernelSyscallInfoEntry = 1,
		KernelSyscallInfoExit = 2,
		KernelSyscallInfoSeccomp = 3
	};

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


	PtraceEngine::PtraceEngine(EventHandler handler) : m_core(std::make_shared<EventCore>())
	{
		m_core->handler = std::make_shared<const EventHandler>(std::move(handler));
	}


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
			// Nothing is called after this, and what was queued is dropped
			{
				std::lock_guard<std::mutex> lock(m_core->mutex);
				m_core->stop = true;
				m_core->handler.reset();
				m_core->events.clear();
			}
			m_core->cv.notify_all();

			if (m_eventThread.get_id() == std::this_thread::get_id())
			{
				// Destroyed by its own handler, which cannot wait for itself
				m_eventThread.detach();
			}
			else
			{
				std::unique_lock<std::mutex> lock(m_core->mutex);
				bool finished = m_core->doneCv.wait_for(
					lock, std::chrono::milliseconds(m_teardownWaitMs.load()), [this] { return m_core->done; });
				lock.unlock();
				if (finished)
					m_eventThread.join();
				else
					m_eventThread.detach();
			}
		}

		if (m_masterFd >= 0)
			close(m_masterFd);
		if (m_memFd >= 0)
			close(m_memFd);
	}


	PtraceEngine::WaitResult PtraceEngine::WaitForThread(pid_t tid, int& status, std::chrono::milliseconds timeout)
	{
		auto deadline = std::chrono::steady_clock::now() + timeout;
		int idle = 0;
		while (true)
		{
			pid_t result = waitpid(tid, &status, __WALL | WNOHANG);
			if (result == tid)
				return WaitResult::Status;
			if (result < 0)
			{
				if (errno == EINTR)
					continue;
				return WaitResult::Gone;
			}
			if (std::chrono::steady_clock::now() >= deadline)
				return WaitResult::Timeout;

			// A thread that was asked to stop usually has by the time it is looked at again, so yield first
			if (++idle < 50)
				sched_yield();
			else
				std::this_thread::sleep_for(std::chrono::microseconds(50 << std::min((idle - 50) / 20, 5)));
		}
	}


	// Kills a task that is ours and waits a while for it to be gone
	void PtraceEngine::KillAndReap(pid_t pid)
	{
		kill(pid, SIGKILL);
		auto deadline = std::chrono::steady_clock::now() + WaitTimeout();
		while (true)
		{
			int status = 0;
			auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
			auto result = WaitForThread(pid, status, std::max(remaining, std::chrono::milliseconds(0)));
			if (result != WaitResult::Status || WIFEXITED(status) || WIFSIGNALED(status))
				return;
		}
	}


	static std::string ToHex(uint64_t value)
	{
		char buffer[32];
		snprintf(buffer, sizeof(buffer), "%" PRIx64, value);
		return buffer;
	}


	// The thread group that a task belongs to, or -1 if there is no such task
	pid_t PtraceEngine::ThreadGroupOf(pid_t tid)
	{
		std::ifstream status("/proc/" + std::to_string(tid) + "/status");
		std::string line;
		while (std::getline(status, line))
		{
			if (line.rfind("Tgid:", 0) == 0)
				return atoi(line.c_str() + 5);
		}
		return -1;
	}


	// The threads that were given up on, for an event. The ones that are not in m_threads are only told once.
	std::vector<uint32_t> PtraceEngine::TakeUnresponsive()
	{
		std::vector<uint32_t> result = std::move(m_lingering);
		m_lingering.clear();
		for (const auto& [tid, info] : m_threads)
		{
			if (info.unresponsive && !info.stopped)
				result.push_back(tid);
		}
		return result;
	}


	bool PtraceEngine::Launch(const LaunchOptions& options, std::string& error)
	{
		m_options = options;
		auto result = m_launchResult.get_future();
		m_eventThread = std::thread(&PtraceEngine::EventLoop, m_core);
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
		m_eventThread = std::thread(&PtraceEngine::EventLoop, m_core);
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


	bool PtraceEngine::ResumeToSyscall(SyscallMode mode)
	{
		if (mode == SyscallMode::None)
			return false;
		return RunOnTracer([this, mode] { return DoResume(false, 0, mode); });
	}


	bool PtraceEngine::GetSyscallInfo(uint32_t tid, SyscallInfo& info)
	{
		return RunOnTracer([this, tid, &info] { return DoGetSyscallInfo(tid, info); });
	}


	bool PtraceEngine::SetSyscallInfo(uint32_t tid, const SyscallInfo& info)
	{
		return RunOnTracer([this, tid, &info] { return DoSetSyscallInfo(tid, info); });
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
		if (m_masterFd < 0 || m_ioStop)
			return false;

		// Input is drained by the I/O thread. Writing synchronously to the nonblocking PTY would either spin on EAGAIN
		// or block a debugger thread while the target is stopped. Keep the queue bounded so an unresponsive target
		// cannot make the debugger consume memory without limit.
		constexpr size_t maxPendingInput = 8 << 20;
		std::lock_guard<std::mutex> lock(m_inputMutex);
		if (data.size() > maxPendingInput - m_pendingInputBytes)
			return false;
		if (!data.empty())
		{
			m_pendingInputBytes += data.size();
			m_inputQueue.push_back(data);
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


	bool PtraceEngine::DiscardBreakpoint(uint64_t address)
	{
		return RunOnTracer([this, address] { return DoDiscardBreakpoint(address); });
	}


	bool PtraceEngine::AddHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size)
	{
		return RunOnTracer([this, address, type, size] { return DoAddHardwareBreakpoint(address, type, size); });
	}


	bool PtraceEngine::RemoveHardwareBreakpoint(uint64_t address, PtraceHwType type, size_t size)
	{
		return RunOnTracer([this, address, type, size] { return DoRemoveHardwareBreakpoint(address, type, size); });
	}


	bool PtraceEngine::WaitForDetachedExit(int& status, std::chrono::milliseconds timeout)
	{
		std::shared_ptr<DetachedExit> exit;
		{
			std::lock_guard<std::mutex> lock(m_infoMutex);
			exit = m_detachedExit;
		}
		if (!exit)
			return false;

		std::unique_lock<std::mutex> lock(exit->mutex);
		if (!exit->cv.wait_for(lock, timeout, [&exit] { return exit->done; }))
			return false;
		status = exit->status;
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
			std::lock_guard<std::mutex> lock(m_core->mutex);
			if (event.type == OutputEvent)
			{
				m_core->pendingOutput += event.data.size();
				// Output that has not been taken up yet is joined with what comes after it, which keeps the order, and
				// which is one round trip to the handler instead of many when it is slow
				static constexpr size_t maxChunk = 64 * 1024;
				if (!m_core->events.empty() && m_core->events.back().type == OutputEvent
					&& m_core->events.back().data.size() + event.data.size() <= maxChunk)
				{
					m_core->events.back().data += event.data;
					return;
				}
			}
			m_core->events.push_back(event);
		}
		m_core->cv.notify_one();
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


	void PtraceEngine::EventLoop(std::shared_ptr<EventCore> core)
	{
		while (true)
		{
			Event event;
			std::shared_ptr<const EventHandler> handler;
			{
				std::unique_lock<std::mutex> lock(core->mutex);
				core->cv.wait(lock, [&core] { return core->stop || !core->events.empty(); });
				if (core->stop)
					break;

				event = std::move(core->events.front());
				core->events.pop_front();
				// This call is made with a share of the handler, so that the engine letting go of it does not end it
				handler = core->handler;
			}
			if (event.type == OutputEvent)
			{
				core->pendingOutput -= event.data.size();
				std::lock_guard<std::mutex> lock(core->outputMutex);
				core->outputCv.notify_all();
			}
			if (event.type == TaskEvent)
				event.task();
			else if (handler && *handler)
				(*handler)(event);
		}

		{
			std::lock_guard<std::mutex> lock(core->mutex);
			core->done = true;
		}
		core->doneCv.notify_all();
	}


	// What is in the terminal when the reading is asked to stop. The amount is capped, because a target that goes on writing
	// never runs out of it.
	void PtraceEngine::DrainOutput(char* buffer, size_t size)
	{
		for (int chunk = 0; chunk < 64; chunk++)
		{
			auto count = read(m_masterFd, buffer, size);
			if (count <= 0)
			{
				if (count < 0 && errno == EINTR)
					continue;
				return;
			}

			Event event;
			event.type = OutputEvent;
			event.data.assign(buffer, count);
			PushEvent(event);
		}
	}


	void PtraceEngine::IoMain()
	{
		char buffer[4096];
		while (true)
		{
			if (m_ioStop)
			{
				DrainOutput(buffer, sizeof(buffer));
				return;
			}

			short events = 0;
			bool wantInput = false;
			{
				std::lock_guard<std::mutex> lock(m_inputMutex);
				wantInput = !m_inputQueue.empty();
			}
			if (m_core->pendingOutput < m_outputLimit)
				events |= POLLIN;
			if (wantInput)
				events |= POLLOUT;
			if (!events)
			{
				// Too much output is waiting for the handler, and there is nothing to write. Not reading is what makes the
				// target wait when its terminal is full.
				std::unique_lock<std::mutex> lock(m_core->outputMutex);
				m_core->outputCv.wait_for(lock, std::chrono::milliseconds(50),
					[this] { return m_ioStop || m_core->pendingOutput < m_outputLimit; });
				continue;
			}
			pollfd fd {m_masterFd, events, 0};
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

			if (fd.revents & POLLOUT)
			{
				bool writeFailed = false;
				std::lock_guard<std::mutex> lock(m_inputMutex);
				if (!m_inputQueue.empty())
				{
					const auto& input = m_inputQueue.front();
					auto count = write(m_masterFd, input.data() + m_inputOffset, input.size() - m_inputOffset);
					if (count > 0)
					{
						m_inputOffset += count;
						m_pendingInputBytes -= count;
						if (m_inputOffset == input.size())
						{
							m_inputQueue.pop_front();
							m_inputOffset = 0;
						}
					}
					else if (count < 0 && errno != EINTR && errno != EAGAIN)
						writeFailed = true;
				}
				if (writeFailed)
					return;
			}

			if (fd.revents & POLLIN)
			{
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
			else if (fd.revents & (POLLERR | POLLHUP | POLLNVAL))
			{
				if (events & POLLIN)
					return;

				// The terminal is closed, but there is output that has not been read, and it is not read while the handler is
				// behind. It is read when the handler has caught up.
				std::unique_lock<std::mutex> lock(m_core->outputMutex);
				m_core->outputCv.wait_for(lock, std::chrono::milliseconds(50),
					[this] { return m_ioStop || m_core->pendingOutput < m_outputLimit; });
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

			winsize size = {};
			size.ws_row = m_options.rows;
			size.ws_col = m_options.columns;
			ioctl(m_masterFd, TIOCSWINSZ, &size);
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
				if (setsid() < 0)
					ChildFail(errorPipe[1]);
				int slave = open(slaveName, O_RDWR);
				if (slave < 0)
					ChildFail(errorPipe[1]);
				// A terminal that cannot be the controlling one still works for input and output
				ioctl(slave, TIOCSCTTY, 0);
				if (dup2(slave, 0) < 0 || dup2(slave, 1) < 0 || dup2(slave, 2) < 0)
					ChildFail(errorPipe[1]);
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
			int ignored = 0;
			WaitForThread(pid, ignored, WaitTimeout());
			return std::string("failed to execute ") + m_options.path + ": " + strerror(childError);
		}

		int status = 0;
		auto waited = WaitForThread(pid, status, WaitTimeout());
		if (waited == WaitResult::Timeout)
		{
			KillAndReap(pid);
			return "the target did not stop within " + std::to_string(WaitTimeout().count()) + " ms of being started";
		}
		if (waited == WaitResult::Gone || !WIFSTOPPED(status))
			return "the target exited before it could be traced";

		if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
				(void*)(uintptr_t)(PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
					| PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD)) != 0)
		{
			int error = errno;
			KillAndReap(pid);
			return std::string("failed to configure ptrace options: ") + strerror(error);
		}

		m_pid = pid;
		auto adoptError = AdoptTarget();
		if (!adoptError.empty())
		{
			KillAndReap(pid);
			m_pid = -1;
			return adoptError;
		}
		ThreadInfo info;
		info.stopped = true;
		m_threads[pid] = info;
		Publish();

		if (m_masterFd >= 0)
		{
			fcntl(m_masterFd, F_SETFL, fcntl(m_masterFd, F_GETFL) | O_NONBLOCK);
			m_ioThread = std::thread(&PtraceEngine::IoMain, this);
		}

		// A container can forbid personality(), and then the target runs with ASLR on, which is not what was asked
		if (m_options.disableAslr)
		{
			std::ifstream file("/proc/" + std::to_string(pid) + "/personality");
			unsigned long personalityBits = 0;
			file >> std::hex >> personalityBits;
			if (file && !(personalityBits & ADDR_NO_RANDOMIZE))
				Note("ASLR could not be turned off for the target. The system does not allow personality(), which is how "
					 "a container with the default seccomp profile is set up. The addresses of the target change on every run.");
		}

		Event event;
		event.type = StoppedEvent;
		event.tid = pid;
		event.signal = WSTOPSIG(status);
		event.notes = TakeNotes();
		PushEvent(event);
		return "";
	}


	std::string PtraceEngine::AdoptTarget()
	{
		m_memFd = open(("/proc/" + std::to_string(m_pid) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
		if (m_memFd < 0)
			return "failed to open target memory: " + std::string(strerror(errno));

		m_arch = m_options.arch ? m_options.arch : DetectPtraceArch(m_pid);
		if (!m_arch)
		{
			close(m_memFd);
			m_memFd = -1;
			return "unsupported target architecture";
		}
		if (m_arch && m_arch->hwDebug)
			m_hardwareSlots.resize(m_arch->hwDebug->SlotCount());
		return "";
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

		// Whether a thread has gone, or is going: it is not in the list any more, or it is a zombie. It can take a moment
		// for the state to show, so it is looked at a few times.
		auto threadIsGoing = [pid](pid_t tid) {
			for (int attempt = 0; attempt < 5; attempt++)
			{
				std::ifstream status("/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid) + "/status");
				if (!status)
					return true;

				std::string line;
				while (std::getline(status, line))
				{
					if (line.rfind("State:", 0) == 0)
					{
						auto at = line.find_first_not_of(" \t", 6);
						if (at != std::string::npos && (line[at] == 'Z' || line[at] == 'X'))
							return true;
						break;
					}
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(2));
			}
			return false;
		};

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
					// A thread that is exiting can still be listed, and refuses with ESRCH, or with EPERM once its memory
					// is gone. That is not a refusal to trace the process.
					if (tid != pid && (error == ESRCH || error == EPERM) && threadIsGoing(tid))
						continue;
					detachAll();
					return AttachErrorMessage(pid, error);
				}

				// A signal can reach the thread before the SIGSTOP that attaching sends. It is passed on, and the
				// SIGSTOP comes after it.
				bool stopped = false;
				bool gone = false;
				auto stopDeadline = std::chrono::steady_clock::now() + WaitTimeout();
				for (int attempt = 0; attempt < 16 && !stopped && !gone; attempt++)
				{
					int status = 0;
					auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
						stopDeadline - std::chrono::steady_clock::now());
					auto waited = WaitForThread(tid, status, std::max(remaining, std::chrono::milliseconds(0)));
					if (waited == WaitResult::Timeout)
					{
						// Not stopped, and not gone: the message below says so
						break;
					}
					if (waited == WaitResult::Gone)
					{
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
							ptrace(PTRACE_CONT, tid, nullptr, (void*)(intptr_t)signal);
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
		{
			if (ptrace(PTRACE_SETOPTIONS, tid, nullptr,
					(void*)(uintptr_t)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
						| PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD)) != 0)
			{
				int error = errno;
				detachAll();
				return "failed to configure ptrace options for thread " + std::to_string(tid) + ": "
					+ strerror(error);
			}
		}

		m_pid = pid;
		auto adoptError = AdoptTarget();
		if (!adoptError.empty())
		{
			detachAll();
			m_pid = -1;
			return adoptError;
		}
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
		event.notes = TakeNotes();
		event.errors = TakeErrors();
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


	// Works out who owns a SIGTRAP. Returns false if an internal trap is not worth reporting.
	bool PtraceEngine::ClassifyTrap(pid_t tid, ThreadInfo& info, Classified& result)
	{
		siginfo_t signalInfo {};
		bool haveInfo = ptrace(PTRACE_GETSIGINFO, tid, nullptr, &signalInfo) == 0;
		int code = haveInfo ? signalInfo.si_code : 0;

		// Delivering a caught signal with PTRACE_SINGLESTEP stops after the kernel has entered its handler. Ordinarily
		// that is TRAP_TRACE. When the delivered signal is SIGTRAP, Linux can retain its original non-positive si_code;
		// in that case the changed PC proves that signal delivery entered the handler.
		bool handlerEntry = info.handlerSignal && haveInfo && code == TRAP_TRACE;
		if (info.handlerSignal && info.handlerResumePcValid)
		{
			uint64_t pc = 0;
			handlerEntry |= ReadPc(tid, pc) && pc != info.handlerResumePc;
		}
		if (handlerEntry)
		{
			result.signalHandler = info.handlerSignal;
			info.handlerSignal = 0;
			info.handlerResumePcValid = false;
			result.trapOrigin = TrapOrigin::SignalHandler;
			return true;
		}

		// Signals explicitly sent by the target are never debugger breakpoints, even if the interrupted PC happens to be
		// next to one. AArch64 also produces code-zero, pid-zero traps for some requested single steps, so SI_USER only
		// identifies a sender when the kernel supplied one.
		bool sentSignal = haveInfo && (code < 0 || (code == SI_USER && signalInfo.si_pid != 0));
		if (sentSignal)
		{
			info.pendingSignal = SIGTRAP;
			result.trapOrigin = TrapOrigin::Target;
			return true;
		}

		if (code == TRAP_HWBKPT)
		{
			// A slot that is in use is not enough to make the trap ours: when the architecture can say which slots the trap
			// is for, one of them has to be it
			bool known = false;
			uint64_t triggered = m_arch && m_arch->hwDebug ? m_arch->hwDebug->TriggeredSlots(tid, known) : 0;
			bool ours = false;
			for (size_t i = 0; i < m_hardwareSlots.size(); i++)
				ours |= m_hardwareSlots[i].used && (!known || ((triggered >> i) & 1));
			if (ours && m_arch && m_arch->hwDebug)
			{
				m_arch->hwDebug->OnTrap(tid);
				result.hardware = true;
				result.trapOrigin = TrapOrigin::HardwareBreakpoint;
			}
			else
			{
				info.pendingSignal = SIGTRAP;
				result.trapOrigin = TrapOrigin::Target;
			}
			return true;
		}

		if (code == TRAP_TRACE)
		{
			if (info.stepping)
			{
				result.stepTrap = true;
				result.trapOrigin = TrapOrigin::SingleStep;
			}
			else
			{
				info.pendingSignal = SIGTRAP;
				result.trapOrigin = TrapOrigin::Target;
			}
			return true;
		}

		// Architectures report a CPU breakpoint as TRAP_BRKPT or, notably for x86 int3, SI_KERNEL. Only those codes may
		// be matched by PC: a user-generated SIGTRAP can stop at the same PC by coincidence.
		bool breakpointCode = !haveInfo || code == TRAP_BRKPT || code == SI_KERNEL;
		bool unownedTrapInstruction = haveInfo && code == TRAP_BRKPT;
		uint64_t pc = 0;
		if (breakpointCode && m_arch && !m_arch->breakpointInstruction.empty() && ReadPc(tid, pc)
			&& pc >= m_arch->breakpointPcAdjust)
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
				if (m_arch->breakpointPcAdjust && !WritePc(tid, address))
					Error("thread " + std::to_string(tid) + " stopped at the breakpoint at 0x" + ToHex(address)
						+ ", and its PC could not be moved back to it. The PC that is reported is 0x" + ToHex(pc)
						+ ", which is after the breakpoint.");
				// A thread that trapped on a breakpoint that has just been removed only needs to run again
				if (removed)
				{
					result.trapOrigin = TrapOrigin::Internal;
					return false;
				}

				result.breakpoint = true;
				result.trapOrigin = TrapOrigin::SoftwareBreakpoint;
				return true;
			}

			// SI_KERNEL is also used for some debugger-requested traps. It is target-owned when the instruction at the
			// adjusted PC is the architecture's trap opcode. TRAP_BRKPT itself is already definitive.
			std::vector<uint8_t> instruction(m_arch->breakpointInstruction.size());
			unownedTrapInstruction |= code == SI_KERNEL && RawReadMemory(address, instruction.data(), instruction.size())
				&& instruction == m_arch->breakpointInstruction;

			// The same trap can come from another encoding, which ends at the PC and not one byte before it
			if (code == SI_KERNEL && !unownedTrapInstruction)
			{
				for (const auto& encoding : m_arch->trapInstructions)
				{
					std::vector<uint8_t> found(encoding.size());
					if (pc >= encoding.size() && RawReadMemory(pc - encoding.size(), found.data(), found.size())
						&& found == encoding)
					{
						unownedTrapInstruction = true;
						break;
					}
				}
			}
		}

		// Some kernels report a requested step around a syscall with a generic kernel trap rather than TRAP_TRACE. Preserve
		// that compatibility fallback, but never let it consume a trap instruction or an explicitly sent signal.
		if (info.stepping && !unownedTrapInstruction)
		{
			result.stepTrap = true;
			result.trapOrigin = TrapOrigin::SingleStep;
		}
		else
		{
			info.pendingSignal = SIGTRAP;
			result.trapOrigin = TrapOrigin::Target;
		}
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
				FinishGuard(tid, threadAlive);
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
		info.unresponsive = false;
		int signal = WSTOPSIG(status);
		int event = status >> 16;

		if (event == PTRACE_EVENT_CLONE)
		{
			unsigned long newTid = 0;
			if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &newTid) != 0 || newTid == 0)
			{
				Error("thread " + std::to_string(tid) + " made a new task, and its id could not be read, so the new task is "
					  "not managed and stays stopped");
				return result;
			}

			// Any clone that is not a fork or a vfork is reported like this, and not all of them make a thread. One that does
			// not is a process of its own, which is dealt with like the child of a fork.
			if (ThreadGroupOf((pid_t)newTid) != m_pid)
			{
				Note("thread " + std::to_string(tid) + " made a process with clone, and it was let go of");
				HandleFork((pid_t)newTid, false);
				return result;
			}

			ThreadInfo created;
			created.awaitingInitialStop = true;
			m_threads[(pid_t)newTid] = created;
			Publish();
			return result;
		}
		if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK)
		{
			unsigned long child = 0;
			if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &child) != 0 || child == 0)
			{
				Error("thread " + std::to_string(tid) + " made a child process, and its id could not be read, so the child is "
					  "not let go of and stays stopped");
				return result;
			}
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

		// A stop at a system call, which only happens to a thread that was resumed to one
		if (signal == (SIGTRAP | 0x80))
		{
			endGuard(true);
			result.kind = StopKind::Report;
			result.signal = SIGTRAP;
			result.syscall = true;
			result.trapOrigin = TrapOrigin::Syscall;
			return result;
		}

		if (signal == SIGSTOP)
		{
			if (info.awaitingInitialStop)
			{
				info.awaitingInitialStop = false;
				if (!ApplyHardwareToThread(tid))
					Error("the hardware breakpoints could not be set for the new thread " + std::to_string(tid)
						+ ", which will not stop at them");
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
			// A different signal interrupted any outstanding single-step-to-handler operation.
			info.handlerSignal = 0;
			info.handlerResumePcValid = false;
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
		bool step = info.stepping;

		// Resuming with a single step and a signal delivers the signal and stops at the first instruction of its
		// handler
		int handlerSignal = 0;
		uint64_t handlerResumePc = 0;
		bool handlerResumePcValid = false;
		if (signal && !step && m_debugSignalHandlers && HasSignalHandler(signal))
		{
			step = true;
			handlerSignal = signal;
			handlerResumePcValid = ReadPc(tid, handlerResumePc);
		}

		int request = PTRACE_CONT;
		if (step)
			request = PTRACE_SINGLESTEP;
		else if (m_syscallMode == SyscallMode::Trace)
			request = PTRACE_SYSCALL;
		else if (m_syscallMode == SyscallMode::Emulate)
			request = PTRACE_SYSEMU;
		if (ptrace((__ptrace_request)request, tid, nullptr, (void*)(intptr_t)signal) != 0 && errno != ESRCH)
			return false;

		// Only commit the transition after the kernel accepted it. Otherwise a stopped thread would disappear from
		// future resume attempts, and a pending signal could be lost.
		info.pendingSignal = 0;
		info.stopped = false;
		info.handlerSignal = handlerSignal;
		info.handlerResumePc = handlerResumePc;
		info.handlerResumePcValid = handlerResumePcValid;
		info.atReportedStop = false;
		return true;
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
	bool PtraceEngine::BeginGuard(pid_t tid, uint64_t address)
	{
		auto& info = m_threads[tid];
		info.guardAddress = address;
		bool success = true;

		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			auto it = m_breakpoints.find(address);
			if (it != m_breakpoints.end() && it->second.inserted)
			{
				if (RawWriteMemory(address, it->second.original.data(), it->second.original.size()))
				{
					it->second.inserted = false;
					info.guardSoftware = true;
				}
				else
				{
					success = false;
				}
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
				if (m_arch->hwDebug->Clear(tid, i))
					info.guardSlots.push_back(i);
				else
					success = false;
			}
		}
		return success;
	}


	// Puts back what a step over took out. A breakpoint that cannot be put back is lost to the user without a word if nobody says
	// so, and the guard stays, so that it is tried again at the next stop.
	void PtraceEngine::FinishGuard(pid_t tid, bool threadAlive)
	{
		uint64_t address = m_threads[tid].guardAddress;
		bool software = m_threads[tid].guardSoftware;
		if (!EndGuard(tid, threadAlive))
			Error(software ? "could not put back the breakpoint at 0x" + ToHex(address) + " after thread "
							+ std::to_string(tid) + " stepped over it. It is not in the target, and it is tried again at the next stop."
						   : "could not put back the hardware breakpoints of thread " + std::to_string(tid)
							+ " after it stepped over one");
	}


	bool PtraceEngine::EndGuard(pid_t tid, bool threadAlive)
	{
		auto& info = m_threads[tid];
		bool success = true;
		if (info.guardSoftware)
		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			auto it = m_breakpoints.find(info.guardAddress);
			if (it != m_breakpoints.end() && !it->second.inserted && !it->second.suspended)
			{
				if (threadAlive && !RawWriteMemory(
						info.guardAddress, m_arch->breakpointInstruction.data(), m_arch->breakpointInstruction.size()))
				{
					success = false;
				}
				else
				{
					it->second.inserted = threadAlive;
					info.guardSoftware = false;
				}
			}
			else
			{
				info.guardSoftware = false;
			}
		}

		info.hardwareBeforeAccess = false;
		auto slots = std::move(info.guardSlots);
		info.guardSlots.clear();
		for (size_t index : slots)
		{
			const auto& slot = m_hardwareSlots[index];
			if (threadAlive && slot.used && !m_arch->hwDebug->Set(tid, index, slot.address, slot.type, slot.size))
			{
				info.guardSlots.push_back(index);
				success = false;
			}
		}
		return success;
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

			if (!BeginGuard(tid, pc))
			{
				FinishGuard(tid, true);
				return false;
			}
			it->second.stepping = true;
			m_stepOverTid = tid;
			if (ResumeThread(tid))
				return true;
			it->second.stepping = false;
			FinishGuard(tid, true);
			return false;
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
		auto waited = WaitForThread(child, status, WaitTimeout());
		if (waited == WaitResult::Timeout)
		{
			// It stays as it is, stopped and traced, because nothing here can let go of it before it has stopped
			m_lingering.push_back(child);
			return;
		}
		if (waited == WaitResult::Gone || !WIFSTOPPED(status))
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

					// A clone with CLONE_VM that is not a thread shares the memory of the target, and is not told by a
					// vfork event when it is done with it. What was written to the child is then what is in the target now,
					// and the breakpoints are put back.
					for (const auto& [address, breakpoint] : m_breakpoints)
					{
						if (!breakpoint.inserted)
							continue;

						std::vector<uint8_t> now(breakpoint.original.size());
						if (RawReadMemory(address, now.data(), now.size()) && now == breakpoint.original)
						{
							for (auto& [otherAddress, other] : m_breakpoints)
							{
								if (other.inserted)
									RawWriteMemory(otherAddress, m_arch->breakpointInstruction.data(),
										m_arch->breakpointInstruction.size());
							}
							Note("a process made with clone shares the memory of the target, so it can run into the "
								 "breakpoints, which stay where they are");
						}
						break;
					}
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


	bool PtraceEngine::ApplyHardwareToThread(pid_t tid)
	{
		bool all = true;
		for (size_t i = 0; i < m_hardwareSlots.size(); i++)
		{
			const auto& slot = m_hardwareSlots[i];
			if (slot.used)
				all &= m_arch->hwDebug->Set(tid, i, slot.address, slot.type, slot.size);
		}
		return all;
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
		// A thread that was given up on may have stopped since. It is looked at, and not waited for.
		std::vector<pid_t> given;
		for (const auto& [tid, info] : m_threads)
		{
			if (info.unresponsive && !info.stopped)
				given.push_back(tid);
		}
		for (pid_t tid : given)
		{
			int status = 0;
			pid_t result = waitpid(tid, &status, __WALL | WNOHANG);
			if (result == tid)
				Classify(tid, status);
			if (m_done)
				return;
		}

		while (!m_done)
		{
			pid_t next = -1;
			for (const auto& [tid, info] : m_threads)
			{
				if (!info.stopped && !info.unresponsive)
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
			auto waited = WaitForThread(next, status, WaitTimeout());
			if (waited == WaitResult::Timeout)
			{
				m_threads[next].unresponsive = true;
				continue;
			}
			if (waited == WaitResult::Gone)
				status = 0;
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
		event.trapOrigin = stop.trapOrigin;
		event.exec = stop.exec;
		event.signalHandler = stop.signalHandler;
		event.syscall = stop.syscall;
		event.singleStep = stop.stepTrap;
		event.unresponsive = TakeUnresponsive();
		event.notes = TakeNotes();
		event.errors = TakeErrors();

		for (auto& [id, info] : m_threads)
			info.stepping = false;

		// Once everything is stopped, no thread can still trap on a breakpoint that was removed. A thread that was given
		// up on may still be running, and can.
		bool allStopped = true;
		for (const auto& [id, info] : m_threads)
			allStopped &= info.stopped;
		if (allStopped)
			m_recentlyRemoved.clear();
		// Any stop is a pause, so a request for one that has not been seen yet is answered
		m_interruptWanted = false;

		auto& info = m_threads[tid];
		info.atReportedStop = ReadPc(tid, info.reportedPc);
		info.hardwareBeforeAccess =
			stop.hardware && m_arch && m_arch->hwDebug && m_arch->hwDebug->DataTrapsBeforeAccess();
		// The first instruction of a program is where a breakpoint of the new program may be, and it has not run yet. At
		// the entry of a system call the instruction after it has not run either.
		if (stop.exec || stop.syscall)
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
		event.unresponsive = TakeUnresponsive();
		event.notes = TakeNotes();
		event.errors = TakeErrors();
		if (WIFEXITED(status))
			event.exitCode = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			event.signal = WTERMSIG(status);
		PushEvent(event);
	}


	bool PtraceEngine::DoResume(bool step, pid_t tid, SyscallMode mode)
	{
		if (m_done || m_running)
			return false;

		auto stepping = m_threads.find(tid);
		if (step && (stepping == m_threads.end() || !stepping->second.stopped))
			return false;
		if (mode == SyscallMode::Emulate && (!m_arch || !m_arch->sysemu))
			return false;

		m_syscallMode = step ? SyscallMode::None : mode;
		m_continueMode = !step;
		std::vector<pid_t> stepOver;
		for (auto& [id, info] : m_threads)
		{
			if (!info.stopped || (step && id != tid))
				continue;

			if (NeedsStepOver(id, info))
				stepOver.push_back(id);
		}

		bool resumed;
		if (step)
		{
			uint64_t pc;
			if (!stepOver.empty() && ReadPc(tid, pc) && !BeginGuard(tid, pc))
			{
				FinishGuard(tid, true);
				return false;
			}

			stepping->second.stepping = true;
			resumed = ResumeThread(tid);
			if (!resumed)
			{
				stepping->second.stepping = false;
				if (stepping->second.guardSoftware || !stepping->second.guardSlots.empty())
					FinishGuard(tid, true);
			}
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


	bool PtraceEngine::DoGetSyscallInfo(pid_t tid, SyscallInfo& info)
	{
		auto it = m_threads.find(tid);
		if (m_done || m_running || it == m_threads.end() || !it->second.stopped)
			return false;

		KernelSyscallInfo raw = {};
		long size = ptrace((__ptrace_request)PTRACE_GET_SYSCALL_INFO, tid, (void*)sizeof(raw), &raw);
		// The header comes before the union, so that is the least that there can be
		if (size < (long)offsetof(KernelSyscallInfo, entry))
			return false;

		info = SyscallInfo();
		info.arch = raw.arch;
		info.instructionPointer = raw.instructionPointer;
		info.stackPointer = raw.stackPointer;
		switch (raw.op)
		{
		case KernelSyscallInfoEntry:
			info.op = SyscallInfo::Entry;
			info.number = raw.entry.number;
			memcpy(info.args, raw.entry.args, sizeof(info.args));
			break;
		case KernelSyscallInfoExit:
			info.op = SyscallInfo::Exit;
			info.returnValue = raw.exit.returnValue;
			info.isError = raw.exit.isError != 0;
			break;
		case KernelSyscallInfoSeccomp:
			info.op = SyscallInfo::Seccomp;
			info.number = raw.seccomp.number;
			memcpy(info.args, raw.seccomp.args, sizeof(info.args));
			info.seccompData = raw.seccomp.data;
			break;
		default:
			break;
		}
		return true;
	}


	bool PtraceEngine::DoSetSyscallInfo(pid_t tid, const SyscallInfo& info)
	{
		// Only what the stop has is changed, so the rest is taken from the stop
		SyscallInfo current;
		if (!DoGetSyscallInfo(tid, current) || current.op != info.op)
			return false;

		KernelSyscallInfo raw = {};
		raw.arch = current.arch;
		raw.instructionPointer = current.instructionPointer;
		raw.stackPointer = current.stackPointer;
		switch (info.op)
		{
		case SyscallInfo::Entry:
			raw.op = KernelSyscallInfoEntry;
			raw.entry.number = info.number;
			memcpy(raw.entry.args, info.args, sizeof(raw.entry.args));
			break;
		case SyscallInfo::Exit:
			raw.op = KernelSyscallInfoExit;
			raw.exit.returnValue = info.returnValue;
			raw.exit.isError = info.isError;
			break;
		case SyscallInfo::Seccomp:
			raw.op = KernelSyscallInfoSeccomp;
			raw.seccomp.number = info.number;
			memcpy(raw.seccomp.args, info.args, sizeof(raw.seccomp.args));
			raw.seccomp.data = current.seccompData;
			break;
		default:
			return false;
		}
		return ptrace((__ptrace_request)PTRACE_SET_SYSCALL_INFO, tid, (void*)sizeof(raw), &raw) == 0;
	}


	bool PtraceEngine::DoAddBreakpoint(uint64_t address)
	{
		if (m_done || !m_arch || m_arch->breakpointInstruction.empty())
			return false;

		std::lock_guard<std::mutex> lock(m_breakpointMutex);
		auto existing = m_breakpoints.find(address);
		if (existing != m_breakpoints.end())
		{
			// A mapping can disappear and later be replaced at the same address. The saved record then says that the
			// breakpoint is inserted even though the new mapping contains its original instruction. Revalidate an
			// idempotent add so a loader rendezvous can repair that state.
			if (!existing->second.inserted || existing->second.suspended)
				return true;

			std::vector<uint8_t> current(m_arch->breakpointInstruction.size());
			if (!RawReadMemory(address, current.data(), current.size()))
				return false;
			if (current == m_arch->breakpointInstruction)
				return true;

			if (!RawWriteMemory(address, m_arch->breakpointInstruction.data(), m_arch->breakpointInstruction.size()))
				return false;
			existing->second.original = std::move(current);
			return true;
		}

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

		if (it->second.inserted && !m_done
			&& !RawWriteMemory(address, it->second.original.data(), it->second.original.size()))
			return false;
		m_breakpoints.erase(it);

		// A thread that is running may just have trapped on it
		if (m_running)
			m_recentlyRemoved.insert(address);
		return true;
	}


	bool PtraceEngine::DoDiscardBreakpoint(uint64_t address)
	{
		if (m_running)
			return false;

		std::lock_guard<std::mutex> lock(m_breakpointMutex);
		return m_breakpoints.erase(address) != 0;
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

			bool cleared = true;
			for (const auto& [tid, info] : m_threads)
			{
				if (info.stopped && !m_arch->hwDebug->Clear(tid, index))
					cleared = false;
			}
			if (!cleared)
				return false;
			slot.used = false;
			return true;
		}
		return false;
	}


	// Puts the target back the way it was before we let go of it
	bool PtraceEngine::RemoveAllBreakpoints()
	{
		bool success = true;
		for (auto& [tid, info] : m_threads)
		{
			if (info.guardSoftware || !info.guardSlots.empty())
				success &= EndGuard(tid, true);
		}

		{
			std::lock_guard<std::mutex> lock(m_breakpointMutex);
			for (auto it = m_breakpoints.begin(); it != m_breakpoints.end();)
			{
				auto& [address, breakpoint] = *it;
				if (breakpoint.inserted
					&& !RawWriteMemory(address, breakpoint.original.data(), breakpoint.original.size()))
				{
					success = false;
					it++;
				}
				else
				{
					it = m_breakpoints.erase(it);
				}
			}
		}

		for (size_t index = 0; index < m_hardwareSlots.size(); index++)
		{
			if (!m_hardwareSlots[index].used)
				continue;

			bool cleared = true;
			for (const auto& [tid, info] : m_threads)
				cleared &= m_arch->hwDebug->Clear(tid, index);
			if (cleared)
				m_hardwareSlots[index].used = false;
			else
				success = false;
		}
		if (success)
		{
			m_stepOverQueue.clear();
			m_stepOverTid = -1;
		}
		return success;
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

		// One deadline for all of them, so that a number of threads that do not die is not a number of timeouts
		int status = SIGKILL;
		auto deadline = std::chrono::steady_clock::now() + WaitTimeout();
		for (pid_t tid : tids)
		{
			while (true)
			{
				int threadStatus = 0;
				auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
					deadline - std::chrono::steady_clock::now());
				auto waited = WaitForThread(tid, threadStatus, std::max(remaining, std::chrono::milliseconds(0)));
				if (waited == WaitResult::Gone)
					break;
				if (waited == WaitResult::Timeout)
				{
					m_lingering.push_back(tid);
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
			auto waited = WaitForThread(pending, status, WaitTimeout());
			if (waited == WaitResult::Timeout)
			{
				m_threads[pending].unresponsive = true;
				m_threads[pending].expectedStops = 0;
				break;
			}
			if (waited == WaitResult::Gone)
				break;
			Classify(pending, status);
			if (m_done)
				return false;
		}

		// The threads that were given up on are not in the map any more once they are let go of, so they are noted now
		auto givenUp = TakeUnresponsive();
		if (!RemoveAllBreakpoints())
		{
			m_lingering = givenUp;
			return false;
		}

		bool detached = true;
		std::vector<pid_t> tids;
		for (const auto& [tid, info] : m_threads)
			tids.push_back(tid);
		for (pid_t tid : tids)
		{
			auto it = m_threads.find(tid);
			if (it == m_threads.end())
				continue;
			if (ptrace(PTRACE_DETACH, tid, nullptr, (void*)(intptr_t)it->second.pendingSignal) == 0 || errno == ESRCH)
				m_threads.erase(it);
			else
				detached = false;
		}
		if (!detached)
		{
			m_lingering = givenUp;
			Publish();
			return false;
		}

		m_done = true;
		m_finished = true;
		m_running = false;
		Publish();
		StopIo();

		if (!m_attached)
		{
			auto exit = std::make_shared<DetachedExit>();
			{
				std::lock_guard<std::mutex> lock(m_infoMutex);
				m_detachedExit = exit;
			}
			std::thread([exit, pid = m_pid]() {
				int status = 0;
				pid_t result;
				do
				{
					result = waitpid(pid, &status, __WALL);
				} while (result < 0 && errno == EINTR);

				std::lock_guard<std::mutex> lock(exit->mutex);
				exit->status = result < 0 ? 0 : status;
				exit->done = true;
				exit->cv.notify_all();
			}).detach();
		}

		Event event;
		event.type = DetachedEvent;
		event.unresponsive = givenUp;
		event.notes = TakeNotes();
		event.errors = TakeErrors();
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
