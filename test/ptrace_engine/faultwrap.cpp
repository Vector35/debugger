#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

static std::atomic<bool> g_failResume {false};
static std::atomic<bool> g_failPwrite {false};
static std::atomic<bool> g_failSetOptions {false};
static std::atomic<bool> g_failMemOpen {false};

extern "C" void PtraceTestFailNextResume()
{
	g_failResume = true;
}

extern "C" void PtraceTestFailNextPwrite()
{
	g_failPwrite = true;
}

extern "C" void PtraceTestFailNextSetOptions()
{
	g_failSetOptions = true;
}

extern "C" void PtraceTestFailNextMemOpen()
{
	g_failMemOpen = true;
}

extern "C" long __real_ptrace(enum __ptrace_request request, ...);
extern "C" long __wrap_ptrace(enum __ptrace_request request, ...)
{
	va_list args;
	va_start(args, request);
	pid_t pid = va_arg(args, pid_t);
	void* address = va_arg(args, void*);
	void* data = va_arg(args, void*);
	va_end(args);
	if ((request == PTRACE_CONT || request == PTRACE_SINGLESTEP) && g_failResume.exchange(false))
	{
		errno = EIO;
		return -1;
	}
	if (request == PTRACE_SETOPTIONS && g_failSetOptions.exchange(false))
	{
		errno = EIO;
		return -1;
	}
	return __real_ptrace(request, pid, address, data);
}

extern "C" ssize_t __real_pwrite(int fd, const void* buffer, size_t size, off_t offset);
extern "C" ssize_t __wrap_pwrite(int fd, const void* buffer, size_t size, off_t offset)
{
	if (g_failPwrite.exchange(false))
	{
		errno = EIO;
		return -1;
	}
	return __real_pwrite(fd, buffer, size, offset);
}

extern "C" int __real_open(const char* path, int flags, ...);
extern "C" int __wrap_open(const char* path, int flags, ...)
{
	mode_t mode = 0;
	if (flags & O_CREAT)
	{
		va_list args;
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}
	if (g_failMemOpen && path && !strncmp(path, "/proc/", 6)
		&& strlen(path) >= 4 && !strcmp(path + strlen(path) - 4, "/mem"))
	{
		g_failMemOpen = false;
		errno = EACCES;
		return -1;
	}
	return __real_open(path, flags, mode);
}
