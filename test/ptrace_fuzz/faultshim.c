// LD_PRELOAD shim that randomly fails the system calls the ptrace adapter depends on.
//   FAULT_SEED       base seed (default 1)
//   FAULT_PERMILLE   chance of a failure per call, in 1/1000 (default 3)
//   FAULT_AFTER_MS   no failures until this long after load (default 0)
// What fails: ptrace(2) of any request except PTRACE_TRACEME, pread/pwrite on /proc/<pid>/mem (failed or cut short),
// and waitpid/wait4/waitid with a spurious EINTR. A debugger is expected to survive all of it without crashing or
// hanging, report the problem, and still be able to kill its target.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

//   FAULT_ERRNO      with FAULT_NTH, the errno to inject instead of a random one (for example 3 for ESRCH, 5 for EIO)
//   FAULT_NTH        if set, fail exactly the Nth intercepted call (ptrace, or I/O on /proc/<pid>/mem), once, and nothing
//                    else; the failure is described on stderr as "FAULT#N ..."
static uint64_t g_seed = 1;
static long g_nth = 0;
static int g_waitKind = 0;  // FAULT_KIND=waitpid: FAULT_NTH counts and fails waitpid/wait4 (EINTR) instead
static atomic_long g_count = 0;
#include <stdio.h>
#include <execinfo.h>
static int g_permille = 3;
static uint64_t g_startNs = 0;
static uint64_t g_afterNs = 0;
#define MAXFD 4096
static atomic_uchar g_memFd[MAXFD];

static uint64_t nowNs(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

__attribute__((constructor)) static void init(void)
{
	const char* s = getenv("FAULT_SEED");
	if (s) g_seed = strtoull(s, 0, 10);
	s = getenv("FAULT_PERMILLE");
	if (s) g_permille = atoi(s);
	s = getenv("FAULT_NTH");
	if (s) g_nth = atol(s);
	s = getenv("FAULT_KIND");
	if (s && !strcmp(s, "waitpid")) g_waitKind = 1;
	s = getenv("FAULT_AFTER_MS");
	if (s) g_afterNs = strtoull(s, 0, 10) * 1000000ull;
	g_startNs = nowNs();
}

static __thread uint64_t t_state;
static uint64_t rnd(void)
{
	if (!t_state)
		t_state = (g_seed * 0x9E3779B97F4A7C15ull) ^ ((uint64_t)syscall(SYS_gettid) * 0xD1B54A32D192ED03ull) ^ 0x1234567ull;
	uint64_t x = t_state;
	x ^= x << 13; x ^= x >> 7; x ^= x << 17;
	return t_state = x;
}

// For the deterministic mode: true for exactly the Nth call
static int nthCall(void)
{
	return g_nth > 0 && !g_waitKind && atomic_fetch_add(&g_count, 1) + 1 == g_nth;
}

static int nthWait(void)
{
	return g_nth > 0 && g_waitKind && atomic_fetch_add(&g_count, 1) + 1 == g_nth;
}

static int fail(void)
{
	if (g_nth > 0)
		return 0;
	if (g_permille <= 0 || nowNs() - g_startNs < g_afterNs)
		return 0;
	return (int)(rnd() % 1000) < g_permille;
}

static int isMemPath(const char* p)
{
	size_t n = p ? strlen(p) : 0;
	return n > 9 && !strncmp(p, "/proc/", 6) && !strcmp(p + n - 4, "/mem");
}

static int noteOpen(int fd, const char* path)
{
	if (fd >= 0 && fd < MAXFD)
		atomic_store(&g_memFd[fd], isMemPath(path));
	return fd;
}

int open(const char* path, int flags, ...)
{
	static int (*real)(const char*, int, ...);
	if (!real) real = dlsym(RTLD_NEXT, "open");
	mode_t mode = 0;
	if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, mode_t); va_end(a); }
	return noteOpen(real(path, flags, mode), path);
}

int open64(const char* path, int flags, ...)
{
	static int (*real)(const char*, int, ...);
	if (!real) real = dlsym(RTLD_NEXT, "open64");
	mode_t mode = 0;
	if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, mode_t); va_end(a); }
	return noteOpen(real(path, flags, mode), path);
}

int close(int fd)
{
	static int (*real)(int);
	if (!real) real = dlsym(RTLD_NEXT, "close");
	if (fd >= 0 && fd < MAXFD)
		atomic_store(&g_memFd[fd], 0);
	return real(fd);
}

static int isMemFd(int fd) { return fd >= 0 && fd < MAXFD && atomic_load(&g_memFd[fd]); }

#define WRAP_RW(name, ret_t, constq)                                                                          \
	ret_t name(int fd, constq void* buf, size_t size, off_t off)                                              \
	{                                                                                                         \
		static ret_t (*real)(int, constq void*, size_t, off_t);                                               \
		if (!real) real = dlsym(RTLD_NEXT, #name);                                                            \
		if (isMemFd(fd) && (nthCall() ? (fprintf(stderr, "FAULT#%ld %s size=%zu\n", g_nth, #name, size), 1) : fail())) \
		{                                                                                                     \
			if (size > 1 && (rnd() & 1))                                                                      \
				return real(fd, buf, size / 2, off); /* cut short */                                          \
			errno = (rnd() & 1) ? EIO : EFAULT;                                                               \
			return -1;                                                                                        \
		}                                                                                                     \
		return real(fd, buf, size, off);                                                                      \
	}
WRAP_RW(pwrite, ssize_t, const)
WRAP_RW(pwrite64, ssize_t, const)
WRAP_RW(pread, ssize_t, )
WRAP_RW(pread64, ssize_t, )

long ptrace(enum __ptrace_request request, ...)
{
	static long (*real)(enum __ptrace_request, ...);
	if (!real) real = dlsym(RTLD_NEXT, "ptrace");
	va_list args;
	va_start(args, request);
	pid_t pid = va_arg(args, pid_t);
	void* address = va_arg(args, void*);
	void* data = va_arg(args, void*);
	va_end(args);
	int injectNth = g_nth > 0 && (int)request != PTRACE_TRACEME && nthCall();
	if (injectNth)
	{
		fprintf(stderr, "FAULT#%ld ptrace request=%d tid=%d\n", g_nth, (int)request, (int)pid);
		void* frames[24];
		int depth = backtrace(frames, 24);
		backtrace_symbols_fd(frames, depth, 2);
	}
	if (injectNth || ((int)request != PTRACE_TRACEME && fail()))
	{
		static const int errs[] = {EIO, ESRCH, EPERM, EBUSY, EFAULT, EINVAL};
		errno = errs[rnd() % 6];
		if (getenv("FAULT_ERRNO"))
			errno = atoi(getenv("FAULT_ERRNO"));
		return -1;
	}
	return real(request, pid, address, data);
}

pid_t waitpid(pid_t pid, int* status, int options)
{
	static pid_t (*real)(pid_t, int*, int);
	if (!real) real = dlsym(RTLD_NEXT, "waitpid");
	if (nthWait())
	{
		fprintf(stderr, "FAULT#%ld waitpid pid=%d\n", g_nth, (int)pid);
		void* frames[24];
		int depth = backtrace(frames, 24);
		backtrace_symbols_fd(frames, depth, 2);
		errno = EINTR;
		return -1;
	}
	if (fail()) { errno = EINTR; return -1; }
	return real(pid, status, options);
}

pid_t wait4(pid_t pid, int* status, int options, struct rusage* ru)
{
	static pid_t (*real)(pid_t, int*, int, struct rusage*);
	if (!real) real = dlsym(RTLD_NEXT, "wait4");
	if (nthWait())
	{
		fprintf(stderr, "FAULT#%ld wait4 pid=%d\n", g_nth, (int)pid);
		errno = EINTR;
		return -1;
	}
	if (fail()) { errno = EINTR; return -1; }
	return real(pid, status, options, ru);
}
