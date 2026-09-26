#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <spawn.h>
extern char** environ;
#include <sys/ioctl.h>
#ifdef PAD
__attribute__((noinline)) int pad1(int a) { volatile int x = a; for (int i = 0; i < 3; i++) x += i * a; return x; }
__attribute__((noinline)) int pad2(int a) { return pad1(a) + pad1(a + 1) + pad1(a + 2); }
#endif
static int counter;
__attribute__((noinline)) void level3(void) { void* p = &&here; printf("label=%p\n", p); raise(SIGUSR1); here: asm volatile("nop"); counter++; }
__attribute__((noinline)) void level2(void) { level3(); counter++; }
__attribute__((noinline)) void level1(void) { level2(); counter++; }
__attribute__((noinline)) void marker(void) { __sync_fetch_and_add(&counter, 1); }
static volatile int wvar;
__attribute__((noinline)) void callee(void) { volatile int x = 0; for (int i = 0; i < 3; i++) x += i; marker(); }
__attribute__((noinline)) void slowcallee(void) { for (int i = 0; i < 100; i++) usleep(10000); marker(); }
__attribute__((noinline)) void caller(int slow) { void* p = &&here; printf("here=%p\n", p); raise(SIGUSR1); here: asm volatile("nop"); if (slow) slowcallee(); else callee(); counter += 10; }
__attribute__((noinline)) int recurse(int n) { if (n == 0) return 0; if (n == 3) { void* p = &&site; printf("site=%p\n", p); raise(SIGUSR1); site: asm volatile("nop"); } int r = recurse(n - 1); counter++; return r + 1; }
__attribute__((noinline)) void inner(void) { void* p = &&there; printf("there=%p\n", p); raise(SIGUSR1); there: asm volatile("nop"); counter++; }
__attribute__((noinline)) void outer(void) { inner(); counter += 100; }
__attribute__((noinline)) void work_item(void) { __sync_fetch_and_add(&counter, 1); }
static void* stepWorker(void* a) { for (int i = 0; i < 300; i++) { if (a == (void*)0 && i == 5) { void* p = &&sync; printf("sync=%p\n", p); raise(SIGUSR1); sync: asm volatile("nop"); } work_item(); usleep(100); } return 0; }
static volatile int handled;
__attribute__((noinline)) void sigHandler(int s) { handled++; }
__attribute__((noinline)) void infoHandler(int s, siginfo_t* i, void* c) { handled += 10; }
__attribute__((noinline)) void trapHandler(int s, siginfo_t* i, void* context)
{
	handled++;
#if defined(__aarch64__)
	// AArch64 reports BRK at the trapping instruction, so returning without advancing would execute it forever. Signals
	// sent with raise/tgkill have a non-positive si_code and already have the correct return PC.
	if (i && i->si_code > 0)
		((ucontext_t*)context)->uc_mcontext.pc += 4;
#endif
}
__attribute__((noinline)) void raiseTrap(void) { raise(SIGTRAP); }
extern char before_trap_instruction[];
extern char target_trap_instruction[];
__attribute__((noinline)) void instructionTrap(void)
{
#if defined(__x86_64__)
	asm volatile(".global before_trap_instruction\n before_trap_instruction:\n nop\n"
		".global target_trap_instruction\n target_trap_instruction:\n int3");
#elif defined(__aarch64__)
	asm volatile(".global before_trap_instruction\n before_trap_instruction:\n nop\n"
		".global target_trap_instruction\n target_trap_instruction:\n brk #0");
#endif
}
static void* handlerWaiter(void* a) { while (!handled) usleep(1000); return 0; }
static int bad;
static void* execWorker(void* a) { usleep(100000); execl("/work/progs", "progs", "hello", (char*)0); return 0; }
static void* forker(void* a) { for (int i = 0; i < 20; i++) { pid_t c = fork(); if (c == 0) { marker(); _exit(0); } int st = 0; waitpid(c, &st, 0); if (WIFSIGNALED(st)) __sync_fetch_and_add(&bad, 1); marker(); } return 0; }
static void* markerThread(void* a) { for (int i = 0; i < 3; i++) { marker(); usleep(2000); } return 0; }
static void* writer(void* a) { usleep(20000); wvar = 7; return 0; }
static int cloneChild(void* a) { return 0; }
static void* spin(void* a) { volatile unsigned long x = 0; while (1) x++; return 0; }
static void* shortlived(void* a) { usleep(1000); return 0; }
static int libraryRange(uintptr_t* first, uintptr_t* last) { FILE* f = fopen("/proc/self/maps", "r"); char line[512]; *first = UINTPTR_MAX; *last = 0; if (!f) return 0; while (fgets(line, sizeof(line), f)) { unsigned long a, b; if (strstr(line, "/work/libtest.so") && sscanf(line, "%lx-%lx", &a, &b) == 2) { if (a < *first) *first = a; if (b > *last) *last = b; } } fclose(f); return *last > *first; }
int main(int argc, char** argv)
{
	const char* mode = argc > 1 ? argv[1] : "hello";
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!strcmp(mode, "hello")) { printf("hello from target\n"); return 7; }
	if (!strcmp(mode, "loop")) { volatile unsigned long x = 0; while (1) x++; }
	if (!strcmp(mode, "threads")) { pthread_t t[3]; for (int i = 0; i < 3; i++) pthread_create(&t[i], 0, spin, 0); while (1) usleep(1000); }
	if (!strcmp(mode, "churn")) { for (int i = 0; i < 50; i++) { pthread_t t; pthread_create(&t, 0, shortlived, 0); pthread_join(t, 0); } printf("churn done\n"); return 0; }
	if (!strcmp(mode, "churnloop")) { while (1) { pthread_t t; pthread_create(&t, 0, shortlived, 0); pthread_join(t, 0); } }
	if (!strcmp(mode, "sig")) { printf("raising\n"); raise(SIGUSR1); printf("survived\n"); return 0; }
	if (!strcmp(mode, "sigchld")) { signal(SIGUSR2, SIG_IGN); if (fork() == 0) _exit(0); sleep(1); printf("after child\n"); return 5; }
	if (!strcmp(mode, "sleeper")) { sleep(2); printf("done sleeping\n"); return 3; }
	if (!strcmp(mode, "args")) { char c[256]; getcwd(c, 256); printf("cwd=%s argc=%d", c, argc); for (int i = 2; i < argc; i++) printf(" [%s]", argv[i]); printf("\n"); return 0; }
	if (!strcmp(mode, "cat")) { char b[256]; if (fgets(b, 256, stdin)) printf("got: %s", b); return 0; }
	if (!strcmp(mode, "mem")) { static char buf[32] = "hello memory"; signal(SIGUSR1, SIG_IGN); printf("buf=%p main=%p\n", (void*)buf, (void*)main); raise(SIGUSR1); printf("%s\n", buf); return 0; }
	if (!strcmp(mode, "bp")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); for (int i = 0; i < 5; i++) marker(); return counter; }
	if (!strcmp(mode, "bpthreads")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); pthread_t t[4]; for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, markerThread, 0); for (int i = 0; i < 4; i++) pthread_join(t[i], 0); return counter; }
	if (!strcmp(mode, "bploop")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); while (1) marker(); }
	if (!strcmp(mode, "detachbp")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); sleep(1); marker(); return counter; }
	if (!strcmp(mode, "watch")) { signal(SIGUSR1, SIG_IGN); printf("wvar=%p\n", (void*)&wvar); raise(SIGUSR1); for (int i = 0; i < 3; i++) { wvar = i + 1; usleep(1000); } return wvar; }
	if (!strcmp(mode, "watchthread")) { signal(SIGUSR1, SIG_IGN); printf("wvar=%p\n", (void*)&wvar); raise(SIGUSR1); pthread_t t; pthread_create(&t, 0, writer, 0); pthread_join(t, 0); return wvar; }
	if (!strcmp(mode, "frames")) { signal(SIGUSR1, SIG_IGN); level1(); return counter; }
	if (!strcmp(mode, "syms")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p puts=%p\n", (void*)marker, dlsym(RTLD_DEFAULT, "puts")); raise(SIGUSR1); return 0; }
	if (!strcmp(mode, "dl")) { signal(SIGUSR1, SIG_IGN); printf("ready\n"); raise(SIGUSR1); void* h = dlopen("/work/libtest.so", RTLD_NOW); printf("loaded=%p\n", h); void (*f)(void) = (void (*)(void))dlsym(h, "libfunc"); printf("libfunc=%p\n", (void*)f); raise(SIGUSR1); f(); return 0; }
	if (!strcmp(mode, "dlcycle")) { signal(SIGUSR1, SIG_IGN); for (int i = 1; i <= 2; i++) { void* h = dlopen("/work/libtest.so", RTLD_NOW); void (*f)(void) = (void (*)(void))dlsym(h, "libfunc"); printf("cycle%d=%p\n", i, (void*)f); raise(SIGUSR1); f(); dlclose(h); } return 0; }
	if (!strcmp(mode, "dlrebase")) { signal(SIGUSR1, SIG_IGN); void* h = dlopen("/work/libtest.so", RTLD_NOW); void (*f)(void) = (void (*)(void))dlsym(h, "libfunc"); uintptr_t lo, hi; int range = libraryRange(&lo, &hi); printf("cycle1=%p\n", (void*)f); raise(SIGUSR1); f(); dlclose(h); void* held = range ? mmap((void*)lo, hi - lo, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) : MAP_FAILED; h = dlopen("/work/libtest.so", RTLD_NOW); f = (void (*)(void))dlsym(h, "libfunc"); printf("reserved=%p cycle2=%p\n", held, (void*)f); raise(SIGUSR1); f(); dlclose(h); return held == MAP_FAILED; }
	if (!strcmp(mode, "stepover")) { signal(SIGUSR1, SIG_IGN); caller(0); return counter; }
	if (!strcmp(mode, "stepslow")) { signal(SIGUSR1, SIG_IGN); caller(1); return counter; }
	if (!strcmp(mode, "recurse")) { signal(SIGUSR1, SIG_IGN); recurse(3); return counter; }
	if (!strcmp(mode, "stepret")) { signal(SIGUSR1, SIG_IGN); outer(); return counter; }
	if (!strcmp(mode, "stepthreads")) { signal(SIGUSR1, SIG_IGN); pthread_t t[3]; for (long i = 0; i < 3; i++) pthread_create(&t[i], 0, stepWorker, (void*)i); for (int i = 0; i < 3; i++) pthread_join(t[i], 0); return counter > 255 ? 255 : counter; }
	if (!strcmp(mode, "forkbp")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); pid_t c = fork(); if (c == 0) { marker(); _exit(0); } int st = 0; waitpid(c, &st, 0); return WIFSIGNALED(st) ? 100 + WTERMSIG(st) : WEXITSTATUS(st); }
	if (!strcmp(mode, "execer")) { signal(SIGUSR1, SIG_IGN); raise(SIGUSR1); execl("/work/progs", "progs", "hello", (char*)0); return 99; }
	if (!strcmp(mode, "winsize")) { struct winsize w = {0}; int r = ioctl(0, TIOCGWINSZ, &w); printf("tty=%d ioctl=%d rows=%d cols=%d\n", isatty(0), r, w.ws_row, w.ws_col); return 0; }
	if (!strcmp(mode, "forkbp2")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); pid_t c = fork(); if (c == 0) { marker(); _exit(0); } int st = 0; waitpid(c, &st, 0); marker(); return WIFSIGNALED(st) ? 100 + WTERMSIG(st) : WEXITSTATUS(st); }
	if (!strcmp(mode, "vforkbp")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); pid_t c = vfork(); if (c == 0) { marker(); _exit(0); } int st = 0; waitpid(c, &st, 0); marker(); return WIFSIGNALED(st) ? 100 + WTERMSIG(st) : WEXITSTATUS(st); }
	if (!strcmp(mode, "spawnbp")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); pid_t c; char* av[] = {"progs", "hello", 0}; posix_spawn(&c, "/work/progs", 0, 0, av, environ); int st = 0; waitpid(c, &st, 0); marker(); return WIFSIGNALED(st) ? 100 + WTERMSIG(st) : WEXITSTATUS(st); }
	if (!strcmp(mode, "forkthreads")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); pthread_t t[3]; for (int i = 0; i < 3; i++) pthread_create(&t[i], 0, forker, 0); for (int i = 0; i < 3; i++) pthread_join(t[i], 0); return bad; }
	if (!strcmp(mode, "execbp")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); execl("/work/progs", "progs", "bp", (char*)0); return 99; }
	if (!strcmp(mode, "execloop")) { signal(SIGUSR1, SIG_IGN); raise(SIGUSR1); execl("/work/progs", "progs", "loop", (char*)0); return 99; }
	if (!strcmp(mode, "execthread")) { signal(SIGUSR1, SIG_IGN); pthread_t t; pthread_create(&t, 0, execWorker, 0); raise(SIGUSR1); pthread_join(t, 0); return 99; }
	if (!strcmp(mode, "sighandler")) { signal(SIGUSR1, SIG_IGN); struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = infoHandler; sa.sa_flags = SA_SIGINFO | SA_RESTART; sigaction(SIGUSR2, &sa, 0); signal(SIGWINCH, sigHandler); printf("info=%p handler=%p\n", (void*)infoHandler, (void*)sigHandler); raise(SIGUSR1); raise(SIGUSR2); raise(SIGWINCH); raise(SIGCHLD); return handled; }
	if (!strcmp(mode, "sigthread")) { signal(SIGUSR1, SIG_IGN); signal(SIGWINCH, sigHandler); printf("handler=%p\n", (void*)sigHandler); pthread_t t; pthread_create(&t, 0, handlerWaiter, 0); raise(SIGUSR1); usleep(50000); pthread_kill(t, SIGWINCH); pthread_join(t, 0); return handled; }
	if (!strcmp(mode, "sigtrap_raise")) { signal(SIGUSR1, SIG_IGN); struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = trapHandler; sa.sa_flags = SA_SIGINFO; sigaction(SIGTRAP, &sa, 0); printf("raiser=%p handler=%p\n", (void*)raiseTrap, (void*)trapHandler); raise(SIGUSR1); raiseTrap(); return handled; }
	if (!strcmp(mode, "sigtrap_kill")) { signal(SIGUSR1, SIG_IGN); struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = trapHandler; sa.sa_flags = SA_SIGINFO; sigaction(SIGTRAP, &sa, 0); raise(SIGUSR1); kill(getpid(), SIGTRAP); return handled; }
	if (!strcmp(mode, "sigtrap_instruction")) { signal(SIGUSR1, SIG_IGN); struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_sigaction = trapHandler; sa.sa_flags = SA_SIGINFO; sigaction(SIGTRAP, &sa, 0); printf("before=%p trap=%p handler=%p\n", (void*)before_trap_instruction, (void*)target_trap_instruction, (void*)trapHandler); raise(SIGUSR1); instructionTrap(); return handled; }
	if (!strcmp(mode, "sigtrap_unhandled")) { signal(SIGUSR1, SIG_IGN); raise(SIGUSR1); raise(SIGTRAP); return 99; }
	if (!strcmp(mode, "execpad")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); execl("/work/progs_pad", "progs_pad", "bp", (char*)0); return 99; }
	if (!strcmp(mode, "abort")) { abort(); }
	// A clone that is not a thread. Its exit signal is not SIGCHLD, so the kernel reports it as a clone and not as a fork. SIGURG
	// is one that the engine does not stop for.
	if (!strcmp(mode, "cloneproc")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); pid_t c = syscall(SYS_clone, SIGURG, 0, 0, 0, 0); if (c == 0) { marker(); _exit(0); } int st = 0; waitpid(c, &st, __WALL); marker(); return WIFSIGNALED(st) ? 100 + WTERMSIG(st) : WEXITSTATUS(st); }
	if (!strcmp(mode, "cloneshared")) { signal(SIGUSR1, SIG_IGN); printf("marker=%p\n", (void*)marker); raise(SIGUSR1); char* stack = malloc(65536); pid_t c = clone(cloneChild, stack + 65536, SIGURG | CLONE_VM, 0); int st = 0; waitpid(c, &st, __WALL); marker(); return WIFSIGNALED(st) ? 100 + WTERMSIG(st) : WEXITSTATUS(st); }
	if (!strcmp(mode, "flood")) { char b[4096]; memset(b, 'x', sizeof b); while (1) if (write(1, b, sizeof b) < 0) break; return 0; }
	if (!strcmp(mode, "lastwords")) { char b[8192]; memset(b, 'y', sizeof b); write(1, b, sizeof b); write(1, "THE END\n", 8); return 4; }
	// Raw system calls only, so that the first ones after the SIGUSR1 stop are the two that the tests look for
	if (!strcmp(mode, "syscalls")) { signal(SIGUSR1, SIG_IGN); long p = getpid(), t = syscall(SYS_gettid); syscall(SYS_tgkill, p, t, SIGUSR1); long r = syscall(SYS_getppid); syscall(SYS_close, 9999); return (int)(r & 0xff); }
	if (!strcmp(mode, "fdwrite")) { for (int i = 2; i < argc; i++) { int fd = atoi(argv[i]); char b[32]; int n = snprintf(b, 32, "fd%d\n", fd); if (write(fd, b, n) != n) printf("write to %d failed\n", fd); } return 0; }
	if (!strcmp(mode, "fdread")) { char b[64]; ssize_t n = read(atoi(argv[2]), b, 63); if (n < 0) n = 0; b[n] = 0; printf("read: %s", b); return 0; }
	if (!strcmp(mode, "fdopen")) { for (int i = 2; i < argc; i++) { int fd = atoi(argv[i]); printf("fd%d=%s ", fd, fcntl(fd, F_GETFD) >= 0 ? "open" : "closed"); } printf("\n"); return 0; }
	if (!strcmp(mode, "both")) { printf("to stdout\n"); fprintf(stderr, "to stderr\n"); return 0; }
	return 99;
}
