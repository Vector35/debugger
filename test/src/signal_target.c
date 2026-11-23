// A debuggee driven by signal handlers, for test/adapter_signal_fuzz_test.py. Each mode raises signals that
// its handlers count and fold into a checksum, then checks the result and exits 0 only if the handlers ran
// exactly as often, and in the order, that the signals it raised require. A debugger that drops, duplicates,
// or reorders a signal, or loses a single-step, makes the program exit with a nonzero code.
//
//   sync    synchronous signals and nested handlers
//   segv    a SIGSEGV that the handler recovers from, repeatedly
//   timer   SIGALRM from an interval timer while the main thread computes
//   sleep   SIGALRM interrupting nanosleep, which the program restarts
//   thread  signals sent to another thread with pthread_kill
//
// The handlers are noinline and have distinct names so tests can put breakpoints in them.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define NOINLINE __attribute__((noinline))

enum
{
	ExitOk = 0,
	ExitBadUsage = 2,
	ExitWrongCount = 10,
	ExitWrongChecksum = 11,
	ExitWrongThread = 12,
	ExitTimerStarved = 13,
	ExitSleepCut = 14,
};

static const int rounds = 20;
// Slower than a debugger takes to resume, so a breakpoint in the SIGALRM handler cannot keep the program from running
static const long TimerIntervalMicroseconds = 100 * 1000;

static volatile sig_atomic_t usr1_count, usr2_count, segv_count, alarm_count, wrong_thread;
static volatile unsigned checksum;
static sigjmp_buf recover;
static pthread_t worker_thread;

static unsigned mix(unsigned sum, unsigned value)
{
	return sum * 31 + value;
}

NOINLINE void handler_usr2(int signal)
{
	(void)signal;
	usr2_count++;
	checksum = mix(checksum, 2);
}

NOINLINE void handler_usr1(int signal)
{
	(void)signal;
	usr1_count++;
	checksum = mix(checksum, 1);
	if (usr1_count % 3 == 0)
		raise(SIGUSR2);
}

NOINLINE void handler_segv(int signal)
{
	(void)signal;
	segv_count++;
	checksum = mix(checksum, 3);
	siglongjmp(recover, 1);
}

NOINLINE void handler_alarm(int signal)
{
	(void)signal;
	alarm_count++;
}

NOINLINE void handler_thread(int signal)
{
	(void)signal;
	if (!pthread_equal(pthread_self(), worker_thread))
		wrong_thread = 1;
	usr1_count++;
	checksum = mix(checksum, 5);
}

static void install(int signal_number, void (*handler)(int), int flags)
{
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = flags;
	sigaction(signal_number, &action, NULL);
}

static int run_sync(void)
{
	install(SIGUSR1, handler_usr1, 0);
	install(SIGUSR2, handler_usr2, 0);

	unsigned expected = 0;
	int expected_usr1 = 0, expected_usr2 = 0;
	for (int round = 0; round < rounds; round++)
	{
		raise(SIGUSR1);
		expected = mix(expected, 1);
		if (++expected_usr1 % 3 == 0)
		{
			expected = mix(expected, 2);
			expected_usr2++;
		}

		raise(SIGUSR2);
		expected = mix(expected, 2);
		expected_usr2++;
	}

	if (usr1_count != expected_usr1 || usr2_count != expected_usr2)
		return ExitWrongCount;
	return checksum == expected ? ExitOk : ExitWrongChecksum;
}

static int run_segv(void)
{
	install(SIGSEGV, handler_segv, SA_NODEFER);
	install(SIGBUS, handler_segv, SA_NODEFER);

	unsigned expected = 0;
	for (int round = 0; round < rounds; round++)
	{
		if (sigsetjmp(recover, 1) == 0)
			*(volatile int*)0 = round;
		expected = mix(expected, 3);
	}

	if (segv_count != rounds)
		return ExitWrongCount;
	return checksum == expected ? ExitOk : ExitWrongChecksum;
}

static volatile unsigned long sink;

static void start_timer(long microseconds)
{
	struct itimerval timer;
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = microseconds;
	timer.it_value = timer.it_interval;
	setitimer(ITIMER_REAL, &timer, NULL);
}

static void stop_timer(void)
{
	struct itimerval timer;
	memset(&timer, 0, sizeof(timer));
	setitimer(ITIMER_REAL, &timer, NULL);
}

static int run_timer(void)
{
	install(SIGALRM, handler_alarm, 0);
	start_timer(TimerIntervalMicroseconds);
	time_t deadline = time(NULL) + 30;
	while (alarm_count < 5 && time(NULL) < deadline)
		sink = sink * 31 + 7;
	stop_timer();
	return alarm_count >= 5 ? ExitOk : ExitTimerStarved;
}

static long milliseconds_until(const struct timespec* deadline)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (deadline->tv_sec - now.tv_sec) * 1000 + (deadline->tv_nsec - now.tv_nsec) / 1000000;
}

// The wait is measured against the clock, not by what nanosleep reports as left, so time that the program
// spends stopped under a debugger counts. Otherwise a signal that stops it more often than it can sleep
// would keep it from ever finishing.
static int run_sleep(void)
{
	install(SIGALRM, handler_alarm, 0);
	start_timer(TimerIntervalMicroseconds);
	for (int i = 0; i < 20; i++)
	{
		struct timespec deadline;
		clock_gettime(CLOCK_MONOTONIC, &deadline);
		deadline.tv_nsec += 50 * 1000 * 1000;
		deadline.tv_sec += deadline.tv_nsec / 1000000000;
		deadline.tv_nsec %= 1000000000;
		for (long left = milliseconds_until(&deadline); left > 0; left = milliseconds_until(&deadline))
		{
			struct timespec wait = {0, left * 1000 * 1000};
			if (nanosleep(&wait, NULL) != 0 && errno != EINTR)
				return ExitSleepCut;
		}
	}
	stop_timer();
	return alarm_count > 0 ? ExitOk : ExitSleepCut;
}

static void* worker(void* argument)
{
	(void)argument;
	while (usr1_count < rounds)
		sink = sink * 31 + 7;
	return NULL;
}

static int run_thread(void)
{
	install(SIGUSR1, handler_thread, 0);
	pthread_create(&worker_thread, NULL, worker, NULL);
	unsigned expected = 0;
	for (int round = 0; round < rounds; round++)
	{
		int before = usr1_count;
		pthread_kill(worker_thread, SIGUSR1);
		time_t deadline = time(NULL) + 30;
		while (usr1_count == before && time(NULL) < deadline)
			sink = sink * 31 + 7;
		expected = mix(expected, 5);
	}
	pthread_join(worker_thread, NULL);
	if (wrong_thread)
		return ExitWrongThread;
	if (usr1_count != rounds)
		return ExitWrongCount;
	return checksum == expected ? ExitOk : ExitWrongChecksum;
}

int main(int argc, char** argv)
{
	const char* mode = argc > 1 ? argv[1] : "sync";
	int result;
	if (!strcmp(mode, "sync"))
		result = run_sync();
	else if (!strcmp(mode, "segv"))
		result = run_segv();
	else if (!strcmp(mode, "timer"))
		result = run_timer();
	else if (!strcmp(mode, "sleep"))
		result = run_sleep();
	else if (!strcmp(mode, "thread"))
		result = run_thread();
	else
		return ExitBadUsage;
	printf("signal_target %s: exit %d\n", mode, result);
	return result;
}
