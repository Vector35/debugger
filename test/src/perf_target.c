// The debuggee for test/perf_benchmark.py. It runs forever doing a small amount of pure computation, with
// no system calls in the loop, so the benchmark can step, break, and resume it as many times as it likes
// without the target exiting or the timings being dominated by the target's own work.
//
// perf_leaf is called twice per pass through perf_work. The benchmark breaks on perf_leaf, steps out of it
// (StepReturn), and steps through perf_work; the noinline attributes keep those calls as real calls.
// perf_unused is never called; see below.
#include <stdint.h>

#ifdef _WIN32
#define PERF_EXPORT __declspec(dllexport)
#define PERF_NOINLINE __declspec(noinline)
#else
#define PERF_EXPORT __attribute__((visibility("default")))
#define PERF_NOINLINE __attribute__((noinline))
#endif

volatile uint64_t perf_sink;

PERF_EXPORT PERF_NOINLINE uint64_t perf_leaf(uint64_t x)
{
	return x * 7 + 1;
}

PERF_EXPORT PERF_NOINLINE uint64_t perf_work(uint64_t x)
{
	x = perf_leaf(x);
	x ^= x >> 3;
	x = perf_leaf(x);
	return x + 5;
}

// Never called. It gives the benchmark a run of instructions to put breakpoints on that the program cannot
// execute, so breakpoint bookkeeping (even a leaked breakpoint) cannot change where the target stops. The
// volatile keeps the compiler from folding it into a few instructions at higher optimization levels.
PERF_EXPORT PERF_NOINLINE uint64_t perf_unused(uint64_t x)
{
	volatile uint64_t v = x;
	for (int round = 0; round < 12; round++)
	{
		v = v * 3 + 1;
		v ^= v >> 5;
		v += round;
	}
	return v;
}

int main(void)
{
	for (;;)
		perf_sink = perf_work(perf_sink);
}
