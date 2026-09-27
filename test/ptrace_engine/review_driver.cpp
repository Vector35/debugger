// Repros for the findings of the code review in PTRACE_REVIEW_FINDINGS.md.
//
// Every test here is written so that it FAILS while the finding it is named after stands, and passes once the finding is
// fixed. The exceptions are `resume_can_fail` and `maps_cost`, which establish a fact about the engine that a finding
// about `ptraceadapter.cpp` rests on: the adapter cannot be linked here, because it needs Binary Ninja.
//
// `./review_driver` runs all of them, `./review_driver <name>` runs one. The directory that holds `progs` comes from
// PTRACE_TEST_DIR, and is /work by default, which is where the Docker image of this harness mounts it.

#include "ptracearch.h"
#include "ptraceengine.h"
#include "ptracestep.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace BinaryNinjaDebugger;
using namespace std::chrono_literals;

extern "C" void PtraceTestFailNextResume();
extern "C" void PtraceTestFailNextPwrite();

static int failures = 0;
#define CHECK(condition) do { if (!(condition)) { printf("  FAIL line %d: %s\n", __LINE__, #condition); failures++; } } while (0)

static std::string TestDir()
{
	const char* dir = getenv("PTRACE_TEST_DIR");
	return dir && *dir ? dir : "/work";
}


struct Log
{
	std::mutex mutex;
	std::condition_variable condition;
	std::deque<PtraceEngine::Event> events;
	std::string output;

	void Push(const PtraceEngine::Event& event)
	{
		std::lock_guard<std::mutex> lock(mutex);
		if (event.type == PtraceEngine::OutputEvent)
			output += event.data;
		events.push_back(event);
		condition.notify_all();
	}

	bool Wait(PtraceEngine::EventType type, PtraceEngine::Event& result, std::chrono::milliseconds timeout = 5s)
	{
		std::unique_lock<std::mutex> lock(mutex);
		auto deadline = std::chrono::steady_clock::now() + timeout;
		while (true)
		{
			for (auto it = events.begin(); it != events.end(); ++it)
			{
				if (it->type != type)
					continue;
				result = *it;
				events.erase(it);
				return true;
			}
			if (condition.wait_until(lock, deadline) == std::cv_status::timeout)
				return false;
		}
	}
};


#if defined(__aarch64__)
// The built-in tables are x86 and x86_64, so aarch64 needs one of its own. This is the same table the other drivers of
// this harness use.
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#define NT_ARM_HW_WATCH 0x403
#endif
struct ArmHw : PtraceHwDebug
{
	struct State { uint32_t info; uint32_t pad; struct { uint64_t addr; uint32_t ctrl; uint32_t pad; } regs[16]; };
	size_t SlotCount() const override { return 8; }
	bool SlotSupports(size_t slot, PtraceHwType type) const override { return (slot < 4) == (type == PtraceHwType::Execute); }
	bool Program(pid_t tid, size_t slot, uint64_t addr, uint32_t ctrl)
	{
		int note = slot < 4 ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH; size_t index = slot % 4;
		State st; memset(&st, 0, sizeof st); iovec iov = {&st, sizeof st};
		if (ptrace(PTRACE_GETREGSET, tid, (void*)(uintptr_t)note, &iov) != 0) return false;
		st.regs[index].addr = addr; st.regs[index].ctrl = ctrl;
		iov.iov_len = offsetof(State, regs) + (index + 1) * sizeof(st.regs[0]);
		return ptrace(PTRACE_SETREGSET, tid, (void*)(uintptr_t)note, &iov) == 0;
	}
	bool Set(pid_t tid, size_t slot, uint64_t address, PtraceHwType type, size_t size) override
	{
		if (type == PtraceHwType::Execute) return Program(tid, slot, address, (0xf << 5) | (2 << 1) | 1);
		uint32_t lsc = type == PtraceHwType::Write ? 2 : (type == PtraceHwType::Read ? 1 : 3);
		return Program(tid, slot, address, (((1u << size) - 1) << 5) | (lsc << 3) | (2 << 1) | 1);
	}
	bool Clear(pid_t tid, size_t slot) override { return Program(tid, slot, 0, 0); }
	bool DataTrapsBeforeAccess() const override { return true; }
};
static ArmHw g_armHw;
static PtraceArch BuildTestArch()
{
	PtraceArch arch;
	arch.name = "aarch64";
	arch.pc = "pc";
	arch.sp = "sp";
	arch.regsets = {NT_PRSTATUS};
	arch.breakpointInstruction = {0x00, 0x00, 0x20, 0xd4};
	arch.hwDebug = &g_armHw;
	for (size_t i = 0; i < 31; i++)
		arch.registers.push_back({"x" + std::to_string(i), NT_PRSTATUS, i * 8, 8});
	arch.registers.push_back({"sp", NT_PRSTATUS, 31 * 8, 8});
	arch.registers.push_back({"pc", NT_PRSTATUS, 32 * 8, 8});
	return arch;
}
static PtraceArch g_arch = BuildTestArch();
static const PtraceArch* TestArch() { return &g_arch; }
// A call is 4 bytes, and a breakpoint traps at the instruction itself
constexpr size_t kCallLength = 4;
#else
// Detected from the target, the way the adapter does it
static const PtraceArch* TestArch() { return nullptr; }
constexpr size_t kCallLength = 5;
#endif


static std::unique_ptr<PtraceEngine> Start(Log& log, const std::string& mode)
{
	auto engine = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& event) { log.Push(event); });
	PtraceEngine::LaunchOptions options;
	options.path = TestDir() + "/progs";
	options.args = {mode};
	options.arch = TestArch();
	std::string error;
	if (!engine->Launch(options, error))
	{
		printf("  launch failed: %s\n", error.c_str());
		failures++;
		return nullptr;
	}
	return engine;
}


static uint64_t AddressFromOutput(Log& log, const char* key)
{
	for (int attempt = 0; attempt < 300; attempt++)
	{
		{
			std::lock_guard<std::mutex> lock(log.mutex);
			auto at = log.output.find(key);
			if (at != std::string::npos)
			{
				unsigned long long value = 0;
				sscanf(log.output.c_str() + at + strlen(key), "%llx", &value);
				return value;
			}
		}
		std::this_thread::sleep_for(10ms);
	}
	return 0;
}


// Runs a target that prints an address and then raises SIGUSR1, and comes back with it stopped at that signal
static std::unique_ptr<PtraceEngine> StartAtSignal(Log& log, const std::string& mode, PtraceEngine::Event& event)
{
	auto engine = Start(log, mode);
	if (!engine)
		return nullptr;

	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	CHECK(engine->Resume(false, 0));
	if (!log.Wait(PtraceEngine::StoppedEvent, event) || event.signal != SIGUSR1)
	{
		printf("  the target did not stop at SIGUSR1\n");
		failures++;
		engine->Kill();
		return nullptr;
	}
	return engine;
}


// Reads the memory of the target without going through the engine, so that what the engine believes and what is really
// there can be told apart
static std::vector<uint8_t> RawRead(pid_t pid, uint64_t address, size_t size)
{
	std::vector<uint8_t> data(size);
	int fd = open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
	if (fd < 0)
		return {};
	auto count = pread(fd, data.data(), size, address);
	close(fd);
	if (count != (ssize_t)size)
		return {};
	return data;
}


static std::string Hex(const std::vector<uint8_t>& bytes)
{
	std::string text;
	char buffer[8];
	for (uint8_t byte : bytes)
	{
		snprintf(buffer, sizeof(buffer), "%02x ", byte);
		text += buffer;
	}
	return text;
}


// F4. WriteMemory records the bytes it puts underneath a breakpoint before it knows that the write went through. When
// the write fails, the saved bytes are the ones that were never written, and taking the breakpoint out puts those into
// the target instead of the instruction that was there.
static void WriteMemoryRollback()
{
	printf("[write_memory_rollback]\n");
	Log log;
	PtraceEngine::Event event;
	auto engine = StartAtSignal(log, "bp", event);
	if (!engine)
		return;

	uint64_t marker = AddressFromOutput(log, "marker=");
	CHECK(marker != 0);
	size_t size = engine->GetArch()->breakpointInstruction.size();
	auto original = RawRead(engine->GetPid(), marker, size);
	CHECK(original.size() == size);
	CHECK(engine->AddBreakpoint(marker));

	// A write over a breakpoint whose underlying pwrite fails. /proc/<pid>/mem does that for real when the range runs
	// off the end of a mapping, which is what a write across the edge of a segment does.
	std::vector<uint8_t> replacement(size, 0x90);
	PtraceTestFailNextPwrite();
	CHECK(!engine->WriteMemory(marker, replacement.data(), replacement.size()));

	// Nothing was written, so taking the breakpoint out has to leave the instruction that was there
	CHECK(engine->RemoveBreakpoint(marker));
	auto now = RawRead(engine->GetPid(), marker, size);
	printf("  was %s, the failed write wanted %s, the target now has %s\n", Hex(original).c_str(),
		Hex(replacement).c_str(), Hex(now).c_str());
	CHECK(now == original);
	CHECK(engine->Kill());
}


// F5. The exit of the thread group leader is taken for the exit of the process. A leader that calls pthread_exit()
// while another thread runs on leaves the group alive, and the debugger should not say that the target is gone.
static void LeaderExit()
{
	printf("[leader_exit]\n");
	Log log;
	PtraceEngine::Event event;
	auto engine = StartAtSignal(log, "leaderexit", event);
	if (!engine)
		return;

	pid_t pid = engine->GetPid();
	CHECK(engine->Resume(false, 0));

	// The leader leaves now. The worker thread goes on for about a second, and then ends the process with 7.
	bool early = log.Wait(PtraceEngine::ExitedEvent, event, 600ms);
	bool alive = kill(pid, 0) == 0;
	if (early)
		printf("  the engine reported the target as exited (code %d) while the process is %s\n", event.exitCode,
			alive ? "still alive" : "gone");
	CHECK(!early);

	if (early)
	{
		// The engine has stopped looking at the target, so the rest of the group is left behind: clean it up by hand
		printf("  the group is %s after the report\n", alive ? "still running" : "gone");
		CHECK(alive);
		kill(pid, SIGKILL);
		int status = 0;
		waitpid(pid, &status, __WALL);
		return;
	}

	CHECK(log.Wait(PtraceEngine::ExitedEvent, event, 5s));
	printf("  the target exited with %d\n", event.exitCode);
	CHECK(event.exitCode == 7);
}


// F6. An interrupt is a SIGSTOP that the engine counts. A SIGSTOP that the engine sends itself to stop a thread can
// consume the one that the interrupt sent, because two pending SIGSTOPs of the same thread are one signal. The count of
// interrupts on their way is then never brought down again, and every later interrupt is coalesced into one that will
// never arrive: pausing the target stops working for good.
static void InterruptLeak()
{
	printf("[interrupt_leak]\n");
	Log log;
	PtraceEngine::Event event;
	// Four threads that run into a breakpoint over and over and never end. Every one of those stops makes the engine
	// stop the other three with a SIGSTOP of its own, which is the signal that can swallow an interrupt's.
	auto engine = StartAtSignal(log, "markerthreads", event);
	if (!engine)
		return;

	uint64_t marker = AddressFromOutput(log, "marker=");
	CHECK(marker != 0);
	CHECK(engine->AddBreakpoint(marker));

	// Interrupts from a thread of their own, so that they land at every moment of a stop and not only after one
	std::atomic<bool> stopHammering {false};
	std::atomic<int> interrupts {0};
	std::thread hammer([&]() {
		for (unsigned round = 0; !stopHammering; round++)
		{
			if (engine->Interrupt())
				interrupts++;
			std::this_thread::sleep_for(std::chrono::microseconds(20 + (round * 53) % 400));
		}
	});

	// Once the count of interrupts on their way has leaked it stays leaked, so this can be looked for more than once
	int stops = 0;
	bool lost = false;
	for (int attempt = 0; attempt < 8 && !lost; attempt++)
	{
		for (int round = 0; round < 200; round++)
		{
			if (!log.Wait(PtraceEngine::StoppedEvent, event, 2s))
			{
				printf("  nothing stopped after %d stops\n", stops);
				break;
			}
			stops++;
			if (!engine->Resume(false, 0))
				break;
		}

		// Ask for a pause with nothing else going on. If an interrupt that was sent was swallowed by one of the
		// engine's own SIGSTOPs, the count never came down, and this one is coalesced into it: no signal is sent.
		stopHammering = true;
		hammer.join();
		for (int drain = 0; drain < 20 && engine->IsRunning(); drain++)
			log.Wait(PtraceEngine::StoppedEvent, event, 200ms);
		{
			std::lock_guard<std::mutex> lock(log.mutex);
			log.events.clear();
		}
		// Out of the way, so that the stop that answers the pause cannot be a breakpoint's
		CHECK(engine->RemoveBreakpoint(marker));
		CHECK(engine->Resume(false, 0));
		std::this_thread::sleep_for(50ms);
		bool taken = engine->Interrupt();
		bool answered = log.Wait(PtraceEngine::StoppedEvent, event, 3s);
		CHECK(taken);
		lost = taken && !answered;
		if (lost)
		{
			bool alive = kill(engine->GetPid(), 0) == 0;
			printf("  after %d interrupts and %d stops, a pause was taken and never answered. The target is %s.\n",
				interrupts.load(), stops, alive ? "alive" : "gone");
			printf("  every pause from here on is coalesced into it, so the target can no longer be paused\n");
			failures++;
			break;
		}
		if (attempt < 7)
		{
			CHECK(engine->AddBreakpoint(marker));
			stopHammering = false;
			hammer = std::thread([&]() {
				for (unsigned round = 0; !stopHammering; round++)
				{
					if (engine->Interrupt())
						interrupts++;
					std::this_thread::sleep_for(std::chrono::microseconds(20 + (round * 53) % 400));
				}
			});
			CHECK(engine->Resume(false, 0));
		}
	}
	if (!lost)
		printf("  %d interrupts, %d stops, and no pause was lost this time\n", interrupts.load(), stops);
	engine->Kill();
}


// F7. A SIGSTOP that somebody else sends the target is reported like any other signal and then delivered when the
// target is resumed, which stops the whole group in a way the engine does not model. The target should go on running.
static void ExternalSigstop()
{
	printf("[external_sigstop]\n");
	Log log;
	PtraceEngine::Event event;
	auto engine = StartAtSignal(log, "bploop", event);
	if (!engine)
		return;

	uint64_t marker = AddressFromOutput(log, "marker=");
	CHECK(marker != 0);
	CHECK(engine->Resume(false, 0));
	std::this_thread::sleep_for(100ms);

	// Not engine->Interrupt(): this is somebody else stopping the target, a shell with ^Z for example
	CHECK(kill(engine->GetPid(), SIGSTOP) == 0);
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event, 3s));
	printf("  reported signal %d, interrupted=%d\n", event.signal, (int)event.interrupted);

	// The target loops on marker(), so it runs into a breakpoint there as soon as it is running again
	CHECK(engine->AddBreakpoint(marker));
	CHECK(engine->Resume(false, 0));
	bool progressed = log.Wait(PtraceEngine::StoppedEvent, event, 3s) && event.breakpoint;
	if (!progressed)
		printf("  the target did not run again after the SIGSTOP was passed on to it\n");
	CHECK(progressed);
	engine->Kill();
}


// F9. Between fork() and exec() the child clears the signal mask but not the dispositions, and exec keeps the signals
// that are ignored. The target inherits them from the debugger, and behaves differently from the same program started
// by a shell.
static void InheritedSigIgn()
{
	printf("[inherited_sigign]\n");
	auto previous = signal(SIGUSR2, SIG_IGN);
	Log log;
	PtraceEngine::Event event;
	auto engine = Start(log, "hello");
	if (!engine)
	{
		signal(SIGUSR2, previous);
		return;
	}
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));

	uint64_t ignored = 0;
	std::ifstream status("/proc/" + std::to_string(engine->GetPid()) + "/status");
	std::string line;
	while (std::getline(status, line))
	{
		if (line.rfind("SigIgn:", 0) == 0)
		{
			ignored = strtoull(line.c_str() + strlen("SigIgn:"), nullptr, 16);
			break;
		}
	}
	signal(SIGUSR2, previous);

	bool inherited = (ignored >> (SIGUSR2 - 1)) & 1;
	printf("  the target's SigIgn is %016llx, SIGUSR2 is %s\n", (unsigned long long)ignored,
		inherited ? "ignored" : "not ignored");
	CHECK(!inherited);
	CHECK(engine->Kill());
}


// F1. PtraceAdapter::~PtraceAdapter and PtraceAdapter::CreateEngine (ptraceadapter.cpp:201 and :286) destroy the
// stepper before the engine, and the engine is the only thing that stops the thread the handler runs on. This is that
// pair of objects and that order of destruction, with the handler where it really goes: inside the stepper, in the
// callback that gives a breakpoint back, which in the adapter is ReleaseBreakpoint and waits for the tracer thread.
//
// It is run three ways, so that what the order of those two lines is worth can be seen:
//   1. the order the adapter has, the stepper first
//   2. the engine first, which is the obvious fix
//   3. the engine first, and the engine waiting long enough for the handler to finish
//
// Each way runs in a child process, because a use after free can end the process before it can say anything, and that
// is a result and not a reason to lose the rest of the run. The probe is in shared memory so that what the child
// reached is still readable once it is gone.
struct Probe
{
	std::atomic<bool> inRelease {false};
	std::atomic<bool> release {false};
	std::atomic<bool> stepperGone {false};
	std::atomic<bool> usedAfterFree {false};
	std::atomic<bool> handlerRanOnAfterDestruction {false};
	std::atomic<bool> aboutToUseEngine {false};
	std::atomic<bool> engineWasNull {false};
	std::atomic<bool> handlerFinished {false};
};

struct MiniAdapter
{
	// The members of PtraceAdapter, in the order it keeps them
	std::unique_ptr<PtraceStepper> stepper;
	std::unique_ptr<PtraceEngine> engine;
	Probe* probe = nullptr;
	bool engineFirst = false;

	~MiniAdapter()
	{
		if (engineFirst)
		{
			engine.reset();
			stepper.reset();
			probe->stepperGone = true;
			return;
		}
		// PtraceAdapter::~PtraceAdapter, line for line
		stepper.reset();
		probe->stepperGone = true;
		engine.reset();
	}
};

static int TeardownOrderScenario(Probe* probe, bool engineFirst, std::chrono::milliseconds teardownWait)
{
	Log log;
	auto adapter = std::make_unique<MiniAdapter>();
	adapter->probe = probe;
	adapter->engineFirst = engineFirst;
	MiniAdapter* raw = adapter.get();

	// The handler captures the adapter the way the adapter's own lambda captures `this`
	adapter->engine = std::make_unique<PtraceEngine>([&log, raw](const PtraceEngine::Event& event) {
		log.Push(event);
		if (event.type != PtraceEngine::StoppedEvent)
			return;
		if (raw->stepper && raw->stepper->IsActive())
			raw->stepper->OnStop(event, 0, 0, false);
	});
	adapter->engine->SetTeardownWait(teardownWait);
	adapter->stepper = std::make_unique<PtraceStepper>(
		*adapter->engine,
		// Nothing is really put into the target: only the answer matters to the stepper, and a breakpoint that the
		// target ran into would stop it at a moment of its own choosing
		[](uint64_t) { return true; },
		[raw, probe](uint64_t address) {
			// ReleaseBreakpoint waits for the tracer thread, which can be in the middle of stopping the other threads
			probe->inRelease = true;
			for (int attempt = 0; attempt < 160 && !probe->release; attempt++)
				std::this_thread::sleep_for(5ms);
			if (probe->stepperGone)
				probe->usedAfterFree = true;
			// ReleaseBreakpoint's own line: it reaches back into the engine through the adapter. unique_ptr::reset
			// puts the null in before it runs the destructor, so the handler can find nothing there.
			probe->aboutToUseEngine = true;
			probe->engineWasNull = raw->engine == nullptr;
			bool removed = raw->engine->RemoveBreakpoint(address);
			probe->handlerFinished = true;
			return removed;
		});

	PtraceEngine::LaunchOptions options;
	options.path = TestDir() + "/progs";
	options.args = {"loop"};
	options.arch = TestArch();
	std::string error;
	if (!adapter->engine->Launch(options, error))
	{
		printf("    launch failed: %s\n", error.c_str());
		return 4;
	}

	PtraceEngine::Event event;
	if (!log.Wait(PtraceEngine::StoppedEvent, event))
		return 4;
	uint64_t pc = 0;
	std::vector<uint8_t> registers;
	auto arch = adapter->engine->GetArch();
	auto pcRegister = arch ? arch->Find(arch->pc) : nullptr;
	if (!pcRegister || !adapter->engine->GetRegisterSet(event.tid, pcRegister->regset, registers))
		return 4;
	memcpy(&pc, registers.data() + pcRegister->offset, sizeof(pc));

	// A step is going on, so the next stop goes through the stepper, as it does in the adapter
	if (!adapter->stepper->StepOver(event.tid, pc, 0, kCallLength, sizeof(uint64_t)))
		return 4;
	std::this_thread::sleep_for(100ms);
	if (!adapter->engine->Interrupt())
		return 4;

	for (int attempt = 0; attempt < 400 && !probe->inRelease; attempt++)
		std::this_thread::sleep_for(5ms);
	if (!probe->inRelease)
	{
		printf("    the handler never reached the stepper's callback\n");
		probe->release = true;
		return 4;
	}

	// The handler is inside the stepper. This is the destructor of the adapter.
	auto start = std::chrono::steady_clock::now();
	adapter.reset();
	double took = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

	probe->handlerRanOnAfterDestruction = probe->inRelease && !probe->handlerFinished;
	probe->release = true;
	for (int attempt = 0; attempt < 200 && !probe->handlerFinished; attempt++)
		std::this_thread::sleep_for(5ms);

	printf("    the destruction took %.2f s, the handler was %s when it returned\n", took,
		probe->handlerRanOnAfterDestruction ? "still inside the stepper" : "done");
	std::this_thread::sleep_for(100ms);

	// The stepper must not be destroyed while the handler is inside it, and the handler must not still be running when
	// the adapter is gone
	return (probe->usedAfterFree ? 1 : 0) | (probe->handlerRanOnAfterDestruction ? 2 : 0);
}


static void TeardownArm(const char* name, bool engineFirst, std::chrono::milliseconds teardownWait, bool expectClean)
{
	printf("  %s\n", name);
	fflush(stdout);

	void* shared = mmap(nullptr, sizeof(Probe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED)
	{
		printf("    no shared memory for the probe\n");
		failures++;
		return;
	}
	Probe* probe = new (shared) Probe();

	pid_t child = fork();
	if (child == 0)
		_exit(TeardownOrderScenario(probe, engineFirst, teardownWait));
	if (child < 0)
	{
		printf("    fork failed\n");
		failures++;
		munmap(shared, sizeof(Probe));
		return;
	}

	int status = 0;
	auto deadline = std::chrono::steady_clock::now() + 60s;
	while (waitpid(child, &status, WNOHANG) == 0)
	{
		if (std::chrono::steady_clock::now() > deadline)
		{
			kill(child, SIGKILL);
			waitpid(child, &status, 0);
			printf("    it did not finish\n");
			failures++;
			munmap(shared, sizeof(Probe));
			return;
		}
		std::this_thread::sleep_for(20ms);
	}

	bool crashed = WIFSIGNALED(status);
	int result = crashed ? 0 : WEXITSTATUS(status);
	if (crashed)
	{
		printf("    the process died with signal %d\n", WTERMSIG(status));
		printf("    the handler had got as far as: in the callback=%d, the stepper destroyed under it=%d,"
			   " calling back into the engine=%d (which was %s), finished=%d\n",
			(int)probe->inRelease, (int)probe->stepperGone, (int)probe->aboutToUseEngine,
			probe->engineWasNull ? "already null" : "still there", (int)probe->handlerFinished);
		if (expectClean)
			failures++;
	}
	else if (result == 4)
	{
		printf("    the scenario could not be set up\n");
		failures++;
	}
	else
	{
		if (result & 1)
			printf("    the handler went on using the stepper after it was destroyed\n");
		if (result & 2)
			printf("    the handler was still running when the adapter was gone\n");
		if (!result)
			printf("    clean: the handler finished before anything it uses was destroyed\n");
		if (expectClean)
		{
			CHECK(!(result & 1));
			CHECK(!(result & 2));
		}
	}
	probe->~Probe();
	munmap(shared, sizeof(Probe));
}


static void TeardownOrder()
{
	printf("[teardown_order]\n");
	// What the adapter does today, and then the two changes that look like they would put it right. None of them is
	// clean, which is what this test is really saying: the handler has to be stopped, not raced with.
	TeardownArm("the order the adapter has, the stepper first:", false, 300ms, false);
	TeardownArm("the engine first, which is the obvious fix:", true, 300ms, false);
	TeardownArm("the engine first, and waiting for the handler:", true, 5s, true);
}


// F2. The adapter resumes the target by itself at the first stop, at a stop of the dynamic loader and after an exec,
// and drops what Resume says (ptraceadapter.cpp:374, :383 and :1759). This is that Resume saying no at such a stop.
// What follows from it is in ptraceadapter.cpp and debuggercontroller.cpp:2407, which are not linked here.
static void ResumeCanFail()
{
	printf("[resume_can_fail]\n");
	Log log;
	PtraceEngine::Event event;
	auto engine = Start(log, "bp");
	if (!engine)
		return;

	// The first stop, which is where the adapter applies the breakpoints and resumes without reporting anything
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	PtraceTestFailNextResume();
	bool resumed = engine->Resume(false, 0);
	printf("  Resume at the first stop returned %s, and the adapter does not look at it\n", resumed ? "true" : "false");
	CHECK(!resumed);

	// The engine is left in one piece: the caller is meant to notice and say so
	CHECK(!engine->IsRunning());
	CHECK(engine->Resume(false, 0));
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	CHECK(engine->Kill());
}


// F3. ResolveModuleAddress parses the whole of /proc/<pid>/maps, and ApplyBreakpoints calls it once for every
// breakpoint, at every stop of the dynamic loader. This is what one of those parses costs.
static void MapsCost()
{
	printf("[maps_cost]\n");
	Log log;
	PtraceEngine::Event event;
	auto engine = StartAtSignal(log, "bp", event);
	if (!engine)
		return;

	auto start = std::chrono::steady_clock::now();
	constexpr int rounds = 200;
	size_t entries = 0;
	for (int round = 0; round < rounds; round++)
		entries = engine->GetMaps().size();
	double each = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() / rounds;

	printf("  %zu mappings, %.0f us for one parse of the maps\n", entries, each * 1e6);
	printf("  a target with 30 libraries and 50 breakpoints does that %d times in a launch, which is %.0f ms\n",
		30 * 50, 30 * 50 * each * 1e3);
	CHECK(entries > 0);
	CHECK(engine->Kill());
}


int main(int argc, char** argv)
{
	struct { const char* name; void (*run)(); } tests[] = {
		{"write_memory_rollback", WriteMemoryRollback},
		{"leader_exit", LeaderExit},
		{"interrupt_leak", InterruptLeak},
		{"external_sigstop", ExternalSigstop},
		{"inherited_sigign", InheritedSigIgn},
		{"teardown_order", TeardownOrder},
		{"resume_can_fail", ResumeCanFail},
		{"maps_cost", MapsCost}};
	for (auto& test : tests)
	{
		if (argc > 1 && strcmp(argv[1], test.name))
			continue;
		int before = failures;
		test.run();
		printf("  %s\n", failures == before ? "ok" : "FAILED");
		fflush(stdout);
	}
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
