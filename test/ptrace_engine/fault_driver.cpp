#include "ptracearch.h"
#include "ptraceengine.h"
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <elf.h>
#include <mutex>
#include <thread>
using namespace BinaryNinjaDebugger;
using namespace std::chrono_literals;

extern "C" void PtraceTestFailNextResume();
extern "C" void PtraceTestFailNextPwrite();
extern "C" void PtraceTestFailNextSetOptions();
extern "C" void PtraceTestFailNextMemOpen();
extern "C" void PtraceTestHideWaitpid(pid_t tid);
extern "C" void PtraceTestFailPwriteAfter(int writes);
extern "C" void PtraceTestFailNextRequest(int request);
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <cstddef>
#include <sys/wait.h>
#include <fstream>
#include <csignal>

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

static int failures = 0;
#define CHECK(condition) do { if (!(condition)) { printf("  FAIL line %d: %s\n", __LINE__, #condition); failures++; } } while (0)

#if defined(__aarch64__)
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
static PtraceArch TestArch()
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
static PtraceArch g_arch = TestArch();
#endif

static std::unique_ptr<PtraceEngine> Start(Log& log, const std::string& mode)
{
	auto engine = std::make_unique<PtraceEngine>([&](const PtraceEngine::Event& event) { log.Push(event); });
	PtraceEngine::LaunchOptions options;
	options.path = "/work/progs";
	options.args = {mode};
#if defined(__aarch64__)
	options.arch = &g_arch;
#endif
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

static void ResumeFailureKeepsThreadStopped()
{
	printf("[resume_failure_state]\n");
	Log log;
	auto engine = Start(log, "hello");
	if (!engine)
		return;
	PtraceEngine::Event event;
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	PtraceTestFailNextResume();
	CHECK(!engine->Resume(true, event.tid));
	CHECK(engine->Resume(true, event.tid));
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	CHECK(engine->Kill());
}

static void FailedRestorePreventsDetach()
{
	printf("[breakpoint_cleanup_failure]\n");
	Log log;
	auto engine = Start(log, "detachbp");
	if (!engine)
		return;
	PtraceEngine::Event event;
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	CHECK(engine->Resume(false, 0));
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	uint64_t marker = AddressFromOutput(log, "marker=");
	CHECK(marker != 0);
	CHECK(engine->AddBreakpoint(marker));
	CHECK(engine->Resume(false, 0));
	std::this_thread::sleep_for(200ms);
	PtraceTestFailNextPwrite();
	bool detached = engine->Detach();
	CHECK(!detached);
	if (!detached)
	{
		CHECK(engine->Kill());
	}
	else
	{
		CHECK(log.Wait(PtraceEngine::DetachedEvent, event));
		int status = 0;
		CHECK(engine->WaitForDetachedExit(status, 4s));
		printf("  target status after false-success detach: 0x%x\n", status);
	}
}

static void SetOptionsFailureRejectsLaunch()
{
	printf("[setoptions_failure]\n");
	Log log;
	auto engine = std::make_unique<PtraceEngine>([&](const PtraceEngine::Event& event) { log.Push(event); });
	PtraceEngine::LaunchOptions options;
	options.path = "/work/progs";
	options.args = {"hello"};
#if defined(__aarch64__)
	options.arch = &g_arch;
#endif
	PtraceTestFailNextSetOptions();
	std::string error;
	bool launched = engine->Launch(options, error);
	CHECK(!launched);
	CHECK(!error.empty());
	if (launched)
		CHECK(engine->Kill());
}

static void MemoryOpenFailureRejectsLaunch()
{
	printf("[memory_open_failure]\n");
	Log log;
	auto engine = std::make_unique<PtraceEngine>([&](const PtraceEngine::Event& event) { log.Push(event); });
	PtraceEngine::LaunchOptions options;
	options.path = "/work/progs";
	options.args = {"hello"};
#if defined(__aarch64__)
	options.arch = &g_arch;
#endif
	PtraceTestFailNextMemOpen();
	std::string error;
	CHECK(!engine->Launch(options, error));
	CHECK(error.find("target memory") != std::string::npos);
}

// ---- a thread that never answers

static std::string StateOf(pid_t tid)
{
	std::ifstream status("/proc/" + std::to_string(tid) + "/status");
	std::string line;
	while (std::getline(status, line))
	{
		if (line.rfind("State:", 0) == 0)
			return line;
	}
	return "gone";
}

static double Seconds(std::chrono::steady_clock::time_point since)
{
	return std::chrono::duration<double>(std::chrono::steady_clock::now() - since).count();
}

// Runs the target until it has its threads, and returns one thread that is not the first
static pid_t StartThreads(Log& log, std::unique_ptr<PtraceEngine>& engine, pid_t& leader)
{
	engine = Start(log, "threads");
	if (!engine)
		return 0;
	PtraceEngine::Event event;
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event));
	engine->SetWaitTimeout(300ms);
	CHECK(engine->Resume(false, 0));
	for (int i = 0; i < 100 && engine->GetThreads().size() < 4; i++)
		std::this_thread::sleep_for(20ms);
	CHECK(engine->GetThreads().size() == 4);
	leader = engine->GetPid();
	for (uint32_t tid : engine->GetThreads())
	{
		if ((pid_t)tid != leader)
			return tid;
	}
	return 0;
}

static void StopAllGivesUp()
{
	printf("[stopall_timeout]\n");
	Log log;
	std::unique_ptr<PtraceEngine> engine;
	pid_t leader = 0;
	pid_t stuck = StartThreads(log, engine, leader);
	if (!stuck)
		return;

	// This thread's statuses do not reach the debugger, so as far as it can tell the thread does not stop
	PtraceTestHideWaitpid(stuck);
	auto start = std::chrono::steady_clock::now();
	PtraceEngine::Event event;
	CHECK(engine->Interrupt());
	bool stopped = log.Wait(PtraceEngine::StoppedEvent, event, 5s);
	CHECK(stopped);
	printf("  the stop came after %.2f s\n", Seconds(start));
	CHECK(Seconds(start) < 3.0);
	if (stopped)
	{
		CHECK(event.unresponsive.size() == 1 && event.unresponsive[0] == (uint32_t)stuck);
		CHECK(engine->GetThreads().size() == 4);
		std::vector<uint8_t> registers;
		CHECK(engine->GetRegisterSet(leader, NT_PRSTATUS, registers));
		CHECK(!engine->GetRegisterSet(stuck, NT_PRSTATUS, registers));
	}

	// It is not waited for again: the next stop is quick, and says the same
	CHECK(engine->Resume(false, 0));
	std::this_thread::sleep_for(100ms);
	start = std::chrono::steady_clock::now();
	CHECK(engine->Interrupt());
	stopped = log.Wait(PtraceEngine::StoppedEvent, event, 5s);
	CHECK(stopped);
	printf("  the second stop came after %.2f s\n", Seconds(start));
	CHECK(Seconds(start) < 0.25);
	if (stopped)
		CHECK(event.unresponsive.size() == 1);

	// It answers after all, and is a thread like the others again
	PtraceTestHideWaitpid(0);
	CHECK(engine->Resume(false, 0));
	std::this_thread::sleep_for(200ms);
	CHECK(engine->Interrupt());
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event, 5s));
	CHECK(event.unresponsive.empty());
	std::vector<uint8_t> registers;
	CHECK(engine->GetRegisterSet(stuck, NT_PRSTATUS, registers));
	CHECK(engine->Kill());
}

static void KillGivesUp()
{
	printf("[kill_timeout]\n");
	Log log;
	std::unique_ptr<PtraceEngine> engine;
	pid_t leader = 0;
	if (!StartThreads(log, engine, leader))
		return;

	PtraceTestHideWaitpid(leader);
	auto start = std::chrono::steady_clock::now();
	CHECK(engine->Kill());
	PtraceEngine::Event event;
	bool exited = log.Wait(PtraceEngine::ExitedEvent, event, 5s);
	CHECK(exited);
	printf("  the kill was over after %.2f s\n", Seconds(start));
	CHECK(Seconds(start) < 3.0);
	if (exited)
	{
		CHECK(event.signal == SIGKILL);
		CHECK(event.unresponsive.size() == 1 && event.unresponsive[0] == (uint32_t)leader);
	}
	// what was hidden is reaped by whoever can see it
	PtraceTestHideWaitpid(0);
	int status = 0;
	CHECK(waitpid(leader, &status, 0) == leader);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

static void DetachGivesUp()
{
	printf("[detach_timeout]\n");
	Log log;
	std::unique_ptr<PtraceEngine> engine;
	pid_t leader = 0;
	pid_t stuck = StartThreads(log, engine, leader);
	if (!stuck)
		return;

	PtraceTestHideWaitpid(stuck);
	auto start = std::chrono::steady_clock::now();
	bool detached = engine->Detach();
	printf("  the detach was over after %.2f s\n", Seconds(start));
	CHECK(detached);
	CHECK(Seconds(start) < 3.0);
	PtraceEngine::Event event;
	if (detached && log.Wait(PtraceEngine::DetachedEvent, event, 5s))
		CHECK(event.unresponsive.size() == 1 && event.unresponsive[0] == (uint32_t)stuck);
	PtraceTestHideWaitpid(0);
	// the thread that could not be let go of is still traced, and the target dies with the tracer: that is what
	// PTRACE_O_EXITKILL is for
	kill(leader, SIGKILL);
	int status = 0;
	waitpid(leader, &status, 0);
}

static void LaunchGivesUp()
{
	printf("[launch_timeout]\n");
	Log log;
	auto engine = std::make_unique<PtraceEngine>([&](const PtraceEngine::Event& event) { log.Push(event); });
	engine->SetWaitTimeout(300ms);
	PtraceEngine::LaunchOptions options;
	options.path = "/work/progs";
	options.args = {"loop"};
#if defined(__aarch64__)
	options.arch = &g_arch;
#endif
	PtraceTestHideWaitpid(-1);
	auto start = std::chrono::steady_clock::now();
	std::string error;
	bool launched = engine->Launch(options, error);
	printf("  the launch was over after %.2f s: %s\n", Seconds(start), error.c_str());
	CHECK(!launched);
	CHECK(error.find("did not stop") != std::string::npos);
	CHECK(Seconds(start) < 3.0);
	PtraceTestHideWaitpid(0);
	// the child was killed, and nobody has seen it die
	int status = 0;
	while (waitpid(-1, &status, WNOHANG) > 0)
	{}
}

static void AttachGivesUp()
{
	printf("[attach_timeout]\n");
	pid_t target = fork();
	if (target == 0)
	{
		execl("/work/progs", "progs", "threads", (char*)nullptr);
		_exit(127);
	}
	std::this_thread::sleep_for(200ms);

	Log log;
	auto engine = std::make_unique<PtraceEngine>([&](const PtraceEngine::Event& event) { log.Push(event); });
	engine->SetWaitTimeout(300ms);
	PtraceTestHideWaitpid(-1);
	auto start = std::chrono::steady_clock::now();
	std::string error;
	const PtraceArch* arch = nullptr;
#if defined(__aarch64__)
	arch = &g_arch;
#endif
	bool attached = engine->Attach(target, error, arch);
	printf("  the attach was over after %.2f s: %s\n", Seconds(start), error.c_str());
	CHECK(!attached);
	CHECK(error.find("did not stop") != std::string::npos);
	CHECK(Seconds(start) < 3.0);
	PtraceTestHideWaitpid(0);
	engine.reset();

	// the target was let go of, and runs
	std::this_thread::sleep_for(200ms);
	std::string state = StateOf(target);
	printf("  %s\n", state.c_str());
	CHECK(state.find("tracing stop") == std::string::npos && state.find("(stopped)") == std::string::npos);
	kill(target, SIGKILL);
	int status = 0;
	waitpid(target, &status, 0);
}

// ---- things that go wrong that the engine cannot put right

static bool HasError(const PtraceEngine::Event& event, const char* text)
{
	for (const auto& error : event.errors)
	{
		if (error.find(text) != std::string::npos)
			return true;
	}
	return false;
}

// Runs to the stop of the SIGUSR1 that the targets raise once they have printed an address
static bool RunToSignal(Log& log, PtraceEngine& engine, PtraceEngine::Event& event)
{
	return log.Wait(PtraceEngine::StoppedEvent, event) && engine.Resume(false, 0)
		&& log.Wait(PtraceEngine::StoppedEvent, event) && event.signal == SIGUSR1;
}

static void EventMessageFailureIsSaid()
{
	printf("[geteventmsg_failure]\n");
	Log log;
	auto engine = Start(log, "forkbp2");
	if (!engine)
		return;
	PtraceEngine::Event event;
	CHECK(RunToSignal(log, *engine, event));
	// the fork happens, and the id of the child cannot be read
	PtraceTestFailNextRequest(PTRACE_GETEVENTMSG);
	CHECK(engine->Resume(false, 0));
	std::this_thread::sleep_for(300ms);
	CHECK(engine->Interrupt());
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event, 5s));
	CHECK(HasError(event, "could not be read"));
	CHECK(engine->Kill());
}

static void FailedRestoreIsSaid()
{
	printf("[endguard_failure]\n");
	Log log;
	auto engine = Start(log, "bp");
	if (!engine)
		return;
	PtraceEngine::Event event;
	CHECK(RunToSignal(log, *engine, event));
	uint64_t marker = AddressFromOutput(log, "marker=");
	CHECK(marker != 0);
	CHECK(engine->AddBreakpoint(marker));
	CHECK(engine->Resume(false, 0));
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event, 5s));
	CHECK(event.breakpoint);

	// stepping over the breakpoint takes it out, which works, and puts it back, which does not
	PtraceTestFailPwriteAfter(1);
	CHECK(engine->Resume(false, 0));
	bool exited = log.Wait(PtraceEngine::ExitedEvent, event, 5s);
	if (!exited)
	{
		// or a stop, if the breakpoint was hit again
		CHECK(engine->Interrupt());
		CHECK(log.Wait(PtraceEngine::StoppedEvent, event, 5s));
	}
	CHECK(HasError(event, "put back the breakpoint"));
	if (!exited)
		CHECK(engine->Kill());
}

static void HardwareFailureOnNewThreadIsSaid()
{
	printf("[hw_apply_failure]\n");
	Log log;
	auto engine = Start(log, "watchthread");
	if (!engine)
		return;
	PtraceEngine::Event event;
	CHECK(RunToSignal(log, *engine, event));
	uint64_t wvar = 0;
	{
		std::string key = "wvar=";
		wvar = AddressFromOutput(log, key.c_str());
	}
	if (!engine->AddHardwareBreakpoint(wvar, PtraceHwType::Write, 4))
	{
		printf("  SKIP: no hardware watchpoints\n");
		engine->Kill();
		return;
	}

#if defined(__x86_64__)
	PtraceTestFailNextRequest(PTRACE_POKEUSER);
#else
	PtraceTestFailNextRequest(PTRACE_SETREGSET);
#endif
	CHECK(engine->Resume(false, 0));
	// the new thread does not have the watchpoint, so nothing stops it
	CHECK(log.Wait(PtraceEngine::ExitedEvent, event, 10s));
	CHECK(HasError(event, "hardware breakpoints could not be set"));
}

static void PcRewindFailureIsSaid()
{
	printf("[pc_rewind_failure]\n");
#if defined(__x86_64__)
	Log log;
	auto engine = Start(log, "bp");
	if (!engine)
		return;
	PtraceEngine::Event event;
	CHECK(RunToSignal(log, *engine, event));
	uint64_t marker = AddressFromOutput(log, "marker=");
	CHECK(engine->AddBreakpoint(marker));
	PtraceTestFailNextRequest(PTRACE_SETREGSET);
	CHECK(engine->Resume(false, 0));
	CHECK(log.Wait(PtraceEngine::StoppedEvent, event, 5s));
	CHECK(HasError(event, "could not be moved back"));
	CHECK(engine->Kill());
#else
	printf("  SKIP: only the architectures whose breakpoint traps after it need to move the PC back\n");
#endif
}

int main(int argc, char** argv)
{
	struct { const char* name; void (*run)(); } tests[] = {
		{"resume_failure_state", ResumeFailureKeepsThreadStopped}, {"breakpoint_cleanup_failure", FailedRestorePreventsDetach},
		{"setoptions_failure", SetOptionsFailureRejectsLaunch}, {"memory_open_failure", MemoryOpenFailureRejectsLaunch},
		{"stopall_timeout", StopAllGivesUp}, {"kill_timeout", KillGivesUp}, {"detach_timeout", DetachGivesUp},
		{"launch_timeout", LaunchGivesUp}, {"attach_timeout", AttachGivesUp},
		{"geteventmsg_failure", EventMessageFailureIsSaid}, {"endguard_failure", FailedRestoreIsSaid},
		{"hw_apply_failure", HardwareFailureOnNewThreadIsSaid}, {"pc_rewind_failure", PcRewindFailureIsSaid}};
	for (auto& test : tests)
	{
		if (argc > 1 && strcmp(argv[1], test.name))
			continue;
		test.run();
	}
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
