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
static PtraceArch TestArch()
{
	PtraceArch arch;
	arch.name = "aarch64";
	arch.pc = "pc";
	arch.sp = "sp";
	arch.regsets = {NT_PRSTATUS};
	arch.breakpointInstruction = {0x00, 0x00, 0x20, 0xd4};
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

int main()
{
	ResumeFailureKeepsThreadStopped();
	FailedRestorePreventsDetach();
	SetOptionsFailureRejectsLaunch();
	MemoryOpenFailureRejectsLaunch();
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
