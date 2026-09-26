#include "ptracearch.h"
#include "ptraceengine.h"
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <elf.h>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
using namespace BinaryNinjaDebugger;
using namespace std::chrono_literals;

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

int main(int argc, char** argv)
{
	setvbuf(stdout, nullptr, _IONBF, 0);
	std::string mode = argc > 1 ? argv[1] : "task";
	if (mode != "task" && mode != "handler")
	{
		fprintf(stderr, "usage: %s task|handler\n", argv[0]);
		return 2;
	}

	std::mutex mutex;
	std::condition_variable condition;
	bool stopped = false;
	PtraceEngine engine([&](const PtraceEngine::Event& event) {
		printf("event handler received event type %d on its worker thread\n", event.type);
		if (mode == "handler" && event.type == PtraceEngine::StoppedEvent)
		{
			printf("throwing std::runtime_error from the event handler now\n");
			throw std::runtime_error("event handler demo exception");
		}
		if (event.type == PtraceEngine::StoppedEvent)
		{
			std::lock_guard<std::mutex> lock(mutex);
			stopped = true;
			condition.notify_all();
		}
	});

	PtraceEngine::LaunchOptions options;
	options.path = "/work/progs";
	options.args = {"hello"};
#if defined(__aarch64__)
	options.arch = &g_arch;
#endif
	std::string error;
	if (!engine.Launch(options, error))
	{
		fprintf(stderr, "launch failed: %s\n", error.c_str());
		return 3;
	}

	if (mode == "task")
	{
		std::unique_lock<std::mutex> lock(mutex);
		if (!condition.wait_for(lock, 5s, [&] { return stopped; }))
		{
			fprintf(stderr, "initial stop was not delivered\n");
			return 4;
		}
		lock.unlock();

		engine.PostTask([] {
			printf("throwing std::runtime_error from a posted event task now\n");
			throw std::runtime_error("event task demo exception");
		});
	}

	// Neither mode should reach this point for long: an exception escaping std::thread invokes std::terminate.
	std::this_thread::sleep_for(5s);
	printf("unexpectedly survived the exception\n");
	return 5;
}
