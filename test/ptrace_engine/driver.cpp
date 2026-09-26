#include <binaryninjacore.h>
#include "ptracesignal.h"
#include "ptraceengine.h"
#include "ptracearch.h"
#include "ptraceelf.h"
#include "ptracemodule.h"
#include "ptracestep.h"
#include "ptracesyscall.h"
#include <elf.h>
#include <cstdint>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <fstream>
#include <set>
#include <sys/resource.h>
#include <map>
#include <atomic>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <cstddef>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
using namespace BinaryNinjaDebugger;
using namespace std::chrono_literals;

struct Log
{
	std::mutex m; std::condition_variable cv; std::deque<PtraceEngine::Event> q; std::string output;
	void push(const PtraceEngine::Event& e) { std::lock_guard<std::mutex> l(m); if (e.type == PtraceEngine::OutputEvent) output += e.data; q.push_back(e); cv.notify_all(); }
	bool wait(PtraceEngine::EventType t, PtraceEngine::Event& out, std::chrono::milliseconds to = 5000ms)
	{
		std::unique_lock<std::mutex> l(m);
		auto deadline = std::chrono::steady_clock::now() + to;
		while (true)
		{
			for (auto it = q.begin(); it != q.end(); ++it) if (it->type == t) { out = *it; q.erase(it); return true; }
			if (cv.wait_until(l, deadline) == std::cv_status::timeout) return false;
		}
	}
};

static int failures = 0;
#define CHECK(c) do { if (!(c)) { printf("  FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static std::string prog = "/work/progs";

#if defined(__x86_64__)
// The layout of user_regs_struct, which is what NT_PRSTATUS holds
constexpr size_t kFpOff = 4 * 8, kArg0Off = 14 * 8, kPcOff = 16 * 8, kSpOff = 19 * 8, kPrstatusSize = 27 * 8, kRetOff = 10 * 8;
// x86 has PTRACE_SYSEMU, so it not working there is a failure
constexpr bool kSysemuMayBeMissing = false;
constexpr size_t kCallLength = 5;
// A ret in a deeper call has a lower sp than the one of this frame, so no adjustment is needed
constexpr size_t kMinSpExtra = 0;
constexpr bool kDataTrapsBeforeAccess = false;
constexpr bool kHostSupported = true;
static const char* kScratchRegister = "rbx";
static const char* kLoaderName = "ld-linux-x86-64.so.2";
static const std::vector<uint8_t> kBreakInsn = {0xCC};
// Detected from the target, like the adapter does
static const PtraceArch* TestArch() { return nullptr; }
static const PtraceArch& RegisterTable() { return PtraceArchX86_64(); }
// Where a thread that stepped off the first instruction of a function is. That instruction is 4 bytes long on arm64, and
// on x86 it is a `push %rbp` or an `endbr64`.
static bool SteppedOffFirstInstruction(uint64_t pc, uint64_t start) { return pc > start && pc <= start + 15; }
#elif defined(__aarch64__)
constexpr size_t kFpOff = 29 * 8, kArg0Off = 0, kPcOff = 32 * 8, kSpOff = 31 * 8, kPrstatusSize = 272, kRetOff = 0;
constexpr bool kSysemuMayBeMissing = true;
constexpr size_t kCallLength = 4;
constexpr size_t kMinSpExtra = 1;
constexpr bool kDataTrapsBeforeAccess = true;
constexpr bool kHostSupported = false;
static const char* kScratchRegister = "x28";
static const char* kLoaderName = "ld-linux-aarch64.so.1";
static const std::vector<uint8_t> kBreakInsn = {0x00, 0x00, 0x20, 0xd4};
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

static PtraceArch TestArm64()
{
	PtraceArch a; a.name = "aarch64"; a.pc = "pc"; a.sp = "sp"; a.regsets = {NT_PRSTATUS};
	a.breakpointInstruction = {0x00, 0x00, 0x20, 0xd4}; a.breakpointPcAdjust = 0; a.hwDebug = &g_armHw; a.sysemu = true;
	for (size_t i = 0; i < 31; i++) a.registers.push_back({"x" + std::to_string(i), NT_PRSTATUS, i * 8, 8});
	a.registers.push_back({"sp", NT_PRSTATUS, 31 * 8, 8}); a.registers.push_back({"pc", NT_PRSTATUS, 32 * 8, 8});
	return a;
}

static PtraceArch g_arm = TestArm64();
static const PtraceArch* TestArch() { return &g_arm; }
static const PtraceArch& RegisterTable() { return g_arm; }
static bool SteppedOffFirstInstruction(uint64_t pc, uint64_t start) { return pc == start + 4; }
#else
#error "the harness knows x86_64 and aarch64"
#endif

static std::unique_ptr<PtraceEngine> start(Log& log, const std::string& mode, std::vector<std::string> extra = {}, const std::string& cwd = "", bool pty = true)
{
	auto e = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& ev) { log.push(ev); });
	PtraceEngine::LaunchOptions o; o.path = prog; o.args = {mode}; o.args.insert(o.args.end(), extra.begin(), extra.end()); o.workingDir = cwd; o.usePty = pty; o.arch = TestArch();
	std::string err;
	if (!e->Launch(o, err)) { printf("  launch failed: %s\n", err.c_str()); failures++; return nullptr; }
	return e;
}

static std::string procState(uint32_t pid)
{
	std::ifstream f("/proc/" + std::to_string(pid) + "/status"); std::string l;
	while (std::getline(f, l)) if (l.rfind("State:", 0) == 0) return l;
	return "gone";
}

static void t_hello()
{
	Log log; auto e = start(log, "hello"); if (!e) return;
	PtraceEngine::Event ev;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGTRAP); CHECK(e->GetThreads().size() == 1);
	CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 7); CHECK(ev.signal == 0);
	CHECK(log.output.find("hello from target") != std::string::npos);
	CHECK(!e->Resume(false, 0));
}

static void t_step()
{
	Log log; auto e = start(log, "hello"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	uint32_t tid = ev.tid;
	for (int i = 0; i < 2000; i++)
	{
		if (!e->Resume(true, tid)) { printf("  step %d failed\n", i); failures++; return; }
		if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  step %d no stop\n", i); failures++; return; }
		if (!(ev.singleStep && ev.signal == SIGTRAP && ev.tid == tid)) { printf("  step %d bad event sig=%d step=%d\n", i, ev.signal, ev.singleStep); failures++; return; }
	}
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 7);
}

static void t_interrupt()
{
	Log log; auto e = start(log, "loop"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(!e->Interrupt());
	for (int i = 0; i < 100; i++)
	{
		CHECK(e->Resume(false, 0)); if (failures) return;
		std::this_thread::sleep_for(std::chrono::microseconds(i * 300));
		if (!e->Interrupt()) { printf("  interrupt %d refused\n", i); failures++; return; }
		if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  interrupt %d no stop\n", i); failures++; return; }
		if (!ev.interrupted) { printf("  interrupt %d not flagged (sig %d)\n", i, ev.signal); failures++; return; }
	}
	CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGKILL);
}

static void t_threads()
{
	Log log; auto e = start(log, "threads"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->Resume(false, 0));
	std::this_thread::sleep_for(300ms);
	CHECK(e->GetThreads().size() == 5 - 0 - 0 + 0 - 0 || e->GetThreads().size() == 4);
	for (int i = 0; i < 20; i++)
	{
		CHECK(e->Interrupt()); if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  no stop %d\n", i); failures++; return; }
		auto threads = e->GetThreads();
		if (i == 0) printf("  threads=%zu\n", threads.size());
		CHECK(threads.size() == 4);
		// step one thread that isn't the reporter
		uint32_t other = threads.back() == ev.tid ? threads.front() : threads.back();
		CHECK(e->Resume(true, other)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.tid == other); CHECK(ev.singleStep);
		CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(5ms);
	}
	CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev));
}

static void t_churn()
{
	Log log; auto e = start(log, "churn"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->Resume(false, 0));
	// interrupt repeatedly while threads come and go
	int stops = 0;
	while (true)
	{
		if (log.wait(PtraceEngine::ExitedEvent, ev, 20ms)) break;
		if (e->Interrupt()) { if (log.wait(PtraceEngine::StoppedEvent, ev, 2000ms)) { stops++; CHECK(e->Resume(false, 0)); } }
	}
	CHECK(ev.exitCode == 0); printf("  churn interrupted %d times\n", stops);
	CHECK(log.output.find("churn done") != std::string::npos);
}

static void t_signal()
{
	Log log; auto e = start(log, "sig"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1);
	CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGUSR1);
	CHECK(log.output.find("survived") == std::string::npos);

	Log log2; auto e2 = start(log2, "abort"); if (!e2) return;
	CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e2->Resume(false, 0));
	CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGABRT);
	CHECK(e2->Resume(false, 0)); CHECK(log2.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGABRT);
}

static void t_silent()
{
	Log log; auto e = start(log, "sigchld"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 8000ms)); CHECK(ev.exitCode == 5);
	CHECK(log.output.find("after child") != std::string::npos);
}

static void t_detach()
{
	Log log; auto e = start(log, "sleeper"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	uint32_t pid = e->GetPid();
	CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(200ms);
	CHECK(e->Detach());
	CHECK(log.wait(PtraceEngine::DetachedEvent, ev));
	std::this_thread::sleep_for(300ms);
	std::string st = procState(pid); printf("  after detach: %s\n", st.c_str());
	CHECK(st.find("(sleeping)") != std::string::npos || st.find("(running)") != std::string::npos);
	// it must finish on its own, and be reaped
	int status = 0; CHECK(e->WaitForDetachedExit(status, 4s)); std::this_thread::sleep_for(50ms); CHECK(procState(pid) == "gone");
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 3);
}

static void t_kill_running()
{
	Log log; auto e = start(log, "threads"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	std::this_thread::sleep_for(100ms);
	uint32_t pid = e->GetPid();
	CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGKILL);
	CHECK(procState(pid) == "gone");
	CHECK(!e->Kill());
	e.reset();
}

static void t_dtor_kills()
{
	Log log; uint32_t pid;
	{
		auto e = start(log, "loop"); if (!e) return;
		PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
		pid = e->GetPid();
	}
	CHECK(procState(pid) == "gone");
}

static void t_launch_errors()
{
	Log log;
	auto e = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& ev) { log.push(ev); });
	PtraceEngine::LaunchOptions o; o.path = "/nonexistent/bin"; std::string err;
	CHECK(!e->Launch(o, err)); printf("  err: %s\n", err.c_str()); CHECK(!err.empty());
	CHECK(!e->Resume(false, 0)); CHECK(!e->Kill()); CHECK(!e->Detach()); CHECK(!e->Interrupt());
	e.reset();
	Log log2; auto e2 = std::make_unique<PtraceEngine>([&log2](const PtraceEngine::Event& ev) { log2.push(ev); });
	o.path = prog; o.workingDir = "/nonexistent"; CHECK(!e2->Launch(o, err)); printf("  err: %s\n", err.c_str());
}

static void t_args_cwd()
{
	Log log; auto e = start(log, "args", {"a b", "c"}, "/tmp"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev));
	printf("  out: %s", log.output.c_str());
	CHECK(log.output.find("cwd=/tmp argc=4 [a b] [c]") != std::string::npos);
}

static void t_stdin()
{
	Log log; auto e = start(log, "cat"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(e->WriteInput("ping\n"));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev));
	CHECK(log.output.find("got: ping") != std::string::npos);
}

static void t_nopty()
{
	Log log; auto e = start(log, "hello", {}, "", false); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 7); CHECK(!e->WriteInput("x"));
}

static void t_relaunch()
{
	for (int i = 0; i < 20; i++)
	{
		Log log; auto e = start(log, "hello"); if (!e) return;
		PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
		CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 7);
	}
}

static uint64_t le64(const std::vector<uint8_t>& v, size_t off) { uint64_t x = 0; memcpy(&x, v.data() + off, 8); return x; }


static bool waitOutput(Log& log, const std::string& s, int ms = 3000)
{
	for (int i = 0; i < ms / 10; i++) { { std::lock_guard<std::mutex> l(log.m); if (log.output.find(s) != std::string::npos) return true; } std::this_thread::sleep_for(10ms); }
	return false;
}

static void t_regs_step()
{
	const PtraceArch& arch = RegisterTable(); auto pcReg = arch.Find(arch.pc); CHECK(pcReg && arch.Find("nope") == nullptr);
	CHECK((DetectPtraceArch(getpid()) != nullptr) == kHostSupported);   // the arm64 host is not a supported architecture
	Log log; auto e = start(log, "hello"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); uint32_t tid = ev.tid;
	CHECK((DetectPtraceArch(e->GetPid()) != nullptr) == kHostSupported);
	std::vector<uint8_t> regs; CHECK(e->GetRegisterSet(tid, pcReg->regset, regs)); CHECK(regs.size() == kPrstatusSize);
	uint64_t pc1 = le64(regs, pcReg->offset), sp = le64(regs, arch.Find(arch.sp)->offset);
	CHECK(pc1 != 0 && sp != 0);
#if defined(__aarch64__)
	CHECK(pc1 % 4 == 0);
#endif
	std::vector<uint8_t> fp; CHECK(e->GetRegisterSet(tid, NT_PRFPREG, fp)); CHECK(fp.size() >= 512);
	CHECK(e->Resume(true, tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	std::vector<uint8_t> regs2; CHECK(e->GetRegisterSet(tid, NT_PRSTATUS, regs2));
	printf("  pc %llx -> %llx\n", (unsigned long long)pc1, (unsigned long long)le64(regs2, pcReg->offset));
#if defined(__aarch64__)
	CHECK(le64(regs2, pcReg->offset) == pc1 + 4);
#else
	CHECK(le64(regs2, pcReg->offset) != pc1);
#endif
	// write a register, read it back, restore it
	const auto x28 = arch.Find(kScratchRegister)->offset; uint64_t orig = le64(regs2, x28);
	auto mod = regs2; uint64_t magic = 0x1122334455667788ull; memcpy(mod.data() + x28, &magic, 8);
	CHECK(e->SetRegisterSet(tid, NT_PRSTATUS, mod)); std::vector<uint8_t> back; CHECK(e->GetRegisterSet(tid, NT_PRSTATUS, back)); CHECK(le64(back, x28) == magic);
	memcpy(mod.data() + x28, &orig, 8); CHECK(e->SetRegisterSet(tid, NT_PRSTATUS, mod));
	// writing the pc redirects the step
#if defined(__aarch64__)
	auto jump = regs2; uint64_t target = pc1 + 8; memcpy(jump.data() + pcReg->offset, &target, 8);
	CHECK(e->SetRegisterSet(tid, NT_PRSTATUS, jump)); CHECK(e->Resume(true, tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->GetRegisterSet(tid, NT_PRSTATUS, back)); CHECK(le64(back, pcReg->offset) == target + 4);
#else
	// going back to the first pc, the step has the same result again
	uint64_t pc2 = le64(regs2, pcReg->offset);
	CHECK(e->SetRegisterSet(tid, NT_PRSTATUS, regs)); CHECK(e->Resume(true, tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->GetRegisterSet(tid, NT_PRSTATUS, back)); CHECK(le64(back, pcReg->offset) == pc2);
#endif
	// invalid requests
	CHECK(!e->GetRegisterSet(tid + 1000, NT_PRSTATUS, back)); CHECK(!e->GetRegisterSet(tid, 0x7777, back));
	CHECK(e->Kill());
	CHECK(!e->GetRegisterSet(tid, NT_PRSTATUS, back));
}

static void t_regs_running()
{
	Log log; auto e = start(log, "loop"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); uint32_t tid = ev.tid;
	CHECK(e->Resume(false, 0)); std::vector<uint8_t> regs;
	CHECK(!e->GetRegisterSet(tid, NT_PRSTATUS, regs)); CHECK(!e->SetRegisterSet(tid, NT_PRSTATUS, regs));
	CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->GetRegisterSet(ev.tid, NT_PRSTATUS, regs)); CHECK(regs.size() == kPrstatusSize);
	CHECK(e->Kill());
}

static void t_memory()
{
	Log log; auto e = start(log, "mem"); if (!e) return;
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1);
	CHECK(waitOutput(log, "main="));
	unsigned long long bufAddr = 0, mainAddr = 0; sscanf(log.output.c_str(), "buf=%llx main=%llx", &bufAddr, &mainAddr);
	CHECK(bufAddr != 0 && mainAddr != 0);
	char rd[13] = {}; CHECK(e->ReadMemory(bufAddr, rd, 12)); CHECK(!strcmp(rd, "hello memory"));
	CHECK(e->WriteMemory(bufAddr, "HELLO", 5)); CHECK(e->ReadMemory(bufAddr, rd, 12)); CHECK(!strcmp(rd, "HELLO memory"));
	// text pages are read-only, but a debugger must still be able to patch them
	uint8_t code[4]; CHECK(e->ReadMemory(mainAddr, code, 4)); uint8_t patched[4] = {code[0], code[1], code[2], code[3]};
	CHECK(e->WriteMemory(mainAddr, patched, 4));
	// large and unaligned reads
	std::vector<uint8_t> big(3 * 4096 + 17); CHECK(e->ReadMemory(mainAddr & ~0xfffull, big.data(), 4096));
	uint8_t byte; CHECK(!e->ReadMemory(0, &byte, 1)); CHECK(!e->WriteMemory(0, &byte, 1)); CHECK(!e->ReadMemory(~0ull, &byte, 1)); CHECK(!e->ReadMemory(1ull << 52, &byte, 1)); { uint8_t two[2]; CHECK(!e->ReadMemory(0x1000000000000ull - 1, two, 2)); }
	CHECK(e->ReadMemory(bufAddr, &byte, 0));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 0);
	CHECK(log.output.find("HELLO memory") != std::string::npos);
	CHECK(!e->ReadMemory(bufAddr, rd, 4));
}

static std::string readAddr(Log& log, const char* key)
{
	if (!waitOutput(log, key)) return "";
	return log.output.substr(log.output.find(key) + strlen(key));
}

static uint64_t addrOf(Log& log, const char* key) { auto s = readAddr(log, key); return strtoull(s.c_str(), nullptr, 16); }

static std::vector<uint8_t> rawRead(uint32_t pid, uint64_t addr, size_t n)
{
	std::vector<uint8_t> v(n); int fd = open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
	if (fd < 0 || pread(fd, v.data(), n, addr) != (ssize_t)n) v.clear();
	if (fd >= 0) close(fd);
	return v;
}

static uint64_t pcOf(PtraceEngine& e, uint32_t tid)
{
	std::vector<uint8_t> r; if (!e.GetRegisterSet(tid, NT_PRSTATUS, r)) return 0; return le64(r, kPcOff);
}

// Starts the target, runs it to the SIGUSR1 stop that every breakpoint target raises once it has printed an address
static std::unique_ptr<PtraceEngine> startAtSignal(Log& log, const std::string& mode, uint32_t& tid, PtraceEngine::Event& ev)
{
	auto e = start(log, mode); if (!e) return e;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1); tid = ev.tid;
	return e;
}

static void t_bp_basic()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bp", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); CHECK(marker != 0);
	uint32_t pid = e->GetPid();
	auto before = rawRead(pid, marker, 8); CHECK(before.size() == 8);
	CHECK(e->AddBreakpoint(marker)); CHECK(e->AddBreakpoint(marker));
	auto raw = rawRead(pid, marker, kBreakInsn.size()); CHECK((raw == kBreakInsn));
	std::vector<uint8_t> seen(8); CHECK(e->ReadMemory(marker, seen.data(), 8)); CHECK(seen == before);   // the breakpoint is hidden
	std::vector<uint8_t> mid(2); CHECK(e->ReadMemory(marker + 1, mid.data(), 2)); CHECK(mid[0] == before[1] && mid[1] == before[2]);
	for (int i = 1; i <= 5; i++)
	{
		CHECK(e->Resume(false, 0));
		if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  no stop %d\n", i); failures++; return; }
		if (!(ev.breakpoint && ev.signal == SIGTRAP && !ev.singleStep && pcOf(*e, ev.tid) == marker)) { printf("  hit %d wrong: bp=%d sig=%d pc=%llx\n", i, ev.breakpoint, ev.signal, (unsigned long long)pcOf(*e, ev.tid)); failures++; return; }
	}
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 5);
}

static void t_bp_step_remove()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bp", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); uint32_t pid = e->GetPid();
	auto before = rawRead(pid, marker, 4);
	CHECK(e->AddBreakpoint(marker)); CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.breakpoint);
	// stepping off a breakpoint moves one instruction, and the breakpoint is still there afterwards
	CHECK(e->Resume(true, ev.tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.singleStep && !ev.breakpoint);
	CHECK(SteppedOffFirstInstruction(pcOf(*e, ev.tid), marker));
	CHECK((rawRead(pid, marker, kBreakInsn.size()) == kBreakInsn));
	CHECK(e->RemoveBreakpoint(marker)); CHECK(!e->RemoveBreakpoint(marker));
	CHECK(rawRead(pid, marker, 4) == before);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 5);
}

static void t_bp_write()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bp", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); uint32_t pid = e->GetPid();
	auto before = rawRead(pid, marker, 8);
	CHECK(e->AddBreakpoint(marker));
	std::vector<uint8_t> patch = {1, 2, 3, 4, 5, 6, 7, 8};
	CHECK(e->WriteMemory(marker, patch.data(), 8));
	std::vector<uint8_t> seen(8); CHECK(e->ReadMemory(marker, seen.data(), 8)); CHECK(seen == patch);
	auto raw = rawRead(pid, marker, 8); auto wantRaw = patch; for (size_t i = 0; i < kBreakInsn.size(); i++) wantRaw[i] = kBreakInsn[i]; CHECK((raw == wantRaw));
	CHECK(e->RemoveBreakpoint(marker)); CHECK(rawRead(pid, marker, 8) == patch);
	CHECK(e->WriteMemory(marker, before.data(), 8));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 5);
}

static void t_bp_threads()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bpthreads", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); CHECK(e->AddBreakpoint(marker));
	int hits = 0; CHECK(e->Resume(false, 0));
	while (true)
	{
		{ std::unique_lock<std::mutex> l(log.m); bool got = log.cv.wait_for(l, 8s, [&] { for (auto& q : log.q) if (q.type == PtraceEngine::StoppedEvent || q.type == PtraceEngine::ExitedEvent) return true; return false; }); if (!got) { printf("  timeout after %d hits\n", hits); failures++; return; } }
		if (log.wait(PtraceEngine::ExitedEvent, ev, 1ms)) break;
		CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); if (!(ev.breakpoint && pcOf(*e, ev.tid) == marker)) { printf("  stray stop sig=%d\n", ev.signal); failures++; return; }
		hits++; if (!e->Resume(false, 0)) { printf("  resume failed\n"); failures++; return; }
	}
	printf("  hits=%d exit=%d\n", hits, ev.exitCode); CHECK(hits == 12); CHECK(ev.exitCode == 12);
}

// Interrupts race with breakpoint hits, so the number of reports can vary, but the target must never be damaged
static void t_bp_interrupts()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bpthreads", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); CHECK(e->AddBreakpoint(marker));
	std::atomic<bool> stop{false}; std::thread poker([&] { while (!stop) { e->Interrupt(); std::this_thread::sleep_for(700us); } });
	CHECK(e->Resume(false, 0));
	while (true)
	{
		std::unique_lock<std::mutex> l(log.m);
		if (!log.cv.wait_for(l, 8s, [&] { return !log.q.empty(); })) { printf("  timeout\n"); failures++; break; }
		bool exited = false; PtraceEngine::Event last; bool stopped = false;
		for (auto it = log.q.begin(); it != log.q.end();) { if (it->type == PtraceEngine::ExitedEvent) { exited = true; ev = *it; it = log.q.erase(it); } else if (it->type == PtraceEngine::StoppedEvent) { stopped = true; last = *it; it = log.q.erase(it); } else it = log.q.erase(it); }
		l.unlock();
		if (exited) break;
		if (stopped)
		{
			if (!(last.interrupted || (last.breakpoint && pcOf(*e, last.tid) == marker))) { printf("  stray stop sig=%d\n", last.signal); failures++; break; }
			if (!e->Resume(false, 0)) { printf("  resume failed\n"); failures++; break; }
		}
	}
	stop = true; poker.join();
	CHECK(ev.exitCode == 12); CHECK(ev.signal == 0);
}

static void t_bp_remove_running()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bploop", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); auto before = rawRead(e->GetPid(), marker, 4);
	CHECK(e->AddBreakpoint(marker));
	for (int i = 0; i < 60; i++)
	{
		CHECK(e->Resume(false, 0)); if (failures) return;
		std::this_thread::sleep_for(std::chrono::microseconds(200 + (i * 37) % 900));
		CHECK(e->RemoveBreakpoint(marker));
		std::this_thread::sleep_for(std::chrono::microseconds(300 + (i * 91) % 700));
		CHECK(e->AddBreakpoint(marker));
		if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  no stop at %d\n", i); failures++; return; }
		if (!(ev.breakpoint && pcOf(*e, ev.tid) == marker)) { printf("  iteration %d stray stop sig=%d bp=%d pc=%llx\n", i, ev.signal, ev.breakpoint, (unsigned long long)pcOf(*e, ev.tid)); failures++; return; }
	}
	CHECK(e->RemoveBreakpoint(marker)); CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(50ms);
	CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.interrupted);
	CHECK(rawRead(e->GetPid(), marker, 4) == before);
	CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGKILL);
}

static void t_bp_detach()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "detachbp", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); uint32_t pid = e->GetPid();
	CHECK(e->AddBreakpoint(marker)); CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(200ms);
	CHECK(e->Detach()); CHECK(log.wait(PtraceEngine::DetachedEvent, ev));
	int status = 0; CHECK(e->WaitForDetachedExit(status, 4s)); std::this_thread::sleep_for(50ms); CHECK(procState(pid) == "gone");
	printf("  status=%x\n", status);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);   // it would have died of SIGTRAP if the breakpoint had stayed
}

static void t_hw_watch()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "watch", tid, ev); if (!e) return;
	uint64_t wvar = addrOf(log, "wvar="); CHECK(wvar != 0);
	if (!e->AddHardwareBreakpoint(wvar, PtraceHwType::Write, 4)) { printf("  SKIP: no hardware watchpoints\n"); e->Kill(); return; }
	CHECK(e->AddHardwareBreakpoint(wvar, PtraceHwType::Write, 4));
	for (int i = 1; i <= 3; i++)
	{
		CHECK(e->Resume(false, 0)); if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  no hit %d\n", i); failures++; return; }
		CHECK(ev.hardware && !ev.breakpoint); CHECK(ev.signal == SIGTRAP);
		uint32_t value = 0; CHECK(e->ReadMemory(wvar, &value, 4)); CHECK(value == (uint32_t)(kDataTrapsBeforeAccess ? i - 1 : i));   // arm64 traps before the write is done, x86 after
	}
	CHECK(e->RemoveHardwareBreakpoint(wvar, PtraceHwType::Write, 4)); CHECK(!e->RemoveHardwareBreakpoint(wvar, PtraceHwType::Write, 4));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 3);

	Log log2; auto e2 = startAtSignal(log2, "watch", tid, ev); if (!e2) return;
	wvar = addrOf(log2, "wvar="); CHECK(e2->AddHardwareBreakpoint(wvar, PtraceHwType::Write, 4)); CHECK(e2->RemoveHardwareBreakpoint(wvar, PtraceHwType::Write, 4));
	CHECK(e2->Resume(false, 0)); CHECK(log2.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 3);   // no stops
	// the four slots run out, and a watchpoint cannot use an execute slot
	Log log3; auto e3 = startAtSignal(log3, "watch", tid, ev); if (!e3) return;
	wvar = addrOf(log3, "wvar=");
	for (int i = 0; i < 4; i++) CHECK(e3->AddHardwareBreakpoint(wvar + 4 * (i + 1), PtraceHwType::Write, 4));
	CHECK(!e3->AddHardwareBreakpoint(wvar + 100, PtraceHwType::Write, 4));
	CHECK(e3->Resume(false, 0)); CHECK(!e3->AddHardwareBreakpoint(wvar, PtraceHwType::Write, 4));   // not while running
	CHECK(e3->Kill());
}

static void t_hw_thread()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "watchthread", tid, ev); if (!e) return;
	uint64_t wvar = addrOf(log, "wvar=");
	if (!e->AddHardwareBreakpoint(wvar, PtraceHwType::Write, 4)) { printf("  SKIP: no hardware watchpoints\n"); e->Kill(); return; }
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.hardware);
	CHECK(ev.tid != e->GetPid());   // it was the new thread, so it inherited the watchpoint
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 7);
}

static void t_hw_exec()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bp", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker=");
	if (!e->AddHardwareBreakpoint(marker, PtraceHwType::Execute, 4)) { printf("  SKIP: no hardware breakpoints\n"); e->Kill(); return; }
	for (int i = 1; i <= 5; i++)
	{
		CHECK(e->Resume(false, 0)); if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  no hit %d\n", i); failures++; return; }
		if (!(ev.hardware && pcOf(*e, ev.tid) == marker)) { printf("  hit %d wrong hw=%d pc=%llx\n", i, ev.hardware, (unsigned long long)pcOf(*e, ev.tid)); failures++; return; }
	}
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 5);
}

static void t_hw_detach()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "watch", tid, ev); if (!e) return;
	uint64_t wvar = addrOf(log, "wvar="); uint32_t pid = e->GetPid();
	if (!e->AddHardwareBreakpoint(wvar, PtraceHwType::Write, 4)) { printf("  SKIP\n"); e->Kill(); return; }
	CHECK(e->Detach()); CHECK(log.wait(PtraceEngine::DetachedEvent, ev));
	int status = 0; CHECK(e->WaitForDetachedExit(status, 4s)); std::this_thread::sleep_for(50ms); CHECK(procState(pid) == "gone");
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 3);   // it would have been killed by SIGTRAP if the watchpoint had stayed
}

static std::vector<PtraceModuleInfo> modulesOf(PtraceEngine& e)
{
	return BuildModules(e.GetMaps(), [&e](uint64_t a) { uint8_t m[4]; return e.ReadMemory(a, m, 4) && !memcmp(m, "\x7f" "ELF", 4); });
}

static const PtraceModuleInfo* findModule(const std::vector<PtraceModuleInfo>& mods, const std::string& base)
{
	for (auto& m : mods) if (m.path.size() >= base.size() && m.path.compare(m.path.size() - base.size(), base.size(), base) == 0) return &m;
	return nullptr;
}

static void t_modules()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bp", tid, ev); if (!e) return;
	auto mods = modulesOf(*e); auto maps = e->GetMaps();
	for (auto& m : mods) printf("  %-40s %llx +%llx  (%s)\n", m.path.c_str(), (unsigned long long)m.base, (unsigned long long)m.size, m.shortName.c_str());
	auto exe = findModule(mods, "/progs"); auto libc = findModule(mods, "libc.so.6"); auto ld = findModule(mods, kLoaderName);
	CHECK(exe && libc && ld); if (!exe || !libc || !ld) return;
	CHECK(exe->shortName == "progs"); CHECK(exe->base == 0x400000);
	// no module overlaps another, and every mapping of a module's file is inside it
	for (auto& a : mods) for (auto& b : mods) if (&a != &b) CHECK(a.base + a.size <= b.base || b.base + b.size <= a.base);
	for (auto& m : maps) if (m.path == libc->path) CHECK(m.start >= libc->base && m.end <= libc->base + libc->size);
	for (auto& m : mods) CHECK(m.base % 0x1000 == 0 && m.size % 0x1000 == 0);
	// everything reported is an ELF object, so the files that are only mapped for their data are left out
	for (auto& m : mods) CHECK(m.path.find("locale") == std::string::npos);
	// short names are unique
	std::set<std::string> names; for (auto& m : mods) CHECK(names.insert(m.shortName).second);
	auto regions = e->GetMaps(); CHECK(!regions.empty());
	bool sawStack = false; for (auto& r : regions) { CHECK(r.end > r.start); if (r.path == "[stack]") { sawStack = true; CHECK(r.read && r.write && !r.execute); } } CHECK(sawStack);
	e->Kill();
}

static void t_symbols()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "syms", tid, ev); if (!e) return;
	waitOutput(log, "puts="); unsigned long long marker = 0, puts = 0; sscanf(log.output.c_str(), "marker=%llx puts=%llx", &marker, &puts);
	auto mods = modulesOf(*e); auto exe = findModule(mods, "/progs"); auto libc = findModule(mods, "libc.so.6"); CHECK(exe && libc); if (!exe || !libc) return;
	ElfInfo elf, libcElf; CHECK(ReadElfFile(exe->path, elf)); CHECK(ReadElfFile(libc->path, libcElf));
	CHECK(elf.is64 && elf.type == ET_EXEC && elf.linkBase == 0x400000 && elf.interpreter.find("ld-linux") != std::string::npos);
	CHECK(libcElf.type == ET_DYN && libcElf.linkBase == 0);
	printf("  progs: %zu symbols, libc: %zu symbols, interpreter %s\n", elf.symbols.size(), libcElf.symbols.size(), elf.interpreter.c_str());
	// symbols are found where the running program says they are
	uint64_t found = 0; for (auto& s : elf.symbols) if (s.name == "marker") { found = s.address + exe->base - elf.linkBase; CHECK(s.isFunction && s.size > 0); }
	CHECK(found == marker && marker != 0);
	uint64_t foundPuts = 0; for (auto& s : libcElf.symbols) if (s.name == "puts") foundPuts = s.address + libc->base - libcElf.linkBase;
	CHECK(foundPuts == puts && puts != 0);
	// lookups by address
	auto sym = FindElfSymbol(elf, marker - exe->base + elf.linkBase + 4); CHECK(sym && sym->name == "marker");
	CHECK(FindElfSymbol(elf, 0) == nullptr);
	for (size_t i = 1; i < libcElf.symbols.size(); i++) CHECK(libcElf.symbols[i - 1].address <= libcElf.symbols[i].address);
	ElfInfo bad; CHECK(!ReadElfFile("/etc/passwd", bad)); CHECK(!ReadElfFile("/nonexistent", bad));
	e->Kill();
}

static void t_frames()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "frames", tid, ev); if (!e) return;
	uint64_t label = addrOf(log, "label="); CHECK(label != 0);
	CHECK(e->AddBreakpoint(label)); CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.breakpoint);
	std::vector<uint8_t> regs; CHECK(e->GetRegisterSet(ev.tid, NT_PRSTATUS, regs));
	uint64_t pc = le64(regs, kPcOff), sp = le64(regs, kSpOff), fp = le64(regs, kFpOff); CHECK(pc == label);
	auto maps = e->GetMaps();
	auto isExec = [&](uint64_t a) { for (auto& m : maps) if (m.execute && a >= m.start && a < m.end) return true; return false; };
	auto readWord = [&](uint64_t a, uint64_t& v) { v = 0; return e->ReadMemory(a, &v, 8); };
	auto frames = UnwindFramePointers(pc, sp, fp, 8, readWord, isExec);
	auto mods = modulesOf(*e); auto exe = findModule(mods, "/progs"); ElfInfo elf; CHECK(ReadElfFile(exe->path, elf));
	printf("  %zu frames:", frames.size());
	std::vector<std::string> names;
	for (auto& f : frames) { auto s = FindElfSymbol(elf, f.pc); names.push_back(s ? s->name : "?"); printf(" %s", names.back().c_str()); } printf("\n");
	CHECK(frames.size() >= 4); if (frames.size() < 4) return;
	CHECK(names[0] == "level3" && names[1] == "level2" && names[2] == "level1" && names[3] == "main");
	for (size_t i = 1; i < frames.size(); i++) CHECK(frames[i].sp > frames[i - 1].sp);
	// a bad frame pointer stops the walk instead of misbehaving
	CHECK(UnwindFramePointers(pc, sp, 0, 8, readWord, isExec).size() == 1);
	CHECK(UnwindFramePointers(pc, sp, fp + 1, 8, readWord, isExec).size() == 1);
	CHECK(UnwindFramePointers(pc, sp, sp - 16, 8, readWord, isExec).size() == 1);
	CHECK(UnwindFramePointers(pc, sp, fp, 8, [](uint64_t, uint64_t& v) { v = 0; return false; }, isExec).size() == 1);
	CHECK(UnwindFramePointers(pc, sp, fp, 8, readWord, isExec, 2).size() == 2);
	e->Kill();
}

static void t_loader()
{
	Log log; PtraceEngine::Event ev; auto e = start(log, "dl"); if (!e) return;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	// what the adapter does: find _dl_debug_state in the dynamic loader
	auto mods = modulesOf(*e); auto exe = findModule(mods, "/progs"); auto ld = findModule(mods, kLoaderName); CHECK(exe && ld); if (!exe || !ld) return;
	ElfInfo exeElf, ldElf; CHECK(ReadElfFile(exe->path, exeElf)); CHECK(ReadElfFile(ld->path, ldElf));
	CHECK(!exeElf.interpreter.empty() && exeElf.interpreter.find(kLoaderName) != std::string::npos);
	uint64_t state = 0; for (auto& s : ldElf.symbols) if (s.name == "_dl_debug_state") state = s.address + ld->base - ldElf.linkBase;
	CHECK(state != 0); if (!state) return;
	CHECK(e->AddBreakpoint(state));
	int hits = 0; bool sawLib = false; bool libBeforeDlopen = false; bool atSignal = false; uint64_t libfuncAddr = 0;
	CHECK(e->Resume(false, 0));
	for (int i = 0; i < 200; i++)
	{
		if (!log.wait(PtraceEngine::StoppedEvent, ev, 4000ms)) { printf("  timeout\n"); failures++; break; }
		bool haveLib = findModule(modulesOf(*e), "libtest.so") != nullptr;
		if (ev.breakpoint)
		{
			std::vector<uint8_t> r; e->GetRegisterSet(ev.tid, NT_PRSTATUS, r); uint64_t at = le64(r, kPcOff);
			if (libfuncAddr && at == libfuncAddr) { printf("  hit the breakpoint in the library\n"); break; }
			hits++; CHECK(at == state); if (haveLib) sawLib = true; if (haveLib && !atSignal) libBeforeDlopen = true;
		}
		else if (ev.signal == SIGUSR1)
		{
			if (!atSignal) { atSignal = true; CHECK(!haveLib); }
			else
			{
				// the library is loaded now: a breakpoint by module and offset resolves and is hit
				auto libMods = modulesOf(*e); auto lib = findModule(libMods, "libtest.so"); CHECK(lib != nullptr); if (!lib) break;
				ElfInfo libElf; CHECK(ReadElfFile(lib->path, libElf));
				for (auto& s : libElf.symbols) if (s.name == "libfunc") libfuncAddr = s.address + lib->base - libElf.linkBase;
				CHECK(libfuncAddr != 0); CHECK(e->AddBreakpoint(libfuncAddr));
				CHECK(e->RemoveBreakpoint(state));
			}
		}
		else if (ev.breakpoint == false && ev.signal == SIGTRAP) { std::vector<uint8_t> r; e->GetRegisterSet(ev.tid, NT_PRSTATUS, r); if (libfuncAddr && le64(r, kPcOff) == libfuncAddr) break; }
		CHECK(e->Resume(false, 0));
	}
	printf("  loader hits: %d, library seen after load: %d\n", hits, sawLib);
	CHECK(hits >= 3); CHECK(sawLib); CHECK(!libBeforeDlopen); CHECK(libfuncAddr != 0);
	e->Kill();
}

static void t_library_reload_breakpoint()
{
	Log log; auto e = start(log, "dlcycle"); if (!e) return; PtraceEngine::Event ev;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1);
	uint64_t first = addrOf(log, "cycle1="); CHECK(first != 0); CHECK(e->AddBreakpoint(first));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.breakpoint && pcOf(*e, ev.tid) == first);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1);
	uint64_t second = addrOf(log, "cycle2="); CHECK(second != 0);
	if (second != first)
	{
		printf("  SKIP: loader chose a different address (%llx -> %llx)\n", (unsigned long long)first, (unsigned long long)second);
		e->Kill(); return;
	}
	// The old record survived dlclose. Even asking to add the same breakpoint again reports success without
	// reinstalling it into the replacement mapping.
	CHECK(e->AddBreakpoint(second));
	auto raw = rawRead(e->GetPid(), second, kBreakInsn.size());
	printf("  reloaded at the same address; physical breakpoint present=%d\n", raw == kBreakInsn);
	CHECK(raw == kBreakInsn);
	CHECK(e->RemoveBreakpoint(second)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 0);
}

static void t_library_rebase_breakpoint()
{
	Log log; auto e = start(log, "dlrebase"); if (!e) return; PtraceEngine::Event ev;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	uint64_t first = addrOf(log, "cycle1="); CHECK(first != 0); CHECK(e->AddBreakpoint(first));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.breakpoint);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	uint64_t second = addrOf(log, "cycle2="); CHECK(second != 0); CHECK(second != first);
	// The adapter must discard the physical record without restoring stale bytes into the replacement mapping, then
	// resolve the logical module-relative breakpoint at its new address.
	CHECK(e->DiscardBreakpoint(first)); CHECK(e->AddBreakpoint(second));
	auto raw = rawRead(e->GetPid(), second, kBreakInsn.size());
	printf("  rebased %llx -> %llx; physical breakpoint at replacement=%d\n", (unsigned long long)first,
		(unsigned long long)second, raw == kBreakInsn);
	CHECK(raw == kBreakInsn);
	CHECK(e->RemoveBreakpoint(second)); CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev));
}

static void t_library_rebase_hardware()
{
	Log log; auto e = start(log, "dlrebase"); if (!e) return; PtraceEngine::Event ev;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	uint64_t first = addrOf(log, "cycle1="); CHECK(first != 0);
	if (!e->AddHardwareBreakpoint(first, PtraceHwType::Execute, 4)) { printf("  SKIP: no hardware breakpoints\n"); e->Kill(); return; }
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.hardware);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	uint64_t second = addrOf(log, "cycle2="); CHECK(second != 0); CHECK(second != first);
	// A module-relative hardware breakpoint must move with the mapping rather than remaining armed at the old address.
	CHECK(e->RemoveHardwareBreakpoint(first, PtraceHwType::Execute, 4));
	CHECK(e->AddHardwareBreakpoint(second, PtraceHwType::Execute, 4));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.hardware && pcOf(*e, ev.tid) == second);
	CHECK(e->RemoveHardwareBreakpoint(second, PtraceHwType::Execute, 4));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 0);
}

static void t_processes()
{
	Log log; auto e = start(log, "sleeper"); if (!e) return;
	auto list = ListProcesses(); bool self = false, target = false;
	for (auto& p : list) { if (p.pid == (uint32_t)getpid()) { self = true; CHECK(p.name == "driver"); CHECK(p.commandLine.find("driver") != std::string::npos); } if (p.pid == e->GetPid()) { target = true; CHECK(p.name == "progs"); CHECK(p.commandLine.find("sleeper") != std::string::npos); } }
	CHECK(self && target); for (size_t i = 1; i < list.size(); i++) CHECK(list[i - 1].pid < list[i].pid);
	e->Kill();
}

// ---- stepping
struct StepEnv
{
	Log log;   // first, so that it outlives the engine that posts to it
	PtraceEngine::Event ev; uint32_t tid = 0;
	std::map<uint64_t, int> refs; std::set<uint64_t> user;
	std::unique_ptr<PtraceEngine> e;
	std::unique_ptr<PtraceStepper> stepper;
	bool acquire(uint64_t a) { if (refs[a] == 0 && !e->AddBreakpoint(a)) { refs.erase(a); return false; } refs[a]++; return true; }
	bool release(uint64_t a) { auto it = refs.find(a); if (it == refs.end()) return false; if (--it->second > 0) return true; refs.erase(it); return e->RemoveBreakpoint(a); }
	bool begin(const std::string& mode)
	{
		e = startAtSignal(log, mode, tid, ev); if (!e) return false;
		stepper = std::make_unique<PtraceStepper>(*e, [this](uint64_t a) { return acquire(a); }, [this](uint64_t a) { return release(a); });
		return true;
	}
	uint64_t reg(size_t offset) { std::vector<uint8_t> r; if (!e->GetRegisterSet(tid, NT_PRSTATUS, r)) return 0; return le64(r, offset); }
	uint64_t pc() { return reg(kPcOff); }
	uint64_t sp() { return reg(kSpOff); }
	// Runs to a label that the target printed, by a temporary breakpoint of the engine
	bool runTo(uint64_t address)
	{
		CHECK(e->AddBreakpoint(address)); CHECK(e->Resume(false, 0));
		if (!log.wait(PtraceEngine::StoppedEvent, ev, 5s)) { printf("  runTo: no stop\n"); failures++; return false; }
		tid = ev.tid; CHECK(pc() == address); CHECK(e->RemoveBreakpoint(address)); return pc() == address;
	}
	uint32_t insnAt(uint64_t a) { uint32_t v = 0; e->ReadMemory(a, &v, 4); return v; }
#if defined(__x86_64__)
	static bool isCall(uint32_t i) { return (i & 0xFF) == 0xE8; }   // call rel32, which is what a direct call compiles to
#else
	static bool isCall(uint32_t i) { return (i & 0xFC000000) == 0x94000000 || (i & 0xFFFFFC1F) == 0xD63F0000; }
#endif
	// single-steps until the instruction at the pc is a call
	bool stepToCall()
	{
		for (int i = 0; i < 40; i++)
		{
			if (isCall(insnAt(pc()))) return true;
			if (!e->Resume(true, tid) || !log.wait(PtraceEngine::StoppedEvent, ev, 5s)) { failures++; return false; }
		}
		printf("  no call found\n"); failures++; return false;
	}
	// feeds the stops to the stepper until it is finished with them
	PtraceStepper::Result follow(std::chrono::milliseconds timeout = 8000ms)
	{
		while (true)
		{
			if (!log.wait(PtraceEngine::StoppedEvent, ev, timeout)) { printf("  follow: no stop\n"); failures++; return PtraceStepper::Result::Ignored; }
			uint64_t p = 0, s = 0; { std::vector<uint8_t> r; if (e->GetRegisterSet(ev.tid, NT_PRSTATUS, r)) { p = le64(r, kPcOff); s = le64(r, kSpOff); } }
			auto res = stepper->OnStop(ev, p, s, user.count(p) > 0);
			if (res != PtraceStepper::Result::Consumed) { tid = ev.tid; return res; }
		}
	}
	bool exitsWith(int code) { if (!e->Resume(false, 0)) { failures++; return false; } bool got = false; for (int i = 0; i < 300 && !got; i++) { std::unique_lock<std::mutex> l(log.m); log.cv.wait_for(l, 30ms); for (auto it = log.q.begin(); it != log.q.end(); ++it) if (it->type == PtraceEngine::ExitedEvent) { ev = *it; got = true; break; } } if (!got) { printf("  no exit\n"); failures++; return false; } CHECK(ev.exitCode == code); return ev.exitCode == code; }
};

static std::vector<uint64_t> retSitesOf(const ElfInfo& elf, const std::string& name)
{
	std::vector<uint64_t> sites;
#if defined(__x86_64__)
	// the program has frame pointers, so the epilogue is `leave; ret` or `pop %rbp; ret`
	for (auto& s : elf.symbols) if (s.name == name)
	{
		std::vector<uint8_t> code(s.size); std::ifstream f("/work/progs", std::ios::binary); f.seekg(s.address - 0x400000); f.read((char*)code.data(), code.size());
		for (size_t i = 1; i < code.size(); i++) if (code[i] == 0xC3 && (code[i - 1] == 0xC9 || code[i - 1] == 0x5D)) sites.push_back(s.address + i);
	}
#else
	for (auto& s : elf.symbols) if (s.name == name) for (uint64_t a = s.address; a < s.address + s.size; a += 4) { uint32_t insn; std::ifstream f("/work/progs", std::ios::binary); f.seekg(a - 0x400000); f.read((char*)&insn, 4); if (insn == 0xd65f03c0) sites.push_back(a); }
#endif
	return sites;
}

static uint64_t symbolAddr(const ElfInfo& elf, const std::string& name) { for (auto& s : elf.symbols) if (s.name == name) return s.address; return 0; }

static void t_stepover_basic()
{
	StepEnv t; if (!t.begin("stepover")) return;
	uint64_t here = addrOf(t.log, "here="); CHECK(t.runTo(here));
	CHECK(t.stepToCall()); uint64_t callPc = t.pc(), spBefore = t.sp();
	// a plain instruction is a single step
	CHECK(t.stepper->StepOver(t.tid, callPc - 4, spBefore, 0, 8) == true); CHECK(t.follow() == PtraceStepper::Result::Ignored); CHECK(t.ev.singleStep);
	// the call runs to its end
	StepEnv u; if (!u.begin("stepover")) return;
	uint64_t here2 = addrOf(u.log, "here="); CHECK(u.runTo(here2)); CHECK(u.stepToCall()); callPc = u.pc(); spBefore = u.sp();
	CHECK(u.stepper->StepOver(u.tid, callPc, spBefore, kCallLength, 8));
	CHECK(u.follow() == PtraceStepper::Result::Finished);
	CHECK(u.pc() == callPc + kCallLength); CHECK(u.sp() == spBefore); CHECK(!u.stepper->IsActive());
	CHECK(u.refs.empty());   // the temporary breakpoint is gone
	{ auto raw = rawRead(u.e->GetPid(), callPc + kCallLength, 4); uint32_t seen = 0; u.e->ReadMemory(callPc + kCallLength, &seen, 4); CHECK(raw.size() == 4 && !memcmp(raw.data(), &seen, 4)); }   // no breakpoint bytes left behind
	CHECK(u.exitsWith(11));
}

static void t_stepover_user_breakpoint()
{
	StepEnv t; if (!t.begin("stepover")) return;
	uint64_t here = addrOf(t.log, "here="); CHECK(t.runTo(here)); CHECK(t.stepToCall());
	uint64_t callPc = t.pc(), spBefore = t.sp();
	ElfInfo elf; auto mods = modulesOf(*t.e); auto exe = findModule(mods, "/progs"); CHECK(exe != nullptr); CHECK(ReadElfFile(exe->path, elf));
	uint64_t marker = symbolAddr(elf, "marker"); CHECK(marker != 0);
	CHECK(t.acquire(marker)); t.user.insert(marker);
	CHECK(t.stepper->StepOver(t.tid, callPc, spBefore, kCallLength, 8));
	auto res = t.follow(); CHECK(res == PtraceStepper::Result::Ignored); CHECK(t.ev.breakpoint); CHECK(t.pc() == marker);
	CHECK(!t.stepper->IsActive()); CHECK(t.refs.size() == 1 && t.refs.count(marker));   // only the user's breakpoint is left
	CHECK(t.exitsWith(11));
}

static void t_stepover_interrupt()
{
	StepEnv t; if (!t.begin("stepslow")) return;
	uint64_t here = addrOf(t.log, "here="); CHECK(t.runTo(here)); CHECK(t.stepToCall());
	uint64_t callPc = t.pc(), spBefore = t.sp();
	CHECK(t.stepper->StepOver(t.tid, callPc, spBefore, kCallLength, 8)); CHECK(t.stepper->IsActive());
	std::this_thread::sleep_for(100ms); CHECK(t.e->Interrupt());
	auto res = t.follow(); CHECK(res == PtraceStepper::Result::Ignored); CHECK(t.ev.interrupted);
	CHECK(!t.stepper->IsActive()); CHECK(t.refs.empty());
	// stepping over again works from wherever it stopped, and cancelling releases the breakpoint
	CHECK(t.stepper->StepReturn(t.tid, t.pc(), t.sp(), {}, callPc + kCallLength, spBefore)); CHECK(t.stepper->IsActive() && !t.refs.empty());
	t.stepper->Cancel(); CHECK(t.refs.empty()); CHECK(!t.stepper->IsActive());
	CHECK(t.e->Kill());
}

static void t_stepover_recursion()
{
	StepEnv t; if (!t.begin("recurse")) return;
	uint64_t site = addrOf(t.log, "site="); CHECK(t.runTo(site)); CHECK(t.stepToCall());
	uint64_t callPc = t.pc(), spBefore = t.sp();
	ElfInfo elf; auto mods = modulesOf(*t.e); auto exe = findModule(mods, "/progs"); CHECK(ReadElfFile(exe->path, elf));
	uint64_t counterAddr = symbolAddr(elf, "counter"); CHECK(counterAddr != 0);
	CHECK(t.stepper->StepOver(t.tid, callPc, spBefore, kCallLength, 8));
	CHECK(t.follow() == PtraceStepper::Result::Finished);
	// it stopped in the frame that made the call, after all the calls beneath it had returned
	CHECK(t.pc() == callPc + kCallLength); CHECK(t.sp() == spBefore);
	int counter = 0; CHECK(t.e->ReadMemory(counterAddr, &counter, 4)); CHECK(counter == 2);
	CHECK(t.exitsWith(3));
}

static void t_stepreturn_sites()
{
	StepEnv t; if (!t.begin("stepret")) return;
	uint64_t there = addrOf(t.log, "there="); CHECK(t.runTo(there));
	ElfInfo elf; auto mods = modulesOf(*t.e); auto exe = findModule(mods, "/progs"); CHECK(ReadElfFile(exe->path, elf));
	auto sites = retSitesOf(elf, "inner"); CHECK(sites.size() >= 1);
	// where the function returns to, from the frame pointers
	auto maps = t.e->GetMaps(); auto isExec = [&](uint64_t a) { for (auto& m : maps) if (m.execute && a >= m.start && a < m.end) return true; return false; };
	auto readWord = [&](uint64_t a, uint64_t& v) { v = 0; return t.e->ReadMemory(a, &v, 8); };
	auto frames = UnwindFramePointers(t.pc(), t.sp(), t.reg(kFpOff), 8, readWord, isExec); CHECK(frames.size() >= 2);
	CHECK(t.stepper->StepReturn(t.tid, t.pc(), t.sp() + kMinSpExtra, sites, 0, 0));
	CHECK(t.follow() == PtraceStepper::Result::Finished);
	CHECK(t.pc() == frames[1].pc); CHECK(t.sp() >= frames[1].sp); CHECK(t.refs.empty());   // on arm64 the frame size is not known, so the unwound sp is a lower bound
	CHECK(t.exitsWith(102 - 1));   // inner adds 1 and outer adds 100
}

static void t_stepreturn_address()
{
	StepEnv t; if (!t.begin("stepret")) return;
	uint64_t there = addrOf(t.log, "there="); CHECK(t.runTo(there));
	auto maps = t.e->GetMaps(); auto isExec = [&](uint64_t a) { for (auto& m : maps) if (m.execute && a >= m.start && a < m.end) return true; return false; };
	auto readWord = [&](uint64_t a, uint64_t& v) { v = 0; return t.e->ReadMemory(a, &v, 8); };
	auto frames = UnwindFramePointers(t.pc(), t.sp(), t.reg(kFpOff), 8, readWord, isExec); CHECK(frames.size() >= 2);
	CHECK(!t.stepper->StepReturn(t.tid, t.pc(), t.sp(), {}, 0, 0));   // nothing to run to
	CHECK(t.stepper->StepReturn(t.tid, t.pc(), t.sp(), {}, frames[1].pc, frames[1].sp));
	CHECK(t.follow() == PtraceStepper::Result::Finished);
	CHECK(t.pc() == frames[1].pc); CHECK(t.sp() >= frames[1].sp); CHECK(t.refs.empty());
	CHECK(t.exitsWith(101));
}

static void t_stepreturn_recursion()
{
	StepEnv t; if (!t.begin("recurse")) return;
	uint64_t site = addrOf(t.log, "site="); CHECK(t.runTo(site));
	ElfInfo elf; auto mods = modulesOf(*t.e); auto exe = findModule(mods, "/progs"); CHECK(ReadElfFile(exe->path, elf));
	auto sites = retSitesOf(elf, "recurse"); CHECK(sites.size() >= 1);
	auto maps = t.e->GetMaps(); auto isExec = [&](uint64_t a) { for (auto& m : maps) if (m.execute && a >= m.start && a < m.end) return true; return false; };
	auto readWord = [&](uint64_t a, uint64_t& v) { v = 0; return t.e->ReadMemory(a, &v, 8); };
	auto frames = UnwindFramePointers(t.pc(), t.sp(), t.reg(kFpOff), 8, readWord, isExec); CHECK(frames.size() >= 2);
	// the deeper calls return through the same instructions first, and none of them is the end of this one
	CHECK(t.stepper->StepReturn(t.tid, t.pc(), t.sp() + kMinSpExtra, sites, 0, 0));
	CHECK(t.follow() == PtraceStepper::Result::Finished);
	CHECK(t.pc() == frames[1].pc); CHECK(t.sp() >= frames[1].sp);
	int counter = 0; CHECK(t.e->ReadMemory(symbolAddr(elf, "counter"), &counter, 4)); CHECK(counter == 3);   // the frame has finished, including its own increment
	CHECK(t.exitsWith(3));
}

static void t_stepover_threads()
{
	StepEnv t; if (!t.begin("stepthreads")) return;
	uint64_t sync = addrOf(t.log, "sync="); CHECK(t.runTo(sync));
	CHECK(t.stepToCall()); uint64_t callPc = t.pc(), spBefore = t.sp(); uint32_t stepper = t.tid;
	CHECK(t.stepper->StepOver(t.tid, callPc, spBefore, kCallLength, 8));
	// the other threads run through the same call and return address all the while
	CHECK(t.follow() == PtraceStepper::Result::Finished);
	CHECK(t.ev.tid == stepper); CHECK(t.pc() == callPc + kCallLength); CHECK(t.sp() == spBefore); CHECK(t.refs.empty());
	CHECK(t.e->Kill());
}

// Runs a target that forks or spawns with a breakpoint set, and counts the hits of the parent
static void forkTest(const char* mode, int expectedHits, int expectedExit)
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, mode, tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); CHECK(e->AddBreakpoint(marker));
	int hits = 0; CHECK(e->Resume(false, 0));
	while (true)
	{
		{ std::unique_lock<std::mutex> l(log.m); bool got = log.cv.wait_for(l, 10s, [&] { for (auto& q : log.q) if (q.type == PtraceEngine::StoppedEvent || q.type == PtraceEngine::ExitedEvent) return true; return false; }); if (!got) { printf("  timeout after %d hits\n", hits); failures++; return; } }
		if (log.wait(PtraceEngine::ExitedEvent, ev, 1ms)) break;
		CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); if (!(ev.breakpoint && pcOf(*e, ev.tid) == marker)) { printf("  stray stop sig=%d\n", ev.signal); failures++; return; }
		CHECK((rawRead(e->GetPid(), marker, kBreakInsn.size()) == kBreakInsn));   // our own breakpoint is back
		hits++; if (!e->Resume(false, 0)) { printf("  resume failed\n"); failures++; return; }
	}
	printf("  hits=%d exit=%d signal=%d\n", hits, ev.exitCode, ev.signal); CHECK(hits == expectedHits); CHECK(ev.exitCode == expectedExit);
}

static void t_fork_child() { forkTest("forkbp", 0, 0); forkTest("forkbp2", 1, 0); }
static void t_vfork() { forkTest("vforkbp", 1, 0); }
static void t_spawn() { forkTest("spawnbp", 1, 7); }
static void t_fork_threads() { forkTest("forkthreads", 60, 0); }

static void t_exec_basic()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "execbp", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); uint32_t pid = e->GetPid();
	CHECK(e->AddBreakpoint(marker)); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.exec); CHECK(ev.tid == pid); CHECK(!ev.breakpoint); CHECK(e->GetThreads().size() == 1);
	// the memory is the new program's, and the breakpoint of the old one is gone from it and from what we know
	uint32_t seen = 0; CHECK(e->ReadMemory(marker, &seen, 4)); auto raw = rawRead(pid, marker, 4); CHECK(raw.size() == 4 && !memcmp(raw.data(), &seen, 4));
	CHECK(!std::equal(kBreakInsn.begin(), kBreakInsn.end(), raw.begin()));
	CHECK(pcOf(*e, pid) != 0);
	CHECK(!e->RemoveBreakpoint(marker));   // nothing is left of it
	// the new program runs its five calls without a stop, because there is no breakpoint any more
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1 && !ev.exec);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 5);
}

static void t_exec_rebreak()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "execbp", tid, ev); if (!e) return;
	uint64_t marker = addrOf(log, "marker="); CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.exec);
	// breakpoints work in the new program, in the same way as in the first one
	CHECK(e->AddBreakpoint(marker)); CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1);
	for (int i = 1; i <= 5; i++) { CHECK(e->Resume(false, 0)); if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  no hit %d\n", i); failures++; return; } CHECK(ev.breakpoint && pcOf(*e, ev.tid) == marker); }
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 5);
}

static void t_exec_thread()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "execthread", tid, ev); if (!e) return;
	uint32_t pid = e->GetPid(); CHECK(e->GetThreads().size() == 2);
	CHECK(e->Resume(false, 0));
	// the thread that runs exec is not the main thread, and the main thread is gone
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s)); CHECK(ev.exec); CHECK(ev.tid == pid); CHECK(e->GetThreads() == std::vector<uint32_t>{pid});
	CHECK(pcOf(*e, pid) != 0);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 7);
}

static void t_exec_continue()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "execloop", tid, ev); if (!e) return;
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.exec);
	// everything still works afterwards: running, interrupting, stepping, registers
	CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(100ms); CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.interrupted && !ev.exec);
	uint64_t pc = pcOf(*e, ev.tid); CHECK(pc != 0);
	CHECK(e->Resume(true, ev.tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.singleStep);
	CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGKILL);
}

static void t_winsize()
{
	Log log; auto e = start(log, "winsize"); if (!e) return; PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev));
	CHECK(log.output.find("tty=1 ioctl=0 rows=24 cols=80") != std::string::npos);

	Log log2; auto e2 = std::make_unique<PtraceEngine>([&log2](const PtraceEngine::Event& x) { log2.push(x); });
	PtraceEngine::LaunchOptions o; o.path = prog; o.args = {"winsize"}; o.arch = TestArch(); o.rows = 50; o.columns = 132; std::string err;
	CHECK(e2->Launch(o, err)); CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e2->Resume(false, 0)); CHECK(log2.wait(PtraceEngine::ExitedEvent, ev));
	CHECK(log2.output.find("tty=1 ioctl=0 rows=50 cols=132") != std::string::npos);
}

static void t_repro_echo()
{
	Log log; auto e = start(log, "cat"); if (!e) return; PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	e->WriteInput("ping\n"); CHECK(log.wait(PtraceEngine::ExitedEvent, ev));
	std::string shown; for (char c : log.output) shown += c == '\r' ? "\\r" : (c == '\n' ? "\\n" : std::string(1, c));
	printf("  REPRO stdin echo: output was [%s]\n", shown.c_str());
}

static double cpuSeconds();

static void t_stdin_backpressure()
{
	Log log; auto e = start(log, "cat"); if (!e) return; PtraceEngine::Event ev;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	std::string input(8 << 20, 'x');
	double c0 = cpuSeconds();
	auto writer = std::async(std::launch::async, [&] { return e->WriteInput(input); });
	std::this_thread::sleep_for(300ms);
	double cpu = cpuSeconds() - c0;
	printf("  debugger used %.0f ms of CPU during 300 ms of stopped-target backpressure\n", cpu * 1000);
	CHECK(writer.wait_for(0s) == std::future_status::ready);
	// Release the writer even on the buggy path. The target reads one line and exits, closing the PTY.
	CHECK(e->Resume(false, 0));
	CHECK(writer.wait_for(5s) == std::future_status::ready);
	if (writer.wait_for(0s) == std::future_status::ready)
		writer.get();
}

static void t_repro_sigchld_ignored()
{
	signal(SIGCHLD, SIG_IGN);
	Log log; auto e = start(log, "sleeper"); if (!e) { signal(SIGCHLD, SIG_DFL); return; } PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
	bool exited = log.wait(PtraceEngine::ExitedEvent, ev, 6000ms);
	printf("  REPRO SIGCHLD ignored in the debugger process: exit reported=%d code=%d signal=%d (the target exits with 3 after 2s)\n", exited, ev.exitCode, ev.signal);
	signal(SIGCHLD, SIG_DFL);
}

static double cpuSeconds() { rusage u; getrusage(RUSAGE_SELF, &u); return u.ru_utime.tv_sec + u.ru_stime.tv_sec + (u.ru_utime.tv_usec + u.ru_stime.tv_usec) / 1e6; }
static double nowSeconds() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

static void t_perf()
{
	{ // a target that is only waiting, and one that is spinning
		for (const char* mode : {"sleeper", "loop"})
		{
			Log log; PtraceEngine::Event ev; auto e = start(log, mode); if (!e) return; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0));
			std::this_thread::sleep_for(300ms); double c0 = cpuSeconds(), w0 = nowSeconds(); std::this_thread::sleep_for(1500ms);
			double cpu = cpuSeconds() - c0, wall = nowSeconds() - w0;
			printf("  PERF debugger CPU while a %s target runs: %.1f%% of one core\n", mode, 100 * cpu / wall); e->Kill();
		}
	}
	{
		Log log; PtraceEngine::Event ev; auto e = start(log, "hello"); if (!e) return; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); uint32_t tid = ev.tid;
		double t0 = nowSeconds(); int n = 3000; for (int i = 0; i < n; i++) { if (!e->Resume(true, tid) || !log.wait(PtraceEngine::StoppedEvent, ev, 5s)) { failures++; break; } }
		double dt = nowSeconds() - t0; printf("  PERF single steps: %.0f per second (%.0f us each)\n", n / dt, 1e6 * dt / n); e->Kill();
	}
	{
		Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bploop", tid, ev); if (!e) return; uint64_t marker = addrOf(log, "marker="); CHECK(e->AddBreakpoint(marker));
		int n = 2000; double t0 = nowSeconds(); for (int i = 0; i < n; i++) { if (!e->Resume(false, 0) || !log.wait(PtraceEngine::StoppedEvent, ev, 5s)) { failures++; break; } }
		double dt = nowSeconds() - t0; printf("  PERF breakpoint hits: %.0f per second (%.0f us each)\n", n / dt, 1e6 * dt / n); e->Kill();
	}
	{
		Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "bp", tid, ev); if (!e) return; std::vector<uint8_t> buf(1 << 20);
		uint64_t base = 0, len = 0; for (auto& m : e->GetMaps()) if (m.read && m.end - m.start >= (1 << 20) && m.path.find("libc.so") != std::string::npos) { base = m.start; len = 1 << 20; break; }
		CHECK(base != 0); double t0 = nowSeconds(); int n = 200; int bad = 0;
		for (int i = 0; i < n; i++) if (!e->ReadMemory(base, buf.data(), len)) bad++;
		double dt = nowSeconds() - t0; printf("  PERF memory reads: %.0f MB/s in 1 MB reads (%d failed)\n", n * 1.0 / dt, bad);
		t0 = nowSeconds(); n = 5000; bad = 0; for (int i = 0; i < n; i++) if (!e->ReadMemory(base, buf.data(), 64)) bad++; dt = nowSeconds() - t0; printf("  PERF small memory reads: %.1f us each (%d failed)\n", 1e6 * dt / n, bad);
		std::vector<uint8_t> regs; t0 = nowSeconds(); n = 2000; for (int i = 0; i < n; i++) e->GetRegisterSet(ev.tid, NT_PRSTATUS, regs); dt = nowSeconds() - t0; printf("  PERF register reads: %.0f us each\n", 1e6 * dt / n); e->Kill();
	}
}

static void t_detach_reaped()
{
	Log log; auto e = start(log, "sleeper"); if (!e) return; PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); uint32_t pid = e->GetPid();
	int status = 0; CHECK(!e->WaitForDetachedExit(status, 10ms));
	CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(100ms); CHECK(e->Detach()); CHECK(log.wait(PtraceEngine::DetachedEvent, ev));
	CHECK(!e->WaitForDetachedExit(status, 200ms));
	CHECK(e->WaitForDetachedExit(status, 4s)); CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 3);
	std::this_thread::sleep_for(50ms); CHECK(procState(pid) == "gone");
	// and the engine can go away while the target is still running
	Log log2; auto e2 = start(log2, "sleeper"); if (!e2) return; CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); uint32_t pid2 = e2->GetPid();
	CHECK(e2->Resume(false, 0)); std::this_thread::sleep_for(50ms); CHECK(e2->Detach()); CHECK(log2.wait(PtraceEngine::DetachedEvent, ev)); e2.reset();
	std::this_thread::sleep_for(2500ms); CHECK(procState(pid2) == "gone");
}

static bool twoAddrs(Log& log, uint64_t& a, uint64_t& b)
{
	if (!waitOutput(log, "handler=")) return false;
	unsigned long long x = 0, y = 0; sscanf(log.output.c_str(), "info=%llx handler=%llx", &x, &y); a = x; b = y; return x && y;
}

static uint64_t x0Of(PtraceEngine& e, uint32_t tid) { std::vector<uint8_t> r; return e.GetRegisterSet(tid, NT_PRSTATUS, r) ? le64(r, kArg0Off) : ~0ull; }

static void t_handlers_off()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sighandler", tid, ev); if (!e) return;
	uint64_t info, handler; CHECK(twoAddrs(log, info, handler));
	// by default the signal stops the target where it is delivered, and the handler then runs on its own
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR2 && ev.signalHandler == 0);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 11);   // both handlers ran, with no stop

	// a breakpoint in a handler works with or without the setting
	Log log2; auto e2 = startAtSignal(log2, "sighandler", tid, ev); if (!e2) return; twoAddrs(log2, info, handler);
	CHECK(e2->AddBreakpoint(handler)); CHECK(e2->Resume(false, 0)); CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR2);
	CHECK(e2->Resume(false, 0)); CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.breakpoint && pcOf(*e2, ev.tid) == handler && ev.signalHandler == 0);
	CHECK(e2->Resume(false, 0)); CHECK(log2.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 11);
}

static void t_handlers_on()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sighandler", tid, ev); if (!e) return;
	uint64_t info, handler; CHECK(twoAddrs(log, info, handler)); e->SetDebugSignalHandlers(true);
	// the signal still stops where it is delivered
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR2 && ev.signalHandler == 0);
	// and then the target stops at the first instruction of the handler, with the signal number as its argument
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signalHandler == SIGUSR2 && !ev.breakpoint && !ev.singleStep && ev.signal == SIGTRAP); CHECK(pcOf(*e, ev.tid) == info); CHECK(x0Of(*e, ev.tid) == SIGUSR2);
	// a signal that does not stop the target has its handler stopped at, without a stop for the signal itself
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signalHandler == SIGWINCH); CHECK(pcOf(*e, ev.tid) == handler); CHECK(x0Of(*e, ev.tid) == SIGWINCH);
	// stepping from there goes through the handler like through any function
	CHECK(e->Resume(true, ev.tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.singleStep && ev.signalHandler == 0);
	// a signal that has no handler goes by, and the program finishes
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 11);
}

static void t_handlers_toggle()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sighandler", tid, ev); if (!e) return;
	uint64_t info, handler; twoAddrs(log, info, handler); e->SetDebugSignalHandlers(true);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR2);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signalHandler == SIGUSR2);
	// turned off in the middle of it, the next handler runs on its own
	e->SetDebugSignalHandlers(false);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 11);
}

static void t_handlers_thread()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigthread", tid, ev); if (!e) return;
	waitOutput(log, "handler="); unsigned long long handler = 0; sscanf(log.output.c_str(), "handler=%llx", &handler);
	e->SetDebugSignalHandlers(true); uint32_t pid = e->GetPid();
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s));
	// the handler runs in the thread that the signal was sent to
	CHECK(ev.signalHandler == SIGWINCH); CHECK(ev.tid != pid); CHECK(pcOf(*e, ev.tid) == handler); CHECK(e->GetThreads().size() == 2);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

static void t_sigtrap_raise()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_raise", tid, ev); if (!e) return;
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target);
	CHECK(!ev.breakpoint && !ev.hardware && !ev.singleStep && ev.signalHandler == 0);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

static void t_sigtrap_kill()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_kill", tid, ev); if (!e) return;
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target);
	CHECK(!ev.breakpoint && !ev.singleStep);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

static void t_sigtrap_handler_debug()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_raise", tid, ev); if (!e) return;
	e->SetDebugSignalHandlers(true);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signalHandler == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::SignalHandler);
	CHECK(!ev.breakpoint && !ev.hardware && !ev.singleStep);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

static void t_sigtrap_instruction()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_instruction", tid, ev); if (!e) return;
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target);
	CHECK(!ev.breakpoint && !ev.singleStep);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

static void t_sigtrap_instruction_handler_debug()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_instruction", tid, ev); if (!e) return;
	e->SetDebugSignalHandlers(true);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signalHandler == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::SignalHandler);
	CHECK(!ev.breakpoint && !ev.singleStep);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

static void t_sigtrap_unhandled()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_unhandled", tid, ev); if (!e) return;
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGTRAP);
}

static void t_sigtrap_after_breakpoint()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_raise", tid, ev); if (!e) return;
	uint64_t raiser = addrOf(log, "raiser="); CHECK(raiser != 0); CHECK(e->AddBreakpoint(raiser));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.breakpoint && ev.trapOrigin == PtraceEngine::TrapOrigin::SoftwareBreakpoint);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target && !ev.breakpoint);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

static void t_sigtrap_while_stepping()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "sigtrap_instruction", tid, ev); if (!e) return;
	uint64_t before = addrOf(log, "before="); uint64_t trap = addrOf(log, "trap=");
	CHECK(before != 0 && trap != 0); CHECK(e->AddBreakpoint(before));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.breakpoint);
	CHECK(e->Resume(true, ev.tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.singleStep && ev.trapOrigin == PtraceEngine::TrapOrigin::SingleStep); CHECK(pcOf(*e, ev.tid) == trap);
	CHECK(e->Resume(true, ev.tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(ev.signal == SIGTRAP && ev.trapOrigin == PtraceEngine::TrapOrigin::Target);
	CHECK(!ev.singleStep && !ev.breakpoint);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 1);
}

// Many interrupts at once must make one pause, and leave nothing behind that stops the target again later or gets passed on to it
static void t_interrupt_burst()
{
	Log log; PtraceEngine::Event ev; auto e = start(log, "loop"); if (!e) return; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); uint32_t pid = e->GetPid();
	for (int round = 0; round < 40; round++)
	{
		CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(std::chrono::microseconds(200 + round * 50));
		std::vector<std::thread> pokers; for (int i = 0; i < 4; i++) pokers.emplace_back([&] { for (int k = 0; k < 25; k++) e->Interrupt(); });
		for (auto& t : pokers) t.join();
		if (!log.wait(PtraceEngine::StoppedEvent, ev, 3000ms)) { printf("  round %d: no stop\n", round); failures++; break; }
		if (!ev.interrupted) { printf("  round %d: stop was not the interrupt (signal %d)\n", round, ev.signal); failures++; break; }
		// nothing else is waiting to stop it
		if (log.wait(PtraceEngine::StoppedEvent, ev, 20ms)) { printf("  round %d: a second stop for the same interrupt\n", round); failures++; break; }
	}
	// and resuming does not stop it again, nor pass a stop on to it
	CHECK(e->Resume(false, 0)); CHECK(!log.wait(PtraceEngine::StoppedEvent, ev, 150ms));
	CHECK(procState(pid).find("(stopped)") == std::string::npos);
	CHECK(e->Kill());
}

static void t_elf_names()
{
	auto mods = std::vector<PtraceModuleInfo>(); ElfInfo elf; CHECK(ReadElfFile("/work/progs", elf));
	bool amb = true; auto m = FindElfFunctionByName(elf, "marker", &amb); CHECK(m != nullptr && !amb && m->isFunction);
	// a data symbol is not a function, and a name that is not there is nothing
	amb = true; CHECK(FindElfFunctionByName(elf, "counter", &amb) == nullptr && !amb);
	CHECK(FindElfFunctionByName(elf, "no_such_function", &amb) == nullptr && !amb); CHECK(FindElfFunctionByName(elf, "marker") == m);
	// the start of a function and a place inside it are told apart by the offset
	auto at = FindElfSymbol(elf, m->address); CHECK(at && at->name == "marker" && at->address == m->address);
	auto inside = FindElfSymbol(elf, m->address + 4); CHECK(inside && inside->name == "marker" && inside->address != m->address + 4);
	// one function at two addresses is not a name to go by, but the same one twice is
	ElfInfo fake; fake.symbols = {{"dup", 0x100, 8, true}, {"dup", 0x200, 8, true}, {"same", 0x300, 8, true}, {"same", 0x300, 8, true}, {"mixed", 0x400, 8, true}, {"mixed", 0x500, 8, false}};
	amb = false; CHECK(FindElfFunctionByName(fake, "dup", &amb) == nullptr && amb);
	amb = true; auto same = FindElfFunctionByName(fake, "same", &amb); CHECK(same && same->address == 0x300 && !amb);
	amb = true; auto mixed = FindElfFunctionByName(fake, "mixed", &amb); CHECK(mixed && mixed->address == 0x400 && !amb);   // the data symbol does not count
}

// What the adapter does after an exec, on the real engine: the breakpoint that was at the start of a function is put at the start of
// the function with the same name in the new program, which is not at the same address
static void t_exec_by_name()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "execpad", tid, ev); if (!e) return;
	uint64_t oldMarker = addrOf(log, "marker="); CHECK(e->AddBreakpoint(oldMarker));
	auto oldMods = modulesOf(*e); auto oldExe = findModule(oldMods, "/progs"); ElfInfo oldElf; CHECK(oldExe && ReadElfFile(oldExe->path, oldElf));
	auto atStart = FindElfSymbol(oldElf, oldMarker - oldExe->base + oldElf.linkBase); CHECK(atStart && atStart->isFunction && atStart->address == oldMarker - oldExe->base + oldElf.linkBase);
	std::string function = atStart ? atStart->name : ""; CHECK(function == "marker");

	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.exec);
	auto mods = modulesOf(*e); auto exe = findModule(mods, "/progs_pad"); CHECK(exe != nullptr); if (!exe) return;
	CHECK(findModule(mods, "/progs") == nullptr || findModule(mods, "/progs")->path != exe->path);
	ElfInfo elf; CHECK(ReadElfFile(exe->path, elf)); bool amb = false; auto found = FindElfFunctionByName(elf, function, &amb); CHECK(found && !amb); if (!found) return;
	uint64_t newMarker = found->address + exe->base - elf.linkBase;
	printf("  marker moved from %llx to %llx\n", (unsigned long long)oldMarker, (unsigned long long)newMarker); CHECK(newMarker != oldMarker);
	CHECK(e->AddBreakpoint(newMarker));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGUSR1);
	for (int i = 1; i <= 5; i++) { CHECK(e->Resume(false, 0)); if (!log.wait(PtraceEngine::StoppedEvent, ev)) { printf("  no hit %d\n", i); failures++; return; } CHECK(ev.breakpoint && pcOf(*e, ev.tid) == newMarker); }
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 5);
}

// ---- the scenarios of the unit tests of the repository (test/debugger_test.py), on its own test binaries
static const std::string bins = "/bins/";

static std::unique_ptr<PtraceEngine> startBin(Log& log, const std::string& name, std::vector<std::string> args = {})
{
	auto e = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& ev) { log.push(ev); });
	PtraceEngine::LaunchOptions o; o.path = bins + name; o.args = args; o.arch = TestArch(); std::string err;
	if (!e->Launch(o, err)) { printf("  launch of %s failed: %s\n", name.c_str(), err.c_str()); failures++; return nullptr; }
	return e;
}

// What the adapter does at the first stop: the breakpoint at the entry point of the program, by module and offset
static bool entryBreakpoint(PtraceEngine& e, Log& log, PtraceEngine::Event& ev, const std::string& name, uint64_t& entry)
{
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); auto mods = modulesOf(e); auto exe = findModule(mods, "/" + name); CHECK(exe != nullptr); if (!exe) return false;
	ElfInfo elf; CHECK(ReadElfFile(exe->path, elf)); entry = elf.entry - elf.linkBase + exe->base; CHECK(e.AddBreakpoint(entry));
	CHECK(e.Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s)); return true;
}

static void t_signal_reasons()
{
	CHECK(StopReasonFromLinuxSignal(SIGSEGV) == SignalSegv); CHECK(StopReasonFromLinuxSignal(SIGFPE) == SignalFpe);
	CHECK(StopReasonFromLinuxSignal(SIGBUS) == SignalBus); CHECK(StopReasonFromLinuxSignal(SIGABRT) == SignalAbrt);
	CHECK(StopReasonFromLinuxSignal(SIGILL) == IllegalInstruction); CHECK(StopReasonFromLinuxSignal(SIGSYS) == SignalSys);
	CHECK(StopReasonFromLinuxSignal(SIGUSR1) == SignalUsr1); CHECK(StopReasonFromLinuxSignal(SIGUSR2) == SignalUsr2);
	CHECK(StopReasonFromLinuxSignal(SIGCHLD) == SignalChld); CHECK(StopReasonFromLinuxSignal(SIGTERM) == SignalTerm);
	CHECK(StopReasonFromLinuxSignal(SIGKILL) == SignalKill); CHECK(StopReasonFromLinuxSignal(SIGPIPE) == SignalPipe);
	CHECK(StopReasonFromLinuxSignal(SIGALRM) == SignalAlrm); CHECK(StopReasonFromLinuxSignal(SIGWINCH) == SignalWinch);
	CHECK(StopReasonFromLinuxSignal(0) == UnknownReason); CHECK(StopReasonFromLinuxSignal(64) == UnknownReason); CHECK(StopReasonFromLinuxSignal(-1) == UnknownReason);
	for (int s = 1; s < 65; s++) (void)StopReasonFromLinuxSignal(s);
}

static void t_conf_exitcode()
{
	// test_return_code: some systems give the low byte and others the whole code
	struct { const char* arg; int low; } cases[] = {{"-11", 245}, {"-1", 255}, {"-3", 253}, {"0", 0}, {"3", 3}, {"7", 7}, {"123", 123}};
	for (auto& c : cases)
	{
		Log log; PtraceEngine::Event ev; auto e = startBin(log, "exitcode", {c.arg}); if (!e) return;
		CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 5s));
		if (ev.exitCode != c.low) { printf("  exit code for %s: %d, wanted %d\n", c.arg, ev.exitCode, c.low); failures++; }
	}
}

static void t_conf_exceptions()
{
	Log log; PtraceEngine::Event ev; auto e = startBin(log, "do_exception", {"segfault"}); if (!e) return;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s));
	CHECK(ev.signal == SIGSEGV); CHECK(StopReasonFromLinuxSignal(ev.signal) == SignalSegv);
	// going on delivers the signal, which ends the program
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 5s)); CHECK(ev.signal == SIGSEGV);
	// a division by zero only faults on x86, so the arm64 tests skip it too
}

static void t_conf_entry_step_exit()
{
	// test_repeated_use, test_step_into, test_breakpoint: stop at the entry point, step three times, and run to the end, ten times over
	for (int round = 0; round < 10; round++)
	{
		Log log; PtraceEngine::Event ev; auto e = startBin(log, "helloworld", {"foobar"}); if (!e) return; uint64_t entry = 0;
		if (!entryBreakpoint(*e, log, ev, "helloworld", entry)) return;
		CHECK(ev.breakpoint); CHECK(pcOf(*e, ev.tid) == entry); uint32_t tid = ev.tid;
		for (int i = 0; i < 3; i++) { CHECK(e->Resume(true, tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.singleStep && !ev.breakpoint); }
		CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 5s)); CHECK(ev.exitCode == 10);   // helloworld returns 10
	}
}

static void t_conf_memory_registers()
{
	Log log; PtraceEngine::Event ev; auto e = startBin(log, "helloworld"); if (!e) return; uint64_t entry = 0; if (!entryBreakpoint(*e, log, ev, "helloworld", entry)) return;
	// test_memory_read_write
	uint64_t addr = pcOf(*e, ev.tid) + 10; std::vector<uint8_t> orig(256), back(256), aa(256, 0xAA), none(16);
	CHECK(e->ReadMemory(addr, orig.data(), 256)); CHECK(!e->WriteMemory(0, "heheHAHAherherHARHAR", 20)); CHECK(!e->ReadMemory(0, none.data(), 16));
	CHECK(e->WriteMemory(addr, aa.data(), 256)); CHECK(e->ReadMemory(addr, back.data(), 256)); CHECK(back == aa);
	CHECK(e->WriteMemory(addr, orig.data(), 256)); CHECK(e->ReadMemory(addr, back.data(), 256)); CHECK(back == orig);
	// test_register_read_write, with the first two argument registers
	std::vector<uint8_t> regs; CHECK(e->GetRegisterSet(ev.tid, NT_PRSTATUS, regs)); auto saved = regs; uint64_t a = 0xAAAAAAAADEADBEEFull, b = 0xBBBBBBBBCAFEBABEull;
	memcpy(regs.data(), &a, 8); memcpy(regs.data() + 8, &b, 8); CHECK(e->SetRegisterSet(ev.tid, NT_PRSTATUS, regs));
	std::vector<uint8_t> read; CHECK(e->GetRegisterSet(ev.tid, NT_PRSTATUS, read)); CHECK(le64(read, 0) == a && le64(read, 8) == b);
	CHECK(e->SetRegisterSet(ev.tid, NT_PRSTATUS, saved)); CHECK(e->GetRegisterSet(ev.tid, NT_PRSTATUS, read)); CHECK(read == saved);
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 5s));
}

static void t_conf_threads_restart()
{
	// test_thread and test_restart: run, pause, see more than one thread, and start over
	for (int round = 0; round < 3; round++)
	{
		Log log; PtraceEngine::Event ev; auto e = startBin(log, "helloworld_thread"); if (!e) return;
		CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(500ms);
		CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s)); CHECK(ev.interrupted); CHECK(e->GetThreads().size() > 1);
		CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(500ms);
		CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s)); CHECK(e->GetThreads().size() > 1);
		// a restart while it runs: the target is killed, and a new one is started
		CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(100ms); CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 5s));
	}
}

static void t_conf_symbols_modules()
{
	// test_load_module_symbols: a module other than the main one has symbols to load
	Log log; PtraceEngine::Event ev; auto e = startBin(log, "helloworld"); if (!e) return; uint64_t entry = 0; if (!entryBreakpoint(*e, log, ev, "helloworld", entry)) return;
	auto mods = modulesOf(*e); CHECK(mods.size() >= 3);   // the program, the C library and the loader
	size_t withSymbols = 0; for (auto& m : mods) { if (m.path.find("/helloworld") != std::string::npos) continue; ElfInfo elf; if (ReadElfFile(m.path, elf) && !elf.symbols.empty()) withSymbols++; }
	CHECK(withSymbols >= 1); CHECK(e->Kill());
}


// ---- attach

// Starts a program that is not a child of ours, the way an attach usually finds one
static pid_t spawnDetached(const std::string& mode, std::vector<std::string> extra = {})
{
	int fds[2]; if (pipe(fds) != 0) return -1;
	pid_t mid = fork();
	if (mid == 0)
	{
		setsid();
		pid_t grand = fork();
		if (grand == 0)
		{
			int n = open("/dev/null", O_RDWR); dup2(n, 0); dup2(n, 1); dup2(n, 2);
			std::vector<std::string> a = {prog, mode}; a.insert(a.end(), extra.begin(), extra.end());
			std::vector<char*> av; for (auto& x : a) av.push_back(x.data()); av.push_back(nullptr);
			execv(prog.c_str(), av.data()); _exit(127);
		}
		[[maybe_unused]] auto w = write(fds[1], &grand, sizeof(grand)); _exit(0);
	}
	close(fds[1]);
	pid_t grand = -1; [[maybe_unused]] auto r = read(fds[0], &grand, sizeof(grand)); close(fds[0]);
	waitpid(mid, nullptr, 0);
	std::this_thread::sleep_for(100ms);
	return grand;
}

static std::unique_ptr<PtraceEngine> attachTo(Log& log, pid_t pid, std::string* error = nullptr)
{
	auto e = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& ev) { log.push(ev); });
	std::string err;
	bool ok = e->Attach(pid, err, TestArch());
	if (error) *error = err;
	if (!ok) { if (!error) { printf("  attach failed: %s\n", err.c_str()); failures++; } return nullptr; }
	return e;
}

static bool processAlive(pid_t pid) { std::string s = procState(pid); return s != "gone" && s.find("zombie") == std::string::npos; }

static void t_attach_threads()
{
	pid_t pid = spawnDetached("threads"); CHECK(pid > 0);
	Log log; auto e = attachTo(log, pid); if (!e) { kill(pid, SIGKILL); return; }
	PtraceEngine::Event ev;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.signal == SIGSTOP); CHECK((pid_t)ev.tid == pid);
	CHECK(e->GetPid() == (uint32_t)pid); CHECK(e->GetThreads().size() == 4); CHECK(!e->IsRunning());
	for (uint32_t tid : e->GetThreads()) { std::string st = procState(tid); CHECK(st.find("tracing stop") != std::string::npos); }
	std::vector<uint8_t> regs; CHECK(e->GetRegisterSet(pid, NT_PRSTATUS, regs));
	// the target keeps running after a resume, and can be stopped again
	for (int i = 0; i < 3; i++)
	{
		CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(50ms);
		CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.interrupted);
		CHECK(e->GetThreads().size() == 4);
	}
	CHECK(e->Detach()); CHECK(log.wait(PtraceEngine::DetachedEvent, ev));
	std::this_thread::sleep_for(100ms);
	CHECK(processAlive(pid)); CHECK(procState(pid).find("tracing stop") == std::string::npos);
	kill(pid, SIGKILL);
}

static void t_attach_breakpoint()
{
	ElfInfo elf; CHECK(ReadElfFile(prog, elf)); uint64_t marker = symbolAddr(elf, "marker"); CHECK(marker != 0);
	pid_t pid = spawnDetached("bploop"); CHECK(pid > 0);
	Log log; auto e = attachTo(log, pid); if (!e) { kill(pid, SIGKILL); return; }
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->AddBreakpoint(marker));
	for (int i = 0; i < 5; i++)
	{
		CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
		CHECK(ev.breakpoint); CHECK(pcOf(*e, ev.tid) == marker);
	}
	// at a breakpoint, the memory that we read is the original one
	auto bytes = rawRead(pid, marker, 4); std::vector<uint8_t> seen(4); CHECK(e->ReadMemory(marker, seen.data(), 4)); CHECK(bytes != seen);
	CHECK(e->RemoveBreakpoint(marker));
	CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(100ms); CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.interrupted);
	CHECK(e->Detach()); CHECK(log.wait(PtraceEngine::DetachedEvent, ev));
	std::this_thread::sleep_for(100ms); CHECK(processAlive(pid)); kill(pid, SIGKILL);
}

static void t_attach_step_at_breakpoint()
{
	// A breakpoint where the target stopped is stepped over when it is resumed, not hit again right away
	ElfInfo elf; CHECK(ReadElfFile(prog, elf)); uint64_t marker = symbolAddr(elf, "marker");
	pid_t pid = spawnDetached("bploop");
	Log log; auto e = attachTo(log, pid); if (!e) { kill(pid, SIGKILL); return; }
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	uint64_t pc = pcOf(*e, ev.tid); CHECK(pc != 0);
	CHECK(e->AddBreakpoint(pc));
	CHECK(e->Resume(true, ev.tid)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(ev.singleStep); CHECK(pcOf(*e, ev.tid) != pc);
	(void)marker;
	CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGKILL);
}

static void t_attach_exit()
{
	pid_t pid = spawnDetached("sleeper");
	Log log; auto e = attachTo(log, pid); if (!e) { kill(pid, SIGKILL); return; }
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 6000ms)); CHECK(ev.exitCode == 3); CHECK(ev.signal == 0);
	CHECK(!e->Resume(false, 0));
}

static void t_attach_kill()
{
	pid_t pid = spawnDetached("threads");
	Log log; auto e = attachTo(log, pid); if (!e) { kill(pid, SIGKILL); return; }
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(50ms);
	CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.signal == SIGKILL);
	std::this_thread::sleep_for(100ms); CHECK(!processAlive(pid));
}

static void t_attach_dtor_detaches()
{
	pid_t pid = spawnDetached("threads");
	{
		Log log; auto e = attachTo(log, pid); if (!e) { kill(pid, SIGKILL); return; }
		PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
		CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(50ms);
	}
	std::this_thread::sleep_for(100ms);
	CHECK(processAlive(pid)); CHECK(procState(pid).find("tracing stop") == std::string::npos);
	kill(pid, SIGKILL);
}

static void t_attach_errors()
{
	Log log; std::string err;
	CHECK(!attachTo(log, 999999, &err)); printf("  %s\n", err.c_str()); CHECK(err.find("no such process") != std::string::npos);

	pid_t pid = spawnDetached("threads");
	auto first = attachTo(log, pid); CHECK(first != nullptr);
	Log log2; auto second = attachTo(log2, pid, &err); CHECK(!second); printf("  %s\n", err.c_str()); CHECK(err.find("already being traced") != std::string::npos);
	// the first is undisturbed
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(first->GetThreads().size() == 4);
	first.reset(); std::this_thread::sleep_for(100ms);
	CHECK(processAlive(pid)); kill(pid, SIGKILL);
}

static void t_attach_churn()
{
	// Threads that come and go while the others are being stopped
	for (int i = 0; i < 12; i++)
	{
		pid_t pid = spawnDetached("churnloop");
		std::this_thread::sleep_for(std::chrono::milliseconds(i * 3));
		Log log; std::string err; auto e = attachTo(log, pid, &err);
		if (!e) { printf("  attach %d failed: %s\n", i, err.c_str()); failures++; kill(pid, SIGKILL); continue; }
		PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
		for (uint32_t tid : e->GetThreads()) { if (procState(tid).find("tracing stop") == std::string::npos) { printf("  thread %u is not stopped: %s\n", tid, procState(tid).c_str()); failures++; } }
		for (int r = 0; r < 3; r++)
		{
			CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(10ms);
			CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
		}
		CHECK(e->Kill()); CHECK(log.wait(PtraceEngine::ExitedEvent, ev));
	}
}

static void t_attach_syscall()
{
	// A target that is blocked in a system call carries on after it
	pid_t pid = spawnDetached("sleeper");
	Log log; auto e = attachTo(log, pid); if (!e) { kill(pid, SIGKILL); return; }
	PtraceEngine::Event ev; CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	auto start = std::chrono::steady_clock::now();
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 6000ms)); CHECK(ev.exitCode == 3);
	auto took = std::chrono::steady_clock::now() - start; CHECK(took < 3500ms);
}

// ---- redirects

static std::string tmpPath(const std::string& name) { return "/tmp/rd_" + std::to_string(getpid()) + "_" + name; }
static std::string slurp(const std::string& path) { std::ifstream f(path); std::stringstream s; s << f.rdbuf(); return s.str(); }
static void spit(const std::string& path, const std::string& text) { std::ofstream f(path); f << text; }

static std::unique_ptr<PtraceEngine> startRedirected(Log& log, const std::string& mode, std::vector<std::string> extra, std::vector<std::string> redirects, const std::string& cwd = "", std::string* error = nullptr)
{
	auto e = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& ev) { log.push(ev); });
	PtraceEngine::LaunchOptions o; o.path = prog; o.args = {mode}; o.args.insert(o.args.end(), extra.begin(), extra.end()); o.workingDir = cwd; o.arch = TestArch();
	for (auto& text : redirects)
	{
		PtraceEngine::FdRedirect r; std::string perr;
		if (!ParseFdRedirect(text, r, perr)) { printf("  parse failed: %s\n", perr.c_str()); failures++; return nullptr; }
		o.redirects.push_back(r);
	}
	std::string err;
	bool ok = e->Launch(o, err);
	if (error) *error = err;
	if (!ok) { if (!error) { printf("  launch failed: %s\n", err.c_str()); failures++; } return nullptr; }
	return e;
}

static int runRedirected(Log& log, PtraceEngine& e)
{
	PtraceEngine::Event ev;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e.Resume(false, 0));
	CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); return ev.exitCode;
}

static void t_redirect_parse()
{
	using R = PtraceEngine::FdRedirect;
	struct Case { const char* text; bool ok; int kind; int fd; int flags; const char* path; int source; };
	Case cases[] = {
		{"0<in.txt", true, R::OpenFile, 0, O_RDONLY, "in.txt", 0},
		{"<in.txt", true, R::OpenFile, 0, O_RDONLY, "in.txt", 0},
		{"1>out.txt", true, R::OpenFile, 1, O_WRONLY | O_CREAT | O_TRUNC, "out.txt", 0},
		{">out.txt", true, R::OpenFile, 1, O_WRONLY | O_CREAT | O_TRUNC, "out.txt", 0},
		{"2>>log", true, R::OpenFile, 2, O_WRONLY | O_CREAT | O_APPEND, "log", 0},
		{">>log", true, R::OpenFile, 1, O_WRONLY | O_CREAT | O_APPEND, "log", 0},
		{"3<>data.bin", true, R::OpenFile, 3, O_RDWR | O_CREAT, "data.bin", 0},
		{"12>  /tmp/a b  ", true, R::OpenFile, 12, O_WRONLY | O_CREAT | O_TRUNC, "/tmp/a b", 0},
		{"2>&1", true, R::Duplicate, 2, 0, "", 1},
		{"5<&3", true, R::Duplicate, 5, 0, "", 3},
		{">&2", true, R::Duplicate, 1, 0, "", 2},
		{"4>&-", true, R::Close, 4, 0, "", 0},
		{"", false, 0, 0, 0, "", 0},
		{"1", false, 0, 0, 0, "", 0},
		{"a>b", false, 0, 0, 0, "", 0},
		{"1>", false, 0, 0, 0, "", 0},
		{"1>  ", false, 0, 0, 0, "", 0},
		{"1>&", false, 0, 0, 0, "", 0},
		{"1>&x", false, 0, 0, 0, "", 0},
		{"1>&2 extra", false, 0, 0, 0, "", 0},
		{"99999999999>x", false, 0, 0, 0, "", 0},
	};
	for (auto& c : cases)
	{
		R r; std::string err; bool ok = ParseFdRedirect(c.text, r, err);
		if (ok != c.ok) { printf("  '%s': parse %s\n", c.text, ok ? "succeeded" : ("failed: " + err).c_str()); failures++; continue; }
		if (!ok) { CHECK(!err.empty()); continue; }
		if (r.kind != c.kind || r.fd != c.fd || r.flags != c.flags || r.path != c.path || r.source != c.source) { printf("  '%s': wrong result\n", c.text); failures++; }
	}
}

static void t_redirect_stdout()
{
	auto out = tmpPath("out"); unlink(out.c_str());
	Log log; auto e = startRedirected(log, "hello", {}, {"1>" + out}); if (!e) return;
	CHECK(runRedirected(log, *e) == 7);
	CHECK(slurp(out) == "hello from target\n"); CHECK(log.output.empty());
	unlink(out.c_str());
}

static void t_redirect_stdin()
{
	auto in = tmpPath("in"); spit(in, "from a file\n");
	Log log; auto e = startRedirected(log, "cat", {}, {"0<" + in}); if (!e) return;
	CHECK(runRedirected(log, *e) == 0);
	CHECK(log.output.find("got: from a file") != std::string::npos);
	unlink(in.c_str());
}

static void t_redirect_stderr_merge()
{
	auto out = tmpPath("both"); unlink(out.c_str());
	Log log; auto e = startRedirected(log, "both", {}, {"1>" + out, "2>&1"}); if (!e) return;
	CHECK(runRedirected(log, *e) == 0);
	auto text = slurp(out); CHECK(text.find("to stdout") != std::string::npos); CHECK(text.find("to stderr") != std::string::npos); CHECK(log.output.empty());
	unlink(out.c_str());

	// Only descriptor 2 goes to the file, and 1 stays on the terminal
	auto err = tmpPath("err"); unlink(err.c_str());
	Log log2; auto e2 = startRedirected(log2, "both", {}, {"2>" + err}); if (!e2) return;
	CHECK(runRedirected(log2, *e2) == 0);
	CHECK(slurp(err) == "to stderr\n"); CHECK(log2.output.find("to stdout") != std::string::npos); CHECK(log2.output.find("to stderr") == std::string::npos);
	unlink(err.c_str());

	// The order matters: 2 copies what 1 is at that moment
	Log log3; auto e3 = startRedirected(log3, "both", {}, {"2>&1", "1>" + out}); if (!e3) return;
	CHECK(runRedirected(log3, *e3) == 0);
	CHECK(slurp(out) == "to stdout\n"); CHECK(log3.output.find("to stderr") != std::string::npos);
	unlink(out.c_str());
}

static void t_redirect_other_fds()
{
	auto in = tmpPath("in6"); spit(in, "six\n");
	auto o5 = tmpPath("o5"), o9 = tmpPath("o9"); unlink(o5.c_str()); unlink(o9.c_str());
	Log log; auto e = startRedirected(log, "fdwrite", {"5", "9", "17"}, {"5>" + o5, "9>" + o9, "17>&9"}); if (!e) return;
	CHECK(runRedirected(log, *e) == 0);
	CHECK(slurp(o5) == "fd5\n"); CHECK(slurp(o9) == "fd9\nfd17\n"); CHECK(log.output.find("failed") == std::string::npos);

	Log log2; auto e2 = startRedirected(log2, "fdread", {"6"}, {"6<" + in}); if (!e2) return;
	CHECK(runRedirected(log2, *e2) == 0); CHECK(log2.output.find("read: six") != std::string::npos);

	// Without a redirect the descriptors are not there, with one they are, and 3 can be closed again
	Log log3; auto e3 = startRedirected(log3, "fdopen", {"3", "4", "5", "6"}, {"3>" + o5, "4>" + o5, "4>&-", "5<" + in}); if (!e3) return;
	CHECK(runRedirected(log3, *e3) == 0);
	CHECK(log3.output.find("fd3=open fd4=closed fd5=open fd6=closed") != std::string::npos);
	unlink(in.c_str()); unlink(o5.c_str()); unlink(o9.c_str());
}

static void t_redirect_append_readwrite()
{
	auto out = tmpPath("app"); spit(out, "first\n");
	Log log; auto e = startRedirected(log, "hello", {}, {"1>>" + out}); if (!e) return;
	CHECK(runRedirected(log, *e) == 7); CHECK(slurp(out) == "first\nhello from target\n");

	auto rw = tmpPath("rw"); unlink(rw.c_str());
	Log log2; auto e2 = startRedirected(log2, "fdwrite", {"3"}, {"3<>" + rw}); if (!e2) return;
	CHECK(runRedirected(log2, *e2) == 0); CHECK(slurp(rw) == "fd3\n");
	unlink(out.c_str()); unlink(rw.c_str());
}

static void t_redirect_relative()
{
	auto dir = tmpPath("dir"); mkdir(dir.c_str(), 0777);
	Log log; auto e = startRedirected(log, "hello", {}, {"1>rel.txt"}, dir); if (!e) return;
	CHECK(runRedirected(log, *e) == 7); CHECK(slurp(dir + "/rel.txt") == "hello from target\n");
	unlink((dir + "/rel.txt").c_str()); rmdir(dir.c_str());
}

static void t_redirect_errors()
{
	std::string err;
	Log log; auto e = startRedirected(log, "hello", {}, {"0</nonexistent/file"}, "", &err);
	CHECK(!e); printf("  %s\n", err.c_str()); CHECK(err.find("/nonexistent/file") != std::string::npos);

	// A descriptor that is not valid to copy is reported by the child
	Log log2; auto e2 = startRedirected(log2, "hello", {}, {"3>&77"}, "", &err);
	CHECK(!e2); printf("  %s\n", err.c_str()); CHECK(!err.empty());

	// A failure after the redirects were set up is still reported: the pipe that tells about it is out of their way
	auto out = tmpPath("high");
	auto bad = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& ev) { log.push(ev); });
	PtraceEngine::LaunchOptions o; o.path = "/nonexistent/program"; o.arch = TestArch();
	for (int fd : {3, 4, 10, 11, 12, 13, 20}) { PtraceEngine::FdRedirect r; ParseFdRedirect(std::to_string(fd) + ">" + out, r, err); o.redirects.push_back(r); }
	CHECK(!bad->Launch(o, err)); printf("  %s\n", err.c_str()); CHECK(err.find("failed to execute") != std::string::npos);

	// Descriptors that are in the way of the ones we keep for ourselves are all set
	Log log3; auto e3 = startRedirected(log3, "fdwrite", {"10", "11", "12", "13", "20"}, {"10>" + out, "11>&10", "12>&10", "13>&10", "20>&10"}); if (!e3) return;
	CHECK(runRedirected(log3, *e3) == 0); CHECK(slurp(out) == "fd10\nfd11\nfd12\nfd13\nfd20\n");
	unlink(out.c_str());

	// Nothing is left open in the debugger
	int open = 0; for (int fd = 3; fd < 64; fd++) if (fcntl(fd, F_GETFD) >= 0) open++;
	printf("  descriptors open in the debugger: %d\n", open);
}

static void t_redirect_leaks()
{
	auto out = tmpPath("leak"); unlink(out.c_str());
	auto count = []() { int n = 0; for (int fd = 3; fd < 256; fd++) if (fcntl(fd, F_GETFD) >= 0) n++; return n; };
	int before = count();
	for (int i = 0; i < 20; i++)
	{
		Log log; auto e = startRedirected(log, "hello", {}, {"1>" + out, "7>" + out}); if (!e) return;
		CHECK(runRedirected(log, *e) == 7);
	}
	// A failed launch too
	for (int i = 0; i < 5; i++) { Log log; std::string err; startRedirected(log, "hello", {}, {"1>" + out, "0</nonexistent"}, "", &err); }
	int after = count();
	CHECK(before == after); printf("  descriptors before %d, after %d\n", before, after);
	unlink(out.c_str());
}

// ---- system calls

using SysInfo = PtraceEngine::SyscallInfo;
using SysMode = PtraceEngine::SyscallMode;

static bool syscallStop(PtraceEngine& e, Log& log, PtraceEngine::Event& ev, SysInfo& info, SysMode mode, SysInfo::Op op)
{
	if (!e.ResumeToSyscall(mode)) { printf("  ResumeToSyscall failed\n"); failures++; return false; }
	if (!log.wait(PtraceEngine::StoppedEvent, ev, 5s)) { printf("  no syscall stop\n"); failures++; return false; }
	CHECK(ev.syscall); CHECK(ev.signal == SIGTRAP); CHECK(!ev.breakpoint && !ev.singleStep && !ev.interrupted);
	if (!e.GetSyscallInfo(ev.tid, info)) { printf("  no syscall info\n"); failures++; return false; }
	CHECK(info.op == op); return info.op == op;
}

// Runs the target until it has made its threads, and stops it
static bool settleThreads(PtraceEngine& e, Log& log, PtraceEngine::Event& ev)
{
	CHECK(e.Resume(false, 0)); std::this_thread::sleep_for(200ms); CHECK(e.Interrupt());
	if (!log.wait(PtraceEngine::StoppedEvent, ev, 5s)) { printf("  no stop\n"); failures++; return false; }
	CHECK(e.GetThreads().size() == 4); return e.GetThreads().size() == 4;
}

static void t_syscall_trace()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "syscalls", tid, ev); if (!e) return;
	SysInfo info; uint32_t self = getpid();
	// the entry of getppid, which has not been executed
	if (!syscallStop(*e, log, ev, info, SysMode::Trace, SysInfo::Entry)) return;
	CHECK(info.number == (uint64_t)SYS_getppid); CHECK(info.arch != 0); CHECK(ev.tid == e->GetPid());
	CHECK(info.instructionPointer == pcOf(*e, ev.tid)); CHECK(e->GetThreads().size() == 1);
	printf("  %s\n", DescribeSyscall(info, true).c_str());
	// and its exit, with the result
	if (!syscallStop(*e, log, ev, info, SysMode::Trace, SysInfo::Exit)) return;
	CHECK(info.returnValue == (int64_t)self); CHECK(!info.isError);
	CHECK(DescribeSyscall(info) == "= " + std::to_string(self));
	// a call that fails
	if (!syscallStop(*e, log, ev, info, SysMode::Trace, SysInfo::Entry)) return;
	CHECK(info.number == (uint64_t)SYS_close); CHECK(info.args[0] == 9999);
	CHECK(DescribeSyscall(info).find("(0x270f, ") != std::string::npos);
	if (!syscallStop(*e, log, ev, info, SysMode::Trace, SysInfo::Exit)) return;
	CHECK(info.isError); CHECK(info.returnValue == -EBADF); CHECK(DescribeSyscall(info) == "= -9 (Bad file descriptor)");
	// an ordinary resume runs to the end, and the stops that it makes are not system calls
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 5s)); CHECK(ev.exitCode == (int)(self & 0xff));
}

static void t_syscall_breakpoint()
{
	// The instruction after the system call has not run at its entry, so a breakpoint there is hit and not stepped over
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "syscalls", tid, ev); if (!e) return;
	SysInfo info; if (!syscallStop(*e, log, ev, info, SysMode::Trace, SysInfo::Entry)) return;
	uint64_t pc = pcOf(*e, ev.tid); CHECK(e->AddBreakpoint(pc));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s));
	CHECK(ev.breakpoint && !ev.syscall); CHECK(pcOf(*e, ev.tid) == pc);
	CHECK(e->Kill());
}

static void t_syscall_emulate()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "syscalls", tid, ev); if (!e) return;
	SysInfo info;
	if (!e->ResumeToSyscall(SysMode::Emulate))
	{
		if (!kSysemuMayBeMissing) { printf("  PTRACE_SYSEMU failed\n"); failures++; }
		else printf("  SKIP: this kernel has no PTRACE_SYSEMU here\n");
		e->Kill(); return;
	}
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s)); CHECK(ev.syscall);
	CHECK(e->GetSyscallInfo(ev.tid, info)); CHECK(info.op == SysInfo::Entry); CHECK(info.number == (uint64_t)SYS_getppid);
	// the call is not made, and the return value is what the debugger puts in the register
	std::vector<uint8_t> regs; CHECK(e->GetRegisterSet(ev.tid, NT_PRSTATUS, regs));
	uint64_t answer = 77; memcpy(regs.data() + kRetOff, &answer, 8); CHECK(e->SetRegisterSet(ev.tid, NT_PRSTATUS, regs));
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev, 5s)); CHECK(ev.exitCode == 77);   // getppid would have given the pid of this program

	// it works on a target that has other threads too
	Log log2; auto e2 = start(log2, "threads"); if (!e2) return;
	CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); if (!settleThreads(*e2, log2, ev)) return; CHECK(e2->ResumeToSyscall(SysMode::Emulate)); CHECK(log2.wait(PtraceEngine::StoppedEvent, ev, 5s)); CHECK(ev.syscall);
	CHECK(e2->GetThreads().size() == 4); CHECK(e2->Kill());
}

static void t_syscall_set_info()
{
	Log log; PtraceEngine::Event ev; uint32_t tid; auto e = startAtSignal(log, "syscalls", tid, ev); if (!e) return;
	SysInfo info; if (!syscallStop(*e, log, ev, info, SysMode::Trace, SysInfo::Entry)) return;
	// the call is changed into getpid, which needs Linux 6.16
	SysInfo changed = info; changed.number = (uint64_t)SYS_getpid;
	if (!e->SetSyscallInfo(ev.tid, changed)) { printf("  SKIP: PTRACE_SET_SYSCALL_INFO needs Linux 6.16\n"); e->Kill(); return; }
	SysInfo now; CHECK(e->GetSyscallInfo(ev.tid, now)); CHECK(now.number == (uint64_t)SYS_getpid);
	// the kind of the stop has to match
	SysInfo wrong = info; wrong.op = SysInfo::Exit; CHECK(!e->SetSyscallInfo(ev.tid, wrong));
	if (!syscallStop(*e, log, ev, info, SysMode::Trace, SysInfo::Exit)) return;
	CHECK(info.returnValue == (int64_t)e->GetPid());
	CHECK(e->Kill());
}

static void t_syscall_threads()
{
	Log log; PtraceEngine::Event ev; auto e = start(log, "threads"); if (!e) return;
	CHECK(log.wait(PtraceEngine::StoppedEvent, ev)); if (!settleThreads(*e, log, ev)) return;
	for (int i = 0; i < 5; i++)
	{
		CHECK(e->ResumeToSyscall(SysMode::Trace)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s)); CHECK(ev.syscall);
		SysInfo info; CHECK(e->GetSyscallInfo(ev.tid, info)); CHECK(info.op != SysInfo::None);
		auto threads = e->GetThreads(); CHECK(threads.size() == 4);
		for (uint32_t t : threads) if (procState(t).find("tracing stop") == std::string::npos) { printf("  thread %u not stopped: %s\n", t, procState(t).c_str()); failures++; }
	}
	// back to ordinary running, which stops for an interrupt and for nothing else
	CHECK(e->Resume(false, 0)); std::this_thread::sleep_for(100ms); CHECK(e->Interrupt()); CHECK(log.wait(PtraceEngine::StoppedEvent, ev, 5s)); CHECK(ev.interrupted && !ev.syscall);
	CHECK(e->Kill());
}

static void t_syscall_unsupported()
{
	// an architecture without PTRACE_SYSEMU: it is refused, and the target can still be run
	PtraceArch noSysemu = RegisterTable(); noSysemu.sysemu = false;
	Log log; auto e = std::make_unique<PtraceEngine>([&log](const PtraceEngine::Event& x) { log.push(x); });
	PtraceEngine::LaunchOptions o; o.path = prog; o.args = {"hello"}; o.arch = &noSysemu; std::string err; PtraceEngine::Event ev;
	CHECK(e->Launch(o, err)); CHECK(log.wait(PtraceEngine::StoppedEvent, ev));
	CHECK(!e->ResumeToSyscall(SysMode::Emulate)); CHECK(!e->ResumeToSyscall(SysMode::None)); CHECK(!e->IsRunning());
	CHECK(e->Resume(false, 0)); CHECK(log.wait(PtraceEngine::ExitedEvent, ev)); CHECK(ev.exitCode == 7);
	// there is no syscall info when the thread is not stopped at anything, or is running
	Log log2; auto e2 = start(log2, "loop"); if (!e2) return; SysInfo info;
	CHECK(log2.wait(PtraceEngine::StoppedEvent, ev)); CHECK(e2->GetSyscallInfo(ev.tid, info)); CHECK(info.op == SysInfo::None);
	CHECK(e2->Resume(false, 0)); CHECK(!e2->GetSyscallInfo(ev.tid, info)); CHECK(!e2->GetSyscallInfo(99999, info)); CHECK(e2->Kill());
}

static void t_syscall_names()
{
	CHECK(std::string(SyscallName(AuditArchX86_64, 0)) == "read"); CHECK(std::string(SyscallName(AuditArchX86_64, 1)) == "write");
	CHECK(std::string(SyscallName(AuditArchX86_64, 39)) == "getpid"); CHECK(std::string(SyscallName(AuditArchX86_64, 59)) == "execve");
	CHECK(std::string(SyscallName(AuditArchX86_64, 231)) == "exit_group"); CHECK(std::string(SyscallName(AuditArchX86_64, 257)) == "openat");
	CHECK(std::string(SyscallName(AuditArchI386, 1)) == "exit"); CHECK(std::string(SyscallName(AuditArchI386, 4)) == "write");
	CHECK(std::string(SyscallName(AuditArchI386, 11)) == "execve"); CHECK(std::string(SyscallName(AuditArchI386, 20)) == "getpid");
	// 32-bit programs and 64-bit programs number the same call differently
	CHECK(std::string(SyscallName(AuditArchI386, 1)) != SyscallName(AuditArchX86_64, 1));
	CHECK(SyscallName(AuditArchX86_64, 100000) == nullptr); CHECK(SyscallName(AuditArchX86_64, ~0ull) == nullptr); CHECK(SyscallName(0xC00000B7, 64) == nullptr); CHECK(SyscallName(0, 0) == nullptr);
	for (uint64_t n = 0; n < 470; n++) { auto a = SyscallName(AuditArchX86_64, n); auto b = SyscallName(AuditArchI386, n); if (a) CHECK(*a); if (b) CHECK(*b); }

	SysInfo info; info.op = SysInfo::Entry; info.arch = AuditArchX86_64; info.number = 1; info.args[0] = 1; info.args[1] = 0x7ffc1000; info.args[2] = 5;
	CHECK(DescribeSyscall(info) == "write(0x1, 0x7ffc1000, 0x5, 0x0, 0x0, 0x0)");
	info.number = 9999; CHECK(DescribeSyscall(info).rfind("syscall_9999(", 0) == 0);
	info.op = SysInfo::Exit; info.returnValue = 5; CHECK(DescribeSyscall(info) == "= 5");
	info.isError = true; info.returnValue = -2; CHECK(DescribeSyscall(info) == "= -2 (No such file or directory)");
	info.op = SysInfo::None; CHECK(DescribeSyscall(info) == "not stopped at a system call");
	info.op = SysInfo::Entry; info.number = 1; info.instructionPointer = 0x401000; info.stackPointer = 0x7ffe0000;
	CHECK(DescribeSyscall(info, true) == "system call entry: write(0x1, 0x7ffc1000, 0x5, 0x0, 0x0, 0x0)\npc 0x401000, sp 0x7ffe0000");
	info.op = SysInfo::Seccomp; info.seccompData = 0x1234; CHECK(DescribeSyscall(info).find("(seccomp data 0x1234)") != std::string::npos);
}


int main(int argc, char** argv)
{
	struct { const char* n; void (*f)(); } tests[] = {
		{"hello", t_hello}, {"step", t_step}, {"interrupt", t_interrupt}, {"threads", t_threads}, {"churn", t_churn},
		{"signal", t_signal}, {"silent", t_silent}, {"detach", t_detach}, {"kill_running", t_kill_running},
		{"dtor_kills", t_dtor_kills}, {"launch_errors", t_launch_errors}, {"args_cwd", t_args_cwd}, {"stdin", t_stdin}, {"stdin_backpressure", t_stdin_backpressure},
		{"nopty", t_nopty}, {"relaunch", t_relaunch}, {"regs_step", t_regs_step}, {"regs_running", t_regs_running}, {"memory", t_memory}, {"bp_basic", t_bp_basic}, {"bp_step_remove", t_bp_step_remove}, {"bp_write", t_bp_write}, {"bp_threads", t_bp_threads}, {"bp_interrupts", t_bp_interrupts}, {"bp_remove_running", t_bp_remove_running}, {"bp_detach", t_bp_detach}, {"hw_watch", t_hw_watch}, {"hw_thread", t_hw_thread}, {"hw_exec", t_hw_exec}, {"hw_detach", t_hw_detach}, {"modules", t_modules}, {"symbols", t_symbols}, {"frames", t_frames}, {"loader", t_loader}, {"library_reload_breakpoint", t_library_reload_breakpoint}, {"library_rebase_breakpoint", t_library_rebase_breakpoint}, {"library_rebase_hardware", t_library_rebase_hardware}, {"processes", t_processes}, {"stepover_basic", t_stepover_basic}, {"stepover_user_breakpoint", t_stepover_user_breakpoint}, {"stepover_interrupt", t_stepover_interrupt}, {"stepover_recursion", t_stepover_recursion}, {"stepreturn_sites", t_stepreturn_sites}, {"stepreturn_address", t_stepreturn_address}, {"stepreturn_recursion", t_stepreturn_recursion}, {"stepover_threads", t_stepover_threads}, {"perf", t_perf}, {"detach_reaped", t_detach_reaped}, {"fork_child", t_fork_child}, {"vfork", t_vfork}, {"spawn", t_spawn}, {"fork_threads", t_fork_threads}, {"interrupt_burst", t_interrupt_burst}, {"handlers_off", t_handlers_off}, {"handlers_on", t_handlers_on}, {"handlers_toggle", t_handlers_toggle}, {"handlers_thread", t_handlers_thread}, {"sigtrap_raise", t_sigtrap_raise}, {"sigtrap_kill", t_sigtrap_kill}, {"sigtrap_handler_debug", t_sigtrap_handler_debug}, {"sigtrap_instruction", t_sigtrap_instruction}, {"sigtrap_instruction_handler_debug", t_sigtrap_instruction_handler_debug}, {"sigtrap_unhandled", t_sigtrap_unhandled}, {"sigtrap_after_breakpoint", t_sigtrap_after_breakpoint}, {"sigtrap_while_stepping", t_sigtrap_while_stepping}, {"signal_reasons", t_signal_reasons}, {"conf_exitcode", t_conf_exitcode}, {"conf_exceptions", t_conf_exceptions}, {"conf_entry_step_exit", t_conf_entry_step_exit}, {"conf_memory_registers", t_conf_memory_registers}, {"conf_threads_restart", t_conf_threads_restart}, {"conf_symbols_modules", t_conf_symbols_modules}, {"elf_names", t_elf_names}, {"exec_by_name", t_exec_by_name}, {"exec_basic", t_exec_basic}, {"exec_rebreak", t_exec_rebreak}, {"exec_thread", t_exec_thread}, {"exec_continue", t_exec_continue}, {"winsize", t_winsize}, {"repro_echo", t_repro_echo}, {"repro_sigchld_ignored", t_repro_sigchld_ignored}, {"attach_threads", t_attach_threads}, {"attach_breakpoint", t_attach_breakpoint}, {"attach_step_at_breakpoint", t_attach_step_at_breakpoint}, {"attach_exit", t_attach_exit}, {"attach_kill", t_attach_kill}, {"attach_dtor_detaches", t_attach_dtor_detaches}, {"attach_errors", t_attach_errors}, {"attach_churn", t_attach_churn}, {"attach_syscall", t_attach_syscall}, {"redirect_parse", t_redirect_parse}, {"redirect_stdout", t_redirect_stdout}, {"redirect_stdin", t_redirect_stdin}, {"redirect_stderr_merge", t_redirect_stderr_merge}, {"redirect_other_fds", t_redirect_other_fds}, {"redirect_append_readwrite", t_redirect_append_readwrite}, {"redirect_relative", t_redirect_relative}, {"redirect_errors", t_redirect_errors}, {"redirect_leaks", t_redirect_leaks}, {"syscall_trace", t_syscall_trace}, {"syscall_breakpoint", t_syscall_breakpoint}, {"syscall_emulate", t_syscall_emulate}, {"syscall_set_info", t_syscall_set_info}, {"syscall_threads", t_syscall_threads}, {"syscall_unsupported", t_syscall_unsupported}, {"syscall_names", t_syscall_names}};
	for (auto& t : tests)
	{
		if (argc > 1 && strcmp(argv[1], t.n)) continue;
		int before = failures; printf("[%s]\n", t.n); fflush(stdout);
		t.f();
		printf("  %s\n", failures == before ? "ok" : "FAILED"); fflush(stdout);
	}
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
