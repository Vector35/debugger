#include "debuggerapi.h"
#include <atomic>
#include <cstring>

using namespace BinaryNinjaDebuggerAPI;
static std::atomic<unsigned> destroyed {0};
static std::atomic<unsigned> destroyedTypes {0};

class FixtureAdapter final : public CustomDebugAdapter
{
	uint64_t m_ip = 0x1000, m_value = 0;
	std::vector<uint8_t> m_memory = std::vector<uint8_t>(0x1000, 0x90);
	DebugStopReason m_reason = InitialBreakpoint;
	void Stop(DebugStopReason reason)
	{
		m_reason = reason;
		BNDebuggerEvent event {};
		event.type = reason == ProcessExited ? TargetExitedEventType : AdapterStoppedEventType;
		event.data.targetStoppedData.reason = reason;
		event.data.targetStoppedData.lastActiveThread = 1;
		PostEvent(event);
	}
public:
	~FixtureAdapter() override { ++destroyed; }
	bool Execute(const std::string&) override { Stop(InitialBreakpoint); return true; }
	bool ExecuteWithArgs(const std::string& path, const std::string&, const std::string&) override { return Execute(path); }
	bool Go() override { m_value = 43; m_ip = 0x1007; Stop(Breakpoint); return true; }
	bool StepInto() override { m_value = 42; m_ip = 0x1005; Stop(SingleStep); return true; }
	bool StepOver() override { return StepInto(); }
	bool Quit() override { Stop(ProcessExited); return true; }
	bool Detach() override { return Quit(); }
	bool Attach(uint32_t) override { return false; }
	bool Connect(const std::string&, uint32_t) override { return false; }
	bool ConnectToDebugServer(const std::string&, uint32_t) override { return false; }
	std::vector<DebugProcess> GetProcessList() override { return {{1, "api-fixture"}}; }
	uint32_t GetActivePID() override { return 1; }
	std::vector<DebugThread> GetThreadList() override { return {GetActiveThread()}; }
	DebugThread GetActiveThread() override { return {1, m_ip}; }
	uint32_t GetActiveThreadId() override { return 1; }
	bool SetActiveThread(const DebugThread& thread) override { return thread.m_tid == 1; }
	bool SetActiveThreadId(uint32_t tid) override { return tid == 1; }
	bool SuspendThread(uint32_t) override { return false; }
	bool ResumeThread(uint32_t) override { return false; }
	DebugBreakpoint AddBreakpoint(uint64_t address) override { return {"fixture", 0, address, true, "1"}; }
	DebugBreakpoint AddBreakpointRelative(const std::string&, uint64_t) override { return {}; }
	bool RemoveBreakpoint(uint64_t) override { return true; }
	bool RemoveBreakpointRelative(const std::string&, uint64_t) override { return false; }
	std::vector<DebugBreakpoint> GetBreakpointList() override { return {}; }
	std::unordered_map<std::string, DebugRegister> ReadAllRegisters() override
	{
		return {{"rax", {"rax", m_value, 8, 0, "fixture value"}},
			{"rip", {"rip", m_ip, 8, 1, ""}}, {"rsp", {"rsp", 0x1800, 8, 2, ""}}};
	}
	DebugRegister ReadRegister(const std::string& name) override
	{
		auto regs = ReadAllRegisters();
		auto it = regs.find(name);
		return it == regs.end() ? DebugRegister{} : it->second;
	}
	bool WriteRegister(const std::string& name, const std::vector<uint8_t>& bytes) override
	{
		if (name != "rax" || bytes.size() < 8) return false;
		std::memcpy(&m_value, bytes.data(), 8); return true;
	}
	std::vector<uint8_t> ReadMemory(uint64_t address, size_t size) override
	{
		if (address < 0x1000 || address - 0x1000 >= m_memory.size()) return {};
		auto offset = static_cast<size_t>(address - 0x1000);
		auto length = std::min(size, m_memory.size() - offset);
		return {m_memory.begin() + offset, m_memory.begin() + offset + length};
	}
	bool WriteMemory(uint64_t address, const std::vector<uint8_t>& bytes) override
	{
		if (address < 0x1000 || address - 0x1000 > m_memory.size()
			|| bytes.size() > m_memory.size() - (address - 0x1000)) return false;
		std::copy(bytes.begin(), bytes.end(), m_memory.begin() + address - 0x1000); return true;
	}
	std::vector<DebugModule> GetModuleList() override { return {{"api-fixture", "api-fixture", 0x1000, 0x1000, true}}; }
	std::string GetTargetArchitecture() override { return "x86_64"; }
	uint64_t GetInstructionOffset() override { return m_ip; }
	uint64_t GetStackPointer() override { return 0x1800; }
	DebugStopReason StopReason() override { return m_reason; }
	uint64_t ExitCode() override { return 0; }
	bool BreakInto() override { return false; }
	bool GoReverse() override { return false; }
	bool StepIntoReverse() override { return false; }
	bool StepOverReverse() override { return false; }
	bool StepReturn() override { return false; }
	bool StepReturnReverse() override { return false; }
	std::string InvokeBackendCommand(const std::string&) override { return {}; }
	bool SupportFeature(uint32_t) override { return false; }
};

class FixtureType final : public CustomDebugAdapterType
{
public:
	explicit FixtureType(const std::string& name = "CPP_API_TEST") : CustomDebugAdapterType(name) {}
	~FixtureType() override { ++destroyedTypes; }
	std::unique_ptr<CustomDebugAdapter> Create(Ref<BinaryView>) override { return std::make_unique<FixtureAdapter>(); }
	bool IsValidForData(Ref<BinaryView>) override { return true; }
	bool CanExecute(Ref<BinaryView>) override { return true; }
	bool CanConnect(Ref<BinaryView>) override { return false; }
};

#ifdef _WIN32
#define TEST_EXPORT __declspec(dllexport)
#else
#define TEST_EXPORT __attribute__((visibility("default")))
#endif
extern "C" TEST_EXPORT bool RegisterCppAdapterFixture()
{
	DbgRef<FixtureType> type = new FixtureType();
	if (!DebugAdapterType::Register(type))
		return false;
	auto registered = DebugAdapterType::GetByName("CPP_API_TEST");
	return registered && registered->GetObject() == type->GetObject();
}
extern "C" TEST_EXPORT bool CppAdapterEmptyNameRejected() { FixtureType type(""); return !type.Register(); }
extern "C" TEST_EXPORT unsigned CppAdapterDestroyedCount() { return destroyed.load(); }
extern "C" TEST_EXPORT unsigned CppAdapterTypeDestroyedCount() { return destroyedTypes.load(); }
