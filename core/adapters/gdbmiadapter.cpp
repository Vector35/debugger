#include "gdbmiadapter.h"
#include <regex>
#include <sstream>
#include <map>
#include "../debuggercontroller.h" // Assuming this path is correct for your project structure
#include "../../cli/log.h" // For Log::print

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

GdbMiAdapter::GdbMiAdapter(BinaryView* data) : DebugAdapter(data) {
    m_lastStopReason = UnknownReason;
    m_targetRunningAtomic.store(false, std::memory_order_release);

	GenerateDefaultAdapterSettings(data);
}

GdbMiAdapter::~GdbMiAdapter() {
    Stop();
}

intx::uint512 GdbMiAdapter::ParseGdbValue(const std::string& valueStr)
{
    if (valueStr.empty()) return 0;
    try {
        return intx::from_string<intx::uint512>(valueStr);
    } catch(...) {
        LogError("Failed to parse GDB value: \"%s\"", valueStr.c_str());
        return 0;
    }
}

// --- Helper to clear cache when target is resumed ---
void GdbMiAdapter::InvalidateCache() {
    std::unique_lock lock(m_cacheMutex);
    m_cachedThreads.clear();
    m_cachedRegisters.clear();
    m_cachedFrames.clear();
    // Do not clear m_watchList here, as we want to preserve the watch expressions
}

// --- Internal methods to query GDB and fill the cache ---
void GdbMiAdapter::UpdateThreadList() {
    auto result = m_mi->SendCommand("-thread-info");
    if (result.command != "done") {
        LogError("Failed to get thread info: %s", result.fullLine.c_str());
        return;
    }
    
    std::vector<DebugThread> threads;
    LogDebug("Thread info response: %s", result.payload.c_str());
    
    // Try to parse the thread info - the response format varies by GDB version
    auto value = MiValue::Parse(result.payload);
    
    // Check if we have a threads list in the response (newer GDB versions)
    if (value.Exists("threads")) {
        const auto& threadsList = value["threads"].GetList();
        LogDebug("Found %zu threads in thread-info response", threadsList.size());
        
        for(const auto& threadVal : threadsList) {
            try {
                if (!threadVal.Exists("id")) {
                    LogError("Thread entry missing 'id' field");
                    continue;
                }
                uint32_t tid = std::stoi(threadVal["id"].GetString());
				uint64_t pc = 0;
				if (threadVal.Exists("frame.addr"))
				{
					try
					{
						pc = std::stoull(threadVal["frame.addr"].GetString(), nullptr, 16);
					}
					catch (...)
					{
					}
				}
                threads.emplace_back(tid, pc);
                LogDebug("Added thread with id: %u", tid);
            } catch(const std::exception& e) {
                LogError("Failed to parse thread entry: %s", e.what());
            } catch(...) {
                LogError("Unknown error parsing thread entry");
            }
        }
    } 
    // Fallback: Check if we have thread info directly in the payload (older GDB versions)
    else if (result.payload.find("threads") != std::string::npos) {
        threads.emplace_back(1);
        LogDebug("Added fallback thread with id: 1");
    }
    else {
        LogError("No threads list in thread-info response. Payload: %s", result.payload.c_str());
        return;
    }
    
    std::unique_lock cacheLock(m_cacheMutex);
    m_cachedThreads = threads;
    LogDebug("Updated thread list cache with %zu threads", threads.size());
}

void GdbMiAdapter::UpdateAllRegisters() {
    if (m_registerNames.empty()) {
        LogError("Cannot update registers: register names list is empty");
        return;
    }

    auto result = m_mi->SendCommand("-data-list-register-values r");
    if (result.command != "done") {
        LogError("Failed to get register values: %s", result.fullLine.c_str());
        return;
    }
    
    std::unordered_map<std::string, DebugRegister> regs;

	auto gdbmiregisters = MiValue::Parse(result.payload);
	if (!gdbmiregisters.IsDict() || !gdbmiregisters["register-values"].IsList())
	{
		LogError("No register-values in response. Payload: %s", result.payload.c_str());
		return;
	}

	for (int i = 0; i < gdbmiregisters["register-values"].size(); i++)
	{
		auto gdbmi_reg = gdbmiregisters["register-values"][i];
		auto reg_idx = std::stoul(gdbmi_reg["number"].GetString(), 0, 10);
		auto reg_value = ParseGdbValue(gdbmi_reg["value"].GetString());
		if (reg_idx < m_registerNames.size())
		{
			std::string name = m_registerNames[reg_idx];
			if (!name.empty())
			{
				regs[name] = DebugRegister(name, reg_value, 0, reg_idx);
			}
		}
	}

	if (m_remoteArch == "armv7-m" && regs.contains("pc") && regs.contains("sp"))
	{
		m_instructionOffset = static_cast<uint64_t>(regs["pc"].m_value);
		m_stackPointer = static_cast<uint64_t>(regs["sp"].m_value);
	}

    std::unique_lock cacheLock(m_cacheMutex);
    m_cachedRegisters = regs;
    LogInfo("Updated register cache with %zu registers", regs.size());
}

void GdbMiAdapter::UpdateStackFrames(uint32_t tid) {
    if (GetActiveThreadId() != tid) {
        SetActiveThreadId(tid);
    }
    auto result = m_mi->SendCommand("-stack-list-frames");
    if (result.command != "done") {
        LogError("Failed to get stack frames: %s", result.fullLine.c_str());
        return;
    }

    std::vector<DebugFrame> frames;
	auto gdbmi_frames = MiValue::Parse(result.payload);
	for (int i = 0; i < gdbmi_frames["stack"].size(); ++i)
	{
		auto parsed_frame = gdbmi_frames["stack"][i];
		auto debug_frame = DebugFrame(i,
			std::stoull(parsed_frame["frame"]["addr"].GetString(), 0, 16),
			0,
			0,
			parsed_frame["frame"]["func"].GetString(),
			0,
			"n/a");
		frames.push_back(debug_frame);
	}

    std::unique_lock cacheLock(m_cacheMutex);
    m_cachedFrames[tid] = frames;
    LogInfo("Updated stack frames cache with %zu frames for thread %u", frames.size(), tid);
}

void GdbMiAdapter::AsyncRecordHandler(const MiRecord& record)
{
    if (record.command == "stopped")
	{
        // LogDebug("   stopped event");
		m_lastStopReason = GetStopReason(record);

        // Update TID (optional, not holding the event mutex)
        auto value = MiValue::Parse(record.payload);
        if (value.Exists("thread-id"))
        {
            try {
                m_lastStopTid = std::stoi(value["thread-id"].GetString());
                m_currentTid = m_lastStopTid;
            } catch(...) { LogError("GDBMI: error parsing thread-id"); }
        }

		// Update target state BEFORE posting events
        m_targetRunningAtomic.store(false, std::memory_order_release);
        
		 // Kick a background refresh so we don’t block the reader
        ScheduleStateRefresh();

        m_eventCV.notify_all();
	}
    else if (record.command == "running")
    {
        // LogDebug("   running event");
        InvalidateCache();

        m_targetRunningAtomic.store(true, std::memory_order_release);

        DebuggerEvent event;
        event.type = ResumeEventType;
        PostDebuggerEvent(event);

        m_eventCV.notify_all();
    }
	else if (record.command == "error")
	{
		LogError("GDBMI: %s", record.payload.c_str());
	}
	else if (record.type == '~' || record.type == '@' || record.type == '&' || record.type == '=')
	{ // Console stream output
		std::string message;
        std::string raw = record.command;
        if (!record.payload.empty())
            raw += "," + record.payload;

        if (raw.length() > 2 && raw.front() == '"' && raw.back() == '"')
            raw = raw.substr(1, raw.length() - 2);

        for (size_t i = 0; i < raw.length(); ++i) {
            if (raw[i] == '\\' && i + 1 < raw.length()) {
                switch (raw[i+1]) {
                    case 'n': message += '\n'; break;
                    case 'r': message += '\r'; break;
                    case 't': message += '\t'; break;
                    case '"': message += '"'; break;
                    case '\\': message += '\\'; break;
                    default: message += raw[i+1]; break;
                }
                i++;
            } else {
                message += raw[i];
            }
        }

        DebuggerEvent event;
        event.type = BackendMessageEventType;
        event.data.messageData.message = message;
        PostDebuggerEvent(event);
    }
}

void GdbMiAdapter::ScheduleStateRefresh()
{
    // dispatch off-thread to avoid reader blocking
    if (!m_connected || m_targetRunningAtomic) return;
    std::thread([this]{
        // Serialize MI traffic with m_gdbCommandMutex (not the reader/event mutex)?
        {
            std::unique_lock lock(m_gdbCommandMutex);
            UpdateThreadList();
            UpdateAllRegisters();
            UpdateStackFrames(m_currentTid);
        }

        DebuggerEvent ev;
        ev.type = AdapterStoppedEventType;
        ev.data.targetStoppedData.reason = m_lastStopReason;
        PostDebuggerEvent(ev);
    }).detach();
}

DebugStopReason GdbMiAdapter::GetStopReason(const MiRecord& record)
{
	auto value = MiValue::Parse(record.payload);
	if (value.Exists("reason"))
	{
		const std::string& reason = value["reason"].GetString();
		if (reason == "breakpoint-hit")
			return Breakpoint;
		if (reason == "end-stepping-range")
			return SingleStep;
		if (reason == "exited-normally" || reason == "exited")
			return ProcessExited;
		if (reason == "signal-received")
			return SignalInt;
	}
	return UnknownReason;
}

bool GdbMiAdapter::RunMonitorCommand(const std::string& command) const
{
    if (!m_mi) return false;
    // Monitor commands don't use MI syntax, they use the console interpreter
    auto result = m_mi->SendCommand("-interpreter-exec console \"monitor " + command + "\"");
    // The result is usually printed to the console stream ('~' records), which is hard to
    // capture synchronously. For now, we assume it worked if we get a 'done' back.
    // A better implementation would buffer console output between commands.
    return (result.command == "done");
}

bool GdbMiAdapter::Connect(const std::string& server, uint32_t port) {
    auto settings = GetAdapterSettings();
    BNSettingsScope scope = SettingsResourceScope;
    auto data = GetData();
    auto gdbPath = settings->Get<std::string>("gdb.path", data, &scope);
    scope = SettingsResourceScope;
    auto symbolFile = settings->Get<std::string>("gdb.symbolFile", data, &scope);
    scope = SettingsResourceScope;
    auto inputFile = settings->Get<std::string>("common.inputFile", data, &scope);
	scope = SettingsResourceScope;
	auto ipAddress = settings->Get<std::string>("connect.ipAddress", data, &scope);
	scope = SettingsResourceScope;
	auto serverPort = static_cast<uint32_t>(settings->Get<uint64_t>("connect.port", data, &scope));
	if (ipAddress.empty() || serverPort == 0)
	{
		LogError("Missing connection settings for restart.");
		return false;
	}

    m_connected = false;

    if (gdbPath.empty()) return false;

    if (inputFile.empty()) inputFile = symbolFile;

    m_mi = std::make_unique<GdbMiConnector>(gdbPath, inputFile);
    
    // Set up async callback BEFORE starting GDB to avoid race conditions
    m_mi->SetAsyncCallback([this](const MiRecord& record){ this->AsyncRecordHandler(record); });

    if (!m_mi->Start()) return false;

    m_mi->SendCommand("-gdb-set mi-async on");
    m_mi->SendCommand("-gdb-set pagination off");
    m_mi->SendCommand("-gdb-set confirm off");
    m_mi->SendCommand("-enable-frame-filters");
    m_mi->SendCommand("-interpreter-exec console \"add-symbol-file "+symbolFile+"\"");

    m_mi->SendCommand("-file-exec-file " + inputFile);
	// TODO: we should offer an option on whether or not to connect in extended mode
    std::string connectCmd = "-target-select remote " + ipAddress + ":" + std::to_string(serverPort);
	
    auto result = m_mi->SendCommand(connectCmd, 1000);
    m_connected = (result.command == "connected");
	if (!m_connected)
	{
        LogError("Failed to connect to target");
		m_mi->Stop();
		m_mi.reset();
		return false;
	}
    
	// Get architecture and register setup
	LogInfo("Detecting target architecture...");

	// Try multiple methods to detect architecture since $arch may return "void" on embedded targets
	std::string detectedArch;
	auto regListResult = m_mi->SendCommand("-data-list-register-names"); // we might need it for arch detection and then again later
	// Method 1: Try $arch (may return "void" on some targets)
	auto archResult = m_mi->SendCommand("-data-evaluate-expression $arch");

	if (archResult.command == "done")
	{
		auto value = MiValue::Parse(archResult.payload);
		std::string archStr = value["value"].GetString();

		// Remove quotes if present
		if (archStr.length() >= 2 && archStr.front() == '"' && archStr.back() == '"')
		{
			archStr = archStr.substr(1, archStr.length() - 2);
		}

		LogInfo("Raw architecture string from $arch: %s", archStr.c_str());

		if (archStr != "void" && !archStr.empty())
		{
			detectedArch = archStr;
		}
	}

	// Method 2: If $arch failed or returned "void", try to detect from register names
	if (detectedArch.empty())
	{
		LogInfo("$arch returned void or empty, trying register-based detection...");

		// Get register names first to help with architecture detection
		if (regListResult.command == "done")
		{
			LogDebug("Register names for architecture detection: %s", regListResult.payload.c_str());

			// Check for ARM Cortex-M registers (common in embedded)
			if (regListResult.payload.find("r0") != std::string::npos && regListResult.payload.find("sp") != std::string::npos && regListResult.payload.find("lr") != std::string::npos && regListResult.payload.find("pc") != std::string::npos)
			{
				// Check for specific ARM Cortex-M registers
				if (regListResult.payload.find("xpsr") != std::string::npos || regListResult.payload.find("primask") != std::string::npos || regListResult.payload.find("faultmask") != std::string::npos)
				{
					detectedArch = "armv7-m"; // Cortex-M
					LogInfo("Detected ARM Cortex-M architecture from registers");
				}
				else
				{
					detectedArch = "arm"; // Generic ARM
					LogInfo("Detected generic ARM architecture from registers");
				}
			}
			// Check for x86 registers
			else if (regListResult.payload.find("eax") != std::string::npos || regListResult.payload.find("rax") != std::string::npos)
			{
				detectedArch = "x86";
				LogInfo("Detected x86 architecture from registers");
			}
		}
	}

	// Method 3: If still not detected, use fallback based on common patterns
	if (detectedArch.empty())
	{
		LogInfo("Using fallback architecture detection...");

		// Check the initial stop event for architecture hints
		// From logs: arch="armv3m" appears in the stop event
		if (m_lastStopReason != UnknownReason)
		{
			// We know we're dealing with an ARM target from the logs
			detectedArch = "armv7-m"; // Default to Cortex-M for embedded
			LogInfo("Using fallback ARM Cortex-M architecture");
		}
		else
		{
			detectedArch = "arm"; // Final fallback
			LogInfo("Using generic ARM architecture as final fallback");
		}
	}

	// Set the final architecture
	m_remoteArch = detectedArch;
	LogInfo("Final detected remote architecture: %s", m_remoteArch.c_str());

	// Get register names
	if (regListResult.command == "done")
	{
		LogDebug("Register names response: %s", regListResult.payload.c_str());
		auto value = MiValue::Parse(regListResult.payload);

		// Check for register-names in different possible locations
		if (value.Exists("register-names"))
		{
			m_registerNames.clear();
			for (const auto& regVal : value["register-names"].GetList())
			{
				m_registerNames.push_back(regVal.GetString());
			}
			LogInfo("Found %zu registers in register-names list", m_registerNames.size());
		}
		else
		{
			LogError("No register-names in response. Payload: %s", regListResult.payload.c_str());
		}
	}
	else
	{
		LogError("Failed to get register names: %s", regListResult.fullLine.c_str());
		// Fallback for common embedded architectures
		if (m_remoteArch.find("arm") != std::string::npos)
		{
			LogInfo("Using ARM register fallback");
			m_registerNames = { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "xpsr" };
		}
	}

	// AFTER we are connected and stopped, populate the cache for the first time.
	LogInfo("Populating initial state cache...");
	ScheduleStateRefresh();

	LogInfo("Applying breakpoints...");
	ApplyBreakpoints();

    return true;
}

// --- Empty implementations for unsupported actions ---
bool GdbMiAdapter::Execute(const std::string&, const LaunchConfigurations&) { LogWarn("GdbMiAdapter::Execute not implemented"); return false; }
bool GdbMiAdapter::ExecuteWithArgs(const std::string&, const std::string&, const std::string&, const LaunchConfigurations&)
{
	InvalidateCache();
	auto settings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto server = settings->Get<std::string>("connect.ipAddress", data, &scope);
	scope = SettingsResourceScope;
	auto port = static_cast<uint32_t>(settings->Get<uint64_t>("connect.port", data, &scope));
	if (server.empty() || port == 0)
	{
		LogError("Missing connection settings for restart.");
		return false;
	}
	return Connect(server, port);
}
bool GdbMiAdapter::Attach(uint32_t) {
	InvalidateCache();
	auto settings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	auto data = GetData();
	auto server = settings->Get<std::string>("connect.ipAddress", data, &scope);
	scope = SettingsResourceScope;
	auto port = static_cast<uint32_t>(settings->Get<uint64_t>("connect.port", data, &scope));
	if (server.empty() || port == 0)
	{
		LogError("Missing connection settings for restart.");
		return false;
	}

	return Connect(server, port);
}
std::vector<DebugProcess> GdbMiAdapter::GetProcessList() { LogWarn("GdbMiAdapter::GetProcessList not implemented"); return {}; }
bool GdbMiAdapter::SuspendThread(uint32_t) { LogWarn("GdbMiAdapter::SuspendThread not implemented"); return false; }
bool GdbMiAdapter::ResumeThread(uint32_t) { LogWarn("GdbMiAdapter::ResumeThread not implemented"); return false; }

void GdbMiAdapter::Stop()
{
	try
	{
		if (m_mi && m_mi->IsRunning())
		{
			LogDebug("GDB MI connector stopping...");
			m_mi->SetAsyncCallback(nullptr);
			m_mi->Stop();
			m_mi.reset();
			LogDebug("GDB MI connector stopped.");
		}
	}
	catch (const std::exception& e)
	{
		LogError("Exception during GDB MI adapter stop: %s", e.what());
	}
	catch (...)
	{
		LogError("Unknown exception during GDB MI adapter stop");
	}

	// Clear all cached data
	InvalidateCache();

	// Reset target state
    m_targetRunningAtomic.store(false, std::memory_order_release);
    m_connected = false;
}

bool GdbMiAdapter::Quit()
{
	if (m_mi && m_connected) InvokeBackendCommand("kill");
	m_connected = false;
	m_targetRunningAtomic.store(false);

	DebuggerEvent dbgevt;
	dbgevt.type = TargetExitedEventType;
	PostDebuggerEvent(dbgevt);

	Stop();
	return true;
}

bool GdbMiAdapter::Detach() {
	if (m_mi && m_connected) m_mi->SendCommand("-target-detach");
	m_connected = false;
	m_targetRunningAtomic.store(false);

	DebuggerEvent dbgevt;
	dbgevt.type = DetachedEventType;
	PostDebuggerEvent(dbgevt);

	Stop();
    return true;
}

std::vector<DebugThread> GdbMiAdapter::GetThreadList() {
    std::unique_lock lock(m_cacheMutex);
    return m_cachedThreads;
}

std::unordered_map<std::string, DebugRegister> GdbMiAdapter::ReadAllRegisters() {
    std::unique_lock lock(m_cacheMutex);
    return m_cachedRegisters;
}

DebugRegister GdbMiAdapter::ReadRegister(const std::string& reg) {
    std::unique_lock lock(m_cacheMutex);
    if (m_cachedRegisters.contains(reg)) return m_cachedRegisters[reg];

    LogWarn("GdbMiAdapter::ReadRegister failed to retrieve '%s'", reg.c_str());
    return {};
}

std::vector<DebugFrame> GdbMiAdapter::GetFramesOfThread(uint32_t tid) {
    std::unique_lock lock(m_cacheMutex);
    if (m_cachedFrames.contains(tid))
    {
        return m_cachedFrames[tid];
    }

    // If not cached, return an empty list for now and trigger a background refresh.
    // The UI will be updated once the data is available via an event.
    if (!m_targetRunningAtomic)
    {
        ScheduleStateRefresh();
    }
    
    return {};
}

uint32_t GdbMiAdapter::GetActiveThreadId() const { return m_currentTid; }

DebugThread GdbMiAdapter::GetActiveThread() const {
	auto self = const_cast<GdbMiAdapter*>(this);
    uint64_t pc = self->GetInstructionOffset();
    return DebugThread(m_currentTid, pc);
}

bool GdbMiAdapter::SetActiveThreadId(uint32_t tid) {
    if (!m_mi) return false;
    auto result = m_mi->SendCommand("-thread-select " + std::to_string(tid));
    if (result.command == "done") {
        m_currentTid = tid;
        return true;
    }
    return false;
}

bool GdbMiAdapter::SetActiveThread(const DebugThread& thread) { return SetActiveThreadId(thread.m_tid); }

DebugBreakpoint GdbMiAdapter::AddBreakpoint(std::uintptr_t address, unsigned long breakpoint_type) {
    if (!m_mi) { return {}; }

    LogDebug("-break-insert -h *0x%lx", address);
    auto result = m_mi->SendCommand(fmt::format("-break-insert -h *0x{:x}", address));
    if (result.command == "done") {
        DebuggerEvent evt;
		evt.type = BackendMessageEventType;
		evt.data.messageData.message = result.payload;
		PostDebuggerEvent(evt);

        return DebugBreakpoint{address, 0, true};
    }

    LogWarn("Failed to set BP at 0x%lux", address);
    return {};
}

DebugBreakpoint GdbMiAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type) {
	if (!m_mi)
	{
		if (std::ranges::find(m_pendingBreakpoints, address) == m_pendingBreakpoints.end())
			m_pendingBreakpoints.push_back(address);
	}
    else
    {
        uint64_t addr = address.offset + m_originalImageBase;
        
        AddBreakpoint(addr, breakpoint_type);
    }

	return {};
}

bool GdbMiAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint) {
    if (!m_mi) return false;

	auto breakpoints = GetBreakpointList();
	uint64_t id_to_remove = 0;
	int removed = 0;
	for (const auto& bp: breakpoints)
	{
		if (bp.m_address == breakpoint.m_address)
		{
			id_to_remove = bp.m_id;
			auto result = m_mi->SendCommand(fmt::format("-break-delete {}", id_to_remove));

			if (result.command == "done") {
				DebuggerEvent evt;
				evt.type = BackendMessageEventType;
				evt.data.messageData.message = result.payload;
				PostDebuggerEvent(evt);

				removed++;
			}
		}
	}

	if (removed == 0)
	{
		LogWarn("Failed to remove breakpoint at 0x%lX", breakpoint.m_address);
		return false;
	}

	return false;
}

std::vector<DebugBreakpoint> GdbMiAdapter::GetBreakpointList() const {
	if (!m_mi)
		return {};

	auto result = m_mi->SendCommand("-break-list");
	if (result.command != "done")
	{
		LogWarn("Failed to get breakpoint list");
		return {};
	}

	std::vector<DebugBreakpoint> breakpoints;
	auto table = MiValue::Parse(result.payload);
	if (table.Exists("BreakpointTable"))
	{
		auto bp_table = table["BreakpointTable"];
		if (bp_table.Exists("body"))
		{
			for (const auto& item: bp_table["body"].GetList())
			{
				auto bp = item["bkpt"];
				uint64_t addr = std::stoull(bp["addr"].GetString(), 0, 16);
				uint64_t id = std::stoull(bp["number"].GetString(), 0, 10);
				LogDebug("Parsed breakpoint %llu at 0x%llx", id, addr);
				breakpoints.emplace_back(addr, id, true);
			}
		}
	}
	return breakpoints;
}

bool GdbMiAdapter::WriteRegister(const std::string& reg, intx::uint512 value) {
    if (!m_mi) return false;
    std::string cmd = "-gdb-set $" + reg + "=" + to_string(value);
    auto result = m_mi->SendCommand(cmd);
    return result.command == "done";
}

DataBuffer GdbMiAdapter::ReadMemory(std::uintptr_t address, size_t size) {
    if (!m_mi) return {};
	LogDebug("GdbMiAdapter::ReadMemory 0x%lX-0x%lX", address, address+size);
	// TODO: we can use 'info mem' to get list of memory regions available for reading.
	DataBuffer zero(size);

    std::string cmd = fmt::format("-data-read-memory-bytes 0x{:x} {}", address, size);
    auto result = m_mi->SendCommand(cmd);
    if (result.command != "done")
    {
    	LogWarn("Failed to read memory at 0x%lX", address);

	    return zero;
    }

    auto value = MiValue::Parse(result.payload);
    std::string hex_contents = value["memory"][0]["contents"].GetString();
    DataBuffer buffer(hex_contents.length() / 2);
    for(size_t i = 0; i < buffer.GetLength(); i++) {
        buffer[i] = std::stoul(hex_contents.substr(i*2, 2), nullptr, 16);
    }
    return buffer;
}

bool GdbMiAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer) {
    if (!m_mi) return false;
    std::string hex;
    for(size_t i = 0; i < buffer.GetLength(); i++) {
        hex += fmt::format("{:02x}", buffer[i]);
    }
    std::string cmd = fmt::format("-data-write-memory-bytes 0x{:x} \"{}\"", address, hex);
    auto result = m_mi->SendCommand(cmd);
    return result.command == "done";
}

std::vector<DebugModule> GdbMiAdapter::GetModuleList()
{
	if (!m_mi)
		return {};

	// Use -interpreter-exec to run the console command "info proc mappings"
	auto result = m_mi->SendCommand("-interpreter-exec console \"info proc mappings\"");
	if (result.command != "done")
	{
		LogWarn("Failed to get process mappings: %s", result.fullLine.c_str());
		return {};
	}

	std::vector<DebugModule> modules;
	std::map<std::string, int> moduleNameCount; // Track module name occurrences for duplicates
	std::map<std::string, std::vector<std::pair<uint64_t, uint64_t>>> moduleRanges; // path -> list of (start, end)
	std::vector<std::string> moduleOrder; // Track the order in which modules are first seen

	// Parse the console output from async records
	// The output will be in console stream records ('~')
	// We need to accumulate the console output and parse it
	// For now, we'll try to parse from the result payload if available
	
	// Since the output is sent as console stream, we need a different approach.
	// Let's send the command and wait for console output.
	// Actually, the console output should be in the async records.
	// For simplicity, let's use InvokeBackendCommand which also uses -interpreter-exec
	std::string output = InvokeBackendCommand("info proc mappings");
	
	if (output.empty() || output == "error, transport not ready")
	{
		LogWarn("Failed to get process mappings output");
		return {};
	}

	// Parse the output line by line
	// Expected format (from the issue):
	// process 25443
	// Mapped address spaces:
	//
	//           Start Addr           End Addr       Size     Offset  Perms  objfile
	//       0x555555554000     0x555555555000     0x1000        0x0  r--p   /path/to/file
	
	std::istringstream stream(output);
	std::string line;
	bool headerFound = false;
	
	while (std::getline(stream, line))
	{
		// Skip until we find the header line
		if (!headerFound)
		{
			if (line.find("Start Addr") != std::string::npos && 
			    line.find("End Addr") != std::string::npos)
			{
				headerFound = true;
			}
			continue;
		}
		
		// Parse data lines
		// Format: Start_Addr End_Addr Size Offset Perms objfile
		std::istringstream lineStream(line);
		std::string startStr, endStr, sizeStr, offsetStr, perms, objfile;
		
		lineStream >> startStr >> endStr >> sizeStr >> offsetStr >> perms;
		
		// Rest of the line is the objfile (path)
		std::getline(lineStream, objfile);
		
		// Trim leading and trailing whitespace from objfile
		size_t firstNonSpace = objfile.find_first_not_of(" \t");
		if (firstNonSpace == std::string::npos)
		{
			// Line is all whitespace, skip it
			continue;
		}
		objfile = objfile.substr(firstNonSpace);
		
		// Trim trailing whitespace
		size_t lastNonSpace = objfile.find_last_not_of(" \t");
		if (lastNonSpace != std::string::npos)
		{
			objfile = objfile.substr(0, lastNonSpace + 1);
		}
		
		// Skip lines without valid addresses or without objfile
		if (startStr.empty() || endStr.empty() || objfile.empty())
			continue;
		
		// Skip special mappings like [stack], [heap], [vvar], [vdso], etc.
		if (objfile[0] == '[')
			continue;
		
		try
		{
			uint64_t start = std::stoull(startStr, nullptr, 16);
			uint64_t end = std::stoull(endStr, nullptr, 16);
			
			// Track the order of first occurrence
			if (moduleRanges.find(objfile) == moduleRanges.end())
			{
				moduleOrder.push_back(objfile);
			}
			
			// Accumulate ranges for each object file
			moduleRanges[objfile].emplace_back(start, end);
		}
		catch (const std::exception& e)
		{
			LogDebug("Failed to parse address range: %s", e.what());
			continue;
		}
	}
	
	// Now create DebugModule entries in the order they were first encountered
	// For each unique object file, we need to determine its overall address range
	for (const auto& path : moduleOrder)
	{
		const auto& ranges = moduleRanges[path];
		if (ranges.empty())
			continue;
		
		// Find the minimum start and maximum end
		uint64_t minStart = ranges[0].first;
		uint64_t maxEnd = ranges[0].second;
		
		for (const auto& [start, end] : ranges)
		{
			minStart = std::min(minStart, start);
			maxEnd = std::max(maxEnd, end);
		}
		
		// Extract the base name from the path for m_short_name
		std::string shortName = path;
		size_t lastSlash = path.find_last_of("/\\");
		if (lastSlash != std::string::npos)
		{
			shortName = path.substr(lastSlash + 1);
		}
		
		// Handle duplicate names by appending -1, -2, etc.
		// The first occurrence gets the original name, subsequent ones get -1, -2, etc.
		std::string finalName = path;
		if (moduleNameCount.find(path) != moduleNameCount.end())
		{
			// This is a duplicate (shouldn't happen with current logic, but keep for safety)
			int count = ++moduleNameCount[path];
			finalName = path + "-" + std::to_string(count);
		}
		else
		{
			// First occurrence
			moduleNameCount[path] = 0;
		}
		
		DebugModule module;
		module.m_name = finalName;
		module.m_short_name = shortName;
		module.m_address = minStart;
		module.m_size = maxEnd - minStart;
		module.m_loaded = true;
		
		modules.push_back(module);
	}
	
	return modules;
}

bool GdbMiAdapter::Go()
{
    if (!m_mi || m_targetRunningAtomic) return false;
    
    return (m_mi->SendCommand("-exec-continue").command == "running");
}

bool GdbMiAdapter::BreakInto() {
    if (!m_mi || !m_targetRunningAtomic) return false;

	return (m_mi->SendCommand("-exec-interrupt").command == "done");
}

bool GdbMiAdapter::StepInto() {
    if (!m_mi || m_targetRunningAtomic) return false;

	return (m_mi->SendCommand("-exec-step-instruction").command == "running");
}

bool GdbMiAdapter::StepOver() {
    if (!m_mi || m_targetRunningAtomic) return false;

	return (m_mi->SendCommand("-exec-next-instruction").command == "running");
}

bool GdbMiAdapter::StepReturn() {
	if (!m_mi || m_targetRunningAtomic) return false;

	return (m_mi->SendCommand("-exec-finish").command == "running");
}

uint64_t GdbMiAdapter::GetInstructionOffset() {
	LogDebug("GdbMiAdapter::GetInstructionOffset = 0x%llX", m_instructionOffset);
	return m_instructionOffset;
}

uint64_t GdbMiAdapter::GetStackPointer() {
	LogDebug("GdbMiAdapter::GetStackPointer = 0x%llX", m_stackPointer);
	return m_stackPointer;
}

std::string GdbMiAdapter::InvokeBackendCommand(const std::string& command) {
    if (!m_mi) return "error, transport not ready";
    auto result = m_mi->SendCommand("-interpreter-exec console \"" + command + "\"");
    return (result.command == "done") ? result.payload : result.command;
}

uint64_t GdbMiAdapter::ExitCode() { return 0; }

DebugStopReason GdbMiAdapter::StopReason() { return m_lastStopReason; }

std::string GdbMiAdapter::GetTargetArchitecture() { return m_remoteArch; }

bool GdbMiAdapter::SupportFeature(DebugAdapterCapacity feature) {
    switch (feature) {
        case DebugAdapterSupportStepOver: return true;
        case DebugAdapterSupportModules: return true;
        case DebugAdapterSupportThreads: return true;
        case DebugAdapterSupportTTD: return false;
        default: return false;
    }
}

// --- Adapter Type Registration ---
GdbMiAdapterType::GdbMiAdapterType() : DebugAdapterType("GDB MI") {}

DebugAdapter* GdbMiAdapterType::Create(BinaryView* data)
{
    return new GdbMiAdapter(data);
}

Ref<Settings> GdbMiAdapterType::GetAdapterSettings()
{
    static Ref<Settings> settings = RegisterAdapterSettings();
    return settings;
}

Ref<Settings> GdbMiAdapter::GetAdapterSettings()
{
    return GdbMiAdapterType::GetAdapterSettings();
}

void GdbMiAdapter::GenerateDefaultAdapterSettings(BinaryView* data)
{
	auto adapterSettings = GetAdapterSettings();
	BNSettingsScope scope = SettingsResourceScope;
	adapterSettings->Get<std::string>("common.inputFile", data, &scope);
	if (scope != SettingsResourceScope)
		adapterSettings->Set("common.inputFile", data->GetFile()->GetOriginalFilename(), data, SettingsResourceScope);

}

Ref<Settings> GdbMiAdapterType::RegisterAdapterSettings()
{
    Ref<Settings> settings = Settings::Instance("GdbMiAdapterSettings");
    settings->SetResourceId("gdb_mi_adapter_settings");
    settings->RegisterSetting("gdb.path", R"({
        "title": "Full GDB Executable Path",
        "type": "string", "default": "/usr/bin/gdb-multiarch",
        "description": "Path to the GDB executable e.g., gdb-multiarch, arm-none-eabi-gdb.",
        "uiSelectionAction": "file"
    })");
	settings->RegisterSetting("common.inputFile",
		R"({
			"title" : "Input File",
			"type" : "string",
			"default" : "",
			"description" : "Input file to use to find the base address of the binary view",
			"readOnly" : false,
			"uiSelectionAction" : "file"
			})");

	settings->RegisterSetting("connect.ipAddress",
			R"({
			"title" : "IP Address",
			"type" : "string",
			"default" : "127.0.0.1",
			"description" : "IP address of the debug stub to connect to",
			"readOnly" : false
			})");
	settings->RegisterSetting("connect.port",
			R"({
			"title" : "Port",
			"type" : "number",
			"default" : 3333,
			"minValue" : 0,
			"maxValue" : 65535,
			"description" : "Port of the debug stub to connect to",
			"readOnly" : false
			})");
    settings->RegisterSetting("gdb.symbolFile", R"({
        "title": "Symbol File, optional",
        "type": "string", "default": "",
        "description": "Path to the ELF file with DWARF debug info for the target.",
        "uiSelectionAction": "file"
    })");

    return settings;
}

void GdbMiAdapter::ApplyBreakpoints()
{
	for (const auto& bp : m_pendingBreakpoints)
	{
		AddBreakpoint(bp, 0);
	}
	m_pendingBreakpoints.clear();
}


void BinaryNinjaDebugger::InitGdbMiAdapterType()
{
    static GdbMiAdapterType miType;
    DebugAdapterType::Register(&miType);
}
