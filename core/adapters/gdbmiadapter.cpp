#include "gdbmiadapter.h"
#include <sstream>
#include <cinttypes>
#include "../debuggercontroller.h"
#include "../../cli/log.h"

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
    m_moduleCache.reset();
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

    for (size_t i = 0; i < gdbmiregisters["register-values"].size(); i++)
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
	for (size_t i = 0; i < gdbmi_frames["stack"].size(); ++i)
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
        
        // Check if the process has exited
        if (m_lastStopReason == ProcessExited)
        {
            // Parse exit code if available
            if (value.Exists("exit-code"))
            {
                try {
                    m_exitCode = std::stoull(value["exit-code"].GetString(), nullptr, 0);
                } catch(...) {
                    LogWarn("Failed to parse exit code");
                    m_exitCode = 0;
                }
            }
            else
            {
                m_exitCode = 0;
            }

            // Post target exited event
            DebuggerEvent dbgevt;
            dbgevt.type = TargetExitedEventType;
            dbgevt.data.exitData.exitCode = m_exitCode;
            PostDebuggerEvent(dbgevt);

            m_eventCV.notify_all();
        }
        else
        {
            // Normal stop - kick a background refresh so we don't block the reader
            ScheduleStateRefresh();
            m_eventCV.notify_all();
        }
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

        // Buffer console output if capture is enabled (for console commands)
        // When buffering, we DON'T post events - the caller will get the buffered output
        bool shouldPostEvent = true;
        {
            std::unique_lock lock(m_consoleBufferMutex);
            if (m_captureConsoleOutput && record.type == '~')
            {
                m_consoleOutputBuffer += message;
                shouldPostEvent = false; // Don't post events for buffered output
            }
        }

        // Only post event if we're not buffering this output
        if (shouldPostEvent)
        {
            DebuggerEvent event;
            event.type = BackendMessageEventType;
            event.data.messageData.message = message;
            PostDebuggerEvent(event);
        }
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
            // Apply any pending breakpoints that were added while target was running
            // or couldn't be resolved earlier (modules not loaded yet)
            ApplyBreakpoints();
            ApplyPendingHardwareBreakpoints();
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

	// Method 1: Try "show architecture" via console command (most reliable)
	std::string archOutput = InvokeBackendCommand("show architecture");
	if (!archOutput.empty() && archOutput != "error, transport not ready")
	{
		LogInfo("Architecture output from 'show architecture': %s", archOutput.c_str());

		// Parse output like: "The target architecture is set automatically (currently i386:x86-64)"
		// or "The target architecture is set to \"i386:x86-64\"."
		if (archOutput.find("x86-64") != std::string::npos || archOutput.find("x86_64") != std::string::npos)
		{
			detectedArch = "x86_64";
			LogInfo("Detected x86_64 from 'show architecture'");
		}
		else if (archOutput.find("i386") != std::string::npos && archOutput.find("x86-64") == std::string::npos)
		{
			detectedArch = "x86";
			LogInfo("Detected x86 from 'show architecture'");
		}
		else if (archOutput.find("aarch64") != std::string::npos || archOutput.find("arm64") != std::string::npos)
		{
			detectedArch = "aarch64";
			LogInfo("Detected aarch64 from 'show architecture'");
		}
		else if (archOutput.find("armv7") != std::string::npos)
		{
			detectedArch = "armv7-m";
			LogInfo("Detected armv7-m from 'show architecture'");
		}
		else if (archOutput.find("arm") != std::string::npos)
		{
			detectedArch = "arm";
			LogInfo("Detected ARM from 'show architecture'");
		}
	}

	// Method 2: Try $arch (may return "void" on some targets)
	if (detectedArch.empty())
	{
		LogInfo("Method 1 failed, trying $arch...");
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
				LogInfo("Detected architecture from $arch: %s", archStr.c_str());
			}
		}
	}

	// Fetch register list - needed for Method 3 if architecture still not detected,
	// and also needed later for populating m_registerNames
	auto regListResult = m_mi->SendCommand("-data-list-register-names");

	// Method 3: If previous methods failed, try to detect from register names
	if (detectedArch.empty())
	{
		LogInfo("Methods 1 & 2 failed, trying register-based detection...");

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
			// Check for x86/x86_64 registers
			else if (regListResult.payload.find("rax") != std::string::npos)
			{
				detectedArch = "x86_64";
				LogInfo("Detected x86_64 architecture from registers");
			}
			else if (regListResult.payload.find("eax") != std::string::npos)
			{
				detectedArch = "x86";
				LogInfo("Detected x86 (32-bit) architecture from registers");
			}
		}
	}

	// Set the final architecture
	m_remoteArch = detectedArch;
	LogInfo("Final detected remote architecture: %s", m_remoteArch.c_str());

	// Get register names (regListResult already fetched above)
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
	ApplyPendingHardwareBreakpoints();

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

    LogDebug("-break-insert -h *0x%" PRIx64, (uint64_t)address);
    auto result = m_mi->SendCommand(fmt::format("-break-insert -h *0x{:x}", address));
    if (result.command == "done") {
        DebuggerEvent evt;
		evt.type = BackendMessageEventType;
		evt.data.messageData.message = result.payload;
		PostDebuggerEvent(evt);

        return DebugBreakpoint{address, 0, true};
    }

    LogWarn("Failed to set BP at 0x%" PRIx64, (uint64_t)address);
    return {};
}

DebugBreakpoint GdbMiAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type) {
	if (!m_mi)
	{
		// Not connected yet - add to pending list
		if (std::ranges::find(m_pendingBreakpoints, address) == m_pendingBreakpoints.end())
			m_pendingBreakpoints.push_back(address);
		return {};
	}

	// Try to resolve the module base address
	uint64_t base{};
	if (GetModuleBase(address.module, base))
	{
		// Module is loaded - resolve to absolute address
		uint64_t addr = base + address.offset;
		return AddBreakpoint(addr, breakpoint_type);
	}
	else
	{
		// Module not loaded yet - add to pending list for deferred application
		if (std::ranges::find(m_pendingBreakpoints, address) == m_pendingBreakpoints.end())
			m_pendingBreakpoints.push_back(address);
		return {};
	}
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
		LogWarn("Failed to remove breakpoint at 0x%" PRIX64, (uint64_t)breakpoint.m_address);
		return false;
	}

	return true;
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
				LogDebug("Parsed breakpoint %" PRIu64 " at 0x%" PRIx64, id, addr);
				breakpoints.emplace_back(addr, id, true);
			}
		}
	}
	return breakpoints;
}

bool GdbMiAdapter::WriteRegister(const std::string& reg, intx::uint512 value) {
    if (!m_mi) return false;

    // Acquire GDB command mutex to serialize access to GDB
    std::unique_lock cmdLock(m_gdbCommandMutex);

    std::string cmd = "-gdb-set $" + reg + "=" + to_string(value);
    auto result = m_mi->SendCommand(cmd);
    return result.command == "done";
}

DataBuffer GdbMiAdapter::ReadMemory(std::uintptr_t address, size_t size) {
    if (!m_mi) return {};
	LogDebug("GdbMiAdapter::ReadMemory 0x%" PRIX64 "-0x%" PRIX64, (uint64_t)address, (uint64_t)(address+size));
	// TODO: we can use 'info mem' to get list of memory regions available for reading.
	DataBuffer zero(size);

    // Acquire GDB command mutex to serialize access to GDB
    std::unique_lock cmdLock(m_gdbCommandMutex);

    std::string cmd = fmt::format("-data-read-memory-bytes 0x{:x} {}", address, size);
    auto result = m_mi->SendCommand(cmd);
    if (result.command != "done")
    {
    	LogDebug("Failed to read memory at 0x%" PRIX64, (uint64_t)address);

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

    // Acquire GDB command mutex to serialize access to GDB
    std::unique_lock cmdLock(m_gdbCommandMutex);

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
	// Return cached modules if available
	{
		std::unique_lock lock(m_cacheMutex);
		if (m_moduleCache.has_value())
			return m_moduleCache.value();
	}

	if (!m_mi || m_targetRunningAtomic)
		return {};

	// Acquire GDB command mutex to serialize access to GDB
	std::unique_lock cmdLock(m_gdbCommandMutex);

	// Execute "info proc mappings" to get memory mappings
	std::string output = InvokeBackendCommand("info proc mappings");

	if (output.empty() || output == "error, transport not ready")
	{
		LogWarn("Failed to get process mappings");
		return {};
	}

	// Parse the output to extract module information
	// Expected format:
	//   process PID
	//   Mapped address spaces:
	//
	//       Start Addr   End Addr       Size     Offset objfile
	//     0x555555554000 0x555555556000     0x2000        0x0 /usr/bin/executable
	//     0x7ffff7dd5000 0x7ffff7df7000    0x22000        0x0 /lib/x86_64-linux-gnu/libc.so.6

	std::map<std::string, BNAddressRange> moduleRanges;

	// Split output into lines
	std::istringstream stream(output);
	std::string line;

	while (std::getline(stream, line))
	{
		// Skip empty lines and header lines
		if (line.empty() || line.find("Start Addr") != std::string::npos ||
		    line.find("process") != std::string::npos ||
		    line.find("Mapped address spaces") != std::string::npos)
			continue;

		// Split line into columns by whitespace
		std::vector<std::string> columns;
		std::istringstream lineStream(line);
		std::string column;
		while (lineStream >> column)
			columns.push_back(column);

		// Need at least 3 columns: start_addr, end_addr, ..., objfile
		if (columns.size() < 3)
			continue;

		// First column is start address, second is end address, last is objfile name
		std::string startString = columns[0];
		std::string endString = columns[1];
		std::string path = columns.back();

		// Parse addresses (should start with 0x)
		if (startString.substr(0, 2) != "0x" || endString.substr(0, 2) != "0x")
			continue;

		uint64_t start = std::strtoull(startString.c_str(), nullptr, 16);
		uint64_t end = std::strtoull(endString.c_str(), nullptr, 16);

		// Skip special regions like [stack], [heap], [vdso], [vvar], [vsyscall], etc.
		// Only include actual file paths (starting with '/')
		if (path.empty() || path[0] != '/')
			continue;

		// Merge adjacent or overlapping regions for the same module
		auto iter = moduleRanges.find(path);
		if (iter != moduleRanges.end())
		{
			BNAddressRange currentRange = iter->second;
			BNAddressRange newRange;
			newRange.start = std::min<uint64_t>(currentRange.start, start);
			newRange.end = std::max<uint64_t>(currentRange.end, end);
			iter->second = newRange;
		}
		else
		{
			moduleRanges[path] = {start, end};
		}
	}

	// Convert to DebugModule vector and handle duplicate names
	std::vector<DebugModule> result;
	std::map<std::string, int> nameCount; // Track how many times we've seen each short name

	for (auto& iter: moduleRanges)
	{
		DebugModule module;
		module.m_address = iter.second.start;
		module.m_size = iter.second.end - iter.second.start;
		module.m_name = iter.first;

		// Extract short name (base filename)
		size_t lastSlash = iter.first.find_last_of('/');
		if (lastSlash != std::string::npos && lastSlash + 1 < iter.first.length())
			module.m_short_name = iter.first.substr(lastSlash + 1);
		else
			module.m_short_name = iter.first;

		// Handle duplicate short names by appending -1, -2, etc.
		std::string originalShortName = module.m_short_name;
		if (nameCount.find(originalShortName) != nameCount.end())
		{
			int count = nameCount[originalShortName];
			module.m_short_name += "-" + std::to_string(count);
			nameCount[originalShortName] = count + 1;
		}
		else
		{
			nameCount[originalShortName] = 1;
		}

		module.m_loaded = true;
		result.push_back(module);
	}

	// Cache the result
	{
		std::unique_lock lock(m_cacheMutex);
		m_moduleCache = result;
	}

	LogInfo("Loaded %zu modules from process mappings", result.size());
	return result;
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
	std::string ipRegisterName;
	if ((m_remoteArch == "x86") || (m_remoteArch == "i386"))
		ipRegisterName = "eip";
	else if (m_remoteArch == "x86_64")
		ipRegisterName = "rip";
	else
		ipRegisterName = "pc";

	return (uint64_t)this->ReadRegister(ipRegisterName).m_value;
}

uint64_t GdbMiAdapter::GetStackPointer() {
	std::string spRegisterName;
	if ((m_remoteArch == "x86") || (m_remoteArch == "i386"))
		spRegisterName = "esp";
	else if (m_remoteArch == "x86_64")
		spRegisterName = "rsp";
	else
		spRegisterName = "sp";

	return (uint64_t)this->ReadRegister(spRegisterName).m_value;
}

std::string GdbMiAdapter::InvokeBackendCommand(const std::string& command) {
    if (!m_mi) return "error, transport not ready";

    // Enable console output buffering to capture the command's output
    {
        std::unique_lock lock(m_consoleBufferMutex);
        m_captureConsoleOutput = true;
        m_consoleOutputBuffer.clear();
    }

    // Send the command and wait for the result
    // Use a reasonable timeout (5 seconds) for console commands
    auto result = m_mi->SendCommand("-interpreter-exec console \"" + command + "\"", 5000);

    // Collect the buffered output and disable buffering
    std::string output;
    {
        std::unique_lock lock(m_consoleBufferMutex);
        output = m_consoleOutputBuffer;
        m_captureConsoleOutput = false;
        m_consoleOutputBuffer.clear();
    }

    // Return the captured console output if the command succeeded
    return (result.command == "done") ? output : result.command;
}

uint64_t GdbMiAdapter::ExitCode() { return m_exitCode; }

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

bool GdbMiAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	if (m_targetRunningAtomic || !m_mi)
	{
		// Cache the hardware breakpoint to be applied when target stops or connector becomes available
		PendingHardwareBreakpoint pending(address, type, size);
		if (std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
			== m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.push_back(pending);
		}
		return true;
	}

	std::string command;
	switch (type)
	{
		case HardwareExecuteBreakpoint:
			// Hardware execution breakpoint: -break-insert -h *0xADDRESS
			command = fmt::format("-break-insert -h *0x{:x}", address);
			break;
		case HardwareReadBreakpoint:
			// Hardware read watchpoint: -break-watch -r *((char[SIZE]*)0xADDRESS)
			command = fmt::format("-break-watch -r *((char[{}]*)0x{:x})", size, address);
			break;
		case HardwareWriteBreakpoint:
			// Hardware write watchpoint: -break-watch *((char[SIZE]*)0xADDRESS)
			command = fmt::format("-break-watch *((char[{}]*)0x{:x})", size, address);
			break;
		case HardwareAccessBreakpoint:
			// Hardware access watchpoint: -break-watch -a *((char[SIZE]*)0xADDRESS)
			command = fmt::format("-break-watch -a *((char[{}]*)0x{:x})", size, address);
			break;
		default:
			return false;
	}

	LogDebug("GdbMiAdapter: %s", command.c_str());
	auto result = m_mi->SendCommand(command);
	if (result.command == "done")
	{
		DebuggerEvent evt;
		evt.type = BackendMessageEventType;
		evt.data.messageData.message = result.payload;
		PostDebuggerEvent(evt);
		return true;
	}

	LogWarn("Failed to set hardware breakpoint at 0x%" PRIx64 ": %s", address, result.fullLine.c_str());
	return false;
}

bool GdbMiAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	if (m_targetRunningAtomic || !m_mi)
	{
		// Remove from pending list if target is running or connector not available
		PendingHardwareBreakpoint pending(address, type, size);
		auto it = std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending);
		if (it != m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.erase(it);
			return true;
		}
		return false;
	}

	// Get breakpoint list and find matching hardware breakpoint by address
	auto breakpoints = GetBreakpointList();
	int removed = 0;
	for (const auto& bp : breakpoints)
	{
		if (bp.m_address == address)
		{
			auto result = m_mi->SendCommand(fmt::format("-break-delete {}", bp.m_id));
			if (result.command == "done")
			{
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
		LogWarn("Failed to remove hardware breakpoint at 0x%" PRIx64, address);
		return false;
	}
	return true;
}

bool GdbMiAdapter::AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	uint64_t base{};
	if (GetModuleBase(location.module, base))
	{
		// Module is loaded - resolve to absolute address and delegate
		uint64_t address = base + location.offset;
		return AddHardwareBreakpoint(address, type, size);
	}
	else
	{
		// Module not loaded yet - add to pending list with module+offset
		PendingHardwareBreakpoint pending(location, type, size);
		// Also populate the address field for UI display purposes
		pending.address = location.offset + m_originalImageBase;
		if (std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending)
			== m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.push_back(pending);
		}
		return true;
	}
}

bool GdbMiAdapter::RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	uint64_t base{};
	if (GetModuleBase(location.module, base))
	{
		// Module is loaded - resolve to absolute address and delegate
		uint64_t address = base + location.offset;
		return RemoveHardwareBreakpoint(address, type, size);
	}
	else
	{
		// Module not loaded yet - remove from pending list using module+offset
		PendingHardwareBreakpoint pending(location, type, size);
		auto it = std::find(m_pendingHardwareBreakpoints.begin(), m_pendingHardwareBreakpoints.end(), pending);
		if (it != m_pendingHardwareBreakpoints.end())
		{
			m_pendingHardwareBreakpoints.erase(it);
			return true;
		}
		return false;
	}
}

bool GdbMiAdapter::GetModuleBase(const std::string& moduleName, uint64_t& base)
{
	if (moduleName.empty())
	{
		base = 0;
		return true;
	}

	auto modules = GetModuleList();
	for (const auto& module : modules)
	{
		if (module.IsSameBaseModule(moduleName))
		{
			base = module.m_address;
			return true;
		}
	}

	base = 0;
	return false;
}

void GdbMiAdapter::ApplyPendingHardwareBreakpoints()
{
	// Apply pending hardware breakpoints that were added before the target stopped
	std::vector<PendingHardwareBreakpoint> pendingCopy = m_pendingHardwareBreakpoints;
	m_pendingHardwareBreakpoints.clear();

	for (const auto& pending : pendingCopy)
	{
		if (pending.isRelative)
		{
			// Module+offset based hardware breakpoint
			AddHardwareBreakpoint(pending.location, pending.type, pending.size);
		}
		else
		{
			// Absolute address hardware breakpoint
			AddHardwareBreakpoint(pending.address, pending.type, pending.size);
		}
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
	// Make a copy and clear the original list - AddBreakpoint will re-add
	// any breakpoints that can't be resolved yet
	std::vector<ModuleNameAndOffset> pendingCopy = m_pendingBreakpoints;
	m_pendingBreakpoints.clear();

	for (const auto& bp : pendingCopy)
	{
		AddBreakpoint(bp, 0);
	}
}


void BinaryNinjaDebugger::InitGdbMiAdapterType()
{
    static GdbMiAdapterType miType;
    DebugAdapterType::Register(&miType);
}
