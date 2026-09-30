/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "macosrosettaadapter.h"
#include <spawn.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <rapidjson/document.h>

extern char** environ;
using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;


MacOSRosettaAdapter::MacOSRosettaAdapter(BinaryView* data) : GdbAdapter(data), m_inspector(data)
{
	m_socket = nullptr;
	m_remoteArch = "x86_64";
}

void MacOSRosettaAdapter::Join()
{
	if (m_worker.joinable())
		m_worker.join();
}

void MacOSRosettaAdapter::StopServer()
{
	StopIO();
	if (m_server)
	{
		kill(m_server, SIGTERM);
		unsigned i = 0;
		for (; i < 50 && waitpid(m_server, nullptr, WNOHANG) == 0; ++i)
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		if (i == 50)
		{
			kill(m_server, SIGKILL);
			waitpid(m_server, nullptr, 0);
		}
		m_server = 0;
	}
	if (m_socket)
	{
		m_socket->Close();
		delete m_socket;
		m_socket = nullptr;
	}
	m_rspConnector.store(nullptr);
	if (m_stdin >= 0)
		close(m_stdin);
	m_stdin = -1;
	if (!m_ioDirectory.empty())
	{
		unlink((m_ioDirectory + "/stdin").c_str());
		unlink((m_ioDirectory + "/stdout").c_str());
		rmdir(m_ioDirectory.c_str());
		m_ioDirectory.clear();
	}
}

void MacOSRosettaAdapter::StopIO()
{
	m_ioStop = true;
	if (m_ioWorker.joinable())
		m_ioWorker.join();
	if (m_stdout >= 0)
		close(m_stdout);
	m_stdout = -1;
}

MacOSRosettaAdapter::~MacOSRosettaAdapter()
{
	if (m_rspConnector.load())
	{
		if (m_isTargetRunning)
			BreakInto();
		Join();
		if (m_owned)
			Quit();
		else
			Detach();
	}
	Join();
	StopServer();
}

bool MacOSRosettaAdapter::LoadRegisterInfo()
{
	m_registerInfo.clear();
	auto connector = m_rspConnector.load();
	for (unsigned i = 0; i < 256; ++i)
	{
		auto response = connector->TransmitAndReceive(RspData(fmt::format("qRegisterInfo{:x}", i))).AsString();
		if (response.empty() || response[0] == 'E')
			break;
		std::map<std::string, std::string> fields;
		for (const auto& field : RspConnector::Split(response, ";"))
		{
			auto at = field.find(':');
			if (at != std::string::npos)
				fields[field.substr(0, at)] = field.substr(at + 1);
		}
		if (!fields.count("name") || !fields.count("bitsize") || !fields.count("offset"))
			return false;
		m_registerInfo[fields["name"]] = {
			uint32_t(std::stoul(fields["bitsize"])), i, uint32_t(std::stoul(fields["offset"]) * 8)};
	}
	return m_registerInfo.count("rip") && m_registerInfo.count("rsp");
}

bool MacOSRosettaAdapter::Start(const std::vector<std::string>& arguments)
{
	Join();
	// Execute prepares the stdin FIFO before spawning; preserve it here.
	if (m_server || m_socket)
		StopServer();
	InvalidateCache();
	ClearCachedBreakpoints();
	m_temporaryAddress = 0;
	m_hardware.clear();
	m_watchpointStop = false;
	int descriptors[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors))
		return false;
	constexpr int childDescriptor = 198;
	std::vector<std::string> command {"/usr/libexec/rosetta/debugserver", "--fd=" + std::to_string(childDescriptor)};
	if (m_owned)
		command.push_back("--kill-on-error");
	command.insert(command.end(), arguments.begin(), arguments.end());
	std::vector<char*> argv;
	for (auto& item : command)
		argv.push_back(item.data());
	argv.push_back(nullptr);
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	posix_spawn_file_actions_adddup2(&actions, descriptors[1], childDescriptor);
	posix_spawnattr_t attributes;
	posix_spawnattr_init(&attributes);
	posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT);
	int error = posix_spawn(&m_server, command[0].c_str(), &actions, &attributes, argv.data(), environ);
	posix_spawnattr_destroy(&attributes);
	posix_spawn_file_actions_destroy(&actions);
	close(descriptors[1]);
	if (error)
	{
		close(descriptors[0]);
		return false;
	}
	fcntl(descriptors[0], F_SETFD, FD_CLOEXEC);
	m_socket = new Socket(descriptors[0]);
	auto connector = std::make_shared<RspConnector>(m_socket);
	m_rspConnector.store(connector);
	connector->NegotiateCapabilities({});
	if (!LoadRegisterInfo())
	{
		LogError("macOS Native: Rosetta register discovery failed");
		return false;
	}
	auto info = connector->TransmitAndReceive(RspData("qProcessInfo")).AsString();
	m_processPid = 0;
	for (const auto& field : RspConnector::Split(info, ";"))
		if (field.starts_with("pid:"))
			m_processPid = uint32_t(std::stoul(field.substr(4), nullptr, 16));
	auto stopped = RspConnector::PacketToUnorderedMap(connector->TransmitAndReceive(RspData("?")));
	m_lastActiveThreadId = uint32_t(stopped["thread"]);
	m_isTargetRunning = false;
	if (!m_processPid || !m_inspector.InspectTask(m_processPid))
	{
		LogError("macOS Native: unable to inspect Rosetta task %u", m_processPid);
		return false;
	}
	CheckApplyPendingBreakpoints();
	if (m_owned && Settings::Instance()->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction
		&& !Settings::Instance()->Get<bool>("debugger.stopAtSystemEntryPoint"))
	{
		BNSettingsScope scope = SettingsResourceScope;
		auto input = GetAdapterSettings()->Get<std::string>("common.inputFile", GetData(), &scope);
		auto bp = AddBreakpoint(ModuleNameAndOffset(input, m_entryPoint - m_start));
		if (!bp.m_is_active)
		{
			LogError("macOS Native: unable to install Rosetta entry breakpoint for %s", input.c_str());
			return false;
		}
		InvalidateCache();
		GenericGo("c", false);
	}
	DebuggerEvent event;
	event.type = AdapterStoppedEventType;
	event.data.targetStoppedData.reason = InitialBreakpoint;
	PostDebuggerEvent(event);
	return true;
}

bool MacOSRosettaAdapter::Execute(const std::string&, const LaunchConfigurations&)
{
	BNSettingsScope scope = SettingsResourceScope;
	auto settings = GetAdapterSettings();
	auto path = settings->Get<std::string>("launch.executablePath", GetData(), &scope);
	scope = SettingsResourceScope;
	auto args = settings->Get<std::string>("launch.commandLineArguments", GetData(), &scope);
	scope = SettingsResourceScope;
	auto cwd = settings->Get<std::string>("launch.workingDirectory", GetData(), &scope);
	m_owned = true;
	std::vector<std::string> arguments;
	Join();
	StopServer();
	char directory[] = "/private/tmp/bn-rosetta-XXXXXX";
	if (!mkdtemp(directory))
		return false;
	m_ioDirectory = directory;
	auto stdinPath = m_ioDirectory + "/stdin";
	if (mkfifo(stdinPath.c_str(), 0600) || (m_stdin = open(stdinPath.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC)) < 0)
		return false;
	arguments.push_back("--stdin-path=" + stdinPath);
	auto stdoutPath = m_ioDirectory + "/stdout";
	if (mkfifo(stdoutPath.c_str(), 0600) || (m_stdout = open(stdoutPath.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC)) < 0)
		return false;
	arguments.push_back("--stdout-path=" + stdoutPath);
	arguments.push_back("--stderr-path=" + stdoutPath);
	m_ioStop = false;
	m_ioWorker = std::thread([this] {
		do
		{
			pollfd fd {m_stdout, POLLIN, 0};
			poll(&fd, 1, 20);
			char buffer[4096];
			ssize_t count;
			while ((count = read(m_stdout, buffer, sizeof(buffer))) > 0)
			{
				DebuggerEvent event;
				event.type = StdoutMessageEventType;
				event.data.messageData.message.assign(buffer, count);
				PostDebuggerEvent(event);
			}
		} while (!m_ioStop);
	});
	scope = SettingsResourceScope;
	for (const auto& variable :
		settings->Get<std::vector<std::string>>("launch.environmentVariables", GetData(), &scope))
		arguments.push_back("--env=" + variable);
	if (!cwd.empty())
		arguments.push_back("--working-dir=" + cwd);
	arguments.push_back("--");
	arguments.push_back(path);
	std::istringstream input(args);
	std::string item;
	while (input >> std::quoted(item))
		arguments.push_back(item);
	return Start(arguments);
}

bool MacOSRosettaAdapter::ExecuteWithArgs(
	const std::string& path, const std::string& args, const std::string& cwd, const LaunchConfigurations& configs)
{
	auto settings = GetAdapterSettings();
	settings->Set("launch.executablePath", path, GetData(), SettingsResourceScope);
	settings->Set("launch.commandLineArguments", args, GetData(), SettingsResourceScope);
	settings->Set("launch.workingDirectory", cwd, GetData(), SettingsResourceScope);
	return Execute(path, configs);
}

bool MacOSRosettaAdapter::Attach(uint32_t pid)
{
	m_owned = false;
	return Start({"--attach=" + std::to_string(pid)});
}

DebugStopReason MacOSRosettaAdapter::SignalToStopReason(std::unordered_map<std::string, uint64_t>& fields)
{
	// Rosetta reports watchpoints as a three-code Mach breakpoint exception.
	m_watchpointStop = fields.count("watch_addr") || fields.count("watch") || fields.count("rwatch")
		|| fields.count("awatch") || (fields["metype"] == EXC_BREAKPOINT && fields["mecount"] == 3);
	if (fields["metype"] == EXC_BAD_ACCESS)
		return AccessViolation;
	if (fields["metype"] == EXC_BAD_INSTRUCTION)
		return IllegalInstruction;
	if (fields["metype"] == EXC_ARITHMETIC)
		return Calculation;
	if (fields["signal"] == 5)
	{
		if (m_temporaryAddress && GetInstructionOffset() == m_temporaryAddress)
		{
			if (m_temporaryOwned)
				RemoveBreakpoint(DebugBreakpoint(m_temporaryAddress));
			m_temporaryAddress = 0;
			return SingleStep;
		}
		return m_stepping ? SingleStep : DebugStopReason::Breakpoint;
	}
	return GdbAdapter::SignalToStopReason(fields);
}

void MacOSRosettaAdapter::WriteStdin(const std::string& text)
{
	if (m_stdin >= 0)
		write(m_stdin, text.data(), text.size());
}

bool MacOSRosettaAdapter::Resume(bool step)
{
	if (!m_rspConnector.load() || m_isTargetRunning)
		return false;
	Join();
	auto pc = GetInstructionOffset();
	bool breakpoint = BreakpointExists(pc);
	bool hardwareStep = m_watchpointStop || std::any_of(m_hardware.begin(), m_hardware.end(), [pc](const auto& bp) {
		return bp.type == HardwareExecuteBreakpoint && bp.address == pc;
	});
	auto hardware = m_hardware;
	if (step || hardwareStep || breakpoint)
		for (const auto& bp : hardware)
			GdbAdapter::RemoveHardwareBreakpoint(bp.address, bp.type, bp.size);
	if (breakpoint)
		RemoveBreakpoint(DebugBreakpoint(pc));
	InvalidateCache();
	m_isTargetRunning = true;
	DebuggerEvent event;
	event.type = step ? StepIntoEventType : ResumeEventType;
	PostDebuggerEvent(event);
	m_worker = std::thread([this, step, breakpoint, hardwareStep, hardware, pc] {
		m_stepping = step || breakpoint || hardwareStep;
		auto reason = GenericGo(m_stepping ? "s" : "c", false);
		if (breakpoint && reason != ProcessExited)
			AddBreakpoint(pc);
		if (reason != ProcessExited && (step || hardwareStep || breakpoint))
			for (const auto& bp : hardware)
				GdbAdapter::AddHardwareBreakpoint(bp.address, bp.type, bp.size);
		if ((breakpoint || hardwareStep) && !step && reason == SingleStep)
		{
			m_stepping = false;
			InvalidateCache();
			reason = GenericGo("c", false);
		}
		m_lastStopReason = reason;
		DebuggerEvent event;
		if (reason == ProcessExited)
		{
			StopIO();
			event.type = TargetExitedEventType;
			event.data.exitData.exitCode = m_exitCode;
		}
		else
		{
			event.type = AdapterStoppedEventType;
			event.data.targetStoppedData.reason = reason;
		}
		PostDebuggerEvent(event);
	});
	return true;
}

bool MacOSRosettaAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	if (!GdbAdapter::AddHardwareBreakpoint(address, type, size))
		return false;
	if (m_rspConnector.load() && std::none_of(m_hardware.begin(), m_hardware.end(), [&](const auto& bp) {
			return bp.address == address && bp.type == type && bp.size == size;
		}))
		m_hardware.push_back({address, type, size});
	return true;
}

bool MacOSRosettaAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	if (!GdbAdapter::RemoveHardwareBreakpoint(address, type, size))
		return false;
	std::erase_if(m_hardware, [&](const auto& bp) {
		return bp.address == address && bp.type == type && bp.size == size;
	});
	return true;
}

bool MacOSRosettaAdapter::Detach()
{
	Join();
	auto connector = m_rspConnector.load();
	if (!connector || connector->TransmitAndReceive(RspData("D")).AsString() != "OK")
		return false;
	m_isTargetRunning = false;
	InvalidateCache();
	ClearCachedBreakpoints();
	StopServer();
	DebuggerEvent event;
	event.type = DetachedEventType;
	PostDebuggerEvent(event);
	return true;
}

bool MacOSRosettaAdapter::Quit()
{
	Join();
	bool result = GdbAdapter::Quit();
	StopServer();
	return result;
}

std::unordered_map<std::string, DebugRegister> MacOSRosettaAdapter::ReadAllRegisters()
{
	if (m_regCache)
		return *m_regCache;
	auto connector = m_rspConnector.load();
	if (!connector || m_isTargetRunning)
		return {};
	std::unordered_map<std::string, DebugRegister> result;
	for (const auto& [name, info] : m_registerInfo)
	{
		auto bytes = connector->TransmitAndReceive(RspData(fmt::format("p{:x}", info.m_regNum))).AsString();
		if (info.m_bitSize > 512 || bytes.size() != info.m_bitSize / 4)
			continue;
		intx::uint512 value {};
		for (size_t i = 0; i < bytes.size() / 2; ++i)
			value |= intx::uint512(std::stoul(bytes.substr(2 * i, 2), nullptr, 16)) << (8 * i);
		result.emplace(name, DebugRegister(name, value, info.m_bitSize, info.m_regNum));
	}
	m_regCache = result;
	return result;
}

bool MacOSRosettaAdapter::WriteRegister(const std::string& name, intx::uint512 value)
{
	auto connector = m_rspConnector.load();
	auto it = m_registerInfo.find(name);
	if (!connector || m_isTargetRunning || it == m_registerInfo.end() || it->second.m_bitSize > 512)
		return false;
	std::string bytes;
	for (unsigned i = 0; i < it->second.m_bitSize / 8; ++i)
		bytes += fmt::format("{:02x}", uint64_t(value >> (8 * i)) & 0xff);
	bool result =
		connector->TransmitAndReceive(RspData(fmt::format("P{:x}={}", it->second.m_regNum, bytes))).AsString() == "OK";
	InvalidateCache();
	return result;
}

std::vector<DebugModule> MacOSRosettaAdapter::GetModuleList()
{
	if (m_isTargetRunning)
		return {};
	auto connector = m_rspConnector.load();
	if (!connector)
		return {};
	auto packet = connector->TransmitAndReceive(RspData("jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}"));
	auto json = RspConnector::BinaryDecode(packet).AsString();
	rapidjson::Document doc;
	doc.Parse(json.c_str());
	if (doc.HasParseError() || !doc.IsObject() || !doc.HasMember("images") || !doc["images"].IsArray())
		return {};
	std::vector<DebugModule> result;
	for (const auto& image : doc["images"].GetArray())
	{
		if (!image.HasMember("pathname") || !image["pathname"].IsString() || !image.HasMember("load_address")
			|| !image["load_address"].IsUint64())
			continue;
		auto path = std::string(image["pathname"].GetString());
		uint64_t address = image["load_address"].GetUint64(), size = 0;
		if (image.HasMember("segments") && image["segments"].IsArray())
		{
			uint64_t text = 0, end = 0;
			for (const auto& segment : image["segments"].GetArray())
				if (segment.HasMember("name") && segment["name"].IsString() && segment.HasMember("vmaddr")
					&& segment["vmaddr"].IsUint64() && segment.HasMember("vmsize") && segment["vmsize"].IsUint64())
				{
					auto start = segment["vmaddr"].GetUint64();
					if (std::string(segment["name"].GetString()) == "__TEXT")
						text = start;
					end = std::max(end, start + segment["vmsize"].GetUint64());
				}
			size = end >= text ? end - text : 0;
		}
		result.emplace_back(path, std::filesystem::path(path).filename().string(), address, size, true);
	}
	return result;
}
std::vector<DebugMemoryRegion> MacOSRosettaAdapter::GetMemoryMap()
{
	return m_inspector.GetMemoryMap();
}
std::vector<DebugSymbol> MacOSRosettaAdapter::GetSymbolsForModule(const DebugModule& module)
{
	return m_inspector.GetSymbolsForModule(module);
}

std::vector<DebugFrame> MacOSRosettaAdapter::GetFramesOfThread(uint32_t tid)
{
	auto original = GetActiveThreadId();
	if (!SetActiveThreadId(tid))
		return {};
	uint64_t pc = GetInstructionOffset(), sp = GetStackPointer(), fp = uint64_t(ReadRegister("rbp").m_value);
	std::vector<DebugFrame> frames;
	for (unsigned i = 0; pc && i < 128; ++i)
	{
		frames.emplace_back(i, pc, sp, fp, "", 0, "");
		auto bytes = ReadMemory(fp, 16);
		uint64_t chain[2];
		if (!fp || bytes.GetLength() != sizeof(chain))
			break;
		memcpy(chain, bytes.GetData(), sizeof(chain));
		if (chain[0] <= fp || chain[0] - fp > 16 * 1024 * 1024)
			break;
		sp = fp + 16;
		fp = chain[0];
		pc = chain[1];
	}
	SetActiveThreadId(original);
	return frames;
}

bool MacOSRosettaAdapter::StepReturn()
{
	auto frames = GetFramesOfThread(GetActiveThreadId());
	if (frames.size() < 2)
		return false;
	return RunToTemporary(frames[1].m_pc);
}

bool MacOSRosettaAdapter::RunToTemporary(uint64_t address)
{
	m_temporaryOwned = !BreakpointExists(address);
	if (!address || (m_temporaryOwned && !AddBreakpoint(address).m_is_active))
		return false;
	m_temporaryAddress = address;
	return Go();
}

bool MacOSRosettaAdapter::StepOver()
{
	auto pc = GetInstructionOffset();
	auto bytes = ReadMemory(pc, 16);
	InstructionInfo info;
	auto arch = Architecture::GetByName("x86_64");
	if (!arch || !arch->GetInstructionInfo((const uint8_t*)bytes.GetData(), pc, bytes.GetLength(), info))
		return false;
	for (size_t i = 0; i < info.branchCount; ++i)
		if (info.branchType[i] == CallDestination)
			return RunToTemporary(pc + info.length);
	return StepInto();
}

bool MacOSRosettaAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	return feature == DebugAdapterSupportModules || feature == DebugAdapterSupportThreads
		|| feature == DebugAdapterSupportSymbols || feature == DebugAdapterSupportStepReturn
		|| feature == DebugAdapterSupportStepOver;
}
