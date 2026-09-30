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

#include "macosnativeadapter.h"
#include "macosnativearch.h"
#include "macosrosettaadapter.h"
#include <mach/mach_vm.h>
#include <mach/arm/exception.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libproc.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <spawn.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <fstream>

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;
extern char** environ;
extern "C" boolean_t mach_exc_server(mach_msg_header_t*, mach_msg_header_t*);

namespace {
	// MIG dispatches synchronously on each adapter's exception worker.
	thread_local MacOSNativeAdapter* receivingAdapter = nullptr;

	bool SplitArguments(const std::string& text, std::vector<std::string>& args)
	{
		std::string word;
		char quote = 0;
		bool escaped = false, started = false;
		for (char c : text)
		{
			if (escaped)
			{
				word += c;
				escaped = false;
				started = true;
			}
			else if (c == '\\' && quote != '\'')
			{
				escaped = true;
				started = true;
			}
			else if (quote)
			{
				if (c == quote)
					quote = 0;
				else
					word += c;
			}
			else if (c == '\'' || c == '"')
			{
				quote = c;
				started = true;
			}
			else if (isspace((unsigned char)c))
			{
				if (started)
				{
					args.push_back(word);
					word.clear();
					started = false;
				}
			}
			else
			{
				word += c;
				started = true;
			}
		}
		if (quote || escaped)
			return false;
		if (started)
			args.push_back(word);
		return true;
	}

	template <class T>
	bool CopyObject(const DataBuffer& buffer, T& object)
	{
		if (buffer.GetLength() != sizeof(T))
			return false;
		memcpy(&object, buffer.GetData(), sizeof(T));
		return true;
	}
}  // namespace

extern "C" kern_return_t catch_mach_exception_raise(mach_port_t, mach_port_t thread, mach_port_t task,
	exception_type_t type, mach_exception_data_t code, mach_msg_type_number_t count)
{
	return receivingAdapter ? receivingAdapter->ReceiveException(thread, task, type, code, count) : KERN_FAILURE;
}
extern "C" kern_return_t catch_mach_exception_raise_state(mach_port_t, exception_type_t, const mach_exception_data_t,
	mach_msg_type_number_t, int*, const thread_state_t, mach_msg_type_number_t, thread_state_t, mach_msg_type_number_t*)
{
	return KERN_FAILURE;
}
extern "C" kern_return_t catch_mach_exception_raise_state_identity(mach_port_t, mach_port_t, mach_port_t,
	exception_type_t, mach_exception_data_t, mach_msg_type_number_t, int*, thread_state_t, mach_msg_type_number_t,
	thread_state_t, mach_msg_type_number_t*)
{
	return KERN_FAILURE;
}

bool MacOSNativeAdapterType::IsValidForData(BinaryView* data)
{
	return data->GetTypeName() == "Mach-O" && data->GetDefaultArchitecture()
		&& (data->GetDefaultArchitecture()->GetName() == "aarch64"
			|| data->GetDefaultArchitecture()->GetName() == "x86_64");
}

DebugAdapter* MacOSNativeAdapterType::Create(BinaryView* data)
{
	if (data->GetDefaultArchitecture()->GetName() == "x86_64")
		return new MacOSRosettaAdapter(data);
	return new MacOSNativeAdapter(data);
}

bool MacOSNativeAdapter::InspectTask(pid_t pid)
{
	std::lock_guard lock(m_mutex);
	Cleanup();
	m_inspectionOnly = true;
	m_pid = pid;
	if (task_for_pid(mach_task_self(), pid, &m_task) != KERN_SUCCESS)
		return false;
	RefreshThreads();
	return true;
}

Ref<Settings> MacOSNativeAdapterType::GetAdapterSettings()
{
	static Ref<Settings> settings = [] {
		auto result = Settings::Instance("MacOSNativeAdapterSettings");
		result->SetResourceId("macos_native_adapter_settings");
		for (const auto& group : {"common", "launch", "attach"})
			result->RegisterGroup(group, group);
		for (const auto& key :
			{"common.inputFile", "launch.executablePath", "launch.workingDirectory", "launch.commandLineArguments",
				"launch.redirectStdin", "launch.redirectStdout", "launch.redirectStderr"})
			result->RegisterSetting(
				key, fmt::format(R"({{"title":"{}","description":"{}","type":"string","default":""}})", key, key));
		result->RegisterSetting("launch.environmentVariables",
			R"({"title":"Environment variables","description":"Environment entries in NAME=value form","type":"array","default":[],"sorted":false})");
		result->RegisterSetting("attach.pid",
			R"({"title":"PID","description":"Process ID to attach to","type":"number","default":0,"minValue":0,"maxValue":4294967295})");
		return result;
	}();
	return settings;
}

Ref<Settings> MacOSNativeAdapter::GetAdapterSettings()
{
	return MacOSNativeAdapterType::GetAdapterSettings();
}

Ref<Metadata> MacOSNativeAdapter::GetProperty(const std::string& name)
{
	auto settings = GetAdapterSettings();
	if (!settings->Contains(name))
		return nullptr;
	BNSettingsScope scope = SettingsResourceScope;
	if (name == "launch.environmentVariables")
		return new Metadata(settings->Get<std::vector<std::string>>(name, GetData(), &scope));
	if (name == "attach.pid")
		return new Metadata(settings->Get<uint64_t>(name, GetData(), &scope));
	return new Metadata(settings->Get<std::string>(name, GetData(), &scope));
}

bool MacOSNativeAdapter::SetProperty(const std::string& name, const Ref<Metadata>& value)
{
	auto settings = GetAdapterSettings();
	return value && settings->Contains(name)
		&& settings->SetJson(name, value->GetJsonString(), GetData(), SettingsResourceScope);
}

void BinaryNinjaDebugger::InitMacOSNativeAdapterType()
{
	static MacOSNativeAdapterType type;
	DebugAdapterType::Register(&type);
}

MacOSNativeAdapter::MacOSNativeAdapter(BinaryView* data) : DebugAdapter(data)
{
	auto settings = GetAdapterSettings();
	for (const auto& key : {"common.inputFile", "launch.executablePath", "launch.workingDirectory"})
	{
		BNSettingsScope scope = SettingsResourceScope;
		settings->Get<std::string>(key, data, &scope);
		if (scope != SettingsResourceScope)
		{
			auto value = data->GetFile()->GetOriginalFilename();
			if (std::string(key) == "launch.workingDirectory")
				value = std::filesystem::path(value).parent_path().string();
			settings->Set(key, value, data, SettingsResourceScope);
		}
	}
}

MacOSNativeAdapter::~MacOSNativeAdapter()
{
	pid_t ownedChild = m_child ? m_pid : 0;
	// Attached processes belong to the caller; do not kill them on adapter disposal.
	if (m_task && !m_inspectionOnly)
	{
		if (m_child)
			Quit();
		else
			Detach();
	}
	m_shutdown = true;
	if (m_worker.joinable())
		m_worker.join();
	if (ownedChild)
		waitpid(ownedChild, nullptr, 0);
	Cleanup();
}

void MacOSNativeAdapter::Error(const std::string& message, bool launch)
{
	DebuggerEvent event;
	event.type = launch ? LaunchFailureEventType : ErrorEventType;
	event.data.errorData.shortError = "macOS native debugger";
	event.data.errorData.error = message;
	PostDebuggerEvent(event);
}

void MacOSNativeAdapter::StopEvent(DebugStopReason reason)
{
	DebuggerEvent event;
	event.type = AdapterStoppedEventType;
	event.data.targetStoppedData.reason = reason;
	PostDebuggerEvent(event);
}

bool MacOSNativeAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	return ExecuteWithArgs(path, "", "", configs);
}

bool MacOSNativeAdapter::ExecuteWithArgs(
	const std::string&, const std::string&, const std::string&, const LaunchConfigurations&)
{
	if (m_task && !m_shutdown)
		return false;
	if (m_worker.joinable())
		m_worker.join();
	Cleanup();
	auto data = GetData();
	auto settings = GetAdapterSettings();
	auto get = [&](const char* key) {
		BNSettingsScope scope = SettingsResourceScope;
		return settings->Get<std::string>(key, data, &scope);
	};
	m_executable = get("launch.executablePath");
	std::vector<std::string> args {m_executable};
	if (!SplitArguments(get("launch.commandLineArguments"), args))
	{
		Error("Unterminated command line quote or escape", true);
		return false;
	}
	std::vector<char*> argv;
	for (auto& arg : args)
		argv.push_back(arg.data());
	argv.push_back(nullptr);
	std::vector<std::string> env;
	for (char** entry = environ; *entry; ++entry)
		env.emplace_back(*entry);
	BNSettingsScope scope = SettingsResourceScope;
	for (const auto& entry : settings->Get<std::vector<std::string>>("launch.environmentVariables", data, &scope))
	{
		auto equal = entry.find('=');
		if (equal == std::string::npos || equal == 0)
		{
			Error("Environment entries must be NAME=value", true);
			return false;
		}
		auto prefix = entry.substr(0, equal + 1);
		env.erase(
			std::remove_if(env.begin(), env.end(), [&](const auto& e) { return e.rfind(prefix, 0) == 0; }), env.end());
		env.push_back(entry);
	}
	std::vector<char*> envp;
	for (auto& entry : env)
		envp.push_back(entry.data());
	envp.push_back(nullptr);
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t actions;
	posix_spawnattr_init(&attr);
	posix_spawn_file_actions_init(&actions);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT);
	auto cwd = get("launch.workingDirectory");
	if (!cwd.empty())
		posix_spawn_file_actions_addchdir_np(&actions, cwd.c_str());
	int pipeEnds[3][2] {{-1, -1}, {-1, -1}, {-1, -1}};
	int status = 0;
	const char* redirects[] = {"launch.redirectStdin", "launch.redirectStdout", "launch.redirectStderr"};
	for (int fd = 0; fd < 3 && !status; ++fd)
	{
		auto path = get(redirects[fd]);
		if (!path.empty())
			status = posix_spawn_file_actions_addopen(
				&actions, fd, path.c_str(), fd == 0 ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0644);
		else
		{
			if (pipe(pipeEnds[fd]))
			{
				status = errno;
				break;
			}
			status = posix_spawn_file_actions_adddup2(&actions, pipeEnds[fd][fd == 0 ? 0 : 1], fd);
		}
	}
	pid_t pid = 0;
	if (!status)
		status = posix_spawn(&pid, m_executable.c_str(), &actions, &attr, argv.data(), envp.data());
	posix_spawn_file_actions_destroy(&actions);
	posix_spawnattr_destroy(&attr);
	for (int fd = 0; fd < 3; ++fd)
	{
		int childEnd = fd == 0 ? 0 : 1;
		if (pipeEnds[fd][childEnd] >= 0)
			close(pipeEnds[fd][childEnd]);
	}
	m_stdin = pipeEnds[0][1];
	m_stdout = pipeEnds[1][0];
	m_stderr = pipeEnds[2][0];
	if (m_stdin >= 0)
		fcntl(m_stdin, F_SETNOSIGPIPE, 1);
	for (int fd : {m_stdin, m_stdout, m_stderr})
		if (fd >= 0)
			fcntl(fd, F_SETFL, O_NONBLOCK);
	if (status)
	{
		Error("posix_spawn: " + std::string(strerror(status)), true);
		Cleanup();
		return false;
	}
	if (!Start(pid, true))
	{
		kill(pid, SIGKILL);
		waitpid(pid, nullptr, 0);
		Cleanup();
		return false;
	}
	// Balance the suspension introduced by POSIX_SPAWN_START_SUSPENDED.
	task_resume(m_task);
	return true;
}

bool MacOSNativeAdapter::Attach(uint32_t pid)
{
	if ((m_task && !m_shutdown) || !pid || pid == (uint32_t)getpid())
		return false;
	if (m_worker.joinable())
		m_worker.join();
	Cleanup();
	char path[PROC_PIDPATHINFO_MAXSIZE] {};
	proc_pidpath(pid, path, sizeof(path));
	m_executable = path;
	return Start(pid, false);
}

bool MacOSNativeAdapter::Start(pid_t pid, bool child)
{
	m_pid = pid;
	m_child = child;
	// Restrict this PoC to arm64 targets, including when Attach is used directly.
	std::ifstream file(m_executable, std::ios::binary);
	mach_header_64 header {};
	file.read((char*)&header, sizeof(header));
	if (!file || header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64)
	{
		Error("The native PoC supports thin arm64 Mach-O executables only", true);
		return false;
	}
	auto kr = task_for_pid(mach_task_self(), pid, &m_task);
	if (kr != KERN_SUCCESS)
	{
		Error(fmt::format("task_for_pid({}): {}. Check debugger signing and target get-task-allow.", pid,
				  mach_error_string(kr)),
			true);
		return false;
	}
	m_savedCount = EXC_TYPES_COUNT;
	kr = task_get_exception_ports(
		m_task, ExceptionMask, m_savedMasks, &m_savedCount, m_savedPorts, m_savedBehaviors, m_savedFlavors);
	if (kr != KERN_SUCCESS)
		m_savedCount = 0;
	if (kr == KERN_SUCCESS)
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &m_exceptionPort);
	if (kr == KERN_SUCCESS)
		kr = mach_port_insert_right(mach_task_self(), m_exceptionPort, m_exceptionPort, MACH_MSG_TYPE_MAKE_SEND);
	if (kr == KERN_SUCCESS)
		kr = task_set_exception_ports(
			m_task, ExceptionMask, m_exceptionPort, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
	if (kr != KERN_SUCCESS)
	{
		Error("Exception port setup: " + std::string(mach_error_string(kr)), true);
		Cleanup();
		return false;
	}
	m_shutdown = false;
	m_initial = true;
	m_running = true;
	// Install handlers before attaching so the initial SIGSTOP is delivered to us.
	if (ptrace(PT_ATTACHEXC, pid, nullptr, 0) != 0)
	{
		Error("ptrace(PT_ATTACHEXC): " + std::string(strerror(errno)), true);
		Cleanup();
		return false;
	}
	m_traced = true;
	m_worker = std::thread(&MacOSNativeAdapter::Worker, this);
	return true;
}

kern_return_t MacOSNativeAdapter::ReceiveException(
	thread_t thread, task_t task, exception_type_t type, mach_exception_data_t code, mach_msg_type_number_t count)
{
	if (!m_receiving || task != m_task)
		return KERN_FAILURE;
	m_receiving->thread = thread;
	m_receiving->task = task;
	m_exceptionType = type;
	m_exceptionCodes.assign(code, code + count);
	if (type == EXC_SOFTWARE && count >= 2 && code[0] == EXC_SOFT_SIGNAL)
		m_receiving->signal = (int)code[1];
	return KERN_SUCCESS;
}

void MacOSNativeAdapter::Worker()
{
	receivingAdapter = this;
	while (!m_shutdown)
	{
		alignas(mach_msg_header_t) std::array<uint8_t, 4096> request {};
		auto* msg = (mach_msg_header_t*)request.data();
		auto kr =
			mach_msg(msg, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, request.size(), m_exceptionPort, 20, MACH_PORT_NULL);
		std::vector<DebuggerEvent> events;
		{
			std::lock_guard lock(m_mutex);
			events.swap(m_events);
			if (m_shutdown)
			{
				if (kr == KERN_SUCCESS)
					mach_msg_destroy(msg);
				break;
			}
			if (kr == KERN_SUCCESS)
			{
				Exception exception;
				m_receiving = &exception;
				bool handled = mach_exc_server(msg, (mach_msg_header_t*)exception.reply.data());
				m_receiving = nullptr;
				if (!handled || !exception.thread)
				{
					auto* reply = (mach_msg_header_t*)exception.reply.data();
					if (handled)
						mach_msg(reply, MACH_SEND_MSG | MACH_SEND_TIMEOUT, reply->msgh_size, 0, 0, 20, 0);
					mach_msg_destroy(msg);
				}
				else
				{
					if (!m_suspended && task_suspend(m_task) == KERN_SUCCESS)
						m_suspended = true;
					RefreshThreads();
					for (const auto& [id, thread] : m_threads)
						if (thread == exception.thread)
							m_activeThread = id;
					m_exceptions.push_back(std::move(exception));
					m_running = false;
					bool notify = true;
					DebugStopReason reason = UnknownReason;
					m_watchpointStop = m_exceptionType == EXC_BREAKPOINT && !m_exceptionCodes.empty()
						&& m_exceptionCodes[0] == EXC_ARM_DA_DEBUG;
					if (m_exceptionType == EXC_BAD_ACCESS)
						reason = AccessViolation;
					else if (m_exceptionType == EXC_BAD_INSTRUCTION)
						reason = IllegalInstruction;
					else if (m_exceptionType == EXC_ARITHMETIC)
						reason = Calculation;
					else if (m_exceptionType == EXC_BREAKPOINT)
						reason = DebugStopReason::Breakpoint;
					else if (m_exceptions.back().signal == SIGSTOP)
						reason = UserRequestedBreak;
					else if (m_exceptions.back().signal == SIGSEGV)
						reason = AccessViolation;
					else if (m_exceptions.back().signal == SIGINT)
						reason = UserRequestedBreak;
					if (m_stepThread && m_exceptionType == EXC_BREAKPOINT)
					{
						EndSingleStep();
						if (m_reinsertAddress)
						{
							auto it = m_breakpoints.find(m_reinsertAddress);
							if (it != m_breakpoints.end())
								it->second.installed = WriteRaw(it->first, &MacOSNativeArch::SoftwareTrap, 4);
							m_reinsertAddress = 0;
						}
						reason = SingleStep;
						if (m_continueAfterStep)
						{
							m_continueAfterStep = false;
							notify = !Resume(false, false);
						}
					}
					else if (m_stepThread)
						EndSingleStep();
					uint64_t ip = MacOSNativeArch::InstructionPointer(ActiveThread());
					if (m_temporaryBreakpoint && ip == m_temporaryBreakpoint)
					{
						if (m_temporaryOwned)
							RemoveBreakpoint(DebugBreakpoint(m_temporaryBreakpoint));
						m_temporaryBreakpoint = 0;
						m_temporaryOwned = false;
						reason = SingleStep;
					}
					if (m_initial)
					{
						m_initial = false;
						ApplyPendingBreakpoints();
						if (m_child && !Settings::Instance()->Get<bool>("debugger.stopAtSystemEntryPoint")
							&& Settings::Instance()->Get<bool>("debugger.stopAtEntryPoint") && m_hasEntryFunction)
						{
							BNSettingsScope scope = SettingsResourceScope;
							auto input = GetAdapterSettings()->Get<std::string>("common.inputFile", GetData(), &scope);
							auto address = Resolve(ModuleNameAndOffset(input, m_entryPoint - m_start));
							if (address && AddBreakpoint(address).m_is_active)
							{
								m_initialRunToEntry = true;
								notify = !Resume(false, false);
							}
							else
								reason = InternalError;
						}
						else
							reason = InitialBreakpoint;
					}
					else if (m_initialRunToEntry && reason == DebugStopReason::Breakpoint)
					{
						m_initialRunToEntry = false;
						reason = InitialBreakpoint;
					}
					m_stateChanged.notify_all();
					if (notify && !m_detaching)
					{
						m_reason = reason;
						DebuggerEvent event;
						event.type = AdapterStoppedEventType;
						event.data.targetStoppedData.reason = reason;
						events.push_back(event);
					}
				}
			}
			for (int fd : {m_stdout, m_stderr})
			{
				if (fd < 0)
					continue;
				char buffer[4096];
				// Bound per-iteration output so a noisy target cannot starve exception handling.
				for (int i = 0; i < 16; ++i)
				{
					ssize_t count = read(fd, buffer, sizeof(buffer));
					if (count <= 0)
						break;
					DebuggerEvent event;
					event.type = StdoutMessageEventType;
					event.data.messageData.message.assign(buffer, count);
					events.push_back(event);
				}
			}
			if (m_stdin >= 0 && !m_stdinQueue.empty())
			{
				ssize_t count = write(m_stdin, m_stdinQueue.data(), m_stdinQueue.size());
				if (count > 0)
					m_stdinQueue.erase(0, count);
				else if (count < 0 && errno != EAGAIN && errno != EINTR)
					m_stdinQueue.clear();
			}
			int status = 0;
			pid_t exited = waitpid(m_pid, &status, WNOHANG);
			if (exited == m_pid && (WIFEXITED(status) || WIFSIGNALED(status)))
			{
				m_exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
				m_reason = ProcessExited;
				m_running = false;
				m_shutdown = true;
				m_stateChanged.notify_all();
				DebuggerEvent event;
				event.type = TargetExitedEventType;
				event.data.exitData.exitCode = m_exitCode;
				events.push_back(event);
			}
		}
		// Never invoke controller callbacks while holding the adapter's state lock.
		for (const auto& event : events)
			PostDebuggerEvent(event);
	}
	receivingAdapter = nullptr;
}

void MacOSNativeAdapter::RestoreExceptionPorts()
{
	if (m_task && m_exceptionPort)
	{
		task_set_exception_ports(m_task, ExceptionMask, MACH_PORT_NULL, EXCEPTION_DEFAULT, THREAD_STATE_NONE);
		for (unsigned i = 0; i < m_savedCount; ++i)
			task_set_exception_ports(m_task, m_savedMasks[i], m_savedPorts[i], m_savedBehaviors[i], m_savedFlavors[i]);
	}
}

void MacOSNativeAdapter::Cleanup()
{
	std::lock_guard lock(m_mutex);
	RestoreExceptionPorts();
	EndSingleStep();
	for (auto& exception : m_exceptions)
	{
		auto* reply = (mach_msg_header_t*)exception.reply.data();
		if (reply->msgh_remote_port)
			mach_msg_destroy(reply);
		if (exception.thread)
			mach_port_deallocate(mach_task_self(), exception.thread);
		if (exception.task)
			mach_port_deallocate(mach_task_self(), exception.task);
	}
	m_exceptions.clear();
	m_events.clear();
	for (const auto& [id, thread] : m_threads)
		mach_port_deallocate(mach_task_self(), thread);
	m_threads.clear();
	m_userSuspends.clear();
	for (unsigned i = 0; i < m_savedCount; ++i)
		if (m_savedPorts[i])
			mach_port_deallocate(mach_task_self(), m_savedPorts[i]);
	m_savedCount = 0;
	if (m_exceptionPort)
	{
		mach_port_mod_refs(mach_task_self(), m_exceptionPort, MACH_PORT_RIGHT_RECEIVE, -1);
		mach_port_deallocate(mach_task_self(), m_exceptionPort);
	}
	m_exceptionPort = MACH_PORT_NULL;
	if (m_task)
		mach_port_deallocate(mach_task_self(), m_task);
	m_task = MACH_PORT_NULL;
	m_pid = 0;
	m_traced = false;
	m_running = false;
	m_suspended = false;
	m_initialRunToEntry = false;
	m_activeThread = 0;
	m_reinsertAddress = 0;
	m_continueAfterStep = false;
	m_temporaryBreakpoint = 0;
	m_temporaryOwned = false;
	m_breakpoints.clear();
	m_hardware.clear();
	for (int fd : {m_stdin, m_stdout, m_stderr})
		if (fd >= 0)
			close(fd);
	m_stdin = m_stdout = m_stderr = -1;
	m_stdinQueue.clear();
}

bool MacOSNativeAdapter::ReplyExceptions(bool preserveStop)
{
	bool success = true;
	for (auto& exception : m_exceptions)
	{
		if (exception.signal && !(preserveStop && exception.signal == SIGSTOP)
			&& ptrace(PT_THUPDATE, m_pid, (caddr_t)(uintptr_t)exception.thread, 0))
			success = false;
		auto* reply = (mach_msg_header_t*)exception.reply.data();
		if (mach_msg(reply, MACH_SEND_MSG | MACH_SEND_TIMEOUT, reply->msgh_size, 0, 0, 100, 0) != KERN_SUCCESS)
		{
			success = false;
			mach_msg_destroy(reply);
		}
		mach_port_deallocate(mach_task_self(), exception.thread);
		mach_port_deallocate(mach_task_self(), exception.task);
	}
	m_exceptions.clear();
	return success;
}

void MacOSNativeAdapter::RefreshThreads()
{
	thread_act_array_t threads = nullptr;
	mach_msg_type_number_t count = 0;
	if (!m_task || task_threads(m_task, &threads, &count) != KERN_SUCCESS)
		return;
	std::map<uint32_t, thread_t> next;
	for (unsigned i = 0; i < count; ++i)
	{
		thread_identifier_info_data_t info {};
		mach_msg_type_number_t n = THREAD_IDENTIFIER_INFO_COUNT;
		if (thread_info(threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&info, &n) == KERN_SUCCESS
			&& info.thread_id <= UINT32_MAX)
		{
			next.emplace((uint32_t)info.thread_id, threads[i]);
			for (const auto& bp : m_hardware)
				MacOSNativeArch::SetHardwareBreakpoint(threads[i], bp.slot, bp.address, bp.type, bp.size, true);
		}
		else
			mach_port_deallocate(mach_task_self(), threads[i]);
	}
	vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_t));
	for (const auto& [id, thread] : m_threads)
		mach_port_deallocate(mach_task_self(), thread);
	m_threads = std::move(next);
	if (!m_threads.count(m_activeThread))
		m_activeThread = m_threads.empty() ? 0 : m_threads.begin()->first;
}

thread_t MacOSNativeAdapter::ActiveThread() const
{
	auto it = m_threads.find(m_activeThread);
	return it == m_threads.end() ? MACH_PORT_NULL : it->second;
}

void MacOSNativeAdapter::EndSingleStep()
{
	if (m_stepThread)
	{
		MacOSNativeArch::SetSingleStep(m_stepThread, false);
		for (const auto& bp : m_stepHardware)
			if (std::any_of(m_hardware.begin(), m_hardware.end(), [&](const auto& current) {
					return current.address == bp.address && current.type == bp.type && current.slot == bp.slot;
				}))
				MacOSNativeArch::SetHardwareBreakpoint(m_stepThread, bp.slot, bp.address, bp.type, bp.size, true);
		mach_port_deallocate(mach_task_self(), m_stepThread);
		m_stepThread = MACH_PORT_NULL;
	}
	for (auto thread : m_stepSuspends)
	{
		thread_resume(thread);
		mach_port_deallocate(mach_task_self(), thread);
	}
	m_stepSuspends.clear();
	m_stepHardware.clear();
}

bool MacOSNativeAdapter::Resume(bool step, bool notify)
{
	if (!m_task || m_running || !m_suspended)
		return false;
	RefreshThreads();
	auto thread = ActiveThread();
	if (!thread)
		return false;
	uint64_t ip = MacOSNativeArch::InstructionPointer(thread);
	auto bp = m_breakpoints.find(ip);
	bool stepPast = bp != m_breakpoints.end() && bp->second.installed;
	bool hardwareStepPast = m_reason == DebugStopReason::Breakpoint
		&& (m_watchpointStop || std::any_of(m_hardware.begin(), m_hardware.end(), [&](const auto& hardware) {
			   return hardware.type == HardwareExecuteBreakpoint && hardware.address == ip;
		   }));
	if (stepPast)
	{
		if (!WriteRaw(ip, &bp->second.original, 4))
			return false;
		bp->second.installed = false;
		m_reinsertAddress = ip;
		m_continueAfterStep = !step;
	}
	if (hardwareStepPast)
		m_continueAfterStep = !step;
	if (step || stepPast || hardwareStepPast)
	{
		if (!MacOSNativeArch::SetSingleStep(thread, true))
			return false;
		mach_port_mod_refs(mach_task_self(), thread, MACH_PORT_RIGHT_SEND, 1);
		m_stepThread = thread;
		for (const auto& hardware : m_hardware)
		{
			if (!MacOSNativeArch::SetHardwareBreakpoint(
					thread, hardware.slot, hardware.address, hardware.type, hardware.size, false))
			{
				EndSingleStep();
				return false;
			}
			m_stepHardware.push_back(hardware);
		}
		for (const auto& [id, other] : m_threads)
			if (other != thread && thread_suspend(other) == KERN_SUCCESS)
			{
				mach_port_mod_refs(mach_task_self(), other, MACH_PORT_RIGHT_SEND, 1);
				m_stepSuspends.push_back(other);
			}
	}
	if (!ReplyExceptions())
	{
		EndSingleStep();
		return false;
	}
	if (task_resume(m_task) != KERN_SUCCESS)
	{
		EndSingleStep();
		return false;
	}
	m_suspended = false;
	m_running = true;
	m_watchpointStop = false;
	if (notify)
	{
		DebuggerEvent event;
		event.type = step ? StepIntoEventType : ResumeEventType;
		m_events.push_back(event);
	}
	return true;
}

bool MacOSNativeAdapter::Go()
{
	std::lock_guard lock(m_mutex);
	return Resume(false);
}
bool MacOSNativeAdapter::StepInto()
{
	std::lock_guard lock(m_mutex);
	return Resume(true);
}
bool MacOSNativeAdapter::BreakInto()
{
	std::lock_guard lock(m_mutex);
	return m_task && m_running && kill(m_pid, SIGSTOP) == 0;
}

bool MacOSNativeAdapter::Quit()
{
	std::lock_guard lock(m_mutex);
	if (!m_task || m_shutdown)
		return false;
	EndSingleStep();
	if (kill(m_pid, SIGKILL))
		return false;
	ReplyExceptions();
	if (m_suspended)
	{
		task_resume(m_task);
		m_suspended = false;
	}
	m_running = true;
	return true;
}

bool MacOSNativeAdapter::Detach()
{
	{
		std::unique_lock lock(m_mutex);
		if (!m_task)
			return false;
		if (!m_suspended && task_suspend(m_task) == KERN_SUCCESS)
			m_suspended = true;
		EndSingleStep();
		for (auto& [address, bp] : m_breakpoints)
		{
			if (bp.installed && !WriteRaw(address, &bp.original, 4))
				return false;
			bp.installed = false;
		}
		for (const auto& [id, thread] : m_threads)
		{
			for (const auto& bp : m_hardware)
				MacOSNativeArch::SetHardwareBreakpoint(thread, bp.slot, bp.address, bp.type, bp.size, false);
			for (unsigned i = 0; i < m_userSuspends[id]; ++i)
				thread_resume(thread);
		}
		m_hardware.clear();
		m_userSuspends.clear();
		// PT_DETACH requires a BSD signal stop, not just a Mach suspension or trap.
		// Preserve SIGSTOP when replying so the kernel still regards the task as stopped.
		auto hasStop = [&] {
			return std::any_of(m_exceptions.begin(), m_exceptions.end(), [](const auto& e) {
				return e.signal == SIGSTOP;
			});
		};
		m_detaching = true;
		if (!hasStop())
		{
			if (kill(m_pid, SIGSTOP))
			{
				m_detaching = false;
				return false;
			}
			ReplyExceptions();
			if (m_suspended)
			{
				task_resume(m_task);
				m_suspended = false;
			}
			m_running = true;
			if (!m_stateChanged.wait_for(lock, std::chrono::seconds(2), [&] { return hasStop() || m_shutdown; })
				|| m_shutdown)
			{
				m_detaching = false;
				return false;
			}
		}
		ReplyExceptions(true);
		if (m_traced && ptrace(PT_DETACH, m_pid, (caddr_t)1, 0))
		{
			m_detaching = false;
			Error("ptrace(PT_DETACH): " + std::string(strerror(errno)));
			return false;
		}
		RestoreExceptionPorts();
		m_traced = false;
		if (m_suspended)
		{
			task_resume(m_task);
			m_suspended = false;
		}
		m_shutdown = true;
		m_detaching = false;
	}
	if (m_worker.joinable())
		m_worker.join();
	Cleanup();
	DebuggerEvent event;
	event.type = DetachedEventType;
	PostDebuggerEvent(event);
	return true;
}

DataBuffer MacOSNativeAdapter::ReadRaw(uint64_t address, size_t size)
{
	if (!m_task || !size || size > 64 * 1024 * 1024)
		return {};
	std::vector<uint8_t> data(size);
	mach_vm_size_t count = 0;
	auto kr = mach_vm_read_overwrite(m_task, address, size, (mach_vm_address_t)data.data(), &count);
	return kr == KERN_SUCCESS ? DataBuffer(data.data(), count) : DataBuffer();
}

bool MacOSNativeAdapter::WriteRaw(uint64_t address, const void* data, size_t size)
{
	if (!m_task || !size || address > UINT64_MAX - size)
		return false;
	struct Protection
	{
		mach_vm_address_t start;
		mach_vm_size_t size;
		vm_prot_t original;
	};
	std::vector<Protection> changed;
	uint64_t cursor = address;
	bool success = true;
	while (cursor < address + size)
	{
		mach_vm_address_t start = cursor;
		mach_vm_size_t length = 0;
		vm_region_basic_info_data_64_t info {};
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t object = 0;
		auto kr =
			mach_vm_region(m_task, &start, &length, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
		if (object)
			mach_port_deallocate(mach_task_self(), object);
		if (kr != KERN_SUCCESS || start > cursor || !length)
		{
			success = false;
			break;
		}
		uint64_t end = std::min(start + length, address + size);
		if (!(info.protection & VM_PROT_WRITE))
		{
			uint64_t pageStart = cursor & ~uint64_t(vm_page_size - 1);
			uint64_t pageEnd = (end + vm_page_size - 1) & ~uint64_t(vm_page_size - 1);
			kr = mach_vm_protect(
				m_task, pageStart, pageEnd - pageStart, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
			if (kr != KERN_SUCCESS)
			{
				success = false;
				break;
			}
			changed.push_back({pageStart, pageEnd - pageStart, info.protection});
		}
		kr = mach_vm_write(m_task, cursor, (vm_offset_t)((const uint8_t*)data + cursor - address), end - cursor);
		if (kr != KERN_SUCCESS)
		{
			success = false;
			break;
		}
		cursor = end;
	}
	for (const auto& p : changed)
		if (mach_vm_protect(m_task, p.start, p.size, false, p.original) != KERN_SUCCESS)
			success = false;
	vm_machine_attribute_val_t cache = MATTR_VAL_CACHE_FLUSH;
	mach_vm_machine_attribute(m_task, address, size, MATTR_CACHE, &cache);
	return success;
}

DataBuffer MacOSNativeAdapter::ReadMemory(uintptr_t address, size_t size)
{
	std::lock_guard lock(m_mutex);
	auto result = ReadRaw(address, size);
	for (const auto& [at, bp] : m_breakpoints)
		if (bp.installed && at < address + result.GetLength() && at + 4 > address)
		{
			uint64_t begin = std::max<uint64_t>(at, address),
					 end = std::min<uint64_t>(at + 4, address + result.GetLength());
			memcpy(
				(uint8_t*)result.GetData() + begin - address, (const uint8_t*)&bp.original + begin - at, end - begin);
		}
	return result;
}

bool MacOSNativeAdapter::WriteMemory(uintptr_t address, const DataBuffer& data)
{
	std::lock_guard lock(m_mutex);
	if (!WriteRaw(address, data.GetData(), data.GetLength()))
		return false;
	for (auto& [at, bp] : m_breakpoints)
		if (at < address + data.GetLength() && at + 4 > address)
		{
			uint64_t begin = std::max<uint64_t>(at, address),
					 end = std::min<uint64_t>(at + 4, address + data.GetLength());
			memcpy((uint8_t*)&bp.original + begin - at, (const uint8_t*)data.GetData() + begin - address, end - begin);
			if (bp.installed && !WriteRaw(at, &MacOSNativeArch::SoftwareTrap, 4))
				return false;
		}
	return true;
}

DebugBreakpoint MacOSNativeAdapter::AddBreakpoint(uintptr_t address, unsigned long)
{
	std::lock_guard lock(m_mutex);
	if (!m_task || !address || address % 4)
		return {};
	auto it = m_breakpoints.find(address);
	if (it != m_breakpoints.end())
		return DebugBreakpoint(address, it->second.id, true);
	uint32_t original;
	if (!CopyObject(ReadRaw(address, 4), original) || !WriteRaw(address, &MacOSNativeArch::SoftwareTrap, 4))
		return {};
	unsigned long id = m_nextBreakpointId++;
	m_breakpoints.emplace(address, Breakpoint {original, id, true});
	return DebugBreakpoint(address, id, true);
}

DebugBreakpoint MacOSNativeAdapter::AddBreakpoint(const ModuleNameAndOffset& location, unsigned long type)
{
	std::lock_guard lock(m_mutex);
	auto address = Resolve(location);
	if (address)
		return AddBreakpoint(address, type);
	m_pendingBreakpoints.push_back(location);
	return {};
}

bool MacOSNativeAdapter::RemoveBreakpoint(const DebugBreakpoint& bp)
{
	std::lock_guard lock(m_mutex);
	auto it = m_breakpoints.find(bp.m_address);
	if (it == m_breakpoints.end())
		return false;
	if (it->second.installed && !WriteRaw(it->first, &it->second.original, 4))
		return false;
	m_breakpoints.erase(it);
	return true;
}

bool MacOSNativeAdapter::RemoveBreakpoint(const ModuleNameAndOffset& location)
{
	std::lock_guard lock(m_mutex);
	m_pendingBreakpoints.erase(
		std::remove(m_pendingBreakpoints.begin(), m_pendingBreakpoints.end(), location), m_pendingBreakpoints.end());
	return RemoveBreakpoint(DebugBreakpoint(Resolve(location)));
}

std::vector<DebugBreakpoint> MacOSNativeAdapter::GetBreakpointList() const
{
	std::lock_guard lock(m_mutex);
	std::vector<DebugBreakpoint> result;
	for (const auto& [address, bp] : m_breakpoints)
		result.emplace_back(address, bp.id, bp.installed);
	return result;
}

uint64_t MacOSNativeAdapter::Resolve(const ModuleNameAndOffset& location)
{
	for (const auto& module : GetModuleList())
		if (module.IsSameBaseModule(location.module))
			return module.m_address + location.offset;
	return 0;
}

void MacOSNativeAdapter::ApplyPendingBreakpoints()
{
	auto pending = std::move(m_pendingBreakpoints);
	m_pendingBreakpoints.clear();
	for (const auto& location : pending)
		AddBreakpoint(location);
	auto hardware = std::move(m_pendingHardware);
	m_pendingHardware.clear();
	for (const auto& bp : hardware)
	{
		if (bp.isRelative)
			AddHardwareBreakpoint(bp.location, bp.type, bp.size);
		else
			AddHardwareBreakpoint(bp.address, bp.type, bp.size);
	}
}

bool MacOSNativeAdapter::AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	std::lock_guard lock(m_mutex);
	if (!m_task)
	{
		m_pendingHardware.emplace_back(address, type, size);
		return true;
	}
	if (m_running)
		return false;
	for (const auto& bp : m_hardware)
		if (bp.address == address && bp.type == type && bp.size == size)
			return true;
	RefreshThreads();
	unsigned slot = 0;
	for (; slot < 16; ++slot)
		if (std::none_of(m_hardware.begin(), m_hardware.end(), [&](const auto& bp) {
				return bp.slot == slot && (bp.type == HardwareExecuteBreakpoint) == (type == HardwareExecuteBreakpoint);
			}))
			break;
	if (slot == 16 || m_threads.empty())
		return false;
	std::vector<thread_t> applied;
	for (const auto& [id, thread] : m_threads)
	{
		if (!MacOSNativeArch::SetHardwareBreakpoint(thread, slot, address, type, size, true))
		{
			for (auto previous : applied)
				MacOSNativeArch::SetHardwareBreakpoint(previous, slot, address, type, size, false);
			return false;
		}
		applied.push_back(thread);
	}
	m_hardware.push_back({address, type, size, slot});
	return true;
}

bool MacOSNativeAdapter::RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size)
{
	std::lock_guard lock(m_mutex);
	auto it = std::find_if(m_hardware.begin(), m_hardware.end(), [&](const auto& bp) {
		return bp.address == address && bp.type == type && bp.size == size;
	});
	if (it == m_hardware.end())
		return false;
	for (const auto& [id, thread] : m_threads)
		if (!MacOSNativeArch::SetHardwareBreakpoint(thread, it->slot, address, type, size, false))
			return false;
	m_hardware.erase(it);
	return true;
}

bool MacOSNativeAdapter::AddHardwareBreakpoint(
	const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	std::lock_guard lock(m_mutex);
	auto address = Resolve(location);
	if (address)
		return AddHardwareBreakpoint(address, type, size);
	m_pendingHardware.emplace_back(location, type, size);
	return true;
}
bool MacOSNativeAdapter::RemoveHardwareBreakpoint(
	const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size)
{
	std::lock_guard lock(m_mutex);
	return RemoveHardwareBreakpoint(Resolve(location), type, size);
}

std::string MacOSNativeAdapter::ReadString(uint64_t address)
{
	std::string result;
	for (size_t i = 0; i < 4096; ++i)
	{
		char c;
		if (!CopyObject(ReadRaw(address + i, 1), c))
			return {};
		if (!c)
			return result;
		result += c;
	}
	return {};
}

std::vector<DebugModule> MacOSNativeAdapter::GetModuleList()
{
	std::lock_guard lock(m_mutex);
	std::vector<DebugModule> result;
	if (!m_task)
		return result;
	auto add = [&](uint64_t address, std::string path) {
		mach_header_64 header {};
		if (!CopyObject(ReadRaw(address, sizeof(header)), header) || header.magic != MH_MAGIC_64
			|| header.sizeofcmds > 16 * 1024 * 1024)
			return;
		auto commands = ReadRaw(address + sizeof(header), header.sizeofcmds);
		if (commands.GetLength() != header.sizeofcmds)
			return;
		uint64_t base = UINT64_MAX, limit = 0;
		size_t offset = 0;
		for (unsigned i = 0; i < header.ncmds && offset + sizeof(load_command) <= commands.GetLength(); ++i)
		{
			load_command cmd;
			memcpy(&cmd, (const uint8_t*)commands.GetData() + offset, sizeof(cmd));
			if (cmd.cmdsize < sizeof(cmd) || cmd.cmdsize > commands.GetLength() - offset)
				return;
			if (cmd.cmd == LC_SEGMENT_64 && cmd.cmdsize >= sizeof(segment_command_64))
			{
				segment_command_64 segment;
				memcpy(&segment, (const uint8_t*)commands.GetData() + offset, sizeof(segment));
				if (segment.vmsize && strncmp(segment.segname, "__PAGEZERO", 16))
				{
					base = std::min(base, segment.vmaddr);
					limit = std::max(limit, segment.vmaddr + segment.vmsize);
				}
			}
			offset += cmd.cmdsize;
		}
		if (base != UINT64_MAX)
			result.emplace_back(path, std::filesystem::path(path).filename().string(), address, limit - base, true);
	};
	task_dyld_info_data_t info {};
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	if (task_info(m_task, TASK_DYLD_INFO, (task_info_t)&info, &count) == KERN_SUCCESS)
	{
		// Read only the ABI prefix; later dyld fields are version dependent.
		struct ImageInfos
		{
			uint32_t version, count;
			uint64_t array;
		} images {};
		if (CopyObject(ReadRaw(info.all_image_info_addr, sizeof(images)), images) && images.count < 65536)
		{
			struct Image
			{
				uint64_t address, path, modified;
			};
			auto array = ReadRaw(images.array, images.count * sizeof(Image));
			if (array.GetLength() == images.count * sizeof(Image))
				for (unsigned i = 0; i < images.count; ++i)
				{
					Image image;
					memcpy(&image, (const uint8_t*)array.GetData() + i * sizeof(Image), sizeof(Image));
					add(image.address, ReadString(image.path));
				}
		}
	}
	// Before dyld initializes its image array, the executable is already mapped.
	if (result.empty())
	{
		for (const auto& region : GetMemoryMap())
		{
			mach_header_64 header {};
			if (region.m_read && CopyObject(ReadRaw(region.m_start, sizeof(header)), header)
				&& header.magic == MH_MAGIC_64 && (header.filetype == MH_EXECUTE || header.filetype == MH_DYLINKER))
				add(region.m_start, header.filetype == MH_EXECUTE ? m_executable : "/usr/lib/dyld");
		}
	}
	return result;
}

std::vector<DebugSymbol> MacOSNativeAdapter::GetSymbolsForModule(const DebugModule& module)
{
	std::lock_guard lock(m_mutex);
	std::vector<DebugSymbol> result;
	mach_header_64 header {};
	if (!CopyObject(ReadRaw(module.m_address, sizeof(header)), header) || header.magic != MH_MAGIC_64
		|| header.sizeofcmds > 16 * 1024 * 1024)
		return result;
	auto commands = ReadRaw(module.m_address + sizeof(header), header.sizeofcmds);
	if (commands.GetLength() != header.sizeofcmds)
		return result;
	uint64_t preferredBase = 0, linkeditVM = 0, linkeditFile = 0;
	symtab_command symtab {};
	uint32_t exportsOffset = 0, exportsSize = 0;
	std::vector<std::pair<uint64_t, uint64_t>> codeRanges;
	size_t offset = 0;
	for (unsigned i = 0; i < header.ncmds && offset + sizeof(load_command) <= commands.GetLength(); ++i)
	{
		load_command cmd;
		memcpy(&cmd, (const uint8_t*)commands.GetData() + offset, sizeof(cmd));
		if (cmd.cmdsize < sizeof(cmd) || cmd.cmdsize > commands.GetLength() - offset)
			return {};
		const uint8_t* p = (const uint8_t*)commands.GetData() + offset;
		if (cmd.cmd == LC_SEGMENT_64 && cmd.cmdsize >= sizeof(segment_command_64))
		{
			segment_command_64 segment;
			memcpy(&segment, p, sizeof(segment));
			if (!strncmp(segment.segname, "__TEXT", 16))
				preferredBase = segment.vmaddr;
			if (!strncmp(segment.segname, "__LINKEDIT", 16))
			{
				linkeditVM = segment.vmaddr;
				linkeditFile = segment.fileoff;
			}
			if (segment.initprot & VM_PROT_EXECUTE)
				codeRanges.emplace_back(segment.vmaddr, segment.vmaddr + segment.vmsize);
		}
		else if (cmd.cmd == LC_SYMTAB && cmd.cmdsize >= sizeof(symtab))
			memcpy(&symtab, p, sizeof(symtab));
		else if ((cmd.cmd == LC_DYLD_INFO_ONLY || cmd.cmd == LC_DYLD_INFO) && cmd.cmdsize >= sizeof(dyld_info_command))
		{
			dyld_info_command info;
			memcpy(&info, p, sizeof(info));
			exportsOffset = info.export_off;
			exportsSize = info.export_size;
		}
		else if (cmd.cmd == LC_DYLD_EXPORTS_TRIE && cmd.cmdsize >= sizeof(linkedit_data_command))
		{
			linkedit_data_command info;
			memcpy(&info, p, sizeof(info));
			exportsOffset = info.dataoff;
			exportsSize = info.datasize;
		}
		offset += cmd.cmdsize;
	}
	if (!linkeditVM)
		return result;
	uint64_t slide = module.m_address - preferredBase;
	uint64_t linkedit = linkeditVM + slide - linkeditFile;
	auto add = [&](const std::string& name, uint64_t address) {
		if (name.empty() || !address)
			return;
		bool code = std::any_of(codeRanges.begin(), codeRanges.end(), [&](const auto& range) {
			return address >= range.first + slide && address < range.second + slide;
		});
		result.emplace_back(name, module.m_short_name + "!" + name, name, address, 0, code);
	};
	if (symtab.nsyms && symtab.nsyms < 500000 && symtab.strsize < 16 * 1024 * 1024)
	{
		auto symbols = ReadRaw(linkedit + symtab.symoff, symtab.nsyms * sizeof(nlist_64));
		auto strings = ReadRaw(linkedit + symtab.stroff, symtab.strsize);
		if (symbols.GetLength() == symtab.nsyms * sizeof(nlist_64) && strings.GetLength() == symtab.strsize)
			for (unsigned i = 0; i < symtab.nsyms; ++i)
			{
				nlist_64 symbol;
				memcpy(&symbol, (const uint8_t*)symbols.GetData() + i * sizeof(symbol), sizeof(symbol));
				if ((symbol.n_type & N_STAB) || (symbol.n_type & N_TYPE) != N_SECT
					|| symbol.n_un.n_strx >= strings.GetLength())
					continue;
				const char* name = (const char*)strings.GetData() + symbol.n_un.n_strx;
				const char* end = (const char*)memchr(name, 0, strings.GetLength() - symbol.n_un.n_strx);
				if (end)
					add(std::string(name, end), symbol.n_value + slide);
			}
	}
	if (!result.empty() || !exportsSize || exportsSize > 16 * 1024 * 1024)
		return result;
	// Shared-cache images often retain exports even when local nlist strings aren't mapped.
	auto trie = ReadRaw(linkedit + exportsOffset, exportsSize);
	if (trie.GetLength() != exportsSize)
		return result;
	const uint8_t* bytes = (const uint8_t*)trie.GetData();
	auto uleb = [&](size_t& cursor, uint64_t& value) {
		value = 0;
		for (unsigned shift = 0; shift < 64 && cursor < exportsSize; shift += 7)
		{
			uint8_t byte = bytes[cursor++];
			if (shift == 63 && (byte & 0x7e))
				return false;
			value |= uint64_t(byte & 0x7f) << shift;
			if (!(byte & 0x80))
				return true;
		}
		return false;
	};
	struct Node
	{
		uint64_t offset;
		std::string prefix;
		unsigned depth;
	};
	std::vector<Node> pending {{0, "", 0}};
	unsigned visited = 0;
	while (!pending.empty() && ++visited < 100000)
	{
		auto node = std::move(pending.back());
		pending.pop_back();
		if (node.offset >= exportsSize || node.depth > 64 || node.prefix.size() > 4096)
			continue;
		size_t cursor = node.offset;
		uint64_t terminalSize;
		if (!uleb(cursor, terminalSize) || terminalSize > exportsSize - cursor)
			continue;
		size_t children = cursor + terminalSize;
		if (terminalSize)
		{
			uint64_t flags, address;
			if (uleb(cursor, flags) && !(flags & EXPORT_SYMBOL_FLAGS_REEXPORT) && uleb(cursor, address)
				&& cursor <= children && (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_REGULAR)
				add(node.prefix, module.m_address + address);
		}
		if (children >= exportsSize)
			continue;
		cursor = children;
		unsigned count = bytes[cursor++];
		for (unsigned i = 0; i < count && cursor < exportsSize; ++i)
		{
			const char* label = (const char*)bytes + cursor;
			const char* end = (const char*)memchr(label, 0, exportsSize - cursor);
			if (!end)
				break;
			cursor += end - label + 1;
			uint64_t child;
			if (!uleb(cursor, child))
				break;
			pending.push_back({child, node.prefix + std::string(label, end), node.depth + 1});
		}
	}
	return result;
}

std::vector<DebugMemoryRegion> MacOSNativeAdapter::GetMemoryMap()
{
	std::lock_guard lock(m_mutex);
	std::vector<DebugMemoryRegion> result;
	mach_vm_address_t address = 0;
	unsigned depth = 0;
	while (m_task)
	{
		mach_vm_size_t size = 0;
		vm_region_submap_info_data_64_t info {};
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		if (mach_vm_region_recurse(m_task, &address, &size, &depth, (vm_region_recurse_info_t)&info, &count)
			!= KERN_SUCCESS)
			break;
		if (info.is_submap)
		{
			++depth;
			continue;
		}
		result.emplace_back(address, size, "", info.protection & VM_PROT_READ, info.protection & VM_PROT_WRITE,
			info.protection & VM_PROT_EXECUTE, info.share_mode == SM_SHARED);
		if (!size || address > UINT64_MAX - size)
			break;
		address += size;
	}
	return result;
}

std::vector<DebugProcess> MacOSNativeAdapter::GetProcessList()
{
	int bytes = proc_listallpids(nullptr, 0);
	if (bytes <= 0)
		return {};
	std::vector<pid_t> pids(bytes + 128);
	int count = proc_listallpids(pids.data(), pids.size() * sizeof(pid_t));
	std::vector<DebugProcess> result;
	for (int i = 0; i < count && i < (int)pids.size(); ++i)
	{
		char path[PROC_PIDPATHINFO_MAXSIZE] {};
		if (pids[i] > 0 && proc_pidpath(pids[i], path, sizeof(path)) > 0)
			result.emplace_back(pids[i], path);
	}
	return result;
}

uint32_t MacOSNativeAdapter::GetActivePID()
{
	std::lock_guard lock(m_mutex);
	return m_pid;
}
uint32_t MacOSNativeAdapter::GetActiveThreadId() const
{
	std::lock_guard lock(m_mutex);
	return m_activeThread;
}
DebugThread MacOSNativeAdapter::GetActiveThread() const
{
	std::lock_guard lock(m_mutex);
	return DebugThread(m_activeThread, MacOSNativeArch::InstructionPointer(ActiveThread()));
}
std::vector<DebugThread> MacOSNativeAdapter::GetThreadList()
{
	std::lock_guard lock(m_mutex);
	RefreshThreads();
	std::vector<DebugThread> result;
	for (const auto& [id, thread] : m_threads)
	{
		DebugThread item(id, MacOSNativeArch::InstructionPointer(thread));
		item.m_isFrozen = m_userSuspends[id] > 0;
		result.push_back(item);
	}
	return result;
}
bool MacOSNativeAdapter::SetActiveThread(const DebugThread& thread)
{
	return SetActiveThreadId(thread.m_tid);
}
bool MacOSNativeAdapter::SetActiveThreadId(uint32_t id)
{
	std::lock_guard lock(m_mutex);
	RefreshThreads();
	if (!m_threads.count(id))
		return false;
	m_activeThread = id;
	return true;
}
bool MacOSNativeAdapter::SuspendThread(uint32_t id)
{
	std::lock_guard lock(m_mutex);
	auto it = m_threads.find(id);
	if (it == m_threads.end() || thread_suspend(it->second) != KERN_SUCCESS)
		return false;
	++m_userSuspends[id];
	return true;
}
bool MacOSNativeAdapter::ResumeThread(uint32_t id)
{
	std::lock_guard lock(m_mutex);
	auto it = m_threads.find(id);
	if (it == m_threads.end() || !m_userSuspends[id] || thread_resume(it->second) != KERN_SUCCESS)
		return false;
	--m_userSuspends[id];
	return true;
}

std::unordered_map<std::string, DebugRegister> MacOSNativeAdapter::ReadAllRegisters()
{
	std::lock_guard lock(m_mutex);
	return MacOSNativeArch::ReadRegisters(ActiveThread());
}
DebugRegister MacOSNativeAdapter::ReadRegister(const std::string& name)
{
	auto registers = ReadAllRegisters();
	auto it = registers.find(name);
	return it == registers.end() ? DebugRegister() : it->second;
}
bool MacOSNativeAdapter::WriteRegister(const std::string& name, intx::uint512 value)
{
	std::lock_guard lock(m_mutex);
	return !m_running && MacOSNativeArch::WriteRegister(ActiveThread(), name, value);
}
uint64_t MacOSNativeAdapter::GetInstructionOffset()
{
	std::lock_guard lock(m_mutex);
	return MacOSNativeArch::InstructionPointer(ActiveThread());
}
uint64_t MacOSNativeAdapter::GetStackPointer()
{
	std::lock_guard lock(m_mutex);
	return MacOSNativeArch::StackPointer(ActiveThread());
}
DebugStopReason MacOSNativeAdapter::StopReason()
{
	std::lock_guard lock(m_mutex);
	return m_reason;
}
uint64_t MacOSNativeAdapter::ExitCode()
{
	std::lock_guard lock(m_mutex);
	return m_exitCode;
}

bool MacOSNativeAdapter::TemporaryBreakpoint(uint64_t address)
{
	if (!address || m_temporaryBreakpoint)
		return false;
	m_temporaryOwned = !m_breakpoints.count(address);
	if (!AddBreakpoint(address).m_is_active)
		return false;
	m_temporaryBreakpoint = address;
	return true;
}
bool MacOSNativeAdapter::StepOver()
{
	std::lock_guard lock(m_mutex);
	uint64_t ip = GetInstructionOffset();
	uint32_t instruction;
	if (!CopyObject(ReadMemory(ip, 4), instruction))
		return false;
	if ((instruction & 0xfc000000) != 0x94000000 && (instruction & 0xfffffc1f) != 0xd63f0000)
		return Resume(true);
	return TemporaryBreakpoint(ip + 4) && Resume(false);
}
bool MacOSNativeAdapter::StepReturn()
{
	std::lock_guard lock(m_mutex);
	auto frames = GetFramesOfThread(m_activeThread);
	uint64_t address = frames.size() > 1 ? frames[1].m_pc : MacOSNativeArch::LinkRegister(ActiveThread());
	return TemporaryBreakpoint(address) && Resume(false);
}

std::vector<DebugFrame> MacOSNativeAdapter::GetFramesOfThread(uint32_t id)
{
	std::lock_guard lock(m_mutex);
	auto it = m_threads.find(id);
	if (it == m_threads.end())
		return {};
	uint64_t pc = MacOSNativeArch::InstructionPointer(it->second);
	uint64_t sp = MacOSNativeArch::StackPointer(it->second);
	uint64_t fp = MacOSNativeArch::FramePointer(it->second);
	std::vector<DebugFrame> result;
	auto modules = GetModuleList();
	for (unsigned i = 0; i < 128 && pc; ++i)
	{
		std::string module;
		for (const auto& m : modules)
			if (pc >= m.m_address && pc - m.m_address < m.m_size)
			{
				module = m.m_short_name;
				break;
			}
		result.emplace_back(i, pc, sp, fp, "", 0, module);
		struct Frame
		{
			uint64_t previous, returnAddress;
		} frame {};
		if (!fp || (fp & 15) || !CopyObject(ReadRaw(fp, sizeof(frame)), frame) || frame.previous <= fp
			|| frame.previous - fp > 16 * 1024 * 1024)
			break;
		sp = fp + sizeof(frame);
		fp = frame.previous;
		// A PoC frame chain, not a compact-unwind/DWARF implementation.
		pc = frame.returnAddress & 0x0000ffffffffffff;
	}
	return result;
}

bool MacOSNativeAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	return feature == DebugAdapterSupportStepOver || feature == DebugAdapterSupportStepReturn
		|| feature == DebugAdapterSupportModules || feature == DebugAdapterSupportThreads
		|| feature == DebugAdapterSupportSymbols;
}
std::string MacOSNativeAdapter::InvokeBackendCommand(const std::string& command)
{
	if (command == "c" || command == "continue")
		return Go() ? "" : "continue failed";
	if (command == "si")
		return StepInto() ? "" : "step failed";
	if (command == "ni")
		return StepOver() ? "" : "step failed";
	if (command == "finish")
		return StepReturn() ? "" : "step return failed";
	return "macOS Native does not implement LLDB commands";
}
void MacOSNativeAdapter::WriteStdin(const std::string& message)
{
	std::lock_guard lock(m_mutex);
	if (m_stdin >= 0)
		m_stdinQueue += message;
}
