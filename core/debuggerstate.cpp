/*
Copyright 2020-2024 Vector 35 Inc.

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

#include <chrono>
#include <thread>
#include <utility>
#include <filesystem>
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "debuggerexceptions.h"
#include "debuggerstate.h"
#include "debugadapter.h"
#include "debuggercontroller.h"

using namespace BinaryNinja;
using namespace std;
using namespace BinaryNinjaDebugger;

constexpr size_t MemoryCacheBlock = 0x4000;

DebuggerRegisters::DebuggerRegisters(DebuggerState* state) : m_state(state)
{
	MarkDirty();
}


void DebuggerRegisters::MarkDirty()
{
	m_dirty = true;
	m_registerCache.clear();
}


void DebuggerRegisters::Update()
{
	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return;

	if (!m_state->IsConnected())
		return;

	m_registerCache = adapter->ReadAllRegisters();
	m_dirty = false;
}


uint64_t DebuggerRegisters::GetRegisterValue(const std::string& name)
{
	// Unlike the Python implementation, we require the DebuggerState to explicitly check for dirty caches
	// and update the values when necessary. This is mainly because the update can be expensive.
	if (IsDirty())
		Update();

	auto iter = m_registerCache.find(name);
	if (iter == m_registerCache.end())
		return 0x0;

	return iter->second.m_value;
}


bool DebuggerRegisters::SetRegisterValue(const std::string& name, uint64_t value)
{
	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return false;

	auto iter = m_registerCache.find(name);
	if (iter == m_registerCache.end())
		return false;

	bool ok = adapter->WriteRegister(name, value);
	if (!ok)
		return false;

	// Because some registers are correlated, changing the value of one register could invalidate the value of other
	// registers as well.
	MarkDirty();

	m_state->GetController()->NotifyEvent(RegisterChangedEvent);
	return true;
}


std::vector<DebugRegister> DebuggerRegisters::GetAllRegisters()
{
	if (IsDirty())
		Update();

	std::vector<DebugRegister> result {};
	for (auto& [reg_name, reg] : m_registerCache)
		result.push_back(reg);

	std::sort(result.begin(), result.end(), [](const DebugRegister& lhs, const DebugRegister& rhs) {
		return lhs.m_registerIndex < rhs.m_registerIndex;
	});

	// TODO: maybe we should not hold a m_state at all; instead we just hold a m_controller
	auto controller = m_state->GetController();
	if (!controller->GetState()->IsConnected())
		return result;

	std::map<uint64_t, std::string> regHints;
	for (auto& reg : result)
	{
		auto it = regHints.find(reg.m_value);
		if (it != regHints.end())
        {
            reg.m_hint = it->second;
        }
		else
        {
            const std::string hint = controller->GetAddressInformation(reg.m_value);
            regHints[reg.m_value] = hint;
            reg.m_hint = hint;
        }
	}

	return result;
}


DebuggerThreads::DebuggerThreads(DebuggerState* state) : m_state(state)
{
	MarkDirty();
}


void DebuggerThreads::MarkDirty()
{
	m_dirty = true;
	// clearing these here corrupts thread state updating in ::Update() below
	// m_threads.clear();
	// m_frames.clear();
	// TODO: consider also caching the last active thread
}


void DebuggerThreads::SymbolizeFrames(std::vector<DebugFrame>& frames)
{
	if (!m_state || !m_state->GetController())
		return;

	auto data = m_state->GetController()->GetData();
	if (!data)
		return;

	for (DebugFrame& frame: frames)
	{
		// Try to find a better symbol than the one provided by the debugger backend
		auto funcs = data->GetAnalysisFunctionsContainingAddress(frame.m_pc);
		if (!funcs.empty())
		{
			auto func = funcs[0];
			if (!func)
				continue;

			if (func->GetStart() != frame.m_functionStart)
			{
				// Found a better function start from the analysis, use it
				frame.m_functionStart = func->GetStart();
				auto symbol = func->GetSymbol();
				if (symbol)
					frame.m_functionName = symbol->GetShortName();
				else
					frame.m_functionName = fmt::format("sub_{:x}", func->GetStart());
			}
			else
			{
				std::string symName;
				auto symbol = func->GetSymbol();
				if (symbol)
					symName = symbol->GetShortName();

				auto defaultName = fmt::format("sub_{:x}", func->GetStart());
				if (frame.m_functionName.empty())
				{
					if (!symName.empty())
						frame.m_functionName = symName;
					else
						frame.m_functionName = defaultName;
				}
				else
				{
					if ((!symName.empty()) && symName != defaultName)
						frame.m_functionName = symName;
				}
			}
			continue;
		}
	}
}


void DebuggerThreads::Update()
{
	if (!m_state)
		return;

	if (!m_state->IsConnected())
		return;

	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return;

	m_frames.clear();

	std::vector<DebugThread> newThreads = adapter->GetThreadList();
	for (auto thread = newThreads.begin(); thread != newThreads.end(); thread++)
	{
		auto frames = adapter->GetFramesOfThread(thread->m_tid);
		SymbolizeFrames(frames);
		m_frames[thread->m_tid] = frames;

		// update thread states in new thread list
		auto oldThread = std::find_if(m_threads.begin(), m_threads.end(), [&](DebugThread const& t) {
			return t.m_tid == thread->m_tid;
		});

		if (oldThread != m_threads.end() && thread->m_isFrozen != oldThread->m_isFrozen)
			thread->m_isFrozen = oldThread->m_isFrozen;
	}

	m_threads.clear();
	m_threads = newThreads;

	m_dirty = false;
}


DebugThread DebuggerThreads::GetActiveThread() const
{
	if (!m_state)
		return DebugThread {};

	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return DebugThread {};

	return adapter->GetActiveThread();
}


bool DebuggerThreads::SetActiveThread(const DebugThread& thread)
{
	if (!m_state)
		return false;

	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return false;

	return adapter->SetActiveThread(thread);
}


std::vector<DebugThread> DebuggerThreads::GetAllThreads()
{
	if (IsDirty())
		Update();
	return m_threads;
}


std::vector<DebugFrame> DebuggerThreads::GetFramesOfThread(uint32_t tid)
{
	if (IsDirty())
		Update();

	auto iter = m_frames.find(tid);
	if (iter != m_frames.end())
		return iter->second;

	return {};
}


bool DebuggerThreads::SuspendThread(std::uint32_t tid)
{
	if (!m_state)
		return false;

	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return false;

	auto thread = std::find_if(m_threads.begin(), m_threads.end(), [&](DebugThread const& t) {
		return t.m_tid == tid;
	});

	if (thread == m_threads.end())
		return false;


	if (thread->m_isFrozen)
		return true;

	auto result = adapter->SuspendThread(tid);
	if (!result)
		return false;

	thread->m_isFrozen = true;

	return true;
}

bool DebuggerThreads::ResumeThread(std::uint32_t tid)
{
	if (!m_state)
		return false;

	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return false;

	auto thread = std::find_if(m_threads.begin(), m_threads.end(), [&](DebugThread const& t) {
		return t.m_tid == tid;
	});

	if (thread == m_threads.end())
		return false;

	if (!thread->m_isFrozen)
		return true;

	auto result = adapter->ResumeThread(tid);
	if (!result)
		return false;

	thread->m_isFrozen = false;

	return true;
}

DebuggerModules::DebuggerModules(DebuggerState* state) : m_state(state)
{
	MarkDirty();
}


void DebuggerModules::MarkDirty()
{
	m_dirty = true;
	m_modules.clear();
}


void DebuggerModules::Update()
{
	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return;

	if (!m_state->IsConnected())
		return;

	m_modules = adapter->GetModuleList();
	m_dirty = false;
}


bool DebuggerModules::GetModuleBase(const std::string& name, uint64_t& address)
{
	if (IsDirty())
		Update();

	if (name.empty())
		return false;

	for (const DebugModule& module : m_modules)
	{
		if (module.IsSameBaseModule(name))
		{
			address = module.m_address;
			return true;
		}
	}
	return false;
}


DebugModule DebuggerModules::GetModuleByName(const std::string& name)
{
	if (IsDirty())
		Update();

	for (const DebugModule& module : m_modules)
	{
		if (module.IsSameBaseModule(name))
			return module;
	}
	return DebugModule();
}


DebugModule DebuggerModules::GetModuleForAddress(uint64_t remoteAddress)
{
	if (IsDirty())
		Update();

	// lldb does not properly return the size of a module, so we have to find the nearest module base that is smaller
	// than the remoteAddress
	uint64_t closestAddress = 0;
	DebugModule result {};

	for (const DebugModule& module : m_modules)
	{
		// This is slighlty different from the Python implementation, which finds the largest module start that is
		// smaller than the remoteAddress.
		// if ((module.m_address <= remoteAddress) && (remoteAddress < module.m_address + module.m_size))
		//	return module;
		if ((module.m_address <= remoteAddress) && (module.m_address > closestAddress))
		{
			closestAddress = module.m_address;
			result = module;
		}
	}

	return result;
}


ModuleNameAndOffset DebuggerModules::AbsoluteAddressToRelative(uint64_t absoluteAddress)
{
	if (IsDirty())
		Update();

	DebugModule module = GetModuleForAddress(absoluteAddress);
	uint64_t relativeAddress;

	if (module.m_name != "")
	{
		relativeAddress = absoluteAddress - module.m_address;
	}
	else
	{
		relativeAddress = absoluteAddress;
	}

	return ModuleNameAndOffset(module.m_name, relativeAddress);
}


uint64_t DebuggerModules::RelativeAddressToAbsolute(const ModuleNameAndOffset& relativeAddress)
{
	if (IsDirty())
		Update();

	if (!relativeAddress.module.empty())
	{
		for (const DebugModule& module : m_modules)
		{
			if (module.IsSameBaseModule(relativeAddress.module))
			{
				return module.m_address + relativeAddress.offset;
			}
		}
		if (DebugModule::IsSameBaseModule(m_state->GetController()->GetData()->GetFile()->GetOriginalFilename(),
										  relativeAddress.module))
		{
			return m_state->GetController()->GetViewFileSegmentsStart() + relativeAddress.offset;
		}
	}

	return relativeAddress.offset;
}


std::vector<DebugModule> DebuggerModules::GetAllModules()
{
	if (IsDirty())
		Update();

	return m_modules;
}


DebuggerBreakpoints::DebuggerBreakpoints(DebuggerState* state, std::vector<ModuleNameAndOffset> initial) :
	m_state(state), m_breakpoints(std::move(initial))
{}


bool DebuggerBreakpoints::AddAbsolute(uint64_t remoteAddress)
{
	if (!m_state->GetAdapter())
		return false;

	bool result = false;
	// Always add the breakpoint as long as the adapter is connected, even if it may be already present
	if (m_state->IsConnected())
	{
		m_state->GetAdapter()->AddBreakpoint(remoteAddress);
		result = true;
	}

	if (!ContainsAbsolute(remoteAddress))
	{
		ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(remoteAddress);
		m_breakpoints.push_back(info);
		SerializeMetadata();
	}

	return result;
}


bool DebuggerBreakpoints::AddOffset(const ModuleNameAndOffset& address)
{
	if (!ContainsOffset(address))
	{
		m_breakpoints.push_back(address);
		SerializeMetadata();

		// If the adapter is already created, we ask it to add the breakpoint.
		// Otherwise, all breakpoints will be added to the adapter when the adapter is created.
		if (m_state->GetAdapter() && m_state->IsConnected())
		{
			m_state->GetAdapter()->AddBreakpoint(address);
			return true;
		}
		return true;
	}
	return false;
}


bool DebuggerBreakpoints::RemoveAbsolute(uint64_t remoteAddress)
{
	if (!m_state->GetAdapter())
		return false;

	ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(remoteAddress);
	if (ContainsOffset(info))
	{
		auto iter = std::find(m_breakpoints.begin(), m_breakpoints.end(), info);
		if (iter != m_breakpoints.end())
		{
			m_breakpoints.erase(iter);
		}
		SerializeMetadata();
		m_state->GetAdapter()->RemoveBreakpoint(remoteAddress);
		return true;
	}
	return false;
}


bool DebuggerBreakpoints::RemoveOffset(const ModuleNameAndOffset& address)
{
	if (ContainsOffset(address))
	{
		if (auto iter = std::find(m_breakpoints.begin(), m_breakpoints.end(), address); iter != m_breakpoints.end())
			m_breakpoints.erase(iter);

		SerializeMetadata();

		if (m_state->GetAdapter() && m_state->IsConnected())
		{
			uint64_t remoteAddress = m_state->GetModules()->RelativeAddressToAbsolute(address);
			m_state->GetAdapter()->RemoveBreakpoint(remoteAddress);
			return true;
		}
		return true;
	}
	return false;
}


bool DebuggerBreakpoints::ContainsOffset(const ModuleNameAndOffset& address)
{
	// If there is no backend, then only check if the breakpoint is in the list
	// This is useful when we deal with the breakpoint before the target is launched
	if (!m_state->GetAdapter())
		return std::find(m_breakpoints.begin(), m_breakpoints.end(), address) != m_breakpoints.end();

	// When the backend is live, convert the relative address to absolute address and check its existence
	uint64_t absolute = m_state->GetModules()->RelativeAddressToAbsolute(address);
	return ContainsAbsolute(absolute);
}


bool DebuggerBreakpoints::ContainsAbsolute(uint64_t address)
{
	if (!m_state->GetAdapter())
		return false;

	// We need to convert every ModuleAndOffset to absolute address and compare with the input address
	// Because every ModuleAndOffset can be converted to an absolute address, but there is no guarantee that it works
	// backward
	// Well, that is because lldb does not report the size of the loaded libraries, so it is currently screwed up
	for (const ModuleNameAndOffset& breakpoint : m_breakpoints)
	{
		uint64_t absolute = m_state->GetModules()->RelativeAddressToAbsolute(breakpoint);
		if (absolute == address)
			return true;
	}
	return false;
}


void DebuggerBreakpoints::SerializeMetadata()
{
	// TODO: who should free these Metadata objects?
	std::vector<Ref<Metadata>> breakpoints;
	for (const ModuleNameAndOffset& bp : m_breakpoints)
	{
		std::map<std::string, Ref<Metadata>> info;
		info["module"] = new Metadata(bp.module);
		info["offset"] = new Metadata(bp.offset);
		breakpoints.push_back(new Metadata(info));
	}
	m_state->GetController()->GetData()->StoreMetadata("debugger.breakpoints", new Metadata(breakpoints));
}


void DebuggerBreakpoints::UnserializedMetadata()
{
	Ref<Metadata> metadata = m_state->GetController()->GetData()->QueryMetadata("debugger.breakpoints");
	if (!metadata || (!metadata->IsArray()))
		return;

	vector<Ref<Metadata>> array = metadata->GetArray();
	std::vector<ModuleNameAndOffset> newBreakpoints;

	for (auto& element : array)
	{
		if (!element || (!element->IsKeyValueStore()))
			continue;

		std::map<std::string, Ref<Metadata>> info = element->GetKeyValueStore();
		ModuleNameAndOffset address;

		if (!(info["module"] && info["module"]->IsString()))
			continue;

		address.module = info["module"]->GetString();

		if (!(info["offset"] && info["offset"]->IsUnsignedInteger()))
			continue;

		address.offset = info["offset"]->GetUnsignedInteger();
		newBreakpoints.push_back(address);
	}

	m_breakpoints = newBreakpoints;
}


void DebuggerBreakpoints::Apply()
{
	if (!m_state->GetAdapter())
		return;

	for (const ModuleNameAndOffset& address : m_breakpoints)
		m_state->GetAdapter()->AddBreakpoint(address);
}


DebuggerMemory::DebuggerMemory(DebuggerState* state) : m_state(state) {}


void DebuggerMemory::MarkDirty()
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);
	for (auto& it: m_valueCache)
	{
		if (it.second.status == UpToDateStatus)
			it.second.status = OutOfDateStatus;
		else
			it.second.status = DefaultStatus;
	}
}


DataBuffer DebuggerMemory::ReadBlock(uint64_t block)
{
	auto iter = m_valueCache.find(block);
	if (iter != m_valueCache.end())
	{
		switch (iter->second.status)
		{
		case FailedToReadStatus:
			return {};
		case OutOfDateStatus:
		{
			if (m_state->IsConnected() && m_state->IsRunning())
			{
				// The cache is old but the target is running, return old value
				return iter->second.value;
			}
			// Break out and try to read the new value
			break;
		}
		case UpToDateStatus:
		{
			// Cache is up-to-date, return the value
			return iter->second.value;
		}
		case DefaultStatus:
			// There is no useful information about the status, break out and try to read it
			break;
		}
	}

	// Try to read the memory value from the backend
	if (m_state->IsConnected() && !m_state->IsRunning())
	{
		// The cache is old and the target is stopped, try to update the cache value
		DataBuffer buffer = m_state->GetAdapter()->ReadMemory(block, MemoryCacheBlock);
		if (buffer.GetLength() > 0)
		{
			// Successfully updated
			m_valueCache[block] = {buffer, UpToDateStatus};
			return buffer;
		}
	}

	// Update failed
	m_valueCache[block] = {{}, FailedToReadStatus};
	return {};
}


DataBuffer DebuggerMemory::ReadMemory(uint64_t offset, size_t len)
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);

	DataBuffer result;

	// ProcessView implements read caching in a manner inspired by CPU cache:
	// Reads are aligned on 256-byte boundaries and 256 bytes long

	// Cache read start: round down addr to nearest 256 byte boundary
	size_t cacheStart = offset & (~(MemoryCacheBlock - 1));
	// Cache read end: round up addr+length to nearest 256 byte boundary
	size_t cacheEnd = (offset + len + MemoryCacheBlock - 1) & (~(MemoryCacheBlock - 1));
	// List of 256-byte block addresses to read into the cache to fully cover this region
	for (uint64_t block = cacheStart; block < cacheEnd; block += MemoryCacheBlock)
	{
		auto cached = ReadBlock(block);
		if (cached.GetLength() == 0)
			return result;

		if (offset + len < block + cached.GetLength())
		{
			// Last block
			cached = cached.GetSlice(0, offset + len - block);
		}
		// Note a block can be both the fist and the last block, so we should not put an else here
		if (offset > block)
		{
			// First block
			cached = cached.GetSlice(offset - block, cached.GetLength() - (offset - block));
		}
		result.Append(cached);
	}
	return result;
}


bool DebuggerMemory::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);

	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return false;

	if (!adapter->WriteMemory(address, buffer))
		return false;

	//	TODO: Assume any memory change invalidates memory cache (suboptimal, may not be necessary)
	MarkDirty();
	return true;
}


DebuggerState::DebuggerState(BinaryViewRef data, DebuggerController* controller) : m_controller(controller)
{
	INIT_DEBUGGER_API_OBJECT();

	m_adapter = nullptr;
	m_modules = new DebuggerModules(this);
	m_registers = new DebuggerRegisters(this);
	m_threads = new DebuggerThreads(this);
	m_breakpoints = new DebuggerBreakpoints(this);
	m_breakpoints->UnserializedMetadata();
	m_memory = new DebuggerMemory(this);

	// TODO: A better way to deal with this is to have the adapters return a fitness score, and then we pick the highest
	// one from the list. Similar to what we do for the views.
	m_availableAdapters = DebugAdapterType::GetAvailableAdapters(data);
	m_adapterType = DebugAdapterType::GetBestAdapterForCurrentSystem(data);
	// Check whether there is no available adapters at all
	if (m_availableAdapters.size() == 0)
	{
		m_adapterType = "";
	}
	else if (std::find(m_availableAdapters.begin(), m_availableAdapters.end(), m_adapterType)
		== m_availableAdapters.end())
	{
		// The system's default adapter does not work with the current data, e.g., an .exe is opened on macOS,
		// then pick one from the available ones.
		m_adapterType = m_availableAdapters[0];
	}

	Ref<Metadata> metadata;
	metadata = m_controller->GetData()->QueryMetadata("debugger.command_line_args");
	if (metadata && metadata->IsString())
		m_commandLineArgs = metadata->GetString();

	metadata = m_controller->GetData()->QueryMetadata("debugger.input_file");
	if (metadata && metadata->IsString())
		m_inputFile = metadata->GetString();

	if (m_inputFile == "")
		m_inputFile = m_controller->GetData()->GetFile()->GetOriginalFilename();

	metadata = m_controller->GetData()->QueryMetadata("debugger.executable_path");
	if (metadata && metadata->IsString())
		m_executablePath = metadata->GetString();

	if (m_executablePath == "")
		m_executablePath = m_controller->GetData()->GetFile()->GetOriginalFilename();

	metadata = m_controller->GetData()->QueryMetadata("debugger.working_directory");
	if (metadata && metadata->IsString())
		m_workingDirectory = metadata->GetString();

	if (m_workingDirectory == "")
    {
        // This mitigates https://github.com/Vector35/debugger/issues/469. However, it is NOT a proper fix since the
        // debugger still will not be able to launch the target properly. We will need to deal with the charset issue
        // to get this really fixed.
        try
        {
            m_workingDirectory = filesystem::path(m_executablePath).parent_path().string();
        }
        catch (const exception&)
        {
            LogWarn("Cannot get the default working directory for the input file. "
                    "There might be special characters in the file path. "
                    "The debugger may not be able to launch the target correctly. "
                    "You can try changing the file path to ASCII allow.");
        }
    }

	metadata = m_controller->GetData()->QueryMetadata("debugger.remote_host");
	if (metadata && metadata->IsString())
		m_remoteHost = metadata->GetString();
	if (m_remoteHost.empty())
		m_remoteHost = "127.0.0.1";

	metadata = m_controller->GetData()->QueryMetadata("debugger.remote_port");
	if (metadata && metadata->IsUnsignedInteger())
		m_remotePort = metadata->GetUnsignedInteger();
	if (m_remotePort == 0)
		m_remotePort = 31337;

	metadata = m_controller->GetData()->QueryMetadata("debugger.adapter_type");
	if (metadata && metadata->IsString())
		m_adapterType = metadata->GetString();

	metadata = m_controller->GetData()->QueryMetadata("debugger.terminal_emulator");
	if (metadata && metadata->IsUnsignedInteger())
		m_requestTerminalEmulator = metadata->GetBoolean();
	else
		m_requestTerminalEmulator = false;

	SetConnectionStatus(DebugAdapterNotConnectedStatus);
}


DebuggerState::~DebuggerState()
{
	delete m_adapter;
	delete m_modules;
	delete m_registers;
	delete m_threads;
	delete m_breakpoints;
	delete m_memory;
}


void DebuggerState::AddBreakpoint(uint64_t address)
{
	m_breakpoints->AddAbsolute(address);
}


void DebuggerState::AddBreakpoint(const ModuleNameAndOffset& address)
{
	m_breakpoints->AddOffset(address);
}


void DebuggerState::DeleteBreakpoint(uint64_t address)
{
	m_breakpoints->RemoveAbsolute(address);
}


void DebuggerState::DeleteBreakpoint(const ModuleNameAndOffset& address)
{
	m_breakpoints->RemoveOffset(address);
}


uint64_t DebuggerState::IP()
{
	if (!IsConnected())
		return 0;

	return m_adapter->GetInstructionOffset();
}


uint64_t DebuggerState::StackPointer()
{
	// TODO: we would better have the DebugAdapter either tell us which register holds the stack pointer
	if (!IsConnected())
		return 0;

	return m_adapter->GetStackPointer();
}


bool DebuggerState::SetActiveThread(const DebugThread& thread)
{
	if (!m_threads)
		return false;

	return m_threads->SetActiveThread(thread);
}


void DebuggerState::MarkDirty()
{
	m_registers->MarkDirty();
	m_threads->MarkDirty();
	m_modules->MarkDirty();
	m_memory->MarkDirty();
}


void DebuggerState::UpdateCaches()
{
	// TODO: this is a temporary fix to address the problem of BN handing after the target exits. The core problem is
	// the debugger still tries to update caches after the target has exited and the socket is closed, so it hangs
	// while waiting for data. A proper fix is https://github.com/Vector35/debugger_native/issues/104
	if (!IsConnected())
		return;

	if (m_registers->IsDirty())
		m_registers->Update();

	if (m_threads->IsDirty())
		m_threads->Update();

	if (m_modules->IsDirty())
		m_modules->Update();
}


bool DebuggerState::GetRemoteBase(uint64_t& address)
{
	return m_modules->GetModuleBase(GetInputFile(), address);
}


void DebuggerState::ApplyBreakpoints()
{
	m_breakpoints->Apply();
}


Ref<Architecture> DebuggerState::GetRemoteArchitecture() const
{
	return m_controller->GetData()->GetDefaultArchitecture();
}


void DebuggerState::SetAdapterType(const std::string& adapter)
{
	m_adapterType = adapter;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


void DebuggerState::SetExecutablePath(const std::string& path)
{
	m_executablePath = path;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


void DebuggerState::SetInputFile(const std::string& path)
{
	m_inputFile = path;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


std::string DebuggerState::GetInputFile()
{
	return m_inputFile;
}


void DebuggerState::SetWorkingDirectory(const std::string& directory)
{
	m_workingDirectory = directory;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


void DebuggerState::SetCommandLineArguments(const std::string& arguments)
{
	m_commandLineArgs = arguments;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


void DebuggerState::SetRemoteHost(const std::string& host)
{
	m_remoteHost = host;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


void DebuggerState::SetRemotePort(uint32_t port)
{
	m_remotePort = port;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


void DebuggerState::SetRequestTerminalEmulator(bool requested)
{
	m_requestTerminalEmulator = requested;
	m_controller->NotifyEvent(DebuggerSettingsChangedEvent);
}


void DebuggerState::SetPIDAttach(int32_t pid)
{
	m_pidAttach = pid;
}
