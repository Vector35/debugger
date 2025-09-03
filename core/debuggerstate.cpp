/*
Copyright 2020-2025 Vector 35 Inc.

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

DebuggerRegisters::DebuggerRegisters(DebuggerState* state) : m_state(state)
{
	MarkDirty();
}


void DebuggerRegisters::MarkDirty()
{
	std::unique_lock lock(m_registersMutex);
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

	std::unique_lock lock(m_registersMutex);
	m_registerCache = adapter->ReadAllRegisters();
	m_dirty = false;
}


intx::uint512 DebuggerRegisters::GetRegisterValue(const std::string& name)
{
	auto cachedRegs = GetCachedRegisters();

	auto iter = cachedRegs.find(name);
	if (iter == cachedRegs.end())
		return 0x0;

	return iter->second.m_value;
}


bool DebuggerRegisters::SetRegisterValue(const std::string& name, intx::uint512 value)
{
	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return false;

	auto cachedRegs = GetCachedRegisters();

	auto iter = cachedRegs.find(name);
	if (iter == cachedRegs.end())
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
	auto cachedRegs = GetCachedRegisters();

	std::vector<DebugRegister> result {};
	for (auto& [reg_name, reg] : cachedRegs)
		result.push_back(reg);

	std::sort(result.begin(), result.end(), [](const DebugRegister& lhs, const DebugRegister& rhs) {
		return lhs.m_registerIndex < rhs.m_registerIndex;
	});

	// TODO: maybe we should not hold a m_state at all; instead we just hold a m_controller
	auto controller = m_state->GetController();
	if (!controller->GetState()->IsConnected())
		return result;

	std::map<intx::uint512, std::string> regHints;
	for (auto& reg : result)
	{
		auto it = regHints.find(reg.m_value);
		if (it != regHints.end())
        {
            reg.m_hint = it->second;
        }
		else
        {
			// TODO: create a new GetRegisterHint method that calls GetAddressInformation
            const std::string hint = controller->GetAddressInformation(reg.m_value);
            regHints[reg.m_value] = hint;
            reg.m_hint = hint;
        }
	}

	return result;
}


std::unordered_map<std::string, DebugRegister> DebuggerRegisters::GetCachedRegisters()
{
	std::unique_lock lock(m_registersMutex);

	if (IsDirty())
		Update();

	return m_registerCache;
}


DebuggerThreads::DebuggerThreads(DebuggerState* state) : m_state(state)
{
	MarkDirty();
}


void DebuggerThreads::MarkDirty()
{
	std::unique_lock lock(m_threadsMutex);

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

	std::unique_lock lock(m_threadsMutex);
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

	if (!m_state->IsConnected())
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

	if (!m_state->IsConnected())
		return false;

	DebugAdapter* adapter = m_state->GetAdapter();
	if (!adapter)
		return false;

	return adapter->SetActiveThread(thread);
}


std::vector<DebugThread> DebuggerThreads::GetAllThreads()
{
	std::unique_lock lock(m_threadsMutex);

	if (IsDirty())
		Update();
	return m_threads;
}


std::map<uint32_t, std::vector<DebugFrame>> DebuggerThreads::GetAllFrames()
{
	std::unique_lock lock(m_threadsMutex);

	if (IsDirty())
		Update();
	return m_frames;
}


std::vector<DebugFrame> DebuggerThreads::GetFramesOfThread(uint32_t tid)
{
	auto frame = GetAllFrames();

	auto iter = frame.find(tid);
	if (iter != frame.end())
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

	auto threads = GetAllThreads();
	auto thread = std::find_if(threads.begin(), threads.end(), [&](DebugThread const& t) {
		return t.m_tid == tid;
	});

	if (thread == threads.end())
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

	auto threads = GetAllThreads();
	auto thread = std::find_if(threads.begin(), threads.end(), [&](DebugThread const& t) {
		return t.m_tid == tid;
	});

	if (thread == threads.end())
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
	std::unique_lock lock(m_modulesMutex);
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

	std::unique_lock lock(m_modulesMutex);
	m_modules = adapter->GetModuleList();
	m_dirty = false;
}


bool DebuggerModules::GetModuleBase(const std::string& name, uint64_t& address)
{
	if (name.empty())
		return false;

	for (const DebugModule& module : GetAllModules())
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
	for (const DebugModule& module : GetAllModules())
	{
		if (module.IsSameBaseModule(name))
			return module;
	}
	return DebugModule();
}


DebugModule DebuggerModules::GetModuleForAddress(uint64_t remoteAddress)
{
	// lldb does not properly return the size of a module, so we have to find the nearest module base that is smaller
	// than the remoteAddress
	uint64_t closestAddress = 0;
	DebugModule result {};

	for (const DebugModule& module : GetAllModules())
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
	if (!relativeAddress.module.empty())
	{
		for (const DebugModule& module : GetAllModules())
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
	std::unique_lock lock(m_modulesMutex);

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
		m_enabledState[info] = true; // Enable by default
		SerializeMetadata();
	}

	return result;
}


bool DebuggerBreakpoints::AddOffset(const ModuleNameAndOffset& address)
{
	if (!ContainsOffset(address))
	{
		m_breakpoints.push_back(address);
		m_enabledState[address] = true; // Enable by default
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
		m_enabledState.erase(info); // Remove enabled state
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

		m_enabledState.erase(address); // Remove enabled state
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


bool DebuggerBreakpoints::EnableAbsolute(uint64_t remoteAddress)
{
	ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(remoteAddress);
	return EnableOffset(info);
}


bool DebuggerBreakpoints::EnableOffset(const ModuleNameAndOffset& address)
{
	if (!ContainsOffset(address))
		return false;

	m_enabledState[address] = true;
	SerializeMetadata();

	// If connected, make sure the breakpoint is active in the target
	if (m_state->GetAdapter() && m_state->IsConnected())
	{
		uint64_t remoteAddress = m_state->GetModules()->RelativeAddressToAbsolute(address);
		m_state->GetAdapter()->AddBreakpoint(remoteAddress);
		return true;
	}
	return true;
}


bool DebuggerBreakpoints::DisableAbsolute(uint64_t remoteAddress)
{
	ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(remoteAddress);
	return DisableOffset(info);
}


bool DebuggerBreakpoints::DisableOffset(const ModuleNameAndOffset& address)
{
	if (!ContainsOffset(address))
		return false;

	m_enabledState[address] = false;
	SerializeMetadata();

	// If connected, remove the breakpoint from the target but keep it in our list
	if (m_state->GetAdapter() && m_state->IsConnected())
	{
		uint64_t remoteAddress = m_state->GetModules()->RelativeAddressToAbsolute(address);
		m_state->GetAdapter()->RemoveBreakpoint(remoteAddress);
		return true;
	}
	return true;
}


bool DebuggerBreakpoints::IsEnabledAbsolute(uint64_t address)
{
	ModuleNameAndOffset info = m_state->GetModules()->AbsoluteAddressToRelative(address);
	return IsEnabledOffset(info);
}


bool DebuggerBreakpoints::IsEnabledOffset(const ModuleNameAndOffset& address)
{
	auto iter = m_enabledState.find(address);
	if (iter != m_enabledState.end())
		return iter->second;
	
	// Default to enabled if not explicitly set
	return true;
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


DebuggerMemory::DebuggerMemory(DebuggerState* state) : m_state(state)
{
}


void DebuggerMemory::PrefillValueCache()
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);
	m_valueCachePrefilled.clear();

	if (!m_state->GetController())
		return;

	auto data = m_state->GetController()->GetData();
	if (!data)
		return;

	auto ranges = data->GetBackedAddressRanges();
	for (const auto& range: ranges)
	{
		// If the range is larger than 1G, do not cache its content
		if (range.end - range.start > 1024 * 1024 * 1024)
			continue;

		m_valueCachePrefilled[range.start] = {range.end, data->ReadBuffer(range.start, range.end - range.start)};
	}
}


void DebuggerMemory::OnRebased()
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);
	// If the debugger is not active, do nothing. The pre-filled cache is only generated when starting debugging
	if (!m_state->IsConnected())
		return;

	PrefillValueCache();
	for (auto it = m_valueCache.begin(); it != m_valueCache.end();)
	{
		if (it->second.source == BackingBinaryViewSource)
		{
			it = m_valueCache.erase(it);
		}
		else
		{
			++it;
		}
	}
}


void DebuggerMemory::MarkDirty()
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);
	if (!m_state->IsConnected())
	{
		// After the target exits, discard all the memory cache
		m_valueCache.clear();
		m_valueCachePrefilled.clear();
		return;
	}

	for (auto& it: m_valueCache)
	{
		switch (it.second.status)
		{
		case UpToDateStatus:
			it.second.status = OutOfDateStatus;
			break;
		case FailedToReadStatus:
			it.second.status = DefaultStatus;
			break;
		default:
			break;
		}
	}
}


DataBuffer DebuggerMemory::ReadBlock(uint64_t block)
{
	if (!m_state->IsConnected())
		return {};

	auto iter = m_valueCache.find(block);
	if (iter != m_valueCache.end())
	{
		switch (iter->second.status)
		{
		case FailedToReadStatus:
			return {};
		case OutOfDateStatus:
		{
			if (m_state->IsRunning())
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
	if (!m_state->IsRunning())
	{
		// The cache is old and the target is stopped, try to update the cache value
		DataBuffer buffer = m_state->GetAdapter()->ReadMemory(block, 0x100);
		if (buffer.GetLength() > 0)
		{
			// Successfully updated
			m_valueCache[block] = {buffer, UpToDateStatus, PausedTargetSource};
			return buffer;
		}
	}
	else
	{
		// If the target is running, we try to read the bytes from the original binary view
		auto iter = m_valueCachePrefilled.upper_bound(block);
		if (iter != m_valueCachePrefilled.begin())
		{
			--iter;
			if ((block >= iter->first) && (block < iter->second.first))
			{
				auto offset = block - iter->first;
				auto buffer = iter->second.second.GetSlice(offset, 0x100);
				// When the bytes are readable, we return it, but also mark it as out-of-date so that they can be
				// replaced as soon as the target stops
				if (buffer.GetLength() > 0)
				{
					m_valueCache[block] = {buffer, OutOfDateStatus, BackingBinaryViewSource};
					return buffer;
				}
			}
		}
	}

	// Update failed
	m_valueCache[block] = {{}, FailedToReadStatus, NoSource};
	return {};
}


DataBuffer DebuggerMemory::ReadMemory(uint64_t offset, size_t len)
{
	std::unique_lock<std::recursive_mutex> memoryLock(m_memoryMutex);

	DataBuffer result;

	// ProcessView implements read caching in a manner inspired by CPU cache:
	// Reads are aligned on 256-byte boundaries and 256 bytes long

	// Cache read start: round down addr to nearest 256 byte boundary
	size_t cacheStart = offset & (~0xffLL);
	// Cache read end: round up addr+length to nearest 256 byte boundary
	size_t cacheEnd = (offset + len + 0xFF) & (~0xffLL);
	// List of 256-byte block addresses to read into the cache to fully cover this region
	for (uint64_t block = cacheStart; block < cacheEnd; block += 0x100)
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

	m_availableAdapters = DebugAdapterType::GetAvailableAdapters(data);
	m_adapterType = GetBestAdapter(data);
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


std::string DebuggerState::GetBestAdapter(BinaryViewRef data)
{
	// TODO: A better way to deal with this is to have the adapters return a fitness score, and then we pick the highest
	// one from the list. Similar to what we do for the views.

	// Check whether there is no available adapter at all
	if (m_availableAdapters.size() == 0)
		return "";

	// Next check the saved adapter type
	auto metadata = data->QueryMetadata("debugger.adapter_type");
	if (metadata && metadata->IsString())
	{
		auto candidateAdapter = m_adapterType = metadata->GetString();
		if (std::find(m_availableAdapters.begin(), m_availableAdapters.end(), candidateAdapter)
			!= m_availableAdapters.end())
			return candidateAdapter;
	}

	auto bestAdapterForSystem = DebugAdapterType::GetBestAdapterForCurrentSystem(data);
	if (std::find(m_availableAdapters.begin(), m_availableAdapters.end(), bestAdapterForSystem)
		!= m_availableAdapters.end())
		return bestAdapterForSystem;

	return m_availableAdapters[0];
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


void DebuggerState::EnableBreakpoint(uint64_t address)
{
	m_breakpoints->EnableAbsolute(address);
}


void DebuggerState::EnableBreakpoint(const ModuleNameAndOffset& address)
{
	m_breakpoints->EnableOffset(address);
}


void DebuggerState::DisableBreakpoint(uint64_t address)
{
	m_breakpoints->DisableAbsolute(address);
}


void DebuggerState::DisableBreakpoint(const ModuleNameAndOffset& address)
{
	m_breakpoints->DisableOffset(address);
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
	m_controller->NotifyEvent(DebuggerAdapterChangedEvent);
}


void DebuggerState::SetExecutablePath(const std::string& path)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.executablePath"))
		return;

	settings->Set("launch.executablePath", path, data, scope);
}


void DebuggerState::SetInputFile(const std::string& path)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("common.inputFile"))
		return;

	settings->Set("common.inputFile", path, data, scope);
}


void DebuggerState::SetWorkingDirectory(const std::string& directory)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.workingDirectory"))
		return;

	settings->Set("launch.workingDirectory", directory, data, scope);
}


void DebuggerState::SetCommandLineArguments(const std::string& arguments)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.commandLineArguments"))
		return;

	settings->Set("launch.commandLineArguments", arguments, data, scope);
}


void DebuggerState::SetRemoteHost(const std::string& host)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("connect.ipAddress"))
		return;

	settings->Set("connect.ipAddress", host, data, scope);
}


void DebuggerState::SetRemotePort(uint32_t port)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("connect.port"))
		return;

	settings->Set("connect.port", (uint64_t)port, data, scope);
}


void DebuggerState::SetRequestTerminalEmulator(bool requested)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.terminalEmulator"))
		return;

	settings->Set("launch.terminalEmulator", requested, data, scope);
}


void DebuggerState::SetPIDAttach(int32_t pid)
{
	if (!EnsureDebugAdapterExists())
		return;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("attach.pid"))
		return;

	settings->Set("attach.pid", (uint64_t)pid, data, scope);
}


bool DebuggerState::EnsureDebugAdapterExists()
{
	if (m_adapter)
		return true;

	// If the adapter is nullptr, try to have the controller create the debug adapter
	m_controller->CreateDebugAdapter();
	m_adapter = m_controller->GetAdapter();
	if (m_adapter)
		return true;

	return false;
}


std::string DebuggerState::GetExecutablePath()
{
	if (!EnsureDebugAdapterExists())
		return "";

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.executablePath"))
		return "";

	return settings->Get<std::string>("launch.executablePath", data, &scope);
}


std::string DebuggerState::GetInputFile()
{
	if (!EnsureDebugAdapterExists())
		return "";

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("common.inputFile"))
		return "";

	return settings->Get<std::string>("common.inputFile", data, &scope);
}


std::string DebuggerState::GetWorkingDirectory()
{
	if (!EnsureDebugAdapterExists())
		return "";

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.workingDirectory"))
		return "";

	return settings->Get<std::string>("launch.workingDirectory", data, &scope);
}


std::string DebuggerState::GetCommandLineArguments()
{
	if (!EnsureDebugAdapterExists())
		return "";

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.commandLineArguments"))
		return "";

	return settings->Get<std::string>("launch.commandLineArguments", data, &scope);
}


std::string DebuggerState::GetRemoteHost()
{
	if (!EnsureDebugAdapterExists())
		return "";

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("connect.ipAddress"))
		return "";

	return settings->Get<std::string>("connect.ipAddress", data, &scope);
}


uint32_t DebuggerState::GetRemotePort()
{
	if (!EnsureDebugAdapterExists())
		return 0;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("connect.port"))
		return 0;

	return settings->Get<uint64_t>("connect.port", data, &scope);
}


bool DebuggerState::GetRequestTerminalEmulator()
{
	if (!EnsureDebugAdapterExists())
		return false;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("launch.terminalEmulator"))
		return false;

	return settings->Get<bool>("launch.terminalEmulator", data, &scope);
}


int32_t DebuggerState::GetPIDAttach()
{
	if (!EnsureDebugAdapterExists())
		return false;

	auto settings = m_adapter->GetAdapterSettings();
	auto data = m_controller->GetData();
	auto scope = SettingsResourceScope;
	if (!settings->Contains("attach.pid"))
		return 0;

	return settings->Get<uint64_t>("attach.pid", data, &scope);
}
