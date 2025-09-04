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

#include "customdebugadapter.h"
#include "debuggerexceptions.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

CustomDebugAdapter::CustomDebugAdapter(BinaryView* data, const BNCustomDebugAdapterCallbacks& callbacks)
	: DebugAdapter(data), m_callbacks(callbacks)
{
	INIT_DEBUGGER_API_OBJECT();
}

CustomDebugAdapter::~CustomDebugAdapter()
{
	if (m_callbacks.freeCallback && m_callbacks.context)
		m_callbacks.freeCallback(m_callbacks.context);
}

bool CustomDebugAdapter::Init()
{
	if (m_callbacks.init)
		return m_callbacks.init(m_callbacks.context);
	return true;
}

bool CustomDebugAdapter::Execute(const std::string& path, const LaunchConfigurations& configs)
{
	if (m_callbacks.execute)
		return m_callbacks.execute(m_callbacks.context, path.c_str());
	return false;
}

bool CustomDebugAdapter::ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
	const LaunchConfigurations& configs)
{
	if (m_callbacks.executeWithArgs)
		return m_callbacks.executeWithArgs(m_callbacks.context, path.c_str(), args.c_str(), workingDir.c_str());
	return false;
}

bool CustomDebugAdapter::Attach(std::uint32_t pid)
{
	if (m_callbacks.attach)
		return m_callbacks.attach(m_callbacks.context, pid);
	return false;
}

bool CustomDebugAdapter::Connect(const std::string& server, std::uint32_t port)
{
	if (m_callbacks.connect)
		return m_callbacks.connect(m_callbacks.context, server.c_str(), port);
	return false;
}

bool CustomDebugAdapter::ConnectToDebugServer(const std::string& server, std::uint32_t port)
{
	if (m_callbacks.connectToDebugServer)
		return m_callbacks.connectToDebugServer(m_callbacks.context, server.c_str(), port);
	return false;
}

bool CustomDebugAdapter::Detach()
{
	if (m_callbacks.detach)
		return m_callbacks.detach(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::Quit()
{
	if (m_callbacks.quit)
		return m_callbacks.quit(m_callbacks.context);
	return false;
}

std::vector<DebugProcess> CustomDebugAdapter::GetProcessList()
{
	if (m_callbacks.getProcessList)
	{
		size_t count;
		BNDebugProcess* processes = m_callbacks.getProcessList(m_callbacks.context, &count);
		if (!processes)
			return {};

		std::vector<DebugProcess> result;
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			result.emplace_back(processes[i].m_pid, std::string(processes[i].m_processName ? processes[i].m_processName : ""));
		}

		// Free the returned data
		for (size_t i = 0; i < count; i++)
		{
			if (processes[i].m_processName)
				BNDebuggerFreeString(processes[i].m_processName);
		}
		delete[] processes;
		return result;
	}
	return {};
}

std::vector<DebugThread> CustomDebugAdapter::GetThreadList()
{
	if (m_callbacks.getThreadList)
	{
		size_t count;
		BNDebugThread* threads = m_callbacks.getThreadList(m_callbacks.context, &count);
		if (!threads)
			return {};

		std::vector<DebugThread> result;
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			result.emplace_back(threads[i].m_tid, threads[i].m_rip);
		}

		delete[] threads;
		return result;
	}
	return {};
}

DebugThread CustomDebugAdapter::GetActiveThread() const
{
	if (m_callbacks.getActiveThread)
	{
		BNDebugThread thread = m_callbacks.getActiveThread(m_callbacks.context);
		return ConvertDebugThread(thread);
	}
	return DebugThread();
}

std::uint32_t CustomDebugAdapter::GetActiveThreadId() const
{
	if (m_callbacks.getActiveThreadId)
		return m_callbacks.getActiveThreadId(m_callbacks.context);
	return 0;
}

bool CustomDebugAdapter::SetActiveThread(const DebugThread& thread)
{
	if (m_callbacks.setActiveThread)
	{
		BNDebugThread bnThread = ConvertDebugThread(thread);
		return m_callbacks.setActiveThread(m_callbacks.context, bnThread);
	}
	return false;
}

bool CustomDebugAdapter::SetActiveThreadId(std::uint32_t tid)
{
	if (m_callbacks.setActiveThreadId)
		return m_callbacks.setActiveThreadId(m_callbacks.context, tid);
	return false;
}

bool CustomDebugAdapter::SuspendThread(std::uint32_t tid)
{
	if (m_callbacks.suspendThread)
		return m_callbacks.suspendThread(m_callbacks.context, tid);
	return false;
}

bool CustomDebugAdapter::ResumeThread(std::uint32_t tid)
{
	if (m_callbacks.resumeThread)
		return m_callbacks.resumeThread(m_callbacks.context, tid);
	return false;
}

DebugBreakpoint CustomDebugAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
	if (m_callbacks.addBreakpoint)
	{
		BNDebugBreakpoint bp = m_callbacks.addBreakpoint(m_callbacks.context, address);
		return ConvertDebugBreakpoint(bp);
	}
	return DebugBreakpoint();
}

DebugBreakpoint CustomDebugAdapter::AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type)
{
	if (m_callbacks.addBreakpointRelative)
	{
		BNDebugBreakpoint bp = m_callbacks.addBreakpointRelative(m_callbacks.context, 
			address.module.c_str(), address.offset);
		return ConvertDebugBreakpoint(bp);
	}
	return DebugBreakpoint();
}

bool CustomDebugAdapter::RemoveBreakpoint(const DebugBreakpoint& breakpoint)
{
	if (m_callbacks.removeBreakpoint)
		return m_callbacks.removeBreakpoint(m_callbacks.context, breakpoint.m_address);
	return false;
}

bool CustomDebugAdapter::RemoveBreakpoint(const ModuleNameAndOffset& address)
{
	if (m_callbacks.removeBreakpointRelative)
		return m_callbacks.removeBreakpointRelative(m_callbacks.context, address.module.c_str(), address.offset);
	return false;
}

std::vector<DebugBreakpoint> CustomDebugAdapter::GetBreakpointList() const
{
	if (m_callbacks.getBreakpointList)
	{
		size_t count;
		BNDebugBreakpoint* breakpoints = m_callbacks.getBreakpointList(m_callbacks.context, &count);
		if (!breakpoints)
			return {};

		std::vector<DebugBreakpoint> result;
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			result.push_back(ConvertDebugBreakpoint(breakpoints[i]));
		}

		// Free the returned data
		for (size_t i = 0; i < count; i++)
		{
			if (breakpoints[i].module)
				BNDebuggerFreeString(breakpoints[i].module);
		}
		delete[] breakpoints;
		return result;
	}
	return {};
}

std::unordered_map<std::string, DebugRegister> CustomDebugAdapter::ReadAllRegisters()
{
	if (m_callbacks.readAllRegisters)
	{
		size_t count;
		BNDebugRegister* registers = m_callbacks.readAllRegisters(m_callbacks.context, &count);
		if (!registers)
			return {};

		std::unordered_map<std::string, DebugRegister> result;
		for (size_t i = 0; i < count; i++)
		{
			std::string name = registers[i].m_name ? registers[i].m_name : "";
			std::string hint = registers[i].m_hint ? registers[i].m_hint : "";
			intx::uint512 value = intx::le::load<intx::uint512>(registers[i].m_value);
			
			result[name] = DebugRegister(name, value, registers[i].m_width, registers[i].m_registerIndex);
			result[name].m_hint = hint;
		}

		// Free the returned data
		for (size_t i = 0; i < count; i++)
		{
			if (registers[i].m_name)
				BNDebuggerFreeString(registers[i].m_name);
			if (registers[i].m_hint)
				BNDebuggerFreeString(registers[i].m_hint);
		}
		delete[] registers;
		return result;
	}
	return {};
}

DebugRegister CustomDebugAdapter::ReadRegister(const std::string& reg)
{
	if (m_callbacks.readRegister)
	{
		BNDebugRegister bnReg = m_callbacks.readRegister(m_callbacks.context, reg.c_str());
		std::string name = bnReg.m_name ? bnReg.m_name : "";
		std::string hint = bnReg.m_hint ? bnReg.m_hint : "";
		intx::uint512 value = intx::le::load<intx::uint512>(bnReg.m_value);

		DebugRegister result(name, value, bnReg.m_width, bnReg.m_registerIndex);
		result.m_hint = hint;

		// Free the returned data
		if (bnReg.m_name)
			BNDebuggerFreeString(bnReg.m_name);
		if (bnReg.m_hint)
			BNDebuggerFreeString(bnReg.m_hint);

		return result;
	}
	return DebugRegister();
}

bool CustomDebugAdapter::WriteRegister(const std::string& reg, intx::uint512 value)
{
	if (m_callbacks.writeRegister)
	{
		uint8_t buffer[64];
		intx::le::store(buffer, value);
		return m_callbacks.writeRegister(m_callbacks.context, reg.c_str(), buffer);
	}
	return false;
}

DataBuffer CustomDebugAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	if (m_callbacks.readMemory)
	{
		BNDataBuffer* buffer = m_callbacks.readMemory(m_callbacks.context, address, size);
		if (!buffer)
			return DataBuffer();

		DataBuffer result(buffer);
		return result;
	}
	return DataBuffer();
}

bool CustomDebugAdapter::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	if (m_callbacks.writeMemory)
	{
		// Create a BNDataBuffer from the DataBuffer
		BNDataBuffer* bnBuffer = BNCreateDataBuffer(buffer.GetData(), buffer.GetLength());
		bool result = m_callbacks.writeMemory(m_callbacks.context, address, bnBuffer);
		BNFreeDataBuffer(bnBuffer);
		return result;
	}
	return false;
}

std::vector<DebugModule> CustomDebugAdapter::GetModuleList()
{
	if (m_callbacks.getModuleList)
	{
		size_t count;
		BNDebugModule* modules = m_callbacks.getModuleList(m_callbacks.context, &count);
		if (!modules)
			return {};

		std::vector<DebugModule> result;
		result.reserve(count);
		for (size_t i = 0; i < count; i++)
		{
			std::string name = modules[i].m_name ? modules[i].m_name : "";
			std::string shortName = modules[i].m_short_name ? modules[i].m_short_name : "";
			result.emplace_back(name, shortName, modules[i].m_address, modules[i].m_size, modules[i].m_loaded);
		}

		// Free the returned data
		for (size_t i = 0; i < count; i++)
		{
			if (modules[i].m_name)
				BNDebuggerFreeString(modules[i].m_name);
			if (modules[i].m_short_name)
				BNDebuggerFreeString(modules[i].m_short_name);
		}
		delete[] modules;
		return result;
	}
	return {};
}

std::string CustomDebugAdapter::GetTargetArchitecture()
{
	if (m_callbacks.getTargetArchitecture)
	{
		char* arch = m_callbacks.getTargetArchitecture(m_callbacks.context);
		if (!arch)
			return "";
		
		std::string result(arch);
		BNDebuggerFreeString(arch);
		return result;
	}
	return "";
}

DebugStopReason CustomDebugAdapter::StopReason()
{
	if (m_callbacks.stopReason)
		return static_cast<DebugStopReason>(m_callbacks.stopReason(m_callbacks.context));
	return UnknownStopReason;
}

uint64_t CustomDebugAdapter::ExitCode()
{
	if (m_callbacks.exitCode)
		return m_callbacks.exitCode(m_callbacks.context);
	return 0;
}

bool CustomDebugAdapter::BreakInto()
{
	if (m_callbacks.breakInto)
		return m_callbacks.breakInto(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::Go()
{
	if (m_callbacks.go)
		return m_callbacks.go(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::GoReverse()
{
	if (m_callbacks.goReverse)
		return m_callbacks.goReverse(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::StepInto()
{
	if (m_callbacks.stepInto)
		return m_callbacks.stepInto(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::StepIntoReverse()
{
	if (m_callbacks.stepIntoReverse)
		return m_callbacks.stepIntoReverse(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::StepOver()
{
	if (m_callbacks.stepOver)
		return m_callbacks.stepOver(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::StepOverReverse()
{
	if (m_callbacks.stepOverReverse)
		return m_callbacks.stepOverReverse(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::StepReturn()
{
	if (m_callbacks.stepReturn)
		return m_callbacks.stepReturn(m_callbacks.context);
	return false;
}

bool CustomDebugAdapter::StepReturnReverse()
{
	if (m_callbacks.stepReturnReverse)
		return m_callbacks.stepReturnReverse(m_callbacks.context);
	return false;
}

std::string CustomDebugAdapter::InvokeBackendCommand(const std::string& command)
{
	if (m_callbacks.invokeBackendCommand)
	{
		char* result = m_callbacks.invokeBackendCommand(m_callbacks.context, command.c_str());
		if (!result)
			return "";
		
		std::string resultStr(result);
		BNDebuggerFreeString(result);
		return resultStr;
	}
	return "";
}

uint64_t CustomDebugAdapter::GetInstructionOffset()
{
	if (m_callbacks.getInstructionOffset)
		return m_callbacks.getInstructionOffset(m_callbacks.context);
	return 0;
}

uint64_t CustomDebugAdapter::GetStackPointer()
{
	if (m_callbacks.getStackPointer)
		return m_callbacks.getStackPointer(m_callbacks.context);
	return 0;
}

bool CustomDebugAdapter::SupportFeature(DebugAdapterCapacity feature)
{
	if (m_callbacks.supportFeature)
		return m_callbacks.supportFeature(m_callbacks.context, static_cast<uint32_t>(feature));
	return false;
}

void CustomDebugAdapter::WriteStdin(const std::string& msg)
{
	if (m_callbacks.writeStdin)
		m_callbacks.writeStdin(m_callbacks.context, msg.c_str());
}

BinaryNinja::Ref<BinaryNinja::Metadata> CustomDebugAdapter::GetProperty(const std::string& name)
{
	if (m_callbacks.getProperty)
	{
		BNMetadata* metadata = m_callbacks.getProperty(m_callbacks.context, name.c_str());
		if (metadata)
			return new Metadata(BNNewMetadataReference(metadata));
	}
	return nullptr;
}

bool CustomDebugAdapter::SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value)
{
	if (m_callbacks.setProperty)
		return m_callbacks.setProperty(m_callbacks.context, name.c_str(), value->GetObject());
	return false;
}

Ref<Settings> CustomDebugAdapter::GetAdapterSettings()
{
	if (m_callbacks.getAdapterSettings)
	{
		BNSettings* settings = m_callbacks.getAdapterSettings(m_callbacks.context);
		if (settings)
			return new Settings(BNNewSettingsReference(settings));
	}
	return nullptr;
}

// Helper conversion functions
BNDebugThread CustomDebugAdapter::ConvertDebugThread(const DebugThread& thread) const
{
	BNDebugThread result;
	result.m_tid = thread.m_tid;
	result.m_rip = thread.m_rip;
	result.m_isFrozen = thread.m_isFrozen;
	return result;
}

DebugThread CustomDebugAdapter::ConvertDebugThread(const BNDebugThread& thread) const
{
	DebugThread result;
	result.m_tid = thread.m_tid;
	result.m_rip = thread.m_rip;
	result.m_isFrozen = thread.m_isFrozen;
	return result;
}

BNDebugBreakpoint CustomDebugAdapter::ConvertDebugBreakpoint(const DebugBreakpoint& bp) const
{
	BNDebugBreakpoint result;
	result.address = bp.m_address;
	result.enabled = bp.m_is_active;
	result.module = nullptr;  // Will be filled by the caller if needed
	result.offset = 0;
	return result;
}

DebugBreakpoint CustomDebugAdapter::ConvertDebugBreakpoint(const BNDebugBreakpoint& bp) const
{
	return DebugBreakpoint(bp.address, 0, bp.enabled);
}

// CustomDebugAdapterType implementation
CustomDebugAdapterType::CustomDebugAdapterType(const std::string& name, const BNCustomDebugAdapterTypeCallbacks& callbacks)
	: DebugAdapterType(name), m_callbacks(callbacks)
{
	INIT_DEBUGGER_API_OBJECT();
}

CustomDebugAdapterType::~CustomDebugAdapterType()
{
	if (m_callbacks.freeCallback && m_callbacks.context)
		m_callbacks.freeCallback(m_callbacks.context);
}

DebugAdapter* CustomDebugAdapterType::Create(BinaryNinja::BinaryView* data)
{
	if (m_callbacks.create)
	{
		BNCustomDebugAdapter* adapter = m_callbacks.create(m_callbacks.context, data->GetObject());
		if (adapter)
			return adapter->object;
	}
	return nullptr;
}

bool CustomDebugAdapterType::IsValidForData(BinaryNinja::BinaryView* data)
{
	if (m_callbacks.isValidForData)
		return m_callbacks.isValidForData(m_callbacks.context, data->GetObject());
	return true;  // Default to valid for all data
}

bool CustomDebugAdapterType::CanExecute(BinaryNinja::BinaryView* data)
{
	if (m_callbacks.canExecute)
		return m_callbacks.canExecute(m_callbacks.context, data->GetObject());
	return false;  // Default to cannot execute
}

bool CustomDebugAdapterType::CanConnect(BinaryNinja::BinaryView* data)
{
	if (m_callbacks.canConnect)
		return m_callbacks.canConnect(m_callbacks.context, data->GetObject());
	return false;  // Default to cannot connect
}