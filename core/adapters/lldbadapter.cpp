#include "lldbadapter.h"
#include "SBError.h"
#include "SBThread.h"
#include "SBFrame.h"
#include "SBAddress.h"
#include "SBLaunchInfo.h"
#include "SBBreakpoint.h"

using namespace lldb;
using namespace BinaryNinjaDebugger;

LldbAdapter::LldbAdapter(BinaryView *data): DebugAdapter(data)
{
	SBDebugger::Initialize();
	m_debugger = SBDebugger::Create();
	if (!m_debugger.IsValid())
		LogWarn("invalid debugger");
	m_debugger.SetAsync(false);
}


LldbAdapterType::LldbAdapterType(): DebugAdapterType("LLDB")
{

}


DebugAdapter* LldbAdapterType::Create(BinaryNinja::BinaryView *data)
{
	// TODO: someone should free this.
    return new LldbAdapter(data);
}


bool LldbAdapterType::IsValidForData(BinaryNinja::BinaryView *data)
{
//	it does not matter what the BinaryViewType is -- as long as we can connect to it, it is fine.
	return true;
}


bool LldbAdapterType::CanConnect(BinaryNinja::BinaryView *data)
{
//	We can connect to remote lldb on any host system
    return true;
}


bool LldbAdapterType::CanExecute(BinaryNinja::BinaryView *data)
{
    return true;
}


void BinaryNinjaDebugger::InitLldbAdapterType()
{
    static LldbAdapterType lldbType;
    DebugAdapterType::Register(&lldbType);
}


bool LldbAdapter::Execute(const std::string & path, const LaunchConfigurations & configs)
{
	return ExecuteWithArgs(path, "", configs);
}


bool LldbAdapter::ExecuteWithArgs(const std::string & path, const std::string & args, const LaunchConfigurations & configs)
{
	m_target = m_debugger.CreateTarget(path.c_str());
	if (!m_target.IsValid())
		return false;
	const char** argsArray = new const char*[2];
	argsArray[0] = path.c_str();
	argsArray[1] = nullptr;

	SBLaunchInfo info(argsArray);
	// We must set this flag; otherwise, the target will be launched, run freely, and then exit
	// TODO: check for other useful flags to set
	info.SetLaunchFlags(lldb::eLaunchFlagStopAtEntry);
	// TODO: support setting workding directory and environment
	SBError error;
	m_process = m_target.Launch(info, error);
	return m_process.IsValid() && error.Success();
}


bool LldbAdapter::Attach(std::uint32_t pid){
return false;
}bool LldbAdapter::Connect(const std::string & server, std::uint32_t port){
return false;
}

void LldbAdapter::Detach()
{
	// TODO: return if the operation succeeds
	SBError error = m_process.Detach();
}


void LldbAdapter::Quit()
{
	// TODO: return if the operation succeeds
	SBError error = m_process.Kill();
}


std::vector<DebugThread> LldbAdapter::GetThreadList()
{
	size_t threadCount = m_process.GetNumThreads();
	std::vector<DebugThread> result;
	for (size_t i = 0; i < threadCount; i++)
	{
		SBThread thread = m_process.GetThreadAtIndex(i);
		if (!thread.IsValid())
			continue;
		auto tid = thread.GetThreadID();
		uint64_t pc = 0;

		size_t frameCount = thread.GetNumFrames();
		if (frameCount > 0)
		{
			SBFrame frame = thread.GetFrameAtIndex(0);
			if (frame.IsValid())
				pc = frame.GetPC();
		}
		result.emplace_back(tid, pc);
	}
	return result;
}


DebugThread LldbAdapter::GetActiveThread() const
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return DebugThread{};

	auto tid = thread.GetThreadID();

	uint64_t pc = 0;
	size_t frameCount = thread.GetNumFrames();
	if (frameCount > 0)
	{
		SBFrame frame = thread.GetFrameAtIndex(0);
		if (frame.IsValid())
			pc = frame.GetPC();
	}

	return DebugThread(tid, pc);
}


uint32_t LldbAdapter::GetActiveThreadId() const
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return 0;

	auto tid = thread.GetThreadID();
	// TODO: we should probably change the return value to uint64_t
	return tid;
}


bool LldbAdapter::SetActiveThread(const DebugThread & thread)
{
	return SetActiveThreadId(thread.m_tid);
}


bool LldbAdapter::SetActiveThreadId(std::uint32_t tid)
{
	return m_process.SetSelectedThreadByID(tid);
}


DebugBreakpoint LldbAdapter::AddBreakpoint(const std::uintptr_t address, unsigned long breakpoint_type)
{
	SBBreakpoint bp = m_target.BreakpointCreateByAddress(address);
	if (!bp.IsValid())
		return DebugBreakpoint{};

	return DebugBreakpoint(address, bp.GetID(), bp.IsEnabled());
}


bool LldbAdapter::RemoveBreakpoint(const DebugBreakpoint & breakpoint)
{
	return m_target.BreakpointDelete(breakpoint.m_id);
}


// TODO: this should be deprecated
std::vector<DebugBreakpoint> LldbAdapter::GetBreakpointList() const
{
	return std::vector<DebugBreakpoint>();
}


std::unordered_map<std::string, DebugRegister> LldbAdapter::ReadAllRegisters()
{
	std::unordered_map<std::string, DebugRegister> result;

	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return result;

	size_t frameCount = thread.GetNumFrames();
	if (frameCount == 0)
		return result;

	SBFrame frame = thread.GetFrameAtIndex(0);
	if (!frame.IsValid())
		return result;

	SBValueList regGroups = frame.GetRegisters();
	size_t numGroups = regGroups.GetSize();
	for (size_t i = 0; i < numGroups; i++)
	{
		SBValue regGroupInfo = regGroups.GetValueAtIndex(i);
		size_t numRegs = regGroupInfo.GetNumChildren();
		for (size_t j = 0; j < numRegs; j++)
		{
			SBValue reg = regGroupInfo.GetChildAtIndex(j);
			// TODO: register width and internal index
			result[reg.GetName()] = DebugRegister(reg.GetName(), reg.GetValueAsUnsigned(), 0, 0);
		}
	}
	return result;
}


DebugRegister LldbAdapter::ReadRegister(const std::string & name)
{
	DebugRegister result{};

	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return result;

	size_t frameCount = thread.GetNumFrames();
	if (frameCount == 0)
		return result;

	SBFrame frame = thread.GetFrameAtIndex(0);
	if (!frame.IsValid())
		return result;

	SBValueList regGroups = frame.GetRegisters();
	size_t numGroups = regGroups.GetSize();
	for (size_t i = 0; i < numGroups; i++)
	{
		SBValue regGroupInfo = regGroups.GetValueAtIndex(i);
		size_t numRegs = regGroupInfo.GetNumChildren();
		for (size_t j = 0; j < numRegs; j++)
		{
			SBValue reg = regGroupInfo.GetChildAtIndex(j);
			if (name == reg.GetName())
				// TODO: register width and internal index
				return DebugRegister(name, reg.GetValueAsUnsigned(), 0, 0);
		}
	}
	return result;
}


bool LldbAdapter::WriteRegister(const std::string & name, std::uintptr_t value)
{
	SBThread thread = m_process.GetSelectedThread();
	if (!thread.IsValid())
		return false;

	size_t frameCount = thread.GetNumFrames();
	if (frameCount == 0)
		return false;

	SBFrame frame = thread.GetFrameAtIndex(0);
	if (!frame.IsValid())
		return false;

	SBValue reg = frame.FindRegister(name.c_str());
	if (!reg.IsValid())
		return false;

	SBError error;
	bool ok = reg.SetValueFromCString(fmt::format("{:X}", value).c_str(), error);
	return ok && error.Success();
}


DataBuffer LldbAdapter::ReadMemory(std::uintptr_t address, std::size_t size)
{
	auto buffer = new uint8_t[size];
	SBError error;
	size_t bytesRead = m_process.ReadMemory(address, buffer, size, error);
	DataBuffer result;
	if (bytesRead > 0 && error.Success())
	{
		result.Append(buffer, bytesRead);
	}
	delete []buffer;
	return result;
}


bool LldbAdapter::WriteMemory(std::uintptr_t address, const DataBuffer & buffer)
{
	SBError error;
	size_t bytesWritten = m_process.WriteMemory(address, buffer.GetData(), buffer.GetLength(), error);
	if ((bytesWritten == buffer.GetLength()) && error.Success())
		return true;

	return false;
}


static uint64_t GetModuleSize(SBModule& module, SBTarget& target)
{
	uint64_t largestAddress = 0;
	const size_t numSections = module.GetNumSections();
	for (size_t i = 0; i < numSections; i++)
	{
		SBSection section = module.GetSectionAtIndex(i);
		uint64_t start = section.GetLoadAddress(target);
		size_t size = section.GetByteSize();
		uint64_t end = start + size;
		if (end > largestAddress)
			largestAddress = end;
	}
	return largestAddress;
}


std::vector<DebugModule> LldbAdapter::GetModuleList()
{
	std::vector<DebugModule> result;
	size_t numModules = m_target.GetNumModules();
	for (size_t i = 0; i < numModules; i++)
	{
		SBModule module = m_target.GetModuleAtIndex(i);
		if (!module.IsValid())
			continue;

		DebugModule m;
		SBFileSpec fileSpec = module.GetFileSpec();
		char path[1024];
		size_t len = fileSpec.GetPath(path, 1024);
		m.m_name = std::string(path, len);
		m.m_short_name = fileSpec.GetFilename();
		SBAddress headerAddress = module.GetObjectFileHeaderAddress();
		m.m_address = headerAddress.GetLoadAddress(m_target);
		m.m_size = GetModuleSize(module, m_target);
		m.m_loaded = true;
		result.push_back(m);
	}
	return result;
}


std::string LldbAdapter::GetTargetArchitecture(){
return std::string();
}DebugStopReason LldbAdapter::StopReason(){
return SignalBus;
}unsigned long LldbAdapter::ExecStatus(){
return 0;
}uint64_t LldbAdapter::ExitCode(){
return 0;
}bool LldbAdapter::BreakInto(){
return false;
}DebugStopReason LldbAdapter::Go(){
return SignalBus;
}DebugStopReason LldbAdapter::StepInto(){
return SignalBus;
}DebugStopReason LldbAdapter::StepOver(){
return SignalBus;
}void LldbAdapter::Invoke(const std::string & command){

}uintptr_t LldbAdapter::GetInstructionOffset(){
return 0;
}bool LldbAdapter::SupportFeature(DebugAdapterCapacity feature){
return false;
}
