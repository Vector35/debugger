#include "customdebugadapter.h"

using namespace BinaryNinjaDebugger;
using namespace BinaryNinja;
using namespace std;

CustomDebugAdapter::CustomDebugAdapter(BinaryView* data, BNDebuggerCustomDebugAdapter* adapter):
	DebugAdapter(data), m_adapter(*adapter)
{

}


CustomDebugAdapter::~CustomDebugAdapter()
{
	if (m_adapter.freeObject)
		m_adapter.freeObject(m_adapter.context);
}


bool CustomDebugAdapter::Init()
{
	if (!m_adapter.init)
		return true;
	return m_adapter.init(m_adapter.context);
}


bool CustomDebugAdapter::ExecuteWithArgs(const std::string &path, const std::string &args,
										 const std::string &workingDir,
										 const BinaryNinjaDebugger::LaunchConfigurations &configs)
{
	if (!m_adapter.executeWithArgs)
		return false;

	BNLaunchConfigurations launchConfigs;
	launchConfigs.requestTerminalEmulator = configs.requestTerminalEmulator;
	launchConfigs.inputFile = configs.inputFile.c_str();
	return m_adapter.executeWithArgs(m_adapter.context, path.c_str(), args.c_str(), workingDir.c_str(), &launchConfigs);
}


bool CustomDebugAdapter::Attach(uint32_t pid)
{
	if (!m_adapter.attach)
		return false;
	return m_adapter.attach(m_adapter.context, pid);
}


bool CustomDebugAdapter::Connect(const std::string &server, uint32_t port)
{
	if (!m_adapter.connect)
		return false;
	return m_adapter.connect(m_adapter.context, server.c_str(), port);
}


bool CustomDebugAdapter::ConnectToDebugServer(const std::string &server, uint32_t port)
{
	if (!m_adapter.connectToDebugServer)
		return false;
	return m_adapter.connectToDebugServer(m_adapter.context, server.c_str(), port);
}


bool CustomDebugAdapter::DisconnectDebugServer()
{
	if (!m_adapter.disConnectDebugServer)
		return false;
	return m_adapter.disConnectDebugServer(m_adapter.context);
}


bool CustomDebugAdapter::Detach()
{
	if (!m_adapter.detach)
		return false;
	return m_adapter.detach(m_adapter.context);
}


bool CustomDebugAdapter::Quit()
{
	if (!m_adapter.quit)
		return false;
	return m_adapter.quit(m_adapter.context);
}


std::vector<DebugProcess> CustomDebugAdapter::GetProcessList()
{
	if (!m_adapter.getProcessList)
		return {};

	size_t count = 0;
	std::vector<DebugProcess> result;

	BNDebugProcess* processes = m_adapter.getProcessList(m_adapter.context, &count);
	if (!processes || (count == 0))
		return {};

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugProcess process;
		process.m_pid = processes[i].m_pid;
		process.m_processName = processes[i].m_processName;
		result.push_back(process);
	}

	BNDebuggerFreeProcessList(processes, count);
	return result;
}


std::vector<DebugThread> CustomDebugAdapter::GetThreadList()
{
	if (!m_adapter.getThreadList)
		return {};

	size_t count = 0;
	std::vector<DebugThread> result;

	BNDebugThread* threads = m_adapter.getThreadList(m_adapter.context, &count);
	if (!threads || (count == 0))
		return {};

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugThread thread;
		thread.m_rip = threads[i].m_rip;
		thread.m_tid = threads[i].m_tid;
		thread.m_isFrozen = threads[i].m_isFrozen;
		result.push_back(thread);
	}

	BNDebuggerFreeThreads(threads, count);
	return result;
}


DebugThread CustomDebugAdapter::GetActiveThread() const
{
	if (!m_adapter.getActiveThread)
		return {};

	BNDebugThread thread = m_adapter.getActiveThread(m_adapter.context);
	DebugThread result;
	result.m_tid = thread.m_tid;
	result.m_rip = thread.m_rip;
	result.m_isFrozen = thread.m_isFrozen;
	return result;
}


uint32_t CustomDebugAdapter::GetActiveThreadId() const
{
	if (!m_adapter.getActiveThreadId)
		return 0;
	return m_adapter.getActiveThreadId(m_adapter.context);
}


bool CustomDebugAdapter::SetActiveThread(const BinaryNinjaDebugger::DebugThread &thread)
{
	if (!m_adapter.setActiveThread)
		return false;

	BNDebugThread t;
	t.m_rip = thread.m_rip;
	t.m_tid = thread.m_tid;
	t.m_isFrozen = thread.m_isFrozen;
	return m_adapter.setActiveThread(m_adapter.context, t);
}


bool CustomDebugAdapter::SetActiveThreadId(uint32_t tid)
{
	if (m_adapter.setActiveThreadId)
		return false;
	return m_adapter.setActiveThreadId(m_adapter.context, tid);
}


bool CustomDebugAdapter::SuspendThread(uint32_t tid)
{
	if (m_adapter.suspendThread)
		return false;
	return m_adapter.suspendThread(m_adapter.context, tid);
}


bool CustomDebugAdapter::ResumeThread(uint32_t tid)
{
	if (m_adapter.resumeThread)
		return false;
	return m_adapter.resumeThread(m_adapter.context, tid);
}


std::vector<DebugFrame> CustomDebugAdapter::GetFramesOfThread(uint32_t tid)
{
	if (!m_adapter.getFramesOfThread)
		return {};

	size_t count = 0;
	std::vector<DebugFrame> result;

	BNDebugFrame* frames = m_adapter.getFramesOfThread(m_adapter.context, tid, &count);
	if (!frames || (count == 0))
		return {};

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugFrame frame;
		frame.m_index = frames[i].m_index;
		frame.m_pc = frames[i].m_pc;
		frame.m_sp = frames[i].m_sp;
		frame.m_functionName = frames[i].m_functionName;
		frame.m_functionStart = frames[i].m_functionStart;
		frame.m_module = frames[i].m_module;
		result.push_back(frame);
	}

	BNDebuggerFreeFrames(frames, count);
	return result;
}


DebugBreakpoint CustomDebugAdapter::AddBreakpoint(const uint64_t address, unsigned long breakpoint_type)
{
	if (m_adapter.addBreakpointWithAddress)
		return {};

	BNDebugBreakpoint bp = m_adapter.addBreakpointWithAddress(m_adapter.context, address, breakpoint_type);
	// TODO: the structures to hold information about the breakpoints are different in the API and the core.
	// Better unify them later.
	DebugBreakpoint breakpoint;
	breakpoint.m_address = bp.address;
	breakpoint.m_is_active = true;
	breakpoint.m_id = 0;

	BNDebuggerFreeString(bp.module);
	return breakpoint;
}


DebugBreakpoint CustomDebugAdapter::AddBreakpoint(const BinaryNinjaDebugger::ModuleNameAndOffset &address,
												  unsigned long breakpoint_type)
{
	if (m_adapter.addBreakpointWithModuleAndOffset)
		return {};

	BNDebugBreakpoint bp = m_adapter.addBreakpointWithModuleAndOffset(m_adapter.context, address.module.c_str(),
																	   address.offset, breakpoint_type);
	// TODO: the structures to hold information about the breakpoints are different in the API and the core.
	// Better unify them later.
	DebugBreakpoint breakpoint;
	breakpoint.m_address = bp.address;
	breakpoint.m_is_active = true;
	breakpoint.m_id = 0;

	BNDebuggerFreeString(bp.module);
	return breakpoint;
}


bool CustomDebugAdapter::RemoveBreakpoint(const BinaryNinjaDebugger::DebugBreakpoint &breakpoint)
{
	if (!m_adapter.removeBreakpoint)
		return false;
	BNDebugBreakpoint bp;
	bp.address = breakpoint.m_address;
	return m_adapter.removeBreakpoint(m_adapter.context, bp);
}


bool CustomDebugAdapter::RemoveBreakpoint(const BinaryNinjaDebugger::ModuleNameAndOffset &address)
{
	if (!m_adapter.removeBreakpointWithModuleAndOffset)
		return false;
	return m_adapter.removeBreakpointWithModuleAndOffset(m_adapter.context, address.module.c_str(), address.offset);
}


std::vector<DebugBreakpoint> CustomDebugAdapter::GetBreakpointList() const
{
	if (!m_adapter.getBreakpointList)
		return {};

	size_t count = 0;
	std::vector<DebugBreakpoint> result;

	BNDebugBreakpoint* breakpoints = m_adapter.getBreakpointList(m_adapter.context, &count);
	if (!breakpoints || (count == 0))
		return {};

	result.reserve(count);
	for (size_t i = 0; i < count; i++)
	{
		DebugBreakpoint breakpoint;
		breakpoint.m_address = breakpoints[i].address;
		breakpoint.m_id = 0;
		breakpoint.m_is_active = true;
	}

	BNDebuggerFreeBreakpoints(breakpoints, count);
	return result;
}


std::map<std::string, DebugRegister> CustomDebugAdapter::ReadAllRegisters()
{
	if (!m_adapter.readAllRegisters)
		return {};

	size_t count = 0;
	std::map<std::string, DebugRegister> result;

	BNDebugRegister* registers = m_adapter.readAllRegisters(m_adapter.context, &count);
	if (!registers || (count == 0))
		return {};

	for (size_t i = 0; i < count; i++)
	{
		if (!registers[i].m_name)
			continue;

		DebugRegister reg;
		reg.m_value = registers[i].m_value;
		reg.m_name = registers[i].m_name;
		reg.m_hint = registers[i].m_hint;
		reg.m_registerIndex = registers[i].m_registerIndex;
		reg.m_width = registers[i].m_width;
		result[reg.m_name] = reg;
	}

	BNDebuggerFreeRegisters(registers, count);
	return result;
}


DebugRegister CustomDebugAdapter::ReadRegister(const std::string &reg)
{
	if (!m_adapter.readRegister)
		return {};
	BNDebugRegister* r = m_adapter.readRegister(m_adapter.context, reg.c_str());
	if (!r)
		return {};

	DebugRegister result;
	result.m_name = r->m_name;
	result.m_width= r->m_width;
	result.m_registerIndex = r->m_registerIndex;
	result.m_value = r->m_value;
	result.m_hint = r->m_hint;

	BNDebuggerFreeRegister(r);
	return result;
}


bool CustomDebugAdapter::WriteRegister(const std::string &reg, uint64_t value)
{
	if (!m_adapter.writeRegister)
		return false;
	return m_adapter.writeRegister(m_adapter.context, reg.c_str(), value);
}


size_t CustomDebugAdapter::ReadMemory(void* dest, uint64_t address, size_t size)
{
	if (!m_adapter.readMemory)
		return {};
	return m_adapter.readMemory(m_adapter.context, dest, address, size);
}


bool CustomDebugAdapter::WriteMemory(uint64_t address, const void* buffer, size_t size)
{
	if (!m_adapter.writeMemory)
		return false;
	return m_adapter.writeMemory(m_adapter.context, address, buffer, size);
}


std::vector<DebugModule> CustomDebugAdapter::GetModuleList()
{
	if (!m_adapter.getModuleList)
		return {};

	size_t count = 0;
	std::vector<DebugModule> result;

	BNDebugModule* modules = m_adapter.getModuleList(m_adapter.context, &count);
	if (!modules || (count == 0))
		return {};

	for (size_t i = 0; i < count; i++)
	{
		DebugModule module;
		module.m_name = modules[i].m_name;
		module.m_address = modules[i].m_address;
		module.m_loaded = modules[i].m_loaded;
		module.m_short_name = modules[i].m_short_name;
		module.m_size = modules[i].m_size;
		result.push_back(module);
	}

	BNDebuggerFreeModules(modules, count);
	return result;
}


std::string CustomDebugAdapter::GetTargetArchitecture()
{
	if (!m_adapter.getTargetArchitecture)
		return "";
	char* arch = m_adapter.getTargetArchitecture(m_adapter.context);
	if (!arch)
		return "";
	std::string result = arch;
	BNDebuggerFreeString(arch);
	return result;
}


DebugStopReason CustomDebugAdapter::StopReason()
{
	if (!m_adapter.stopReason)
		return UnknownReason;
	return m_adapter.stopReason(m_adapter.context);
}


uint64_t CustomDebugAdapter::ExitCode()
{
	if (!m_adapter.exitCode)
		return 0;
	return m_adapter.exitCode(m_adapter.context);
}


bool CustomDebugAdapter::BreakInto()
{
	if (!m_adapter.breakInto)
		return false;
	return m_adapter.breakInto(m_adapter.context);
}


bool CustomDebugAdapter::Go()
{
	if (!m_adapter.go)
		return false;
	return m_adapter.go(m_adapter.context);
}


bool CustomDebugAdapter::StepInto()
{
	if (!m_adapter.stepInto)
		return false;
	return m_adapter.stepInto(m_adapter.context);
}


bool CustomDebugAdapter::StepOver()
{
	if (!m_adapter.stepOver)
		return false;
	return m_adapter.stepOver(m_adapter.context);
}


bool CustomDebugAdapter::StepReturn()
{
	if (!m_adapter.stepReturn)
		return false;
	return m_adapter.stepReturn(m_adapter.context);
}


std::string CustomDebugAdapter::InvokeBackendCommand(const std::string &command)
{
	if (!m_adapter.invokeBackendCommand)
		return "";
	char* ret = m_adapter.invokeBackendCommand(m_adapter.context, command.c_str());
	if (!ret)
		return "";
	std::string result = ret;
	BNDebuggerFreeString(ret);
	return result;
}


uint64_t CustomDebugAdapter::GetInstructionOffset()
{
	if (!m_adapter.getInstructionOffset)
		return 0;
	return m_adapter.getInstructionOffset(m_adapter.context);
}


uint64_t CustomDebugAdapter::GetStackPointer()
{
	if (!m_adapter.getStackPointer)
		return 0;
	return m_adapter.getStackPointer(m_adapter.context);
}


bool CustomDebugAdapter::SupportFeature(BinaryNinjaDebugger::DebugAdapterCapacity feature)
{
	// TODO
	return false;
}


void CustomDebugAdapter::WriteStdin(const std::string &msg)
{
	if (!m_adapter.writeStdin)
		return;
	m_adapter.writeStdin(m_adapter.context, msg.c_str());
}


BinaryNinja::Ref<BinaryNinja::Metadata> CustomDebugAdapter::GetProperty(const std::string &name)
{
	// TODO
	return nullptr;
}


bool CustomDebugAdapter::SetProperty(const std::string &name, const BinaryNinja::Ref<BinaryNinja::Metadata> &value)
{
	// TODO
	return false;
}
