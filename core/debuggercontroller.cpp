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

#include "debuggercontroller.h"
#include <thread>
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "highlevelilinstruction.h"
#include "debuggerfileaccessor.h"

using namespace BinaryNinjaDebugger;

DebuggerController::DebuggerController(BinaryViewRef data): BinaryDataNotification(Rebased)
{
	INIT_DEBUGGER_API_OBJECT();

	m_file = data->GetFile();
	m_data = data;
	m_data->RegisterNotification(this);
	m_viewStart = m_data->GetStart();

	m_state = new DebuggerState(data, this);
	m_adapter = nullptr;
	m_shouldAnnotateStackVariable = Settings::Instance()->Get<bool>("debugger.stackVariableAnnotations");
	RegisterEventCallback([this](const DebuggerEvent& event) { EventHandler(event); }, "Debugger Core");

	m_debuggerEventThread = std::thread([&]{ DebuggerMainThread(); });
}


DebuggerController::~DebuggerController()
{
	m_shouldExit = true;
	m_cv.notify_all();
	if (m_debuggerEventThread.joinable())
		m_debuggerEventThread.join();

	m_data->UnregisterNotification(this);
	m_file = nullptr;

	if (m_state)
	{
		delete m_state;
		m_state = nullptr;
	}
}


void DebuggerController::AddBreakpoint(uint64_t address)
{
	m_state->AddBreakpoint(address);
	DebuggerEvent event;
	event.type = AbsoluteBreakpointAddedEvent;
	event.data.absoluteAddress = address;
	PostDebuggerEvent(event);
}


void DebuggerController::AddBreakpoint(const ModuleNameAndOffset& address)
{
	m_state->AddBreakpoint(address);
	DebuggerEvent event;
	event.type = RelativeBreakpointAddedEvent;
	event.data.relativeAddress = address;
	PostDebuggerEvent(event);
}


void DebuggerController::DeleteBreakpoint(uint64_t address)
{
	m_state->DeleteBreakpoint(address);
	DebuggerEvent event;
	event.type = AbsoluteBreakpointRemovedEvent;
	event.data.absoluteAddress = address;
	PostDebuggerEvent(event);
}


void DebuggerController::DeleteBreakpoint(const ModuleNameAndOffset& address)
{
	m_state->DeleteBreakpoint(address);
	DebuggerEvent event;
	event.type = RelativeBreakpointRemovedEvent;
	event.data.relativeAddress = address;
	PostDebuggerEvent(event);
}


bool DebuggerController::SetIP(uint64_t address)
{
	std::string ipRegisterName;
	std::string targetArch = GetRemoteArchitecture()->GetName();

	if ((targetArch == "x86") || (targetArch == "i386"))
		ipRegisterName = "eip";
	else if (targetArch == "x86_64")
		ipRegisterName = "rip";
	else if ((targetArch == "aarch64") || (targetArch == "arm64"))
		ipRegisterName = "pc";
	else
		ipRegisterName = "pc";

	if (!SetRegisterValue(ipRegisterName, address))
		return false;

	// This allows the thread frame widget to update properly
	m_state->GetThreads()->MarkDirty();

	return true;
}


bool DebuggerController::Launch()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return false;

	std::thread([&]() { LaunchAndWait(); }).detach();
	return true;
}


DebugStopReason DebuggerController::LaunchAndWaitInternal()
{
	m_userRequestedBreak = false;

	if (Settings::Instance()->Get<bool>("debugger.safeMode"))
	{
		DebuggerEvent event;
		event.type = LaunchFailureEventType;
		event.data.errorData.shortError = "Safe mode enabled";
		event.data.errorData.error =
			fmt::format("Cannot launch the target because the debugger is in safe mode.");
		PostDebuggerEvent(event);
		return InternalError;
	}

	m_firstLaunch = false;

	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	if (!CreateDebugAdapter())
		return InternalError;

	m_inputFileLoaded = false;
	m_initialBreakpointSeen	 = false;
	m_state->MarkDirty();
	if (!CreateDebuggerBinaryView())
		return InternalError;

	return ExecuteAdapterAndWait(DebugAdapterLaunch);
}


DebugStopReason DebuggerController::LaunchAndWait()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = LaunchAndWaitInternal();
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


bool DebuggerController::Attach()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return false;

	std::thread([&]() { AttachAndWait(); }).detach();
	return true;
}


DebugStopReason DebuggerController::AttachAndWaitInternal()
{
	m_firstAttach = false;
	m_userRequestedBreak = false;

	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	if (!CreateDebugAdapter())
		return InternalError;

	m_inputFileLoaded = false;
	m_initialBreakpointSeen	 = false;
	m_state->MarkDirty();
	if (!CreateDebuggerBinaryView())
		return InternalError;

	return ExecuteAdapterAndWait(DebugAdapterAttach);
}


DebugStopReason DebuggerController::AttachAndWait()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = AttachAndWaitInternal();
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


bool DebuggerController::Connect()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return false;

	std::thread([&]() { ConnectAndWait(); }).detach();
	return true;
}


DebugStopReason DebuggerController::ConnectAndWaitInternal()
{
	m_firstConnect = false;
	m_userRequestedBreak = false;

	DebuggerEvent event;
	event.type = LaunchEventType;
	PostDebuggerEvent(event);

	if (!CreateDebugAdapter())
		return InternalError;

	m_inputFileLoaded = false;
	m_initialBreakpointSeen	 = false;
	m_state->MarkDirty();
	if (!CreateDebuggerBinaryView())
		return InternalError;

	return ExecuteAdapterAndWait(DebugAdapterConnect);
}


DebugStopReason DebuggerController::ConnectAndWait()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanStartDebgging())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = ConnectAndWaitInternal();
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


bool DebuggerController::Execute()
{
	std::unique_lock<std::recursive_mutex> lock(m_targetControlMutex);

	std::string filePath = m_state->GetExecutablePath();
	bool requestTerminal = m_state->GetRequestTerminalEmulator();
	LaunchConfigurations configs = {requestTerminal, m_state->GetInputFile(), m_state->IsConnectedToDebugServer()};

#ifdef WIN32
	/* temporary solution (not great, sorry!), we probably won't have to do this once we introduce std::filesystem::path */
	std::replace(filePath.begin(), filePath.end(), '/', '\\');
#endif

	return m_adapter->ExecuteWithArgs(
		filePath, m_state->GetCommandLineArguments(), m_state->GetWorkingDirectory(), configs);
}


bool DebuggerController::CreateDebugAdapter()
{
	// The current adapter type is the same as the last one, and the last adapter is still valid
	if (m_state->GetAdapterType() == m_lastAdapterName && m_adapter != nullptr)
	{
		ApplyBreakpoints();
		return true;
	}

	DebugAdapterType* type = DebugAdapterType::GetByName(m_state->GetAdapterType());
	if (!type)
	{
		LogWarn("Failed to get an debug adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
	}
	m_adapter = type->Create(GetData());
	if (!m_adapter)
	{
		LogWarn("Failed to create an adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
	}

	if (!m_adapter->Init())
	{
		LogWarn("Failed to init an adapter of type %s", m_state->GetAdapterType().c_str());
		return false;
	}

	m_lastAdapterName = m_state->GetAdapterType();
	m_state->SetAdapter(m_adapter);
	// This is a very hacky way to let the adapter have a handle to the controller, and then be able to access the
	// Binary View object
	m_adapter->SetController(this);

	m_adapterSupportsStepOver = m_adapter->SupportFeature(DebugAdapterSupportStepOver);
	m_adapterSupportsStepOverReverse = m_adapter->SupportFeature(DebugAdapterSupportStepOverReverse);
	m_adapterSupportsTTD = m_adapter->SupportFeature(DebugAdapterSupportTTD);

	ApplyBreakpoints();

	// Forward the DebuggerEvent from the adapters to the controller
	m_adapter->SetEventCallback([this](const DebuggerEvent& event) { PostDebuggerEvent(event); });
	return true;
}


// Apply all breakpoints that are added before the adapter is created
void DebuggerController::ApplyBreakpoints()
{
	m_state->ApplyBreakpoints();
}


bool DebuggerController::CanStartDebgging()
{
	return !m_state->IsConnected();
}


bool DebuggerController::CanResumeTarget()
{
	return m_state->IsConnected() && (!m_state->IsRunning());
}


bool DebuggerController::ExpectSingleStep(DebugStopReason reason)
{
	//	On macOS, the stop reason we get for a single step is also the Breakpoint.
	//	To keep things working, we loosen the check.
	//	TODO: check how it works on other systems
	return (reason == SingleStep) || (reason == Breakpoint) || (reason == UnknownReason);
}


bool DebuggerController::Go()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	std::thread([&]() { GoAndWait(); }).detach();

	return true;
}

bool DebuggerController::GoReverse()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	std::thread([&]() { GoReverseAndWait(); }).detach();

	return true;
}


DebugStopReason DebuggerController::GoAndWait()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = GoAndWaitInternal();
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}

DebugStopReason DebuggerController::GoReverseAndWait()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = GoReverseAndWaitInternal();
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


DebugStopReason DebuggerController::StepIntoIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepIntoAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("step into unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}


DebugStopReason DebuggerController::StepIntoReverseIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepIntoReverseAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepIntoReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("step into unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}


DebugStopReason DebuggerController::StepIntoReverseAndWaitInternal()
{
	m_userRequestedBreak = false;
	// TODO: check if StepInto() succeeds
	return ExecuteAdapterAndWait(DebugAdapterStepIntoReverse);
}

bool DebuggerController::StepInto(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	std::thread([&, il]() { StepIntoAndWait(il); }).detach();

	return true;
}

bool DebuggerController::StepIntoReverse(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	std::thread([&, il]() { StepIntoReverseAndWait(il); }).detach();

	return true;
}

DebugStopReason DebuggerController::StepIntoReverseAndWait(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = StepIntoReverseIL(il);
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}

DebugStopReason DebuggerController::StepIntoAndWait(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = StepIntoIL(il);
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}

DebugStopReason DebuggerController::StepOverIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepOverAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;
			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("step over unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}

DebugStopReason DebuggerController::StepOverReverseIL(BNFunctionGraphType il)
{
	switch (il)
	{
	case NormalFunctionGraph:
	{
		return StepOverReverseAndWaitInternal();
	}
	case LowLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				LowLevelILFunctionRef llil = func->GetLowLevelILIfAvailable();
				if (!llil)
					return SingleStep;

				size_t start = llil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < llil->GetInstructionCount())
				{
					if (llil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case MediumLevelILFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;
			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				MediumLevelILFunctionRef mlil = func->GetMediumLevelILIfAvailable();
				if (!mlil)
					return SingleStep;

				size_t start = mlil->GetInstructionStart(GetData()->GetDefaultArchitecture(), newRemoteRip);
				if (start < mlil->GetInstructionCount())
				{
					if (mlil->GetInstruction(start).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	case HighLevelILFunctionGraph:
	case HighLevelLanguageRepresentationFunctionGraph:
	{
		// TODO: This might cause infinite loop
		while (true)
		{
			DebugStopReason reason = StepOverReverseAndWaitInternal();
			if (!ExpectSingleStep(reason))
				return reason;

			uint64_t newRemoteRip = m_state->IP();
			std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(newRemoteRip);
			if (functions.empty())
				return SingleStep;

			for (FunctionRef& func : functions)
			{
				HighLevelILFunctionRef hlil = func->GetHighLevelILIfAvailable();
				if (!hlil)
					return SingleStep;

				for (size_t i = 0; i < hlil->GetInstructionCount(); i++)
				{
					if (hlil->GetInstruction(i).address == newRemoteRip)
						return SingleStep;
				}
			}
		}
		break;
	}
	default:
		LogWarn("reverse step over unimplemented in the current il type");
		return InvalidStatusOrOperation;
	}
}


bool DebuggerController::StepOver(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	std::thread([&, il]() { StepOverAndWait(il); }).detach();

	return true;
}


bool DebuggerController::StepOverReverse(BNFunctionGraphType il)
{
	if (!CanResumeTarget())
		return false;

	std::thread([&, il]() { StepOverReverseAndWait(il); }).detach();

	return true;
}


DebugStopReason DebuggerController::StepOverAndWait(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = StepOverIL(il);
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


DebugStopReason DebuggerController::StepOverReverseAndWait(BNFunctionGraphType il)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = StepOverReverseIL(il);
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


DebugStopReason DebuggerController::EmulateStepReturnAndWait()
{
	uint64_t address = m_state->IP();
	std::vector<FunctionRef> functions = GetData()->GetAnalysisFunctionsContainingAddress(address);
	if (functions.empty())
		return InternalError;

	std::vector<uint64_t> returnAddresses;
	FunctionRef function = functions[0];
	MediumLevelILFunctionRef mlilFunc = function->GetMediumLevelIL();
	for (size_t i = 0; i < mlilFunc->GetInstructionCount(); i++)
	{
		MediumLevelILInstruction instruction = mlilFunc->GetInstruction(i);
		if ((instruction.operation == MLIL_RET) || (instruction.operation == MLIL_TAILCALL))
			returnAddresses.push_back(instruction.address);
	}

	return RunToAndWaitInternal(returnAddresses);
}


DebugStopReason DebuggerController::StepReturnAndWaitInternal()
{
	m_userRequestedBreak = false;

	if (true /* StepReturnAvailable() */)
	{
		return ExecuteAdapterAndWait(DebugAdapterStepReturn);
	}
	else
	{
		// Emulate a step over
		return EmulateStepReturnAndWait();
	}
}


DebugStopReason DebuggerController::StepReturnReverseAndWaitInternal()
{
	m_userRequestedBreak = false;

	if (true /* StepReturnReverseAvailable() */)
	{
		return ExecuteAdapterAndWait(DebugAdapterStepReturnReverse);
	}
}


bool DebuggerController::StepReturn()
{
	if (!CanResumeTarget())
		return false;

	std::thread([&]() { StepReturnAndWait(); }).detach();

	return true;
}


bool DebuggerController::StepReturnReverse()
{
	if (!CanResumeTarget())
		return false;

	std::thread([&]() { StepReturnReverseAndWait(); }).detach();

	return true;
}


DebugStopReason DebuggerController::StepReturnAndWait()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = StepReturnAndWaitInternal();
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


DebugStopReason DebuggerController::StepReturnReverseAndWait()
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = StepReturnReverseAndWaitInternal();
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


DebugStopReason DebuggerController::RunToAndWaitInternal(const std::vector<uint64_t>& remoteAddresses)
{
	m_userRequestedBreak = false;

	for (uint64_t remoteAddress : remoteAddresses)
	{
		if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
		{
			m_adapter->AddBreakpoint(remoteAddress);
		}
	}

	auto reason = GoAndWaitInternal();

	for (uint64_t remoteAddress : remoteAddresses)
	{
		if (!m_state->GetBreakpoints()->ContainsAbsolute(remoteAddress))
		{
			m_adapter->RemoveBreakpoint(remoteAddress);
		}
	}

	NotifyStopped(reason);
	return reason;
}


bool DebuggerController::RunTo(const std::vector<uint64_t>& remoteAddresses)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return false;

	std::thread([&, remoteAddresses]() { RunToAndWait(remoteAddresses); }).detach();

	return true;
}


DebugStopReason DebuggerController::RunToAndWait(const std::vector<uint64_t>& remoteAddresses)
{
	// This is an API function of the debugger. We only do these checks at the API level.
	if (!CanResumeTarget())
		return InvalidStatusOrOperation;

	if (!m_targetControlMutex.try_lock())
		return InternalError;

	auto reason = RunToAndWaitInternal(remoteAddresses);
	if (!m_userRequestedBreak && (reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);

	m_targetControlMutex.unlock();
	return reason;
}


bool DebuggerController::CreateDebuggerBinaryView()
{
	BinaryViewRef data = GetData();
	auto segment = data->GetSegmentAt(0);
	m_zeroSegmentAddedByDebugger = segment == nullptr;

	if (auto holdAnalysis = Settings::Instance()->Get<bool>("debugger.holdAnalysis"); holdAnalysis)
	{
		auto analysisProgress = data->GetAnalysisProgress();
		m_oldAnalysisState = analysisProgress.state;
		data->SetAnalysisHold(true);
	}

	m_state->GetMemory()->PrefillValueCache();

	m_accessor = new DebuggerFileAccessor(data);
	data->SetFunctionAnalysisUpdateDisabled(true);
	data->GetMemoryMap()->AddRemoteMemoryRegion("debugger", 0, m_accessor);
	data->SetFunctionAnalysisUpdateDisabled(false);


	return true;
}


void DebuggerController::DetectLoadedModule()
{
	// Rebase the binary and create DebugView
	uint64_t remoteBase;
	// Right now we only support applying the analysis info from one module into the debugger view, So we use a bool
	// here. In the future, we would like to support loading multiple modules, and we will need a more
	// robust mechanism.
	if (m_inputFileLoaded || (!m_state->GetRemoteBase(remoteBase)))
		return;

	m_inputFileLoaded = true;
	auto oldBase = GetViewFileSegmentsStart();
	if (remoteBase == oldBase)
		return;

	m_ranges.clear();
	m_oldViewBase = oldBase;
	m_newViewBase = remoteBase;
	auto data = GetData();
	for (const auto& func: data->GetAnalysisFunctionList())
	{
		for (const auto& range: func->GetAddressRanges())
			m_ranges.emplace_back(range);
	}

	if (BinaryNinja::IsUIEnabled())
	{
		// When the UI is enabled, let the debugger UI do the work. It can show a progress bar if the operation takes
		// a while.
		if (m_uiCallbacks)
			m_uiCallbacks->NotifyRebaseBinaryView(remoteBase);
	}
	else
	{
		// Halt analysis before rebasing. Otherwise, the old view may continue analysis which leads to various issues
		data->AbortAnalysis();
		data->UpdateAnalysisAndWait();

		RemoveDebuggerMemoryRegion();

		auto shouldHoldAnalysis = Settings::Instance()->Get<bool>("debugger.holdAnalysis");
		if (shouldHoldAnalysis)
			data->SetAnalysisHold(false);

		// remote base is different from the local base, first need a rebase
		auto viewType = data->GetTypeName();
		if (!m_file->Rebase(data, remoteBase, [&](size_t cur, size_t total) { return true; }))
		{
			LogWarn("rebase failed");
		}
		auto rebasedView = m_file->GetViewOfType(viewType);
		if (!rebasedView)
			return;

		if (shouldHoldAnalysis)
		{
			static auto completionEvent = rebasedView->AddAnalysisCompletionEvent([=](){
				rebasedView->SetAnalysisHold(true);
			});
			rebasedView->UpdateAnalysis();
		}

		ReAddDebuggerMemoryRegion();
	}

	GetData()->UpdateAnalysis();
}


DebugThread DebuggerController::GetActiveThread() const
{
	return m_state->GetThreads()->GetActiveThread();
}


void DebuggerController::SetActiveThread(const DebugThread& thread)
{
	// TODO: check if the new thread is the same as the old one. If so, do nothing and return
	m_state->GetThreads()->SetActiveThread(thread);
	// We only need to update the register values after we switch to a different thread
	m_state->GetRegisters()->Update();
	// Post an event so the stack view can get updated
	DebuggerEvent event;
	event.type = ActiveThreadChangedEvent;
	PostDebuggerEvent(event);
}


bool DebuggerController::SuspendThread(std::uint32_t tid)
{
	auto result = m_state->GetThreads()->SuspendThread(tid);
	if (!result)
		return false;

	DebuggerEvent event;
	event.type = ThreadStateChangedEvent;
	PostDebuggerEvent(event);

	return result;
}

bool DebuggerController::ResumeThread(std::uint32_t tid)
{
	auto result = m_state->GetThreads()->ResumeThread(tid);
	if (!result)
		return false;

	DebuggerEvent event;
	event.type = ThreadStateChangedEvent;
	PostDebuggerEvent(event);

	return result;
}


std::vector<DebugFrame> DebuggerController::GetFramesOfThread(uint64_t tid)
{
	return m_state->GetThreads()->GetFramesOfThread(tid);
}


bool DebuggerController::Restart()
{
	if (!m_state->IsConnected())
		return false;

	std::thread([&]() { RestartAndWait(); }).detach();
	return true;
}


DebugStopReason DebuggerController::RestartAndWait()
{
	if (!m_state->IsConnected())
		return InvalidStatusOrOperation;

	QuitAndWait();
	return LaunchAndWait();
}


bool DebuggerController::ConnectToDebugServer()
{
	m_firstConnectToDebugServer = false;
	if (m_state->IsConnectedToDebugServer())
		return true;

	if (!CreateDebugAdapter())
		return false;

	bool ok = m_adapter->ConnectToDebugServer(m_state->GetRemoteHost(), m_state->GetRemotePort());
	if (!ok)
		LogWarn("Failed to connect to the debug server");
	else
		m_state->SetConnectedToDebugServer(true);

	return ok;
}


bool DebuggerController::DisconnectDebugServer()
{
	if (!m_state->IsConnectedToDebugServer())
		return true;

	bool ok = m_adapter->DisconnectDebugServer();
	if (!ok)
		LogWarn("Failed to disconnect from the debug server");
	else
		m_state->SetConnectedToDebugServer(false);

	return ok;
}


bool DebuggerController::IsConnectedToDebugServer()
{
	return m_state->IsConnectedToDebugServer();
}


void DebuggerController::Detach()
{
	if (!m_state->IsConnected())
		return;

	std::thread([&]() { DetachAndWait(); }).detach();
}


void DebuggerController::DetachAndWait()
{
	bool locked = false;
	if (m_targetControlMutex.try_lock())
		locked = true;

	if (!m_state->IsConnected())
		return;

	// TODO: return whether the operation is successful
	ExecuteAdapterAndWait(DebugAdapterDetach);

	// There is no need to notify a detached event at this point, since the detach event is already processed
	// by all the callback

	if (locked)
		m_targetControlMutex.unlock();
}


void DebuggerController::Quit()
{
	if (!m_state->IsConnected())
		return;

	std::thread([&]() { QuitAndWait(); }).detach();
}


void DebuggerController::QuitAndWait()
{
	bool locked = false;
	if (m_targetControlMutex.try_lock())
		locked = true;

	if (!m_state->IsConnected())
		return;

	if (m_state->IsRunning())
	{
		// We must pause the target if it is currently running, at least for DbgEngAdapter
		PauseAndWait();
	}

	// TODO: return whether the operation is successful
	ExecuteAdapterAndWait(DebugAdapterQuit);

	// There is no need to notify a TargetExitedEvent at this point, since the exit event is already processed
	// by all the callback

	if (locked)
		m_targetControlMutex.unlock();
}


bool DebuggerController::Pause()
{
	if (!m_state->IsConnected())
		return false;

	std::thread([&]() { PauseAndWait(); }).detach();

	return true;
}


DebugStopReason DebuggerController::PauseAndWaitInternal()
{
	m_userRequestedBreak = true;
	return ExecuteAdapterAndWait(DebugAdapterPause);
}


DebugStopReason DebuggerController::PauseAndWait()
{
	if (!m_state->IsConnected())
		return InvalidStatusOrOperation;

	auto reason = PauseAndWaitInternal();
	if ((reason != ProcessExited) && (reason != InternalError))
		NotifyStopped(reason);
	return reason;
}


DebugStopReason DebuggerController::GoAndWaitInternal()
{
	m_userRequestedBreak = false;
	return ExecuteAdapterAndWait(DebugAdapterGo);
}

DebugStopReason DebuggerController::GoReverseAndWaitInternal()
{
	m_userRequestedBreak = false;
	return ExecuteAdapterAndWait(DebugAdapterGoReverse);
}


DebugStopReason DebuggerController::StepIntoAndWaitInternal()
{
	m_userRequestedBreak = false;
	// TODO: check if StepInto() succeeds
	return ExecuteAdapterAndWait(DebugAdapterStepInto);
}


DebugStopReason DebuggerController::EmulateStepOverAndWait()
{
	uint64_t remoteIP = m_state->IP();

	// TODO: support the case where we cannot determined the remote arch
	ArchitectureRef remoteArch = m_state->GetRemoteArchitecture();
	if (!remoteArch)
		return InternalError;

	size_t size = remoteArch->GetMaxInstructionLength();
	DataBuffer buffer = m_adapter->ReadMemory(remoteIP, size);
	size_t bytesRead = buffer.GetLength();

	Ref<LowLevelILFunction> ilFunc = new LowLevelILFunction(remoteArch, nullptr);
	ilFunc->SetCurrentAddress(remoteArch, remoteIP);
	remoteArch->GetInstructionLowLevelIL((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, *ilFunc);

	if (ilFunc->GetInstructionCount() == 0)
		return InternalError;

	const auto& instr = (*ilFunc)[0];
	if (instr.operation != LLIL_CALL)
	{
		return StepIntoAndWaitInternal();
	}
	else
	{
		InstructionInfo info;
		if (!remoteArch->GetInstructionInfo((const uint8_t*)buffer.GetData(), remoteIP, bytesRead, info))
		{
			// Whenever there is a failure, we fail back to step into
			return StepIntoAndWaitInternal();
		}

		if (info.length == 0)
		{
			return StepIntoAndWaitInternal();
		}

		uint64_t remoteIPNext = remoteIP + info.length;
		return RunToAndWaitInternal({remoteIPNext});
	}
}

DebugStopReason DebuggerController::EmulateStepOverReverseAndWait()
{
	// This cannot be implemented here unless we have hardware breakpoint supports
	LogWarn("EmulateStepOverReverseAndWait() is not implemented");
	return InternalError;
}

DebugStopReason DebuggerController::StepOverAndWaitInternal()
{
	m_userRequestedBreak = false;

	if (m_adapterSupportsStepOver)
	{
		return ExecuteAdapterAndWait(DebugAdapterStepOver);
	}
	else
	{
		// Emulate a step over
		return EmulateStepOverAndWait();
	}
}

DebugStopReason DebuggerController::StepOverReverseAndWaitInternal()
{
	m_userRequestedBreak = false;

	if (m_adapterSupportsStepOverReverse)
	{
		return ExecuteAdapterAndWait(DebugAdapterStepOverReverse);
	}
	else
	{
		// Emulate a step over reverse
		return EmulateStepOverReverseAndWait();
	}
}


void DebuggerController::LaunchOrConnect()
{
	std::string adapter = m_state->GetAdapterType();
	auto adapterType = DebugAdapterType::GetByName(adapter);
	if (!adapterType)
		return;

	if (adapterType->CanExecute(GetData()))
		Launch();
	else if (adapterType->CanConnect(GetData()))
		Connect();
}


// Can't use a vector here as initialization order is not guaranteed.
DbgRef<DebuggerController>* DebuggerController::g_debuggerControllers = nullptr;
size_t DebuggerController::g_controllerCount = 0;


DbgRef<DebuggerController> DebuggerController::GetController(BinaryViewRef data)
{
	for (size_t i = 0; i < g_controllerCount; i++)
	{
		DebuggerController* controller = g_debuggerControllers[i];
		if (!controller)
			continue;
		if (controller->m_file == data->GetFile())
			return controller;
	}

	auto controller = new DebuggerController(data);
	g_debuggerControllers = (DbgRef<DebuggerController>*)realloc(g_debuggerControllers,
							sizeof(DbgRef<DebuggerController>) * (g_controllerCount + 1));

	// We must call the DbgRef ctor on the newly allocated space explicitly. If we do a
	// g_debuggerControllers[g_controllerCount] = controller;
	// The `=` operator on the next line will cause a call to `DbgRef<T>& operator=(T* obj)` on an uninitialized DbgRef
	// object, leading to a crash when `DbgRef::m_obj` is de-referenced.
	// In fact, this is how std::vector does things inside `push_back`.
	new (&g_debuggerControllers[g_controllerCount]) DbgRef<DebuggerController>(controller);
	g_controllerCount++;
	return controller;
}


void DebuggerController::DeleteController(BinaryViewRef data)
{
	for (size_t i = 0; i < g_controllerCount; i++)
	{
		DbgRef<DebuggerController> controller = g_debuggerControllers[i];
		if (!controller)
			continue;

		if (controller->GetData() == data)
		{
			g_debuggerControllers[i] = nullptr;
		}
	}
}


bool DebuggerController::ControllerExists(BinaryViewRef data)
{
	for (size_t i = 0; i < g_controllerCount; i++)
	{
		DbgRef<DebuggerController> controller = g_debuggerControllers[i];
		if (!controller)
			continue;
		if (controller->GetData() == data)
			return true;
	}

	return false;
}


DbgRef<DebuggerController> DebuggerController::GetController(FileMetadataRef file)
{
	for (size_t i = 0; i < g_controllerCount; i++)
	{
		DebuggerController* controller = g_debuggerControllers[i];
		if (!controller)
			continue;
		if (controller->GetFile() == file)
			return controller;
	}

	// You cannot create a controller from a file -- you must use a binary view for it
	return nullptr;
}


bool DebuggerController::ControllerExists(FileMetadataRef file)
{
	for (size_t i = 0; i < g_controllerCount; i++)
	{
		DbgRef<DebuggerController> controller = g_debuggerControllers[i];
		if (!controller)
			continue;
		if (controller->GetFile() == file)
			return true;
	}

	return false;
}


void DebuggerController::DeleteController(FileMetadataRef file)
{
	for (size_t i = 0; i < g_controllerCount; i++)
	{
		DbgRef<DebuggerController> controller = g_debuggerControllers[i];
		if (!controller)
			continue;

		if (controller->GetFile() == file)
		{
			g_debuggerControllers[i] = nullptr;
		}
	}
}


void DebuggerController::Destroy()
{
	// Contrary to the name, DebuggerController::Destroy() actually only removes the object from the global debugger
	// controller array (g_debuggerControllers). This enabling its ref count to go down to zero and eventually get freed.
	// The actual cleanup happens in DebuggerController::~DebuggerController().
	// TODO: I should change the function name later
	DebuggerController::DeleteController(m_file);
}


// This is the central hub of event dispatch. All events first arrive here and then get dispatched based on the content
void DebuggerController::EventHandler(const DebuggerEvent& event)
{
	switch (event.type)
	{
	case LaunchEventType:
	case ResumeEventType:
	case StepIntoEventType:
	{
		// Todo: this is just a temporary workaround. Otherwise, the connection status would not be set properly
		m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterRunningStatus);
		break;
	}
	case TargetExitedEventType:
		m_exitCode = event.data.exitData.exitCode;
	case DetachedEventType:
	case LaunchFailureEventType:
	{
		m_state->SetConnectionStatus(DebugAdapterNotConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterInvalidStatus);
		m_state->MarkDirty();
		m_inputFileLoaded = false;
		m_initialBreakpointSeen = false;
		RemoveDebuggerMemoryRegion();
		if (m_oldAnalysisState != HoldState)
		{
			m_data->SetAnalysisHold(false);
		}

		if (m_accessor)
		{
			delete m_accessor;
			m_accessor = nullptr;
		}
		m_lastIP = m_currentIP;
		m_currentIP = 0;
		break;
	}
	case TargetStoppedEventType:
	{
		m_state->SetConnectionStatus(DebugAdapterConnectedStatus);
		m_state->SetExecutionStatus(DebugAdapterPausedStatus);
		m_state->MarkDirty();
		m_state->UpdateCaches();
		m_lastIP = m_currentIP;
		m_currentIP = m_state->IP();
		m_ranges.clear();

		DetectLoadedModule();
		UpdateStackVariables();
		AddRegisterValuesToExpressionParser();
		break;
	}
	case ActiveThreadChangedEvent:
	{
		m_state->UpdateCaches();
		m_lastIP = m_currentIP;
		m_currentIP = m_state->IP();
		AddRegisterValuesToExpressionParser();
		break;
	}
	case RegisterChangedEvent:
	{
		m_lastIP = m_currentIP;
		m_currentIP = m_state->IP();
		AddRegisterValuesToExpressionParser();
		break;
	}
	case ErrorEventType:
	{
		LogError("%s", event.data.errorData.error.c_str());
		break;
	}
	default:
		break;
	}
}


size_t DebuggerController::RegisterEventCallback(
	std::function<void(const DebuggerEvent&)> callback, const std::string& name)
{
	std::unique_lock lock(m_callbackMutex);
	DebuggerEventCallback object;
	object.function = callback;
	object.index = m_callbackIndex++;
	object.name = name;
	m_eventCallbacks.push_back(object);
	return object.index;
}


bool DebuggerController::RemoveEventCallback(size_t index)
{
	std::unique_lock lock(m_callbackMutex);
	for (auto it = m_eventCallbacks.begin(); it != m_eventCallbacks.end(); it++)
	{
		if (it->index == index)
		{
			// It is fine to directly remove the callback from m_eventCallbacks. Because in DebuggerMainThread, the
			// code makes a copy of the events before trying to dispatch them.
			// The reason that we need m_disabledCallbacks is because during dispatching of an earlier event, the code
			// may lead to the deletion of a later event. In that case, the change is not reflected on the copy of the
			// list, so we must look up the index in m_disabledCallbacks before dispatching them
			m_disabledCallbacks.insert(index);
			m_eventCallbacks.erase(it);
			return true;
		}
	}
	return false;
}


bool DebuggerController::RemoveEventCallbackInternal(size_t index)
{
	for (auto it = m_eventCallbacks.begin(); it != m_eventCallbacks.end(); it++)
	{
		if (it->index == index)
		{
			m_eventCallbacks.erase(it);
			return true;
		}
	}
	return false;
}


// The design goal here is:
// 1. The PostDebuggerEvent is blocking, i.e., it only returns when the event has been processed. This is important for
// ensuring proper internal state updates. The only exception is that when a new debugger event is posted from one of
// the callbacks (the caller is already in the dispatcher loop), then PostDebuggerEvent will only queue the event but
// not block on it. Because doing so will cause a deadlock.
// 2. Thread-safe. Any thread can call PostDebuggerEvent and not cause unexpected behavior
// 3. Re-entrant safe. PostDebuggerEvent can be called within a callback, and there would not be chaos. But at the same
// time, as mentioned above, when it is re-entered from the dispatcher loop, the call is non-blocking. This means that
// in DebuggerController::DetectLoadedModule(), the code cannot post a ModuleLoadedEvent and block on it. Instead, a
// direct callback must be used to inform the UI to perform the rebase, and then the core can continue its processing

void DebuggerController::PostDebuggerEvent(const DebuggerEvent& event)
{
	auto pending = std::make_shared<PendingEvent>();
	pending->event = event;
	std::future<void> future = pending->done.get_future();

	{
		std::lock_guard lock(m_eventsMutex);
		m_eventQueue.push(pending);
	}
	m_cv.notify_one();

	if (std::this_thread::get_id() == m_dispatcherThreadId)
	{
		// Posting a new debugger event from a callback should be *fine*, but it will also be non-blocking, so we should
		// be aware of that
		LogWarn("A debugger event with type %d is posted from the dispatcher thread and is unexpected", event.type);
	}
	else
	{
		// Block until the event is handled (unless this is the dispatcher thread)
		future.get();
	}
}


void DebuggerController::DebuggerMainThread()
{
	m_shouldExit = false;
	m_dispatcherThreadId = std::this_thread::get_id();

	while (true)
	{
		std::shared_ptr<PendingEvent> current;
		std::unique_lock lock(m_eventsMutex);
		m_cv.wait(lock, [&] { return !m_eventQueue.empty() || m_shouldExit; });

		if (m_shouldExit && m_eventQueue.empty())
			break;

		current = m_eventQueue.front();
		m_eventQueue.pop();
		lock.unlock();

		std::unique_lock callbackLock(m_callbackMutex);
		std::list<DebuggerEventCallback> eventCallbacks = m_eventCallbacks;
		callbackLock.unlock();

		auto event = current->event;
		if (event.type == AdapterStoppedEventType)
			m_lastAdapterStopEventConsumed = false;

		DebuggerEvent eventToSend = event;
		if ((eventToSend.type == TargetStoppedEventType) && !m_initialBreakpointSeen)
		{
			m_initialBreakpointSeen = true;
			eventToSend.data.targetStoppedData.reason = InitialBreakpoint;
		}

		for (const DebuggerEventCallback& cb : eventCallbacks)
		{
			std::unique_lock callbackLock2(m_callbackMutex);
			if (m_disabledCallbacks.find(cb.index) != m_disabledCallbacks.end())
				continue;

			callbackLock2.unlock();
			cb.function(eventToSend);
		}

		// If the current event is an AdapterStoppedEvent, and it is not consumed by any callback, then the adapter
		// stop is not caused by the debugger core. This can happen when the user run a "ni" command directly.
		// Notify a target stop reason in this case.
		if (event.type == AdapterStoppedEventType && !m_lastAdapterStopEventConsumed)
		{
			DebuggerEvent stopEvent = event;
			stopEvent.type = TargetStoppedEventType;
			if (!m_initialBreakpointSeen)
			{
				m_initialBreakpointSeen = true;
				stopEvent.data.targetStoppedData.reason = InitialBreakpoint;
			}
			for (const DebuggerEventCallback& cb : eventCallbacks)
			{
				std::unique_lock callbackLock2(m_callbackMutex);
				if (m_disabledCallbacks.find(cb.index) != m_disabledCallbacks.end())
					continue;

				callbackLock2.unlock();
				cb.function(stopEvent);
			}
		}

		CleanUpDisabledEvent();
		current->done.set_value();
	}
}


void DebuggerController::CleanUpDisabledEvent()
{
	std::unique_lock lock(m_callbackMutex);
	// We only need to clear the vector of index here because the entries in m_eventCallbacks have already been
	// deleted by RemoveEventCallback
	m_disabledCallbacks.clear();
}


void DebuggerController::NotifyStopped(DebugStopReason reason, void* data)
{
	DebuggerEvent event;
	event.type = TargetStoppedEventType;
	event.data.targetStoppedData.reason = reason;
	event.data.targetStoppedData.data = data;
	PostDebuggerEvent(event);
}


void DebuggerController::NotifyError(const std::string& error, const std::string& shortError, void* data)
{
	DebuggerEvent event;
	event.type = ErrorEventType;
	event.data.errorData.error = error;
	event.data.errorData.shortError = shortError;
	event.data.errorData.data = data;
	PostDebuggerEvent(event);
}


void DebuggerController::NotifyEvent(DebuggerEventType eventType)
{
	DebuggerEvent event;
	event.type = eventType;
	PostDebuggerEvent(event);
}


// We should call these two function instead of DebugAdapter::ReadMemory(), which will skip the memory cache
DataBuffer DebuggerController::ReadMemory(std::uintptr_t address, std::size_t size)
{
	if (!GetData())
		return DataBuffer {};

	if (!m_state->IsConnected())
		return DataBuffer {};

	DebuggerMemory* memory = m_state->GetMemory();
	if (!memory)
		return DataBuffer {};

	return memory->ReadMemory(address, size);
}


bool DebuggerController::WriteMemory(std::uintptr_t address, const DataBuffer& buffer)
{
	if (!GetData())
		return false;

	if (!m_state->IsConnected())
		return false;

	if (m_state->IsRunning())
		return false;

	DebuggerMemory* memory = m_state->GetMemory();
	if (!memory)
		return false;

	return memory->WriteMemory(address, buffer);
}


std::vector<DebugModule> DebuggerController::GetAllModules()
{
	return m_state->GetModules()->GetAllModules();
}

std::vector<DebugProcess> DebuggerController::GetProcessList()
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return {};
	}

	return m_adapter->GetProcessList();
}


std::vector<DebugThread> DebuggerController::GetAllThreads()
{
	return m_state->GetThreads()->GetAllThreads();
}


std::vector<DebugRegister> DebuggerController::GetAllRegisters()
{
	return m_state->GetRegisters()->GetAllRegisters();
}


intx::uint512 DebuggerController::GetRegisterValue(const std::string& name)
{
	return m_state->GetRegisters()->GetRegisterValue(name);
}


bool DebuggerController::SetRegisterValue(const std::string& name, intx::uint512 value)
{
	return m_state->GetRegisters()->SetRegisterValue(name, value);
}


DebugAdapterTargetStatus DebuggerController::GetExecutionStatus()
{
	return m_state->GetTargetStatus();
}


DebugAdapterConnectionStatus DebuggerController::GetConnectionStatus()
{
	return m_state->GetConnectionStatus();
}


ArchitectureRef DebuggerController::GetRemoteArchitecture()
{
	return m_state->GetRemoteArchitecture();
}


uint32_t DebuggerController::GetExitCode()
{
	return m_exitCode;
}


void DebuggerController::WriteStdIn(const std::string message)
{
	if (m_adapter && m_state->IsRunning())
	{
		m_adapter->WriteStdin(message);
	}
	else
	{
		NotifyError("Cannot send to stdin, target is not running", "Cannot send to stdin, target is not running");
	}
}


std::string DebuggerController::InvokeBackendCommand(const std::string& cmd)
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return "Error: invalid adapter\n";
	}

	if (m_adapter)
	{
		std::string cmdToSend = cmd;
		if (cmdToSend.empty())
			cmdToSend = m_lastCommand;
		else
			m_lastCommand = cmdToSend;

		return m_adapter->InvokeBackendCommand(cmdToSend);
	}

	return "Error: invalid adapter\n";
}


void DebuggerController::ProcessOneVariable(uint64_t varAddress, Confidence<Ref<Type>> type, const std::string& name)
{
	StackVariableNameAndType varNameAndType(type, name);
	auto iter = m_debuggerVariables.find(varAddress);
	if ((iter == m_debuggerVariables.end()) || (iter->second != varNameAndType))
	{
		// The variable is not yet defined, or has changed. Define it.
		// Should we use DataVariable, or UserDataVariable?
		GetData()->DefineDataVariable(varAddress, type);
		if (!name.empty())
		{
			SymbolRef sym = new BinaryNinja::Symbol(DataSymbol, name, name, name, varAddress);
			GetData()->DefineUserSymbol(sym);
		}
		m_debuggerVariables[varAddress] = varNameAndType;
	}

	m_addressesWithVariable.insert(varAddress);

	// If there is still a data variable at varAddress, we remove it from the oldAddresses set.
	// After we process all data variables, values in the set oldAddresses means where there was a data var,
	// but there no longer should be one. Later we iterate over it and remove all data vars and symbols at
	// these addresses.
	auto iter2 = m_oldAddresses.find(varAddress);
	if (iter2 != m_oldAddresses.end())
		m_oldAddresses.erase(iter2);
}


void DebuggerController::DefineVariablesRecursive(uint64_t address, Confidence<Ref<Type>> type)
{
	size_t addressSize = GetData()->GetAddressSize();
	if (type->IsPointer())
	{
		auto reader = BinaryReader(GetData());
		reader.Seek(address);
		uint64_t targetAddress = 0;
		bool readOk = false;
		if (addressSize == 8)
		{
			readOk = reader.TryRead64(targetAddress);
		}
		else if (addressSize == 4)
		{
			uint32_t addr;
			readOk = reader.TryRead32(addr);
			if (readOk)
				targetAddress = addr;
		}
		if (readOk)
		{
			// Define a data variable for the child
			ProcessOneVariable(targetAddress, type->GetChildType(), "");
			// Recurse into the child
			DefineVariablesRecursive(targetAddress, type->GetChildType());
		}
	}
	else if (type->IsStructure())
	{
		auto structure = type->GetStructure();
		auto members = structure->GetMembers();
		auto memberType = type->GetChildType();
		for (size_t i = 0; i < members.size(); i++)
		{
			uint64_t memberOffset = address + members[i].offset;
			DefineVariablesRecursive(memberOffset, members[i].type);
		}
	}
	else if (type->IsArray())
	{
		auto memberType = type->GetChildType();
		for (size_t i = 0; i < type->GetElementCount(); i++)
		{
			uint64_t memberOffset = address + i * memberType->GetWidth();
			DefineVariablesRecursive(memberOffset, memberType);
		}
	}
}


void DebuggerController::UpdateStackVariables()
{
	if (!m_shouldAnnotateStackVariable)
		return;

	if (!GetData())
		return;

	auto id = GetData()->BeginUndoActions();
	std::vector<DebugThread> threads = GetAllThreads();
	uint64_t frameAdjustment = 0;
	if (!GetData()->GetDefaultArchitecture())
		return;

	std::string archName = GetData()->GetDefaultArchitecture()->GetName();
	if ((archName == "x86") || (archName == "x86_64"))
		frameAdjustment = 8;

	m_oldAddresses = m_addressesWithVariable;
	m_addressesWithVariable.clear();
	auto oldAddressWithComment = m_addressesWithComment;
	m_addressesWithComment.clear();

	const DebugThread thread = GetActiveThread();
	std::vector<DebugFrame> frames = GetFramesOfThread(thread.m_tid);
	if (frames.size() >= 2)
	{
		for (size_t i = 0; i < frames.size() - 1; i++)
		{
			const DebugFrame& frame = frames[i];
			const DebugFrame& prevFrame = frames[i + 1];
			// If there is no function at a stacktrace function start, add one
			auto functions = GetData()->GetAnalysisFunctionsForAddress(frame.m_functionStart);
			if (functions.empty())
				continue;

			FunctionRef func = functions[0];

			auto vars = func->GetVariables();
			// BN's variable storage offset is calculated against the entry status of the function, i.e.,
			// before the current stack frame is created. Here we take the stack pointer of the previous stack frame,
			// and subtract the size of return address from it
			uint64_t framePointer = prevFrame.m_sp - frameAdjustment;
			for (const auto& [var, varNameAndType] : vars)
			{
				if (var.type != StackVariableSourceType)
					continue;

				uint64_t varAddress = framePointer + var.storage;
				ProcessOneVariable(varAddress, varNameAndType.type, varNameAndType.name);
				DefineVariablesRecursive(varAddress, varNameAndType.type);
			}
		}

		for (const DebugFrame& frame : frames)
		{
			// Annotate the stack pointer and the frame pointer, using the current stack frame
			GetData()->SetCommentForAddress(frame.m_sp, fmt::format("Stack #{}\n====================", frame.m_index));
			GetData()->SetCommentForAddress(frame.m_fp, fmt::format("Frame #{}", frame.m_index));
			m_addressesWithComment.insert(frame.m_sp);
			m_addressesWithComment.insert(frame.m_fp);

			auto iter2 = oldAddressWithComment.find(frame.m_sp);
			if (iter2 != oldAddressWithComment.end())
				oldAddressWithComment.erase(iter2);

			iter2 = oldAddressWithComment.find(frame.m_fp);
			if (iter2 != oldAddressWithComment.end())
				oldAddressWithComment.erase(iter2);
		}
	}

	for (uint64_t address : m_oldAddresses)
	{
		auto iter = m_addressesWithVariable.find(address);
		if (iter != m_addressesWithVariable.end())
			m_addressesWithVariable.erase(iter);

		GetData()->UndefineDataVariable(address);
		auto symbol = GetData()->GetSymbolByAddress(address);
		if (symbol)
			GetData()->UndefineUserSymbol(symbol);
	}

	for (uint64_t address : oldAddressWithComment)
	{
		GetData()->SetCommentForAddress(address, "");
	}
	GetData()->ForgetUndoActions(id);
}


void DebuggerController::AddRegisterValuesToExpressionParser()
{
	auto regs = GetAllRegisters();
	std::vector<std::string> names;
	names.reserve(regs.size());
	std::vector<uint64_t> values;
	values.reserve(regs.size());

	for (const auto& reg: regs)
	{
		names.push_back(std::string(reg.m_name));
		values.emplace_back(reg.m_value);
	}

	GetData()->AddExpressionParserMagicValues(names, values);
}


std::string DebuggerController::GetStopReasonString(DebugStopReason reason)
{
	switch (reason)
	{
	case UnknownReason:
		return "UnknownReason";
	case InitialBreakpoint:
		return "InitialBreakpoint";
	case ProcessExited:
		return "ProcessExited";
	case AccessViolation:
		return "AccessViolation";
	case SingleStep:
		return "SingleStep";
	case Calculation:
		return "Calculation";
	case Breakpoint:
		return "Breakpoint";
	case IllegalInstruction:
		return "IllegalInstruction";
	case SignalHup:
		return "SignalHup";
	case SignalInt:
		return "SignalInt";
	case SignalQuit:
		return "SignalQuit";
	case SignalIll:
		return "SignalIll";
	case SignalAbrt:
		return "SignalAbrt";
	case SignalEmt:
		return "SignalEmt";
	case SignalFpe:
		return "SignalFpe";
	case SignalKill:
		return "SignalKill";
	case SignalBus:
		return "SignalBus";
	case SignalSegv:
		return "SignalSegv";
	case SignalSys:
		return "SignalSys";
	case SignalPipe:
		return "SignalPipe";
	case SignalAlrm:
		return "SignalAlrm";
	case SignalTerm:
		return "SignalTerm";
	case SignalUrg:
		return "SignalUrg";
	case SignalStop:
		return "SignalStop";
	case SignalTstp:
		return "SignalTstp";
	case SignalCont:
		return "SignalCont";
	case SignalChld:
		return "SignalChld";
	case SignalTtin:
		return "SignalTtin";
	case SignalTtou:
		return "SignalTtou";
	case SignalIo:
		return "SignalIo";
	case SignalXcpu:
		return "SignalXcpu";
	case SignalXfsz:
		return "SignalXfsz";
	case SignalVtalrm:
		return "SignalVtalrm";
	case SignalProf:
		return "SignalProf";
	case SignalWinch:
		return "SignalWinch";
	case SignalInfo:
		return "SignalInfo";
	case SignalUsr1:
		return "SignalUsr1";
	case SignalUsr2:
		return "SignalUsr2";
	case SignalStkflt:
		return "SignalStkflt";
	case SignalBux:
		return "SignalBux";
	case SignalPoll:
		return "SignalPoll";
	case ExcEmulation:
		return "ExcEmulation";
	case ExcSoftware:
		return "ExcSoftware";
	case ExcSyscall:
		return "ExcSyscall";
	case ExcMachSyscall:
		return "ExcMachSyscall";
	case ExcRpcAlert:
		return "ExcRpcAlert";
	case ExcCrash:
		return "ExcCrash";
	case InternalError:
		return "InternalError";
	case InvalidStatusOrOperation:
		return "InvalidStatusOrOperation";
	case UserRequestedBreak:
		return "UserRequestedBreak";
	case OperationNotSupported:
		return "OperationNotSupported";
	default:
		return "";
	}
}


DebugStopReason DebuggerController::StopReason() const
{
	if (!m_adapter)
		return UnknownReason;

	return m_adapter->StopReason();
}


DebugStopReason DebuggerController::ExecuteAdapterAndWait(const DebugAdapterOperation operation)
{
	// Due to the nature of the wait, this mutex should NOT be allowed to be locked recursively.
	// If this is a pause operation, do not try to lock the mutex -- it is mostly likely held by another thread
	if ((operation != DebugAdapterPause) && (operation != DebugAdapterQuit) && (operation != DebugAdapterDetach))
	{
		if (!m_adapterMutex.try_lock())
		{
			LogWarn("Cannot obtain mutex1 for debug adapter, operation: %d", operation);
			return InternalError;
		}
	}
	else
	{
		if (!m_adapterMutex2.try_lock())
		{
			LogWarn("Cannot obtain mutex2 for debug adapter, operation: %d", operation);
			return InternalError;
		}
	}

	Semaphore sem;
	DebugStopReason reason = UnknownReason;
	size_t callback = RegisterEventCallback(
		[&](const DebuggerEvent& event) {
			switch (event.type)
			{
			case AdapterStoppedEventType:
				reason = event.data.targetStoppedData.reason;
				sem.Release();
				break;
			// It is a little awkward to add two cases for these events, but we must take them into account,
			// since after we resume the target, the target can either or exit.
			case TargetExitedEventType:
			case DetachedEventType:
				// There is no DebugStopReason for "detach", so we use ProcessExited for now
				reason = ProcessExited;
				sem.Release();
				break;
			default:
				break;
			}
			m_lastAdapterStopEventConsumed = true;
		},
		"WaitForAdapterStop");

	bool resumeOK = false;
	bool operationRequested = false;
	switch (operation)
	{
	case DebugAdapterGo:
		resumeOK = m_adapter->Go();
		break;
	case DebugAdapterGoReverse:
        resumeOK = m_adapter->GoReverse();
        break;
	case DebugAdapterStepInto:
		resumeOK = m_adapter->StepInto();
		break;
	case DebugAdapterStepIntoReverse:
        resumeOK = m_adapter->StepIntoReverse();
        break;
	case DebugAdapterStepOver:
		resumeOK = m_adapter->StepOver();
		break;
	case DebugAdapterStepOverReverse:
        resumeOK = m_adapter->StepOverReverse();
        break;
	case DebugAdapterStepReturn:
		resumeOK = m_adapter->StepReturn();
		break;
	case DebugAdapterStepReturnReverse:
		resumeOK = m_adapter->StepReturnReverse();
		break;
	case DebugAdapterPause:
		operationRequested = m_adapter->BreakInto();
		break;
	case DebugAdapterQuit:
		operationRequested = m_adapter->Quit();
		break;
	case DebugAdapterDetach:
		operationRequested = m_adapter->Detach();
		break;
	case DebugAdapterLaunch:
		resumeOK = Execute();
		break;
	case DebugAdapterAttach:
		resumeOK = m_adapter->Attach(m_state->GetPIDAttach());
		break;
	case DebugAdapterConnect:
		resumeOK = m_adapter->Connect(m_state->GetRemoteHost(), m_state->GetRemotePort());
		break;
	default:
		break;
	}

	bool ok = false;
	if ((operation == DebugAdapterGo) || (operation == DebugAdapterStepInto) || (operation == DebugAdapterStepOver)
		|| (operation == DebugAdapterStepReturn) || (operation == DebugAdapterLaunch)
		|| (operation == DebugAdapterConnect) || (operation == DebugAdapterAttach)
		|| (operation == DebugAdapterGoReverse) || (operation == DebugAdapterStepIntoReverse)
		|| (operation == DebugAdapterStepOverReverse) || (operation == DebugAdapterStepReturnReverse))
	{
		ok = resumeOK;
	}
	else if ((operation == DebugAdapterPause) || (operation == DebugAdapterQuit) || (operation == DebugAdapterDetach))
	{
		ok = operationRequested;
	}
	else
	{
		ok = true;
	}

	if (ok)
		sem.Wait();
	else
		reason = InternalError;

	RemoveEventCallback(callback);
	if ((operation != DebugAdapterPause) && (operation != DebugAdapterQuit) && (operation != DebugAdapterDetach))
		m_adapterMutex.unlock();
	else
		m_adapterMutex2.unlock();

	return reason;
}


Ref<Metadata> DebuggerController::GetAdapterProperty(const std::string& name)
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return nullptr;

		if (!m_adapter)
			return nullptr;
	}

	return m_adapter->GetProperty(name);
}


bool DebuggerController::SetAdapterProperty(
	const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value)
{
	if (!m_adapter)
	{
		if (!CreateDebugAdapter())
			return false;

		if (!m_adapter)
			return false;
	}

	return m_adapter->SetProperty(name, value);
}


bool DebuggerController::ActivateDebugAdapter()
{
	return CreateDebugAdapter();
}


static inline bool IsPrintableChar(uint8_t c)
{
	return (c == '\r') || (c == '\n') || (c == '\t') || ((c >= 0x20) && (c <= 0x7e));
}


static std::string CheckForASCIIString(const DataBuffer& memory)
{
	std::string result;
	size_t i = 0;
	while (true)
	{
		if (i > memory.GetLength() - 1)
			break;
		if (IsPrintableChar(memory[i]))
		{
			result += memory[i];
			i++;
		}
		else
		{
			break;
		}
	}

	if (result.length() >= 4)
		return result;
	else
		return "";
}


static std::string CheckForUTF16String(const DataBuffer& memory)
{
	std::string result;
	size_t i = 0;
	while (true)
	{
		if (i > memory.GetLength() - 2)
			break;
		if (IsPrintableChar(memory[i]) && (memory[i + 1] == 0))
		{
			result += memory[i];
			i += 2;
		}
		else
		{
			break;
		}
	}

	if (result.length() >= 4)
		return result;
	else
		return "";
}


static std::string CheckForUTF32String(const DataBuffer& memory)
{
	std::string result;
	size_t i = 0;
	while (true)
	{
		if (i > memory.GetLength() - 4)
			break;
		if (IsPrintableChar(memory[i]) && (memory[i + 1] == 0) && (memory[i + 2] == 0) && (memory[i + 3] == 0))
		{
			result += memory[i];
			i += 4;
		}
		else
		{
			break;
		}
	}

	if (result.length() >= 4)
		return result;
	else
		return "";
}


static std::string CheckForPrintableString(const DataBuffer& memory)
{
	std::string result;
	result = CheckForASCIIString(memory);
	if (!result.empty())
		return fmt::format("\"{}\"", BinaryNinja::EscapeString(result));

	result = CheckForUTF16String(memory);
	if (!result.empty())
		return fmt::format("L\"{}\"", BinaryNinja::EscapeString(result));;

	result = CheckForUTF32String(memory);
	if (!result.empty())
		return fmt::format("L\"{}\"", BinaryNinja::EscapeString(result));;

	return "";
}


static std::string CheckForLiteralString(intx::uint512 value)
{
	bool ok = true;
	bool zeroFound = false;
	std::string result;
	for (size_t i = 0; i < 64; i++)
	{
		uint8_t c = (uint8_t)(value >> (8 * i)) & 0xff;
		if (IsPrintableChar(c) && (!zeroFound))
		{
			// Add the new char at the end to account for little-endianness
			result += c;
		}
		else if (c == 0)
		{
			// Skip 0x0 (e.g., for unicode strings)
			zeroFound = true;
		}
		else if (c != 0)
		{
			ok = false;
			break;
		}
	}

	if (ok)
		return fmt::format("'{}'", BinaryNinja::EscapeString(result));

	return "";
}


std::string DebuggerController::GetAddressInformation(intx::uint512 value)
{
	// Avoid too many results in the register widget when the address is 0x0
	if (value == 0)
		return "";

	// For the first few things, they still need an address to work with
	uint64_t address = (uint64_t)value;

	const DataBuffer memory = ReadMemory(address, 128);
	auto result = CheckForPrintableString(memory);
	// If we can find a string at the address, return it
	if (!result.empty())
		return result;

	// Check pointer to strings
	auto buffer = GetData()->ReadBuffer(address, GetData()->GetAddressSize());
	if (buffer.GetLength() == GetData()->GetAddressSize())
	{
		uint64_t pointerValue = *reinterpret_cast<std::uintptr_t*>(buffer.GetData());
		if (pointerValue != 0)
		{
			const DataBuffer pointerMemory = ReadMemory(pointerValue, 128);
			result = CheckForPrintableString(pointerMemory);
			if (!result.empty())
				return std::string("&") + result;
		}
	}


	// Look for functions starting at the address
	auto func = GetData()->GetAnalysisFunction(GetData()->GetDefaultPlatform(), address);
	if (func)
	{
		auto sym = func->GetSymbol();
		if (sym)
			return sym->GetShortName();
	}

	// Look for functions containing the address
	for (const auto& func: GetData()->GetAnalysisFunctionsContainingAddress(address))
	{
		auto sym = func->GetSymbol();
		if (sym)
		{
			return fmt::format("{} + 0x{:x}", sym->GetShortName(), address - func->GetStart());
		}
	}

	// Look for symbols
	auto sym = GetData()->GetSymbolByAddress(address);
	if (sym)
	{
		return sym->GetShortName();
	}

	//	Look for data variables
	DataVariable var;
	if (GetData()->GetDataVariableAtAddress(address, var))
	{
		sym = GetData()->GetSymbolByAddress(var.address);
		if (sym)
		{
			return fmt::format("{} + 0x{:x}", sym->GetShortName(), address - var.address);
		}
		else
		{
			result = fmt::format("data_{:x}", var.address);
			if (address != var.address)
				result += fmt::format(" + 0x{:x}", address - var.address);
			return result;
		}
	}

	// Check if the address itself is a printable string, e.g., 0x61626364 ==> "abcd"
	result = CheckForLiteralString(value);
	if (!result.empty())
		return result;

	return "";
}


bool DebuggerController::IsFirstLaunch()
{
	return m_firstLaunch;
}


bool DebuggerController::IsFirstConnect()
{
	return m_firstConnect;
}


bool DebuggerController::IsFirstConnectToDebugServer()
{
	return m_firstConnectToDebugServer;
}


bool DebuggerController::IsFirstAttach()
{
	return m_firstAttach;
}


bool DebuggerController::IsTTD()
{
	if(!m_adapter)
		return false;
	return m_adapter->SupportFeature(DebugAdapterSupportTTD);
}


std::vector<TTDMemoryEvent> DebuggerController::GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType)
{
	std::vector<TTDMemoryEvent> events;
	
	if (!IsTTD())
	{
		LogError("Current adapter does not support TTD");
		return events;
	}
	
	if (m_adapter)
	{
		events = m_adapter->GetTTDMemoryAccessForAddress(startAddress, endAddress, accessType);
	}

	return events;
}

std::vector<TTDCallEvent> DebuggerController::GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress, uint64_t endReturnAddress)
{
	std::vector<TTDCallEvent> events;

	if (!IsTTD())
	{
		LogError("Current adapter does not support TTD");
		return events;
	}

	return m_adapter->GetTTDCallsForSymbols(symbols, startReturnAddress, endReturnAddress);
}


TTDPosition DebuggerController::GetCurrentTTDPosition()
{
	TTDPosition position;
	
	if (!IsTTD())
	{
		LogError("Current adapter does not support TTD");
		return position;
	}
	
	if (m_adapter)
	{
		position = m_adapter->GetCurrentTTDPosition();
	}
	
	return position;
}

bool DebuggerController::SetTTDPosition(const TTDPosition& position)
{
	if (!IsTTD())
	{
		LogError("Current adapter does not support TTD");
		return false;
	}
	
	if (m_adapter)
	{
		return m_adapter->SetTTDPosition(position);
	}

	return false;
}


void DebuggerController::OnRebased(BinaryView* oldView, BinaryView* newView)
{
	m_data = newView;
	m_viewStart = newView->GetStart();
	// UnregisterNotification() is not designed to be called from one of the callbacks, so we cannot call it
	// here. Also, there is no need to do so -- the oldView is about to be deleted
	// oldView->UnregisterNotification(this);
	newView->RegisterNotification(this);
	m_state->GetMemory()->OnRebased();
}


bool DebuggerController::RemoveDebuggerMemoryRegion()
{
	GetData()->SetFunctionAnalysisUpdateDisabled(true);
	auto ret = GetData()->GetMemoryMap()->RemoveMemoryRegion("debugger");
	GetData()->SetFunctionAnalysisUpdateDisabled(false);
	return ret;
}


bool DebuggerController::ReAddDebuggerMemoryRegion()
{
	GetData()->SetFunctionAnalysisUpdateDisabled(true);
	auto ret = GetData()->GetMemoryMap()->AddRemoteMemoryRegion("debugger", 0, GetMemoryAccessor());
	GetData()->SetFunctionAnalysisUpdateDisabled(false);
	return ret;
}



// TODO: these 3 functions should be moved to the BinaryNinjaAPI namespace for wider audiences
static intx::uint512 MaskToSize(intx::uint512 value, size_t size)
{
	if (size >= 64)
		return value;
	if (size == 0)
		return value & 1;
	return value & ((intx::uint512(1) << (size * 8)) - 1);
}


static intx::uint512 ZeroExtend(intx::uint512 value, size_t sourceSize, size_t destSize)
{
	if (destSize <= sourceSize)
		return MaskToSize(value, destSize);
	return MaskToSize(value & ((intx::uint512(1) << (sourceSize * 8)) - 1), destSize);
}


static intx::uint512 SignExtend(intx::uint512 value, size_t sourceSize, size_t destSize)
{
	if (destSize <= sourceSize)
		return MaskToSize(value, destSize);
	if (value & (1LL << ((sourceSize * 8) - 1)))
		return MaskToSize(value | (~((intx::uint512(1) << (sourceSize * 8)) - 1)), destSize);
	else
		return MaskToSize(value & ((intx::uint512(1) << (sourceSize * 8)) - 1), destSize);
}


static inline intx::uint512 GetActualShift(intx::uint512 value, size_t instrSize)
{
	if (instrSize <= 4)
		return value & 0b11111;
	else
		return value & 0b111111;
}


bool DebuggerController::ComputeExprValueAPI(const BinaryNinja::LowLevelILInstruction &instr, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return ComputeExprValue(instr, value);
}


bool DebuggerController::ComputeExprValue(const LowLevelILInstruction &instr, intx::uint512& value)
{
	if (instr.size > 64)
		return false;

	intx::uint512 left, right;
	intx::uint512 sizeMask = (intx::uint512(1) << (instr.size * 8)) - 1;

	switch (instr.operation)
	{
	case LLIL_CONST:
		value = instr.GetConstant<LLIL_CONST>() & sizeMask;
		return true;
	case LLIL_CONST_PTR:
		value = instr.GetConstant<LLIL_CONST_PTR>() & sizeMask;
		return true;
	case LLIL_FLOAT_CONST:
		value = instr.GetConstant<LLIL_FLOAT_CONST>() & sizeMask;
		return true;
	case LLIL_REG:
	{
		auto reg = instr.GetSourceRegister<LLIL_REG>();
		if (LLIL_REG_IS_TEMP(reg))
			return false;

		auto name = GetData()->GetDefaultArchitecture()->GetRegisterName(reg);
		// TODO: what if the name reported by the adapter is different from that in the architecture?
		// GetRegisterValue should return if the value can be retrieved

		// Cheat for arm64
		if (name == "x29") name = "fp";

		value = GetRegisterValue(name) & sizeMask;
		return true;
	}
	case LLIL_ADD:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_ADD>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_ADD>(), right))
			return false;
		value = left + right;
		value &= sizeMask;
		return true;
	case LLIL_SUB:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_SUB>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_SUB>(), right))
			return false;
		value = left - right;
		value &= sizeMask;
		return true;
	case LLIL_LOAD:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_LOAD>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case LLIL_STORE:
	{
		if (!ComputeExprValue(instr.GetDestExpr<LLIL_STORE>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case LLIL_LSL:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_LSL>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_LSL>(), right))
			return false;
		value = left << GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case LLIL_LSR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_LSR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_LSR>(), right))
			return false;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case LLIL_ASR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_ASR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_ASR>(), right))
			return false;
		if (left & (1LL << ((instr.size * 8) - 1)))
			left |= ~sizeMask;
		else
			left &= sizeMask;
		value = ((int64_t)left) >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case LLIL_XOR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_XOR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_XOR>(), right))
			return false;
		value = left ^ right;
		value &= sizeMask;
		return true;
	}
	case LLIL_AND:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_AND>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_AND>(), right))
			return false;
		value = left & right;
		value &= sizeMask;
		return true;
	}
	case LLIL_OR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_OR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_OR>(), right))
			return false;
		value = left | right;
		value &= sizeMask;
		return true;
	}
	case LLIL_NEG:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_NEG>(), left))
			return false;
		value = -left;
		value &= sizeMask;
		return true;
	}
	case LLIL_NOT:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_NOT>(), left))
			return false;
		value = ~left;
		value &= sizeMask;
		return true;
	}
	case LLIL_SX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_SX>(), left))
			return false;
		value = SignExtend(left, instr.GetSourceExpr<LLIL_SX>().size, instr.size);
		return true;
	}
	case LLIL_ZX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_ZX>(), left))
			return false;
		value = ZeroExtend(left, instr.GetSourceExpr<LLIL_ZX>().size, instr.size);
		return true;
	}
	case LLIL_PUSH:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<LLIL_PUSH>(), left))
			return false;
		value &= sizeMask;
		return true;
	}
	case LLIL_POP:
	case LLIL_RET:
	{
		auto stackPointer = GetState()->StackPointer();
		auto buffer = ReadMemory(stackPointer, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case LLIL_CMP_E:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_E>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_E>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_NE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_NE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_NE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SLT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SLT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SLT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_ULT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_ULT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_ULT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SLE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SLE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SLE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_ULE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_ULE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_ULE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SGE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_UGE:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_UGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_UGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_SGT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_SGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_SGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case LLIL_CMP_UGT:
		if (!ComputeExprValue(instr.GetLeftExpr<LLIL_CMP_UGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<LLIL_CMP_UGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	default:
		break;
	}
	return false;
}


intx::uint512 DebuggerController::GetValueFromComparison(const BNLowLevelILOperation op, intx::uint512 left,
	intx::uint512 right, size_t size)
{
	switch (op)
	{
		case LLIL_CMP_E:
			return left == right;
			break;
		case LLIL_CMP_NE:
			return left != right;
			break;
		case LLIL_CMP_SLT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b);
			break;
		}
		case LLIL_CMP_ULT:
			return left < right;
			break;
		case LLIL_CMP_SLE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b) || (a == b);
			break;
		}
		case LLIL_CMP_ULE:
			return left <= right;
			break;
		case LLIL_CMP_SGE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !slt(a, b);
			break;
		}
		case LLIL_CMP_UGE:
			return left >= right;
			break;
		case LLIL_CMP_SGT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !(slt(a, b) || (a == b));
			break;
		}
		case LLIL_CMP_UGT:
			return left > right;
			break;
		default:
			break;
	}
	return -1;
}


intx::uint512 DebuggerController::GetValueFromComparison(const BNMediumLevelILOperation op, intx::uint512 left,
	intx::uint512 right, size_t size)
{
	switch (op)
	{
		case MLIL_CMP_E:
			return left == right;
			break;
		case MLIL_CMP_NE:
			return left != right;
			break;
		case MLIL_CMP_SLT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b);
			break;
		}
		case MLIL_CMP_ULT:
			return left < right;
			break;
		case MLIL_CMP_SLE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b) || (a == b);
			break;
		}
		case MLIL_CMP_ULE:
			return left <= right;
			break;
		case MLIL_CMP_SGE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !slt(a, b);
			break;
		}
		case MLIL_CMP_UGE:
			return left >= right;
			break;
		case MLIL_CMP_SGT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !(slt(a, b) || (a == b));
			break;
		}
		case MLIL_CMP_UGT:
			return left > right;
			break;
		default:
			break;
	}
	return -1;
}


intx::uint512 DebuggerController::GetValueFromComparison(const BNHighLevelILOperation op, intx::uint512 left,
	intx::uint512 right, size_t size)
{
	switch (op)
	{
		case HLIL_CMP_E:
			return left == right;
			break;
		case HLIL_CMP_NE:
			return left != right;
			break;
		case HLIL_CMP_SLT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b);
			break;
		}
		case HLIL_CMP_ULT:
			return left < right;
			break;
		case HLIL_CMP_SLE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return slt(a, b) || (a == b);
			break;
		}
		case HLIL_CMP_ULE:
			return left <= right;
			break;
		case HLIL_CMP_SGE:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !slt(a, b);
			break;
		}
		case HLIL_CMP_UGE:
			return left >= right;
			break;
		case HLIL_CMP_SGT:
		{
			auto a = SignExtend(left, size, 64);
			auto b = SignExtend(right, size, 64);
			return !(slt(a, b) || (a == b));
			break;
		}
		case HLIL_CMP_UGT:
			return left > right;
			break;
		default:
			break;
	}
	return -1;
}


bool DebuggerController::ComputeExprValueAPI(const BinaryNinja::MediumLevelILInstruction &instr, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return ComputeExprValue(instr, value);
}


bool DebuggerController::ComputeExprValue(const MediumLevelILInstruction &instr, intx::uint512& value)
{
	if (instr.size > 64)
		return false;

	intx::uint512 left, right;
	intx::uint512 sizeMask = (intx::uint512(1) << (instr.size * 8)) - 1;

	switch (instr.operation)
	{
	case MLIL_CONST:
		value = instr.GetConstant<MLIL_CONST>() & sizeMask;
		return true;
	case MLIL_CONST_PTR:
		value = instr.GetConstant<MLIL_CONST_PTR>() & sizeMask;
		return true;
	case MLIL_FLOAT_CONST:
		value = instr.GetConstant<MLIL_CONST_PTR>() & sizeMask;
		return true;
	case MLIL_VAR:
	{
		const auto var = instr.GetSourceVariable<MLIL_VAR>();
		return GetVariableValue(var, instr.address, instr.size, value);
		break;
	}
	case MLIL_ADD:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_ADD>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_ADD>(), right))
			return false;
		value = left + right;
		value &= sizeMask;
		return true;
	case MLIL_SUB:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_SUB>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_SUB>(), right))
			return false;
		value = left - right;
		value &= sizeMask;
		return true;
	case MLIL_LOAD:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_LOAD>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case MLIL_STORE:
	{
		if (!ComputeExprValue(instr.GetDestExpr<MLIL_STORE>(), left))
			return false;
		auto buffer = ReadMemory((uint64_t)left, instr.size);
		if (buffer.GetLength() != instr.size)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), instr.size);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}
	case MLIL_LSL:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_LSL>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_LSL>(), right))
			return false;
		value = left << GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case MLIL_LSR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_LSR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_LSR>(), right))
			return false;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case MLIL_ASR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_ASR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_ASR>(), right))
			return false;
		if (left & (1LL << ((instr.size * 8) - 1)))
			left |= ~sizeMask;
		else
			left &= sizeMask;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case MLIL_XOR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_XOR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_XOR>(), right))
			return false;
		value = left ^ right;
		value &= sizeMask;
		return true;
	}
	case MLIL_AND:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_AND>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_AND>(), right))
			return false;
		value = left & right;
		value &= sizeMask;
		return true;
	}
	case MLIL_OR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_OR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_OR>(), right))
			return false;
		value = left | right;
		value &= sizeMask;
		return true;
	}
	case MLIL_NEG:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_NEG>(), left))
			return false;
		value = -left;
		value &= sizeMask;
		return true;
	}
	case MLIL_NOT:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_NOT>(), left))
			return false;
		value = ~left;
		value &= sizeMask;
		return true;
	}
	case MLIL_SX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_SX>(), left))
			return false;
		value = SignExtend(left, instr.GetSourceExpr<MLIL_SX>().size, instr.size);
		return true;
	}
	case MLIL_ZX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<MLIL_ZX>(), left))
			return false;
		value = ZeroExtend(left, instr.GetSourceExpr<MLIL_ZX>().size, instr.size);
		return true;
	}
	case MLIL_CMP_E:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_E>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_E>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_NE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_NE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_NE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SLT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SLT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SLT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_ULT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_ULT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_ULT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SLE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SLE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SLE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_ULE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_ULE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_ULE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SGE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_UGE:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_UGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_UGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_SGT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_SGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_SGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case MLIL_CMP_UGT:
		if (!ComputeExprValue(instr.GetLeftExpr<MLIL_CMP_UGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<MLIL_CMP_UGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	default:
		return false;
	}
}


bool DebuggerController::GetVariableValueAPI(const Variable& var, uint64_t address, size_t size, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return GetVariableValue(var, address, size, value);
}


bool DebuggerController::GetVariableValue(const Variable& var, uint64_t address, size_t size, intx::uint512 &value)
{
	intx::uint512 sizeMask = -1;
	if (size > 0 && size < 64)
		sizeMask = (intx::uint512(1) << (size * 8)) - 1;

	if (var.type == RegisterVariableSourceType)
	{
		auto reg = var.storage;
		if (LLIL_REG_IS_TEMP(reg))
			return false;

		auto name = GetData()->GetDefaultArchitecture()->GetRegisterName(reg);
		// TODO: what if the name reported by the adapter is different from that in the architecture?
		// GetRegisterValue should return if the value can be retrieved

		// Cheat for arm64
		if (name == "x29") name = "fp";

		value = GetRegisterValue(name) & sizeMask;
		return true;
	}
	else if (var.type == StackVariableSourceType)
	{
		auto stack = m_state->StackPointer();
		auto ip = m_state->IP();
		auto funcs = GetData()->GetAnalysisFunctionsContainingAddress(address);
		if (funcs.empty())
			return false;
		auto func = funcs[0];
		if (!func)
			return false;
		auto arch = GetData()->GetDefaultArchitecture();
		if (!arch)
			return false;
		auto stackReg = arch->GetStackPointerRegister();
		auto stackValue = func->GetRegisterValueAtInstruction(arch, ip, stackReg);
		if (stackValue.state != StackFrameOffset)
			return false;
		auto stackAtFuncEntry = stack - stackValue.value;
		auto addrOfVar = stackAtFuncEntry + var.storage;

		auto type = func->GetVariableType(var);
		if (!type)
			return false;

		size_t width = type->GetWidth();
		if (width > 64)
			return false;

		auto buffer = ReadMemory(addrOfVar, width);
		if (buffer.GetLength() != width)
			return false;

		uint8_t intxBuffer[64] = {};
		memcpy(intxBuffer, buffer.GetData(), width);
		value = intx::le::load<intx::uint512>(intxBuffer) & sizeMask;
		return true;
	}

	return false;
}


bool DebuggerController::ComputeExprValueAPI(const BinaryNinja::HighLevelILInstruction &instr, intx::uint512& value)
{
	// We only want to do this check once before the recursion
	if (!m_state->IsConnected() || m_state->IsRunning())
		return false;

	return ComputeExprValue(instr, value);
}


bool DebuggerController::ComputeExprValue(const HighLevelILInstruction &instr, intx::uint512& value)
{
	if (instr.size > 64)
		return false;

	intx::uint512 left, right;
	intx::uint512 sizeMask = (intx::uint512(1) << (instr.size * 8)) - 1;

	switch (instr.operation)
	{
	case HLIL_CONST:
		value = instr.GetConstant<HLIL_CONST>() & sizeMask;
		return true;
	case HLIL_CONST_PTR:
		value = instr.GetConstant<HLIL_CONST_PTR>() & sizeMask;
		return true;
	case HLIL_FLOAT_CONST:
		value = instr.GetConstant<HLIL_CONST_PTR>() & sizeMask;
		return true;
	case HLIL_VAR:
	{
		const auto var = instr.GetVariable<HLIL_VAR>();
		return GetVariableValue(var, instr.address, instr.size, value);
		break;
	}
	case HLIL_ADD:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_ADD>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_ADD>(), right))
			return false;
		value = left + right;
		value &= sizeMask;
		return true;
	case HLIL_SUB:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_SUB>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_SUB>(), right))
			return false;
		value = left - right;
		value &= sizeMask;
		return true;
	case HLIL_LSL:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_LSL>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_LSL>(), right))
			return false;
		value = left << GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case HLIL_LSR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_LSR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_LSR>(), right))
			return false;
		value = left >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case HLIL_ASR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_ASR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_ASR>(), right))
			return false;
		if (left & (1LL << ((instr.size * 8) - 1)))
			left |= ~sizeMask;
		else
			left &= sizeMask;
		value = ((int64_t)left) >> GetActualShift(right, instr.size);
		value &= sizeMask;
		return true;
	}
	case HLIL_XOR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_XOR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_XOR>(), right))
			return false;
		value = left ^ right;
		value &= sizeMask;
		return true;
	}
	case HLIL_AND:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_AND>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_AND>(), right))
			return false;
		value = left & right;
		value &= sizeMask;
		return true;
	}
	case HLIL_OR:
	{
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_OR>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_OR>(), right))
			return false;
		value = left | right;
		value &= sizeMask;
		return true;
	}
	case HLIL_NEG:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_NEG>(), left))
			return false;
		value = -left;
		value &= sizeMask;
		return true;
	}
	case HLIL_NOT:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_NOT>(), left))
			return false;
		value = ~left;
		value &= sizeMask;
		return true;
	}
	case HLIL_SX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_SX>(), left))
			return false;
		value = SignExtend(left, instr.GetSourceExpr<HLIL_SX>().size, instr.size);
		return true;
	}
	case HLIL_ZX:
	{
		if (!ComputeExprValue(instr.GetSourceExpr<HLIL_ZX>(), left))
			return false;
		value = ZeroExtend(left, instr.GetSourceExpr<HLIL_ZX>().size, instr.size);
		return true;
	}
	case HLIL_CMP_E:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_E>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_E>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_NE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_NE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_NE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SLT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SLT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SLT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_ULT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_ULT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_ULT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SLE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SLE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SLE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_ULE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_ULE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_ULE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SGE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_UGE:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_UGE>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_UGE>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_SGT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_SGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_SGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	case HLIL_CMP_UGT:
		if (!ComputeExprValue(instr.GetLeftExpr<HLIL_CMP_UGT>(), left))
			return false;
		if (!ComputeExprValue(instr.GetRightExpr<HLIL_CMP_UGT>(), right))
			return false;
		value = GetValueFromComparison(instr.operation, left, right, instr.size);
		return true;

	default:
		return false;
	}
}


Ref<Settings> DebuggerController::GetAdapterSettings()
{
	CreateDebugAdapter();
	if (!m_adapter)
		return nullptr;

	return m_adapter->GetAdapterSettings();
}


void DebuggerController::SetDebuggerUICallbacks(BNDebuggerUICallbacks* cb, void* ctxt)
{
	m_uiCallbacks = std::make_unique<DebuggerUICallbacks>(cb, ctxt);
}


void DebuggerUICallbacks::NotifyRebaseBinaryView(uint64_t remoteBase)
{
	if (m_callbacks && m_callbacks->rebaseBinaryView)
		m_callbacks->rebaseBinaryView(m_context, remoteBase);
}


bool DebuggerController::FunctionExistsInOldView(uint64_t address)
{
	if (m_ranges.empty())
		return false;

	address -= (m_newViewBase - m_oldViewBase);
	for (const auto& range: m_ranges)
	{
		if (address >= range.start && address < range.end)
			return true;
	}
	return false;
}
