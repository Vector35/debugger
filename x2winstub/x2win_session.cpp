#include "x2win_session.h"
#include "net/connection.h"
#include <thread>

namespace x2win {

	X2WinStubSession::X2WinStubSession(Connection* connection, SessionMode mode) :
		m_connection(connection), m_mode(mode)
	{
		m_engine.SetEventCallback([this](const EngineEvent& event) { OnEngineEvent(event); });
	}


	void X2WinStubSession::OnEngineEvent(const EngineEvent& event)
	{
		if(event.type == EngineEventType::TargetExited){
			m_isStopped = true;
			m_lastStopReason = StopReason_EXITED;

			if(!m_connection) return;

			flatbuffers::FlatBufferBuilder builder;
			auto eventBody = CreateTargetStoppedEvent(builder, StopReason_EXITED, /*address=*/0, event.exitCode);
			auto envelope = CreateEnvelope(builder, /*request_id=*/0, Body_TargetStoppedEvent, eventBody.Union());
			builder.Finish(envelope);
			m_connection->WriteEnvelope(builder);
			return;
		}

		// Only TargetStopped has a wire representation today (TargetStoppedEvent). LaunchFailure/
		// TargetExited/Resumed/StepIntoComplete don't have a proto event yet -- future work, same as
		// the other WindowsDebugEngine capabilities (hardware breakpoints, registers, stepping) that
		// aren't wired through the proto surface yet either.
		if (event.type != EngineEventType::TargetStopped)
			return;

		// Fire the first-stop signal exactly once, regardless of whether a client is connected yet
		// -- target mode waits on this (WaitForFirstStop()) before it has even opened the listen
		// socket, let alone accepted a connection.
		bool expected = false;
		if (m_firstStopSeen.compare_exchange_strong(expected, true))
			m_firstStopPromise.set_value();

		StopReason reason = StopReason_UNKNOWN;
		switch (event.stopReason)
		{
		case InitialBreakpoint: reason = StopReason_INITIAL_BREAKPOINT; break;
		case Breakpoint: reason = StopReason_BREAKPOINT; break;
		case SingleStep: reason = StopReason_SINGLE_STEP; break;
		default: break;
		}

		// Track current stop state regardless of whether a client is connected -- a client that
		// reconnects later (target mode) needs to know this even though it wasn't around when the
		// stop actually happened.
		m_isStopped = true;
		m_lastStopReason = reason;

		if (!m_connection)
			return;  // no client connected yet; target mode sends this stop manually once one is

		flatbuffers::FlatBufferBuilder builder;
		auto eventBody = CreateTargetStoppedEvent(builder, reason, m_engine.GetInstructionOffset(), /*exit_code=*/0);
		auto envelope = CreateEnvelope(builder, /*request_id=*/0, Body_TargetStoppedEvent, eventBody.Union());
		builder.Finish(envelope);
		m_connection->WriteEnvelope(builder);
	}


	bool X2WinStubSession::HandleRequest(const Envelope& request, flatbuffers::FlatBufferBuilder& builder)
	{
		switch (request.body_type())
		{
		case Body_GetTargetArchRequest:{
			auto archOff = builder.CreateString(m_engine.GetTargetArchitecture());
			auto respBody = CreateGetTargetArchResponse(builder, archOff);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GetTargetArchResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_ConnectServerRequest:{
			auto respBody = CreateConnectServerResponse(builder, m_mode == SessionMode::Server);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_ConnectServerResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_AttachRequest:{
			const auto* req = request.body_as<AttachRequest>();
			bool success = false;
			if(req && m_mode == SessionMode::Server){
				success = m_engine.Attach(req->pid());
			}
			auto respBody = CreateAttachResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_AttachResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_GetProcessListRequest:{
			std::vector<flatbuffers::Offset<ProcessInfo>> processOffsets;
			for(const auto& process : m_engine.GetProcessList()){
				auto nameOff = builder.CreateString(process.m_processName);
				processOffsets.push_back(CreateProcessInfo(builder, process.m_pid, nameOff));
			}

			auto processesVec = builder.CreateVector(processOffsets);
			auto respBody = CreateGetProcessListResponse(builder, processesVec);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GetProcessListResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_LaunchRequest:{
			// Real gdbserver (non--multi) doesn't support this either -- it only ever serves the one
			// debuggee it was started with, and gdb can't "run" a new one over the same connection;
			// that needs gdbserver --multi (our server mode). Target mode here is the non-multi
			// equivalent, so a LaunchRequest arriving in target mode -- whether from user error or from
			// BN core's Restart (Quit() then a fresh LaunchRequest) -- gets rejected the same way
			// Body_AttachRequest already rejects an out-of-place AttachRequest, rather than trying (and
			// likely failing, or launching the wrong thing) to execute it.
			if(m_mode != SessionMode::Server){
				auto respBody = CreateLaunchResponse(builder, false);
				auto envelope = CreateEnvelope(builder, request.request_id(), Body_LaunchResponse, respBody.Union());
				builder.Finish(envelope);
				return true;
			}

			// Copied into owned strings (rather than kept as FlatBuffers string views into
			// `request`) because `request` is only valid for the duration of this call -- the
			// caller's underlying byte buffer gets reused for the next request as soon as
			// HandleRequest() returns, but the detached thread below runs well after that.
			const auto* req = request.body_as<LaunchRequest>();
			std::string path = (req && req->path()) ? req->path()->str() : std::string();
			std::string args = (req && req->args()) ? req->args()->str() : std::string();
			std::string workingDir = (req && req->working_dir()) ? req->working_dir()->str() : std::string();
			uint64_t requestId = request.request_id();

			std::thread([this, path, args, workingDir, requestId]() {
				bool ok = m_engine.ExecuteWithArgs(path, args, workingDir);

				flatbuffers::FlatBufferBuilder launchBuilder;
				auto respBody = CreateLaunchResponse(launchBuilder, ok);
				auto envelope = CreateEnvelope(launchBuilder, requestId, Body_LaunchResponse, respBody.Union());
				launchBuilder.Finish(envelope);
				m_connection->WriteEnvelope(launchBuilder);
			}).detach();

			return false;  // response already sent asynchronously above
		}

		case Body_GoRequest:{
			bool success = m_engine.Go();
			if(success) m_isStopped = false;
			auto respBody = CreateGoResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GoResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_StepIntoRequest:{
			bool success = m_engine.StepInto();
			if(success) m_isStopped = false;
			auto respBody = CreateStepIntoResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_StepIntoResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_StepOverRequest:{
			bool success = m_engine.StepOver();
			if(success) m_isStopped = false;
			auto respBody = CreateStepOverResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_StepOverResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_StepReturnRequest:{
			bool success = m_engine.StepReturn();
			if(success) m_isStopped = false;

			auto respBody = CreateStepIntoResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_StepReturnResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}
		
		case Body_BreakIntoRequest:{
			auto respBody = CreateBreakIntoResponse(builder, m_engine.BreakInto());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_BreakIntoResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_RemoveBreakpointRequest:{
			const auto* req = request.body_as<RemoveBreakpointRequest>();
			bool success = false;
			if(req){
				success = m_engine.RemoveBreakpoint(DebugBreakpoint(static_cast<std::uintptr_t>(req->address())));
			}
			auto respBody = CreateRemoveBreakpointResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_RemoveBreakpointResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_SetBreakpointRequest:{
			const auto* req = request.body_as<SetBreakpointRequest>();
			bool success = false;
			uint64_t breakpointId = 0;
			if (!req || req->type() != BreakpointType_SOFTWARE)
			{
				LogError("SetBreakpointRequest: unsupported breakpoint type %d", req ? static_cast<int>(req->type()) : -1);
			}
			else
			{
				DebugBreakpoint bp = m_engine.AddBreakpoint(static_cast<std::uintptr_t>(req->address()));
				success = bp.m_is_active;
				breakpointId = bp.m_is_active ? bp.m_id : 0;
			}
			auto respBody = CreateSetBreakpointResponse(builder, success, breakpointId);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_SetBreakpointResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_SetHardwareBreakpointRequest:{
			const auto* req = request.body_as<SetHardwareBreakpointRequest>();
			bool success = false;
			if (req)
			{
				success = m_engine.AddHardwareBreakpoint(
					req->address(),
					static_cast<DebugBreakpointType>(req->type()),
					static_cast<size_t>(req->size()));
			}
			auto respBody = CreateSetHardwareBreakpointResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_SetHardwareBreakpointResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_RemoveHardwareBreakpointRequest:{
			const auto* req = request.body_as<RemoveHardwareBreakpointRequest>();
			bool success = false;
			if (req)
			{
				success = m_engine.RemoveHardwareBreakpoint(
					req->address(),
					static_cast<DebugBreakpointType>(req->type()),
					static_cast<size_t>(req->size()));
			}
			auto respBody = CreateRemoveHardwareBreakpointResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_RemoveHardwareBreakpointResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_ReadMemoryRequest:{
			const auto* req = request.body_as<ReadMemoryRequest>();
			bool ok = false;
			flatbuffers::Offset<flatbuffers::Vector<uint8_t>> dataOff;
			if (req)
			{
				auto data = m_engine.ReadMemory(req->address(), req->size());
				// A short/partial read is reported as failure, never a truncated buffer -- see the
				// contract documented on ReadMemoryResponse in protocol/x2win.fbs.
				ok = (data.size() == req->size());
				if (ok)
					dataOff = builder.CreateVector(data.data(), data.size());
			}
			auto respBody = CreateReadMemoryResponse(builder, ok, dataOff);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_ReadMemoryResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_WriteMemoryRequest:{
			const auto* req = request.body_as<WriteMemoryRequest>();
			bool ok = false;

			if(req && req->data()){
				std::vector<uint8_t> buffer(req->data()->begin(), req->data()->end());
				ok = m_engine.WriteMemory(req->address(), buffer);
			}

			auto respBody = CreateWriteMemoryResponse(builder, ok);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_WriteMemoryResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_ReadAllRegistersRequest:{
			std::vector<flatbuffers::Offset<RegisterEntry>> regOffsets;
			for (const auto& [name, reg] : m_engine.ReadAllRegisters()){
				auto nameOff = builder.CreateString(reg.m_name);
				regOffsets.push_back(CreateRegisterEntry(builder, nameOff,reg.m_value,
					static_cast<uint32_t>(reg.m_width), static_cast<uint32_t>(reg.m_registerIndex)));
			}

			auto regsVec = builder.CreateVector(regOffsets);
			auto respBody = CreateReadAllRegistersResponse(builder, regsVec);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_ReadAllRegistersResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_ReadRegisterRequest:{
			const auto* req = request.body_as<ReadRegisterRequest>();
			bool success = false;
			DebugRegister reg;
			if(req && req->name()){
				reg = m_engine.ReadRegister(req->name()->str());
				success = !reg.m_name.empty();
			}

			auto respBody = CreateReadRegisterResponse(builder, success, reg.m_value,
				static_cast<uint32_t>(reg.m_width), static_cast<uint32_t>(reg.m_registerIndex));
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_ReadRegisterResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_WriteRegisterRequest:{
			const auto* req = request.body_as<WriteRegisterRequest>();
			bool success = false;
			if(req && req->name()){
				success = m_engine.WriteRegister(req->name()->str(), req->value());
			}
			auto respBody = CreateWriteRegisterResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_WriteRegisterResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_GetModuleListRequest:{
			std::vector<flatbuffers::Offset<ModuleEntry>> moduleOffsets;
			for (const auto& module : m_engine.GetModuleList())
			{
				auto nameOff = builder.CreateString(module.m_name);
				moduleOffsets.push_back(CreateModuleEntry(builder, nameOff, module.m_address, module.m_size));
			}
			auto modulesVec = builder.CreateVector(moduleOffsets);
			auto respBody = CreateGetModuleListResponse(builder, modulesVec);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GetModuleListResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_GetThreadListRequest:{
			std::vector<flatbuffers::Offset<ThreadEntry>> threadOffsets;
			for(const auto& thread : m_engine.GetThreadList()){
				threadOffsets.push_back(CreateThreadEntry(builder, thread.m_tid, thread.m_rip, thread.m_isFrozen));
			}
			auto threadsVec = builder.CreateVector(threadOffsets);
			auto respBody = CreateGetThreadListResponse(builder, threadsVec);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GetThreadListResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_GetFramesOfThreadRequest:{
			const auto* req = request.body_as<GetFramesOfThreadRequest>();
			std::vector<flatbuffers::Offset<FrameEntry>> frameOffsets;
			if(req){
				for(const auto& frame : m_engine.GetFramesOfThread(req->tid())){
					auto functionNameOff = builder.CreateString(frame.m_functionName);
					auto moduleOff = builder.CreateString(frame.m_module);

					frameOffsets.push_back(CreateFrameEntry(builder,
						static_cast<uint32_t>(frame.m_index), frame.m_pc, frame.m_sp, frame.m_fp,
						functionNameOff, frame.m_functionStart, moduleOff));
				}
			}

			auto framesVec = builder.CreateVector(frameOffsets);
			auto respBody = CreateGetFramesOfThreadResponse(builder, framesVec);

			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GetFramesOfThreadResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_GetActiveThreadIdRequest:{
			auto respBody = CreateGetActiveThreadIdResponse(builder, m_engine.GetActiveThreadId());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GetActiveThreadIdResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_GetMemoryMapRequest:{
			std::vector<flatbuffers::Offset<MemoryRegionEntry>> regionOffsets;
			for(const auto& region : m_engine.GetMemoryMap()){
				auto nameOff = builder.CreateString(region.m_name);

				regionOffsets.push_back(CreateMemoryRegionEntry(builder,
					region.m_start, region.m_size, nameOff,
					region.m_read, region.m_write, region.m_execute, region.m_shared));
			}

			auto regionsVec = builder.CreateVector(regionOffsets);
			auto respBody = CreateGetMemoryMapResponse(builder, regionsVec);

			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GetMemoryMapResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_SetActiveThreadIdRequest:{
			const auto* req = request.body_as<SetActiveThreadIdRequest>();
			bool success = false;
			if(req){
				success = m_engine.SetActiveThreadId(req->tid());
			}
			auto respBody = CreateSetActiveThreadIdResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_SetActiveThreadIdResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_SuspendThreadRequest:{
			const auto* req = request.body_as<SuspendThreadRequest>();
			bool success = false;
			if(req){
				success = m_engine.SuspendThread(req->tid());
			}
			auto respBody = CreateSuspendThreadResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_SuspendThreadResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_ResumeThreadRequest:{
			const auto* req = request.body_as<ResumeThreadRequest>();
			bool success = false;
			if(req){
				success = m_engine.ResumeThread(req->tid());
			}
			auto respBody = CreateResumeThreadResponse(builder, success);
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_ResumeThreadResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_QuitRequest:{
			auto respBody = CreateQuitResponse(builder, m_engine.Quit());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_QuitResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_DetachRequest:{
			auto respBody = CreateDetachResponse(builder, m_engine.Detach());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_DetachResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		default:
			LogError("unhandled request body_type=%d", static_cast<int>(request.body_type()));
			return false;
		}
	}

}  // namespace x2win
