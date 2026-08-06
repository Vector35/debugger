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

		if (!m_connection)
			return;  // no client connected yet; target mode sends this stop manually once one is

		StopReason reason = StopReason_UNKNOWN;
		switch (event.stopReason)
		{
		case InitialBreakpoint: reason = StopReason_INITIAL_BREAKPOINT; break;
		case Breakpoint: reason = StopReason_BREAKPOINT; break;
		case SingleStep: reason = StopReason_SINGLE_STEP; break;
		default: break;
		}

		flatbuffers::FlatBufferBuilder builder;
		auto eventBody = CreateTargetStoppedEvent(builder, reason, m_engine.GetInstructionOffset());
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

		case Body_LaunchRequest:{
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
			auto respBody = CreateGoResponse(builder, m_engine.Go());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_GoResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_StepIntoRequest:{
			auto respBody = CreateStepIntoResponse(builder, m_engine.StepInto());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_StepIntoResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}

		case Body_StepOverRequest:{
			auto respBody = CreateStepOverResponse(builder, m_engine.StepOver());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_StepOverResponse, respBody.Union());
			builder.Finish(envelope);
			return true;
		}
		
		case Body_BreakIntoRequest:{
			auto respBody = CreateBreakIntoResponse(builder, m_engine.BreakInto());
			auto envelope = CreateEnvelope(builder, request.request_id(), Body_BreakIntoResponse, respBody.Union());
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
