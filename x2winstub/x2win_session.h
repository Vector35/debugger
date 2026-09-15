#pragma once
#include "debug/windows_debug_engine.h"
#include <x2win_generated.h>
#include <future>
#include <atomic>
#include <mutex>

class Connection;

namespace x2win {

	enum class SessionMode
	{
		Target,  // this process launched/owns the debuggee (x2winstub target <path>)
		Server   // this process is a standalone RPC server (x2winstub server), no owned debuggee
	};

	// Owns one WindowsDebugEngine and parses/dispatches x2win::Envelope proto commands to it --
	// this is the "new class that contains WindowsDebugEngine and does the proto command parsing"
	// that replaces main.cpp's inline HandleClient() switch + the free-function debug_loop.h API.
	//
	// The engine's async events (currently just the initial/regular breakpoint stop) are translated
	// into TargetStoppedEvent envelopes and written to the connection as they happen, via the
	// callback registered in the constructor.
	class X2WinStubSession
	{
	private:
		Connection* m_connection;
		std::mutex m_connectionMutex;
		SessionMode m_mode;

		// Fulfilled the first time the engine reports TargetStopped, independent of whether a
		// connection is attached yet. Target mode launches the debuggee and waits on this before a
		// client has even connected (see WaitForFirstStop()); once a client is connected, that same
		// first stop is otherwise indistinguishable from any later one.
		std::promise<void> m_firstStopPromise;
		std::atomic<bool> m_firstStopSeen {false};

		// Tracks the *current* stop state (independent of whether a client is connected right now) --
		// unlike m_firstStopSeen (one-shot, fires once ever), this reflects "are we stopped right now",
		// so a client reconnecting after a disconnect (target mode) can be told immediately instead of
		// only ever getting this on the very first connection.
		std::atomic<bool> m_isStopped {false};
		std::atomic<StopReason> m_lastStopReason {StopReason_UNKNOWN};

		// Destroy the engine first, joining its event thread before the callback
		// state and connection mutex above are destroyed.
		WindowsDebugEngine m_engine;

		void OnEngineEvent(const EngineEvent& event);

	public:
		X2WinStubSession(Connection* connection, SessionMode mode);
		~X2WinStubSession();

		// Dispatches one already-parsed request. `builder` ends up holding a finished Envelope that
		// should be written by the caller -- unless this returns false for an unhandled request.
		// `builder` is caller-owned (rather than built internally and returned) for the
		// same reason CallSync's callers own theirs on the BN-core side of this protocol: a
		// FlatBuffers table can only be built bottom-up with one builder, and the response body
		// table built by each case below has to share the builder that goes on to wrap it in the
		// Envelope.
		bool HandleRequest(const Envelope& request, flatbuffers::FlatBufferBuilder& builder);

		WindowsDebugEngine& Engine() { return m_engine; }

		// Attaches (or reattaches) the connection used for outgoing events. Target mode constructs
		// the session before any client has connected -- see main.cpp.
		void SetConnection(Connection* connection)
		{
			std::lock_guard<std::mutex> lock(m_connectionMutex);
			m_connection = connection;
		}

		SessionMode Mode() const { return m_mode; }
		bool IsStopped() const { return m_isStopped; }
		StopReason LastStopReason() const { return m_lastStopReason; }

		// Blocks until the engine's first TargetStopped event (target mode's initial breakpoint).
		void WaitForFirstStop() { m_firstStopPromise.get_future().wait(); }
	};

}  // namespace x2win
