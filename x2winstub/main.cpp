#include "net/winsock_library.h"
#include "net/socket_handle.h"
#include "net/connection.h"
#include "x2win_session.h"

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <cstdio>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <memory>

static constexpr uint16_t kListenPort = 31338;

namespace {
	void PrintUsage(const char* argv0){
		fprintf(stderr,
		"usage: \n"
		" %s target <path-to-exe> [--ip <address>] [--port <port>]\n"
		" %s server [--ip <address>] [--port <port>]\n",
		argv0, argv0);
	}

	struct Options{
		enum class Mode{Server, Target};

		Mode mode = Mode::Server;
		std::string targetPath;
		std::string listenIp = "0.0.0.0";
		uint16_t listenPort = kListenPort;
	};

	std::optional<uint16_t> ParsePort(const char* text){
		try{
			int port = std::stoi(text);
			if(port < 0 || port > 65535) return std::nullopt;
			return static_cast<uint16_t>(port);
		}catch(const std::exception){
			return std::nullopt;
		}
	}

	std::optional<Options> ParseArgs(int argc, char** argv){
		if(argc < 2){
			PrintUsage(argv[0]);
			return std::nullopt;
		}

		Options options;

		std::string_view command = argv[1];
		int nextArg = 2;
		if(command == "server"){
			options.mode = Options::Mode::Server;
		}else if(command == "target"){
			options.mode = Options::Mode::Target;
			if(argc < 3){
				fprintf(stderr, "target mode requires a path to the target executable\n");
				PrintUsage(argv[0]);
				return std::nullopt;
			}
			options.targetPath = argv[2];
			nextArg = 3;
		}else{
			fprintf(stderr, "unknown command: %s\n", argv[1]);
			PrintUsage(argv[0]);
			return std::nullopt;
		}

		for(int i = nextArg; i < argc; ++i){
			std::string_view arg = argv[i];
			if(arg == "--ip" && i + 1 < argc){
				auto port = ParsePort(argv[++i]);
				if(!port){
					fprintf(stderr, "invalid port: %s\n", argv[i]);
					PrintUsage(argv[0]);
					return std::nullopt;
				}
				options.listenPort = * port;
			}else{
				fprintf(stderr, "unrecognized argument: %s\n", argv[i]);
				PrintUsage(argv[0]);
				return std::nullopt;
			}
		}

		return options;
	}

	// Shared per-connection request loop, used by both server mode (a fresh session per connection)
	// and target mode (a session that was already launched and stopped at its initial breakpoint
	// before the connection existed -- see main()). This is the dispatch loop that used to be
	// inline in HandleClient(), now delegating each request to X2WinStubSession::HandleRequest --
	// the class that owns the WindowsDebugEngine and does the proto command parsing.
	void RunRequestLoop(Connection* conn, x2win::X2WinStubSession& session){
		X2WinEnvelopeBuffer requestBuf;
		while(conn->ReadEnvelope(requestBuf)){
			const x2win::Envelope* request = requestBuf.Get();
			if(!request) continue;  // ReadEnvelope() already verified the buffer; shouldn't happen

			flatbuffers::FlatBufferBuilder builder;
			if(session.HandleRequest(*request, builder)){
				if(!conn->WriteEnvelope(builder)){
					fprintf(stderr, "WriteEnvelope failed: %d\n", WSAGetLastError());
					break;
				}
			}
		}

		// If the debuggee is still alive when the client disconnects, don't leave it running
		// orphaned -- terminate it, matching the old debug_loop.cpp's HandleDisconnect().
		if(session.Engine().GetActivePID() != 0)
			session.Engine().Quit();
	}

	void HandleClient(std::shared_ptr<Connection> conn, Options::Mode mode){
		x2win::X2WinStubSession session(conn.get(),
			mode == Options::Mode::Server ? x2win::SessionMode::Server : x2win::SessionMode::Target);
		RunRequestLoop(conn.get(), session);
	}
}

std::optional<SocketHandle> CreateListenSocket(const Options& options){
	SocketHandle listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
	if(listener.get() == INVALID_SOCKET){
		fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
		return std::nullopt;
	}

	int reuse = 1;
	setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(options.listenPort);
	if(inet_pton(AF_INET, options.listenIp.c_str(), &addr.sin_addr) != 1){
		fprintf(stderr, "invalid --ip address: %s\n", options.listenIp.c_str());
		return std::nullopt;
	}

	if(bind(listener.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR){
		fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
		return std::nullopt;
	}

	if(listen(listener.get(), 1) == SOCKET_ERROR){
		fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
		return std::nullopt;
	}

	fprintf(stderr, "x2winstub listening on %s:%d\n", options.listenIp.c_str(), options.listenPort);
	return listener;

}

int main(int argc, char** argv){
	std::optional<Options> options = ParseArgs(argc, argv);
	if(!options) return 1;

	// Target mode: launch the debuggee immediately (before any client is connected) and wait for
	// its initial breakpoint, then open the listen socket and, once the adapter connects, tell it
	// about the stop that already happened -- same shape as the old debug_loop.cpp's
	// RunDebugLoop()/WaitForInitialStop() split, just backed by WindowsDebugEngine/X2WinStubSession.
	if(options->mode == Options::Mode::Target){
		// No connection yet -- X2WinStubSession::WaitForFirstStop() fires independent of one.
		x2win::X2WinStubSession session(nullptr, x2win::SessionMode::Target);

		fprintf(stderr, "target mode: launching %s, waiting for initial breakpoint...\n", options->targetPath.c_str());
		if(!session.Engine().Execute(options->targetPath)){
			fprintf(stderr, "failed to launch target\n");
			return 1;
		}
		session.WaitForFirstStop();
		fprintf(stderr, "target stopped at initial breakpoint, waiting for adapter...\n");

		int result = 0;
		try{
			WinsockLibrary winsock;
			auto listener = CreateListenSocket(*options);
			if(!listener){
				result = 1;
			}else{
				SocketHandle clientSocket(accept(listener->get(), nullptr, nullptr));
				if(clientSocket.get() == INVALID_SOCKET){
					fprintf(stderr, "accept() falied: %d\n", WSAGetLastError());
					result = 1;
				}else{
					fprintf(stderr, "client connected\n");
					auto conn = std::make_shared<Connection>(std::move(clientSocket));
					session.SetConnection(conn.get());

					flatbuffers::FlatBufferBuilder stoppedBuilder;
					auto stoppedEventBody = x2win::CreateTargetStoppedEvent(stoppedBuilder,
						x2win::StopReason_INITIAL_BREAKPOINT, session.Engine().GetInstructionOffset());
					auto stoppedEnvelope = x2win::CreateEnvelope(stoppedBuilder, /*request_id=*/0,
						x2win::Body_TargetStoppedEvent, stoppedEventBody.Union());
					stoppedBuilder.Finish(stoppedEnvelope);
					conn->WriteEnvelope(stoppedBuilder);

					RunRequestLoop(conn.get(), session);
					fprintf(stderr, "client disconnected\n");
				}
			}
		}catch(const std::exception& e){
			fprintf(stderr, "%s\n", e.what());
			result = 1;
		}

		// session (and its WindowsDebugEngine) goes out of scope here; ~WindowsDebugEngine() Quit()s
		// and joins the debug thread if the target is somehow still alive and wasn't already handled
		// by RunRequestLoop's disconnect cleanup above.
		return result;
	}

	try{
		WinsockLibrary winsock;
		auto listener = CreateListenSocket(*options);
		if(!listener) return 1;

		for(;;){
			SocketHandle clientSocket(accept(listener->get(), nullptr, nullptr));
			if(clientSocket.get() == INVALID_SOCKET){
				fprintf(stderr, "accept() failed: %d\n", WSAGetLastError());
				continue;
			}

			fprintf(stderr, "client connected\n");
			auto conn = std::make_shared<Connection>(std::move(clientSocket));
			HandleClient(conn, options->mode);
			fprintf(stderr, "client disconnected\n");
		}
	}catch(const std::exception& e){
		fprintf(stderr, "%s\n", e.what());
		return 1;
	}
}
