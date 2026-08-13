// Repro for the RspConnector lifetime race (Sentry BINARYNINJA-4E / C1 / E1 ...).
//
// Production shape being reproduced:
//   thread A (UI / user action) : GdbAdapter::AddBreakpoint -> m_rspConnector->TransmitAndReceive
//   thread B (ResponseHandler / target exit) : GdbAdapter::Quit -> delete m_rspConnector; = nullptr
//
// Neither side synchronizes access to the m_rspConnector field, and neither
// AddBreakpoint nor Quit null-checks it before dereferencing. Result is either a
// use-after-free or a null-`this` deref that faults while locking m_socketLock
// (matching "EXCEPTION_ACCESS_VIOLATION_READ / 0x0" inside mtx_do_lock).

#include <arpa/inet.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include "binaryninjaapi.h"
#include "adapters/gdbadapter.h"

using namespace BinaryNinja;
using namespace BinaryNinjaDebugger;

// ---------------------------------------------------------------------------
// Minimal fake GDB-RSP server.
//
// Acks every packet and answers with the empty packet ($#00 == "unsupported").
// That is enough for GdbAdapter::Connect() to allocate m_rspConnector and walk
// most of the handshake; it then bails at LoadRegisterInfo, which is fine --
// the connector is live either way, which is all the race needs.
// ---------------------------------------------------------------------------
class FakeRspServer
{
public:
	// Binds the GdbAdapter's default connect.port (31337) on 127.0.0.1 (its
	// default connect.ipAddress), so Connect() needs no settings manipulation.
	bool Start(uint16_t port)
	{
		m_listenFd = socket(AF_INET, SOCK_STREAM, 0);
		if (m_listenFd < 0)
			return false;
		int yes = 1;
		setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

		sockaddr_in addr {};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(port);
		if (bind(m_listenFd, (sockaddr*)&addr, sizeof(addr)) < 0)
		{
			perror("bind");
			return false;
		}
		if (listen(m_listenFd, 4) < 0)
			return false;

		m_thread = std::thread([this] { Serve(); });
		return true;
	}

	void Stop()
	{
		m_stop.store(true);
		if (m_listenFd >= 0)
		{
			shutdown(m_listenFd, SHUT_RDWR);
			close(m_listenFd);
			m_listenFd = -1;
		}
		if (m_connFd >= 0)
		{
			shutdown(m_connFd, SHUT_RDWR);
			close(m_connFd);
			m_connFd = -1;
		}
		if (m_thread.joinable())
			m_thread.join();
	}

	~FakeRspServer() { Stop(); }

private:
	void Serve()
	{
		int fd = accept(m_listenFd, nullptr, nullptr);
		if (fd < 0)
			return;
		m_connFd = fd;

		std::string buf;
		char tmp[4096];
		while (!m_stop.load())
		{
			ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
			if (n <= 0)
				break;
			buf.append(tmp, (size_t)n);

			// Consume any complete "$...#XX" packets; ack + reply empty.
			for (;;)
			{
				size_t dollar = buf.find('$');
				if (dollar == std::string::npos)
				{
					buf.clear();  // only acks / noise
					break;
				}
				size_t hash = buf.find('#', dollar);
				if (hash == std::string::npos || hash + 2 >= buf.size())
					break;  // incomplete, wait for more

				buf.erase(0, hash + 3);

				const char ack = '+';
				if (send(fd, &ack, 1, 0) != 1)
					return;
				static const char empty[] = "$#00";
				if (send(fd, empty, sizeof(empty) - 1, 0) != (ssize_t)(sizeof(empty) - 1))
					return;
			}
		}
	}

	int m_listenFd = -1;
	std::atomic<int> m_connFd {-1};
	std::atomic<bool> m_stop {false};
	std::thread m_thread;
};

// ---------------------------------------------------------------------------

static Ref<BinaryView> g_bv;

// One race attempt: fresh adapter, connect, then run AddBreakpoint concurrently
// with Quit. delayUs staggers the teardown so repeated iterations sweep the
// window between "load m_rspConnector" and "use m_rspConnector".
static int g_breakpointsPerIteration = 4;

static void RaceOnce(int iteration, int delayUs)
{
	static const uint16_t kPort = 31337;  // GdbAdapter's default connect.port

	FakeRspServer server;
	if (!server.Start(kPort))
	{
		fprintf(stderr, "[%d] server start failed\n", iteration);
		return;
	}

	auto* adapter = new GdbAdapter(g_bv.GetPtr(), false);
	// No DebuggerController in this harness; DebugAdapter::GetData() null-checks
	// m_controller, but the ctor never initializes it, so set it explicitly.
	adapter->SetController(nullptr);
	adapter->Connect("127.0.0.1", kPort);  // allocates m_rspConnector

	std::atomic<bool> go {false};

	// Thread A: the "user action" side (UI thread applying breakpoints).
	std::thread user([&] {
		while (!go.load(std::memory_order_acquire))
			std::this_thread::yield();
		for (int i = 0; i < g_breakpointsPerIteration; i++)
			adapter->AddBreakpoint((std::uintptr_t)(0x100000 + i * 4));
	});

	// Thread B: the "target exited / user quit" side.
	std::thread teardown([&] {
		while (!go.load(std::memory_order_acquire))
			std::this_thread::yield();
		if (delayUs > 0)
			std::this_thread::sleep_for(std::chrono::microseconds(delayUs));
		adapter->Quit();
	});

	go.store(true, std::memory_order_release);
	user.join();
	teardown.join();

	server.Stop();
	// Deliberately leaked: tearing the adapter down here would obscure which
	// free ASan is reporting.
}

int main(int argc, char** argv)
{
	const char* binary = (argc > 1) ? argv[1]
		: "/Users/xusheng/debugger_build/debugger/test/binaries/Darwin-arm64-signed/helloworld";
	const int iterations = (argc > 2) ? atoi(argv[2]) : 200;
	if (argc > 3)
		g_breakpointsPerIteration = atoi(argv[3]);

	SetBundledPluginDirectory(
		"/Users/xusheng/debugger_build/dependencies/BN-dev/Binary Ninja.app/Contents/MacOS/plugins");
	if (!InitPlugins())
	{
		fprintf(stderr, "InitPlugins failed\n");
		return 1;
	}

	g_bv = Load(binary, true);
	if (!g_bv)
	{
		fprintf(stderr, "failed to load %s\n", binary);
		return 1;
	}
	printf("loaded %s (%s)\n", binary, g_bv->GetTypeName().c_str());

	for (int i = 0; i < iterations; i++)
	{
		// Sweep the stagger: 0us catches "both in flight", larger values catch
		// "teardown lands mid-call".
		RaceOnce(i, i % 40);
		printf("iteration %d/%d ok\n", i, iterations);
		fflush(stdout);
	}

	printf("completed %d iterations with no fault\n", iterations);
	return 0;
}
