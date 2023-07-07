#include "../../api/debuggerapi.h"
#include "binaryninjaapi.h"

namespace BinaryNinjaDebuggerAPI
{
	class Win32DebugAdapter: public DebugAdapter
	{
		struct ThreadInfo
		{
			HANDLE m_handle{};
			DWORD m_tid{};
			uint64_t m_startAddress{};
			uint64_t m_threadLocalStorage{};

		public:
			ThreadInfo() {}
			ThreadInfo(HANDLE handle, DWORD tid, uint64_t addr, uint64_t tls):
				m_handle(handle), m_tid(tid), m_startAddress(addr), m_threadLocalStorage(tls)
			{}
		};

		PROCESS_INFORMATION m_processInfo;
		HANDLE m_debugEvent;
		void DebugLoop();
		void Reset();

		std::map<DWORD, ThreadInfo> m_threads;
		DWORD m_activeThreadID;

	public:
		Win32DebugAdapter(BinaryNinja::BinaryView* data);
		bool ExecuteWithArgs(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs) override;
		bool ExecuteWithArgsInternal(const std::string& path, const std::string& args, const std::string& workingDir,
			const LaunchConfigurations& configs);
		std::map<std::string, DebugRegister> ReadAllRegisters() override;
		size_t ReadMemory(void* dest, uint64_t address, size_t size) override;
		bool WriteMemory(uint64_t address, const void* buffer, size_t size) override;

		std::vector<DebugThread> GetThreadList() override;
		DebugThread GetActiveThread() override;
		uint32_t GetActiveThreadId() override;
//		bool SetActiveThread(const DebugThread& thread) override;
//		bool SetActiveThreadId(uint32_t tid) override;
//		bool SuspendThread(uint32_t tid) override;
//		bool ResumeThread(uint32_t tid) override;
	};


	class Win32DebugAdapterType: public DebugAdapterType
	{
	public:
		Win32DebugAdapterType();
		bool IsValidForData(Ref<BinaryView> data) override;
		bool CanExecute(Ref<BinaryView> data) override;
		bool CanConnect(Ref<BinaryView> data) override;
		DbgRef<DebugAdapter> Create(BinaryNinja::BinaryView* data) override;
	};
}