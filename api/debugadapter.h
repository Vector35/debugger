#include "debuggerapi.h"

using namespace BinaryNinja;

namespace BinaryNinjaDebuggerAPI
{
	class DebugAdapter: public DbgCoreRefCountObject<BNDebugAdapter, BNDebuggerNewDebugAdapterReference,
			BNDebuggerFreeDebugAdapter>
	{
	private:
		static bool InitCallback(void* ctxt);
		static bool ExecuteWithArgsCallback(void* ctxt, const char* path, const char* args, const char* workingDir,
											const BNLaunchConfigurations* configs);
		static bool AttachCallback(void* ctxt, uint32_t pid);
		static bool ConnectCallback(void* ctxt, const char* server, uint32_t port);
		static bool ConnectToDebugServerCallback(void* ctxt, const char* server, uint32_t port);
		static bool DisconnectDebugServerCallback(void* ctxt);
		static bool DetachCallback(void* ctxt);
		static bool QuitCallback(void* ctxt);
		static BNDebugProcess* GetProcessListCallback(void* ctxt, size_t* count);
		static BNDebugThread* GetThreadListCallback(void* ctxt, size_t* count);
		static BNDebugThread GetActiveThreadCallback(void* ctxt);
		static uint32_t GetActiveThreadIdCallback(void* ctxt);
		static bool SetActiveThreadCallback(void* ctxt, BNDebugThread thread);
		static bool SetActiveThreadIdCallback(void* ctxt, uint32_t tid);
		static bool SuspendThreadCallback(void* ctxt, uint32_t tid);
		static bool ResumeThreadCallback(void* ctxt, uint32_t tid);
		static BNDebugFrame* GetFramesOfThreadCallback(void* ctxt, uint32_t tid, size_t* count);
		static BNDebugBreakpoint* AddBreakpointWithAddressCallback(void* ctxt, const uint64_t address, unsigned long breakpoint_type);
		static BNDebugBreakpoint* AddBreakpointWithModuleAndOffsetCallback(void* ctxt, const char* module, uint64_t offset,
																		   unsigned long type);
		static bool RemoveBreakpointCallback(void* ctxt, BNDebugBreakpoint* breakpoint);
		static bool RemoveBreakpointWithModuleAndOffsetCallback(void* ctxt, const char* module, uint64_t offset);
		static BNDebugBreakpoint* GetBreakpointListCallback(void* ctxt, size_t* count);
		static BNDebugRegister* ReadAllRegistersCallback(void* ctxt, size_t* count);
		static BNDebugRegister* ReadRegisterCallback(void* ctxt, const char* reg);
		static bool WriteRegisterCallback(void* ctxt, const char* reg, uint64_t value);
		static BNDataBuffer* ReadMemoryCallback(void* ctxt, uint64_t address, size_t size);
		static bool WriteMemoryCallback(void* ctxt, uint64_t address, BNDataBuffer* buffer);
		static BNDebugModule* GetModuleListCallback(void* ctxt, size_t* count);
		static char* GetTargetArchitectureCallback(void* ctxt);
		static DebugStopReason StopReasonCallback(void* ctxt);
		static uint64_t ExitCodeCallback(void* ctxt);
		static bool BreakIntoCallback(void* ctxt);
		static bool GoCallback(void* ctxt);
		static bool StepIntoCallback(void* ctxt);
		static bool StepOverCallback(void* ctxt);
		static bool StepReturnCallback(void* ctxt);
		static char* InvokeBackendCommandCallback(void* ctxt, const char*command);
		static uint64_t GetInstructionOffsetCallback(void* ctxt);
		static uint64_t GetStackPointerCallback(void* ctxt);
//		bool SupportFeature(DebugAdapterCapacity feature);
		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
		void PostDebuggerEvent(const DebuggerEvent& event);
		static void WriteStdinCallback(void* ctxt, const char* msg);
//		BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name);
//		bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);
	public:
		DebugAdapter(BinaryView* data);
		~DebugAdapter();

		virtual bool Init();
		virtual bool ExecuteWithArgs(const std::string& path, const std::string& args,
									 const std::string& workingDir, const LaunchConfigurations& configs = {});
		virtual bool Attach(uint32_t pid);
		virtual bool Connect(const std::string& server, uint32_t port);
		virtual bool ConnectToDebugServer(const std::string& server, uint32_t port);
		virtual bool DisconnectDebugServer();
		virtual bool Detach();
		virtual bool Quit();
		virtual std::vector<DebugProcess> GetProcessList();
		virtual std::vector<DebugThread> GetThreadList();
		virtual DebugThread GetActiveThread();
		virtual uint32_t GetActiveThreadId();
		virtual bool SetActiveThread(const DebugThread& thread);
		virtual bool SetActiveThreadId(uint32_t tid);
		virtual bool SuspendThread(uint32_t tid);
		virtual bool ResumeThread(uint32_t tid);
		virtual std::vector<DebugFrame> GetFramesOfThread(uint32_t tid);
		virtual DebugBreakpoint AddBreakpoint(const uint64_t address, unsigned long breakpoint_type = 0);
		virtual DebugBreakpoint AddBreakpoint(const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0);
		virtual bool RemoveBreakpoint(const DebugBreakpoint& breakpoint);
		virtual bool RemoveBreakpoint(const ModuleNameAndOffset& address);
		virtual std::vector<DebugBreakpoint> GetBreakpointList();
		virtual std::map<std::string, DebugRegister> ReadAllRegisters();
		virtual DebugRegister ReadRegister(const std::string& reg);
		virtual bool WriteRegister(const std::string& reg, uint64_t value);
		virtual DataBuffer ReadMemory(uint64_t address, size_t size);
		virtual bool WriteMemory(uint64_t address, const DataBuffer& buffer);
		virtual std::vector<DebugModule> GetModuleList();
		virtual std::string GetTargetArchitecture();
		virtual DebugStopReason StopReason();
		virtual uint64_t ExitCode();
		virtual bool BreakInto();
		virtual bool Go();
		virtual bool StepInto();
		virtual bool StepOver();
		virtual bool StepReturn();
		virtual std::string InvokeBackendCommand(const std::string& command);
		virtual uint64_t GetInstructionOffset();
		virtual uint64_t GetStackPointer();
//		bool SupportFeature(DebugAdapterCapacity feature);
		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
//		void PostDebuggerEvent(const DebuggerEvent& event);
		virtual void WriteStdin(const std::string& msg);
//		BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name);
//		bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);

	};
};
