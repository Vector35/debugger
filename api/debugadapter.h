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
		static bool ExecuteWithArgsCallback(void* ctxt, const std::string &path, const std::string &args,
									 const std::string &workingDir, const LaunchConfigurations &configs = {});
		static bool AttachCallback(void* ctxt, uint32_t pid);
		static bool ConnectCallback(void* ctxt, const std::string& server, uint32_t port);
		static bool ConnectToDebugServerCallback(void* ctxt, const std::string& server, uint32_t port);
		static bool DisconnectDebugServerCallback(void* ctxt);
		static bool DetachCallback(void* ctxt);
		static bool QuitCallback(void* ctxt);
		static std::vector<DebugProcess> GetProcessListCallback(void* ctxt);
		static std::vector<DebugThread> GetThreadListCallback(void* ctxt);
		static DebugThread GetActiveThreadCallback(void* ctxt);
		static uint32_t GetActiveThreadIdCallback(void* ctxt);
		static bool SetActiveThreadCallback(void* ctxt, const DebugThread& thread);
		static bool SetActiveThreadIdCallback(void* ctxt, uint32_t tid);
		static bool SuspendThreadCallback(void* ctxt, uint32_t tid);
		static bool ResumeThreadCallback(void* ctxt, uint32_t tid);
		static std::vector<DebugFrame> GetFramesOfThreadCallback(void* ctxt, uint32_t tid);
		static DebugBreakpoint AddBreakpointCallback(void* ctxt, const uint64_t address, unsigned long breakpoint_type = 0);
		static DebugBreakpoint AddBreakpointCallback(void* ctxt, const ModuleNameAndOffset& address, unsigned long breakpoint_type = 0);
		static bool RemoveBreakpointCallback(void* ctxt, const DebugBreakpoint& breakpoint);
		static bool RemoveBreakpointCallback(void* ctxt, const ModuleNameAndOffset& address);
		static std::vector<DebugBreakpoint> GetBreakpointListCallback(void* ctxt);
		static std::map<std::string, DebugRegister> ReadAllRegistersCallback(void* ctxt);
		static DebugRegister ReadRegisterCallback(void* ctxt, const std::string& reg);
		static bool WriteRegisterCallback(void* ctxt, const std::string& reg, uint64_t value);
		static DataBuffer ReadMemoryCallback(void* ctxt, uint64_t address, size_t size);
		static bool WriteMemoryCallback(void* ctxt, uint64_t address, const DataBuffer& buffer);
		static std::vector<DebugModule> GetModuleListCallback(void* ctxt);
		static std::string GetTargetArchitectureCallback(void* ctxt);
		static DebugStopReason StopReasonCallback(void* ctxt);
		static uint64_t ExitCodeCallback(void* ctxt);
		static bool BreakIntoCallback(void* ctxt);
		static bool GoCallback(void* ctxt);
		static bool StepIntoCallback(void* ctxt);
		static bool StepOverCallback(void* ctxt);
		static bool StepReturnCallback(void* ctxt);
		static std::string InvokeBackendCommandCallback(void* ctxt, const std::string& command);
		static uint64_t GetInstructionOffsetCallback(void* ctxt);
		static uint64_t GetStackPointerCallback(void* ctxt);
//		bool SupportFeature(DebugAdapterCapacity feature);
		// This is implemented by the (base) DebugAdapter class.
		// Sub-classes should use it to post debugger events directly (only when needed).
		void PostDebuggerEvent(const DebuggerEvent& event);
		static void WriteStdinCallback(void* ctxt, const std::string& msg);
//		BinaryNinja::Ref<BinaryNinja::Metadata> GetProperty(const std::string& name);
//		bool SetProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);
	public:
		DebugAdapter(BinaryView* data);
		~DebugAdapter();

		bool Init();
	};
};
