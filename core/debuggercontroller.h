/*
Copyright 2020-2026 Vector 35 Inc.

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

#pragma once
#include "binaryninjaapi.h"
#include "base/assertions.h"
#include "debuggerstate.h"
#include "debuggerevent.h"
#include <queue>
#include <list>
#include <future>
#include <functional>
#include <optional>
#include <type_traits>
#include <unordered_set>
#include "ffi_global.h"
#include "refcountobject.h"
#include "debuggerfileaccessor.h"

DECLARE_DEBUGGER_API_OBJECT(BNDebuggerController, DebuggerController);

namespace BinaryNinjaDebugger {
	class DebuggerController;

	// Set to the controller pointer when running on that controller's worker thread,
	// nullptr otherwise. Used by DebuggerController::Submit to detect re-entrant calls
	// without needing to synchronize a thread::id field across threads.
	extern thread_local DebuggerController* t_controllerOnWorker;

	struct DebuggerEventCallback
	{
		std::function<void(const DebuggerEvent& event)> function;
		size_t index;
		std::string name;
	};

	// This is used by the debugger to track stack variables it defined. It is simpler than
	// BinaryNinja::VariableNameAndType that it does not track the Variable and autoDefined.
	struct StackVariableNameAndType
	{
		Confidence<Ref<Type>> type;
		std::string name;

		StackVariableNameAndType() = default;
		StackVariableNameAndType(Confidence<Ref<Type>> t, const std::string& n)
		{
			type = t;
			name = n;
		}

		bool operator==(const StackVariableNameAndType& other) { return (type == other.type) && (name == other.name); }

		bool operator!=(const StackVariableNameAndType& other) { return !(*this == other); }
	};

	struct DebuggerUICallbacks
	{
		BNDebuggerUICallbacks* m_callbacks;
		void* m_context;

		void NotifyRebaseBinaryView(uint64_t base);
	};

	// This is the controller class of the debugger. It receives the input from the UI/API, and then route them to
	// the state and UI, etc. Most actions should reach here.
	class DebuggerController : public DbgRefCountObject, BinaryNinja::BinaryDataNotification
	{
		IMPLEMENT_DEBUGGER_API_OBJECT(BNDebuggerController);

		struct PendingEvent {
			DebuggerEvent event;
			std::promise<void> done;
		};

	private:
		// m_adapter is the active debug adapter for this controller. Written exclusively
		// from the worker thread (in CreateDebugAdapter); read both from the worker
		// (the bulk of references inside ExecuteAdapterAndWait and adapter ops) and
		// from arbitrary caller threads (RequestInterrupt's out-of-band BreakInto).
		//
		// The pointed-to adapter object's lifetime is guaranteed externally: it is
		// destroyed only inside ~DebuggerState, which runs inside ~DebuggerController
		// after both worker threads have joined. Cross-thread callers hold a DbgRef
		// on the controller during their call, so the adapter cannot be destroyed
		// out from under them. See the "Refcount the DebugAdapter" follow-up issue
		// for the structural fix that would make this guarantee enforced by the type.
		DebugAdapter* m_adapter;
		DebuggerState* m_state;
		FileMetadataRef m_file;
		BinaryViewRef m_data;
		DebuggerFileAccessor* m_accessor {};
		// When the backend reports a memory map, we mirror it into the BinaryView as one bounded remote
		// region per entry (instead of the single blanket overlay). These track the live mirror so we can
		// tear it down and diff it against the next stop's map.
		std::vector<DebuggerFileAccessor*> m_regionAccessors;
		// Accessors from a previous memory-map generation. The MemoryMap may still hold copies of their
		// callbacks in an in-flight snapshot, so we retire rather than free them on change and only delete
		// them at teardown. Map changes are rare (module load, new mmap), so this stays small.
		std::vector<DebuggerFileAccessor*> m_retiredAccessors;
		// Names of the memory regions we currently have registered on m_data ("debugger" for the blanket
		// fallback, or "debugger:<i>" for the per-entry mirror).
		std::vector<std::string> m_debuggerRegionNames;
		// The memory map currently reflected in m_data, used to no-op when nothing changed between stops.
		std::vector<DebugMemoryRegion> m_appliedMemoryRegions;
		// Cached "debugger.useMemoryMapSegments" setting, sampled once when the debugger view is created
		// (SyncMemoryRegions runs on every stop, so we do not want to hit Settings each time). When false,
		// the debugger keeps the old blanket overlay instead of mirroring the backend memory map.
		bool m_useMemoryMapSegments = true;
		// This is the start address of the first file segments in the m_data. Unlike the return value of GetStart(),
		// this does not change even if we add the debugger memory region. In the future, this should be provided by
		// the binary view -- we will no longer need to track it ourselves
		uint64_t m_viewStart;

		struct ControllerState
		{
			std::mutex mutex;
			std::vector<DbgRef<DebuggerController>> controllers;
		};
		static ControllerState& GetControllerState();

		std::atomic<size_t> m_callbackIndex = 0;
		std::list<DebuggerEventCallback> m_eventCallbacks;
		std::mutex m_callbackMutex;
		std::set<size_t> m_disabledCallbacks;

		uint64_t m_lastIP = 0;
		uint64_t m_currentIP = 0;

		// This is only meaningful after the target exits. In the future, we should enforce a check for the target
		// status before returning the value
		uint32_t m_exitCode = 0;

		DebugAdapterOperation m_lastOperation = DebugAdapterGo;

		// Adapter-stop channel: internal signal from the adapter thread to the worker.
		// AdapterStoppedEventType posted via PostDebuggerEvent is intercepted and routed
		// here rather than dispatched through the public event queue. WaitForAdapterStop
		// blocks on m_adapterStopCv until either an adapter stop arrives or shutdown is
		// requested. m_inAdapterWait is true for the entire duration of an in-flight
		// ExecuteAdapterAndWait call (including the silent-resume loop between iterations
		// for conditional breakpoints) so that any stop during that window is consumed
		// by WaitForAdapterStop and not treated as spontaneous.
		std::mutex m_adapterStopMutex;
		std::condition_variable m_adapterStopCv;
		std::optional<DebugStopReason> m_adapterStopPending;
		bool m_inAdapterWait = false;
		DebugStopReason WaitForAdapterStop();
		void HandleSpontaneousAdapterStop(DebugStopReason reason);
		bool ShouldSilentResumeAfterStop();

		// Out-of-band: ask the interrupt thread to break the engine. Returns immediately
		// (does not block the caller on the adapter call). Called from Pause/Restart/Quit/
		// Detach before queueing the actual operation, so the worker's in-flight resume op
		// (if any) gets interrupted and the queued task can proceed.
		void RequestInterrupt();

		bool m_inputFileLoaded = false;
		bool m_initialBreakpointSeen = false;

		bool m_firstLaunch = true;
		bool m_firstConnect = true;
		bool m_firstConnectToDebugServer = true;
		bool m_firstAttach = true;

		// Whether to show the adapter settings dialog before the next debug session is started. When the user starts a
		// session whose kind differs from m_lastDebugStartOperation we always show the dialog regardless of this flag,
		// so that switching between e.g. launch and attach never silently reuses stale settings.
		enum LastDebugStartOperation
		{
			NoDebugStartOperation,
			LaunchStartOperation,
			AttachStartOperation,
			ConnectStartOperation,
			ConnectToDebugServerStartOperation,
		};
		bool m_showAdapterSettingsNextTime = true;
		LastDebugStartOperation m_lastDebugStartOperation = NoDebugStartOperation;

		bool m_shouldAnnotateStackVariable = false;

		// Apply the controller's own state mutations for each event type. Called inline
		// from PostDebuggerEvent before the event is enqueued for the dispatcher, so
		// m_state is consistent before any external consumer (or the worker waking from
		// WaitForAdapterStop) observes the change.
		void ApplyOwnStateForEvent(const DebuggerEvent& event);
		// Idempotent "target is gone" cleanup (memory cache + the "debugger" BinaryView region +
		// analysis hold). These call into BN core, which takes the file lock, so this MUST run with
		// no adapter lock held -- see ExecuteAdapterAndWait, which invokes it after releasing the
		// lock. Deliberately NOT done inline in ApplyOwnStateForEvent, which can run while the
		// adapter lock is held (that is the AB-BA deadlock with the analysis read path).
		void FinalizeTargetGoneCleanup();
		void UpdateStackVariables();
		void AddRegisterValuesToExpressionParser();
		void AddModuleValuesToExpressionParser();
		bool EvaluateBreakpointCondition(uint64_t address);
		bool CreateDebuggerBinaryView();

		DebugStopReason StepIntoIL(BNFunctionGraphType il);
		DebugStopReason StepIntoReverseIL(BNFunctionGraphType il);
		DebugStopReason StepOverIL(BNFunctionGraphType il);
		DebugStopReason StepOverReverseIL(BNFunctionGraphType il);

		// Low-level internal synchronous APIs. They resume the target and wait for the adapter to stop.
		// They do NOT dispatch the debugger event callbacks. Higher-level APIs must take care of notifying
		// the callbacks.
		DebugStopReason LaunchAndWaitInternal();
		DebugStopReason AttachAndWaitInternal();
		DebugStopReason ConnectAndWaitInternal();
		DebugStopReason PauseAndWaitInternal();
		DebugStopReason GoAndWaitInternal();
		DebugStopReason GoReverseAndWaitInternal();
		DebugStopReason StepIntoAndWaitInternal();
		DebugStopReason StepIntoReverseAndWaitInternal();
		DebugStopReason EmulateStepOverAndWait();
		DebugStopReason EmulateStepOverReverseAndWait();
		DebugStopReason StepOverAndWaitInternal();
		DebugStopReason StepOverReverseAndWaitInternal();
		DebugStopReason EmulateStepReturnAndWait();
		DebugStopReason StepReturnAndWaitInternal();
		DebugStopReason StepReturnReverseAndWaitInternal();
		DebugStopReason RunToAndWaitInternal(const std::vector<uint64_t> &remoteAddresses);
		DebugStopReason RunToReverseAndWaitInternal(const std::vector<uint64_t> &remoteAddresses);

		// Worker-thread bodies. Each runs on m_workerThread (via Submit) and performs the
		// existing lock-Internal-notify wrapper. The public `XxxAndWait(timeout)` methods
		// below submit one of these and wait on the resulting future.
		DebugStopReason LaunchAndWaitOnWorker();
		DebugStopReason AttachAndWaitOnWorker();
		DebugStopReason ConnectAndWaitOnWorker();
		DebugStopReason GoAndWaitOnWorker();
		DebugStopReason GoReverseAndWaitOnWorker();
		DebugStopReason StepIntoAndWaitOnWorker(BNFunctionGraphType il);
		DebugStopReason StepIntoReverseAndWaitOnWorker(BNFunctionGraphType il);
		DebugStopReason StepOverAndWaitOnWorker(BNFunctionGraphType il);
		DebugStopReason StepOverReverseAndWaitOnWorker(BNFunctionGraphType il);
		DebugStopReason StepReturnAndWaitOnWorker();
		DebugStopReason StepReturnReverseAndWaitOnWorker();
		DebugStopReason RunToAndWaitOnWorker(const std::vector<uint64_t>& remoteAddresses);
		DebugStopReason RunToReverseAndWaitOnWorker(const std::vector<uint64_t>& remoteAddresses);
		DebugStopReason RestartAndWaitOnWorker();
		void DetachAndWaitOnWorker();
		void QuitAndWaitOnWorker();
		// Pause has no *OnWorker variant: it's out-of-band by design. See Pause() /
		// PauseAndWait() -- they call RequestInterrupt (which hands the break to the
		// interrupt thread) rather than queueing work, because the worker is blocked
		// inside an in-flight resume op when Pause is needed.

		// Whether we can start debugging, e.g., launch/attach/connec to a target
		bool CanStartDebgging();
		// Whether we can resume the execution of the target, including stepping.
		bool CanResumeTarget();

		bool ExpectSingleStep(DebugStopReason reason);

		std::map<uint64_t, StackVariableNameAndType> m_debuggerVariables;
		std::set<uint64_t> m_addressesWithVariable;
		std::set<uint64_t> m_oldAddresses;
		std::set<uint64_t> m_addressesWithComment;
		void ProcessOneVariable(uint64_t address, Confidence<Ref<Type>> type, const std::string& name);
		void DefineVariablesRecursive(uint64_t address, Confidence<Ref<Type>> type);

		// Tracks the symbols the debugger has added to the BinaryView from the debugger backend, keyed by
		// the module's base file name. The value is the exact auto symbols that were defined, so they can
		// later be removed -- either per module on user request or in bulk when the target is gone. We keep
		// the Symbol objects (rather than just their addresses) because the linker can fold several distinct
		// symbols onto the same address (e.g. identical .cold stubs), and GetSymbolByAddress only returns
		// one of them. See LoadSymbolsForModule / RemoveSymbolsForModule.
		std::map<std::string, std::vector<Ref<Symbol>>> m_loadedModuleSymbols;
		std::recursive_mutex m_loadedModuleSymbolsMutex;
		// Undefine the given auto symbols and their data variables in a self-contained analysis-update /
		// undo-action window. Returns the number of symbols processed. m_loadedModuleSymbolsMutex must be held.
		size_t UndefineTrackedSymbols(const std::vector<Ref<Symbol>>& symbols);
		// Define / undefine a module's symbols directly in the BinaryView. The caller must hold
		// m_loadedModuleSymbolsMutex, have already disabled function-analysis updates, and manage the
		// undo-action scope. Applying every module inside one such shared window -- rather than opening one
		// per module -- lets a single analysis pass re-resolve every module's references (e.g. IAT pointers
		// to freshly-named API functions); a per-module window would let each module's async re-analysis be
		// superseded by the next module's disable, so only the last module loaded would resolve. See #210.
		size_t ApplyModuleSymbolsLocked(
			BinaryViewRef data, const DebugModule& module, const std::vector<DebugSymbol>& symbols);
		size_t RemoveTrackedSymbolsLocked(BinaryViewRef data, const std::vector<Ref<Symbol>>& symbols);

		void ApplyBreakpoints();

		std::string m_lastAdapterName;
		std::string m_lastCommand;

		bool m_zeroSegmentAddedByDebugger = false;

		BNAnalysisState m_oldAnalysisState = IdleState;

		void DetectLoadedModule();

		std::mutex m_eventsMutex;
		std::condition_variable m_cv;
		std::queue<std::shared_ptr<PendingEvent>> m_eventQueue;
		std::thread::id m_dispatcherThreadId;
		std::atomic_bool m_shouldExit;
		std::thread m_debuggerEventThread;
		void DebuggerMainThread();

		// Worker queue: serializes all controller operations on a single thread.
		// Replaces the per-op `std::thread(...).detach()` pattern. Tasks submitted from any
		// thread run in order on m_workerThread; lifetime is owned and joined in the destructor.
		// If Submit is called from the worker thread itself, the task runs inline to avoid
		// deadlock when an operation needs to invoke another (e.g. Restart calls Quit + Launch).
		std::thread m_workerThread;
		std::mutex m_workQueueMutex;
		std::condition_variable m_workQueueCv;
		std::queue<std::function<void()>> m_workQueue;
		std::atomic_bool m_workerShouldExit;
		void WorkerThreadMain();

		// Interrupt thread: a single owned thread whose only job is to issue out-of-band
		// BreakInto() calls. RequestInterrupt() (called from Pause/Restart/Quit/Detach on
		// arbitrary caller threads) just sets m_interruptRequested and notifies, then
		// returns -- so callers never block on a synchronous adapter call.
		//
		// The BreakInto must run off the worker thread (the worker is blocked inside
		// WaitForAdapterStop on the very op being interrupted) and we don't want it on the
		// caller's thread either (the UI thread must not block on an adapter call). This
		// thread is the third option: owned and joined like m_workerThread, so it can never
		// outlive the controller or touch a destroyed adapter.
		std::thread m_interruptThread;
		std::mutex m_interruptMutex;
		std::condition_variable m_interruptCv;
		bool m_interruptRequested = false;
		bool m_interruptShouldExit = false;
		void InterruptThreadMain();

		// Submit work onto the controller's worker thread. Strictly for external callers
		// (UI / FFI / plugins / adapter event threads). Worker code chains compound
		// operations as direct calls to the *OnWorker / *Internal helpers -- it does NOT
		// re-enter the queue. The assert below catches accidental misuse, which the queue
		// model would silently mishandle (deferred execution in unexpected order, or in
		// SubmitAndWait's case a self-deadlock).
		template<typename F>
		auto Submit(F&& f) -> std::future<std::invoke_result_t<F>>
		{
			BN_RELEASE_ASSERT(t_controllerOnWorker != this);
			using R = std::invoke_result_t<F>;
			auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
			auto future = task->get_future();

			{
				std::lock_guard<std::mutex> lock(m_workQueueMutex);
				if (m_workerShouldExit)
					return future;  // future is left unset; caller's get() will throw broken_promise
				m_workQueue.push([task]() { (*task)(); });
			}
			m_workQueueCv.notify_one();
			return future;
		}

		// Submit a worker task and block the caller until the task completes. A timeout of
		// milliseconds::max() means "wait forever" and bypasses wait_for entirely (avoids
		// overflow inside the stdlib). When the timeout elapses, return a timeout result
		// without interrupting the target; the queued worker task keeps running and will
		// eventually publish its normal events.
		//
		// This is the synchronous public-API path: it must NOT be called from the worker
		// thread itself or from debugger callbacks. Worker-side code that needs to chain
		// operations should call the matching *OnWorker / *Internal helper directly (e.g.
		// RestartAndWaitOnWorker calls QuitAndWaitOnWorker / LaunchAndWaitOnWorker,
		// QuitAndWaitOnWorker uses PauseAndWaitInternal). Callback code should use async
		// APIs such as Go() / StepInto() so it does not wait on the worker while the worker
		// is waiting for event dispatch to complete.
		template<typename F>
		auto SubmitAndWait(F&& f, std::chrono::milliseconds timeout)
			-> std::invoke_result_t<F>
		{
			BN_RELEASE_ASSERT(t_controllerOnWorker != this);
			using R = std::invoke_result_t<F>;
			if (std::this_thread::get_id() == m_dispatcherThreadId)
			{
				LogError("Synchronous debugger API called from debugger callback thread; use async APIs from callbacks");
				if constexpr (std::is_void_v<R>)
					return;
				else if constexpr (std::is_same_v<R, DebugStopReason>)
					return InternalError;
				else
					return R {};
			}
			auto fut = Submit(std::forward<F>(f));
			if (timeout != std::chrono::milliseconds::max())
			{
				if (fut.wait_for(timeout) != std::future_status::ready)
				{
					if constexpr (std::is_void_v<R>)
						return;
					else if constexpr (std::is_same_v<R, DebugStopReason>)
						return TimedOut;
					else
						return R {};
				}
			}
			return fut.get();
		}

		std::unique_ptr<DebuggerUICallbacks> m_uiCallbacks;

		uint64_t m_oldViewBase, m_newViewBase;
		std::vector<BNAddressRange> m_ranges;
		BinaryNinja::Ref<BinaryNinja::AnalysisCompletionEvent> m_rebaseCompletionEvent;

		// TTD Code Coverage Analysis
		std::unordered_map<uint64_t, uint32_t> m_executedInstructionCounts;
		bool m_codeCoverageAnalysisRun = false;

		// TTD Position History for back/forward navigation
		std::vector<TTDPosition> m_ttdPositionHistory;
		int m_ttdPositionHistoryIndex = -1;
		bool m_suppressTTDPositionRecording = false;
		void RecordTTDPosition();

	public:
		DebuggerController(BinaryViewRef data);
		static DbgRef<DebuggerController> GetController(BinaryViewRef data);
		static void DeleteController(BinaryViewRef data);
		static bool ControllerExists(BinaryViewRef data);

		static DbgRef<DebuggerController> GetController(FileMetadataRef file);
		static void DeleteController(FileMetadataRef file);
		static bool ControllerExists(FileMetadataRef file);

		// Explicitly destroy the current controller, so a new controller on the same binaryview will be brand new.
		// I am not super sure that this is the correct way of doing things, but it addresses the controller reuse
		// problem.
		void Destroy();
		~DebuggerController();

		// breakpoints
		void AddBreakpoint(uint64_t address);
		void AddBreakpoint(const ModuleNameAndOffset& address);
		void DeleteBreakpoint(uint64_t address);
		void DeleteBreakpoint(const ModuleNameAndOffset& address);
		void EnableBreakpoint(uint64_t address);
		void EnableBreakpoint(const ModuleNameAndOffset& address);
		void DisableBreakpoint(uint64_t address);
		void DisableBreakpoint(const ModuleNameAndOffset& address);
		bool ContainsBreakpoint(const ModuleNameAndOffset& address);
		DebugBreakpoint GetAllBreakpoints();
		bool SetBreakpointCondition(uint64_t address, const std::string& condition);
		bool SetBreakpointCondition(const ModuleNameAndOffset& address, const std::string& condition);
		std::string GetBreakpointCondition(uint64_t address);
		std::string GetBreakpointCondition(const ModuleNameAndOffset& address);

		// hardware breakpoints
		// Hardware breakpoint methods - absolute address
		bool AddHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size);
		bool RemoveHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size);
		bool EnableHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size);
		bool DisableHardwareBreakpoint(uint64_t address, DebugBreakpointType type, size_t size);

		// Hardware breakpoint methods - module+offset (ASLR-safe)
		bool AddHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size);
		bool RemoveHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size);
		bool EnableHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size);
		bool DisableHardwareBreakpoint(const ModuleNameAndOffset& location, DebugBreakpointType type, size_t size);

		// registers
		intx::uint512 GetRegisterValue(const std::string& name);
		bool SetRegisterValue(const std::string& name, intx::uint512 value);
		std::vector<DebugRegister> GetAllRegisters();

		// processes
		std::vector<DebugProcess> GetProcessList();

		// threads
		DebugThread GetActiveThread() const;
		void SetActiveThread(const DebugThread& thread);
		std::vector<DebugThread> GetAllThreads();
		std::vector<DebugFrame> GetFramesOfThread(uint64_t tid);
		bool SuspendThread(std::uint32_t tid);
		bool ResumeThread(std::uint32_t tid);

		// modules
		std::vector<DebugModule> GetAllModules();
		DebugModule GetModuleByName(const std::string& module);
		bool GetModuleBase(const std::string& name, uint64_t& address);
		DebugModule GetModuleForAddress(uint64_t remoteAddress);
		ModuleNameAndOffset AbsoluteAddressToRelative(uint64_t absoluteAddress);
		uint64_t RelativeAddressToAbsolute(const ModuleNameAndOffset& relativeAddress);

		// memory map
		std::vector<DebugMemoryRegion> GetMemoryMap();

		// symbols (read from the debugger backend on demand)
		// Read the symbols that the debugger backend knows about for the given module and add them to the
		// BinaryView as auto symbols (along with a data variable at each address so they are rendered).
		// By default no backend symbols are loaded; the user requests this explicitly per module. The
		// added symbols are tracked internally so they can be removed later. Returns the number of
		// symbols added, or 0 if the adapter does not support reading symbols or the module is unknown.
		// Loading the same module again is idempotent: any symbols previously loaded for it are removed
		// first, so no duplicates are created.
		size_t LoadSymbolsForModule(const DebugModule& module);
		size_t LoadSymbolsForModule(const std::string& module);
		// Load the backend symbols for every currently-loaded module. Returns the total number added.
		size_t LoadSymbolsForAllModules();
		// Remove the backend symbols previously added for the given module. Returns the number removed.
		size_t RemoveSymbolsForModule(const DebugModule& module);
		size_t RemoveSymbolsForModule(const std::string& module);
		// Remove every backend symbol the debugger has added. Returns the number removed. updateAnalysis
		// controls whether an async analysis update is scheduled afterwards to refresh the views; the
		// target-gone teardown path passes false because it is about to remove the debugger memory region
		// and must not schedule a pass that could read from it mid-teardown.
		size_t RemoveAllLoadedSymbols(bool updateAnalysis = true);
		// The base names of the modules for which backend symbols have been loaded.
		std::vector<std::string> GetModulesWithLoadedSymbols();
		// The number of backend symbols currently loaded for the given module (0 if none). The module may be
		// given as either its base name or its full path.
		size_t GetLoadedSymbolCountForModule(const std::string& module);

		// rebasing
		// Note: Returns true immediately in UI mode (rebase completes asynchronously via UI callback)
		bool RebaseToRemoteBase();
		bool RebaseToAddress(uint64_t address);
		bool GetRemoteBase(uint64_t& address);

		// arch
		ArchitectureRef GetRemoteArchitecture();

		// status
		DebugAdapterConnectionStatus GetConnectionStatus();

		DebugAdapterTargetStatus GetExecutionStatus();

		// memory
		DataBuffer ReadMemory(std::uintptr_t address, std::size_t size);
		bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer);

		// debugger events
		size_t RegisterEventCallback(
			std::function<void(const DebuggerEvent& event)> callback, const std::string& name = "");
		bool RemoveEventCallback(size_t index);
		bool RemoveEventCallbackInternal(size_t index);
		void NotifyStopped(DebugStopReason reason, void* data = nullptr);
		void NotifyError(const std::string& error, const std::string& shortError, void* data = nullptr);
		void NotifyEvent(DebuggerEventType event);
		void PostDebuggerEvent(const DebuggerEvent& event);
		void CleanUpDisabledEvent();

		// shortcut for instruction pointer
		uint64_t GetLastIP() const { return m_lastIP; }
		uint64_t GetCurrentIP() const { return m_currentIP; }
		bool SetIP(uint64_t address);

		// target control
		bool Execute();
		bool Restart();
		bool ConnectToDebugServer();
		bool DisconnectDebugServer();
		bool IsConnectedToDebugServer();
		// Convenience function, either launch the target process or connect to a remote, depending on the selected
		// adapter
		void LaunchOrConnect();

		// Asynchronous APIs.
		bool Launch();
		bool Connect();
		bool Attach();
		void Detach();
		bool Go();
		bool GoReverse();
		void Quit();
		bool StepInto(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepIntoReverse(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepOver(BNFunctionGraphType il = NormalFunctionGraph);
		bool StepOverReverse(BNFunctionGraphType il);
		bool StepReturn();
		bool StepReturnReverse();
		bool RunTo(const std::vector<uint64_t>& remoteAddresses);
		bool RunToReverse(const std::vector<uint64_t>& remoteAddresses);
		bool Pause();

		DebugStopReason ExecuteAdapterAndWait(const DebugAdapterOperation operation);

		// Synchronous APIs
		// Synchronous APIs. They submit the operation to the worker thread and block the
		// caller until it completes (or the optional timeout elapses, in which case the
		// engine is signaled to break and the call returns once the in-flight op settles).
		// Default timeout is "wait forever" so existing callers do not need to change.
		DebugStopReason LaunchAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason GoAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason GoReverseAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason AttachAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason RestartAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason ConnectAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason StepIntoAndWait(BNFunctionGraphType il = NormalFunctionGraph,
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason StepIntoReverseAndWait(BNFunctionGraphType il = NormalFunctionGraph,
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason StepOverAndWait(BNFunctionGraphType il = NormalFunctionGraph,
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason StepOverReverseAndWait(BNFunctionGraphType il,
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason StepReturnAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason StepReturnReverseAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason RunToAndWait(const std::vector<uint64_t>& remoteAddresses,
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason RunToReverseAndWait(const std::vector<uint64_t>& remoteAddresses,
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		DebugStopReason PauseAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		void DetachAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
		void QuitAndWait(
			std::chrono::milliseconds timeout = std::chrono::milliseconds::max());

		// getters
		DebugAdapter* GetAdapter() { return m_adapter; }
		DebuggerState* GetState() { return m_state; }
		BinaryViewRef GetData() { return m_data; }
		FileMetadataRef GetFile() { return m_file; }
		void SetData(BinaryViewRef view) {}
		DebuggerFileAccessor* GetMemoryAccessor() const { return m_accessor; }

		uint32_t GetExitCode();
		uint32_t GetActivePID();

		void WriteStdIn(const std::string message);

		std::string InvokeBackendCommand(const std::string& cmd);

		static std::string GetStopReasonString(DebugStopReason);
		DebugStopReason StopReason() const;

		BinaryNinja::Ref<BinaryNinja::Metadata> GetAdapterProperty(const std::string& name);
		bool SetAdapterProperty(const std::string& name, const BinaryNinja::Ref<BinaryNinja::Metadata>& value);

		bool ActivateDebugAdapter();

		// Dereference an address and check for printable strings, functions, symbols, etc
		std::string GetAddressInformation(intx::uint512 value);

		bool IsFirstLaunch();
		bool IsFirstConnect();
		bool IsFirstConnectToDebugServer();
		bool IsFirstAttach();

		bool ShouldShowAdapterSettingsForLaunch();
		bool ShouldShowAdapterSettingsForAttach();
		bool ShouldShowAdapterSettingsForConnect();
		bool ShouldShowAdapterSettingsForConnectToDebugServer();

		bool ShowAdapterSettingsNextTime();
		void SetShowAdapterSettingsNextTime(bool value);

		bool IsTTD();

		// TTD Memory Analysis Methods
		std::vector<TTDMemoryEvent> GetTTDMemoryAccessForAddress(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType = TTDMemoryRead);
		std::vector<TTDPositionRangeIndexedMemoryEvent> GetTTDMemoryAccessForPositionRange(uint64_t startAddress, uint64_t endAddress, TTDMemoryAccessType accessType, const TTDPosition startTime, const TTDPosition endTime);
		std::vector<TTDCallEvent> GetTTDCallsForSymbols(const std::string& symbols, uint64_t startReturnAddress = 0, uint64_t endReturnAddress = 0);
		std::vector<TTDEvent> GetTTDEvents(TTDEventType eventType);
		std::vector<TTDEvent> GetAllTTDEvents();
		TTDPosition GetCurrentTTDPosition();
		bool SetTTDPosition(const TTDPosition& position);
		std::pair<bool, TTDMemoryEvent> GetTTDNextMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType);
		std::pair<bool, TTDMemoryEvent> GetTTDPrevMemoryAccess(uint64_t address, uint64_t size, TTDMemoryAccessType accessType);
		std::optional<TTDRegisterWriteEvent> GetTTDNextRegisterWrite(const std::string& reg);
		std::optional<TTDRegisterWriteEvent> GetTTDPrevRegisterWrite(const std::string& reg);

		// TTD Position History Navigation
		bool TTDNavigateBack();
		bool TTDNavigateForward();
		bool CanTTDNavigateBack() const;
		bool CanTTDNavigateForward() const;
		void ClearTTDPositionHistory();

		// TTD Bookmark Methods
		std::vector<TTDBookmark> GetTTDBookmarks();
		bool AddTTDBookmark(const TTDPosition& position, const std::string& note = "", uint64_t viewAddress = 0);
		bool RemoveTTDBookmark(const TTDPosition& position);
		bool UpdateTTDBookmark(const TTDPosition& position, const std::string& note, uint64_t viewAddress);
		void ClearTTDBookmarks();

		// TTD Code Coverage Analysis Methods
		bool IsInstructionExecuted(uint64_t address);
		bool RunCodeCoverageAnalysis(uint64_t startAddress, uint64_t endAddress, TTDPosition startTime, TTDPosition endTime);
		size_t GetInstructionExecutionCount(uint64_t address);
		size_t GetExecutedInstructionCount() const;
		bool SaveCodeCoverageToFile(const std::string& filePath) const;
		bool LoadCodeCoverageFromFile(const std::string& filePath);

		void OnRebased(BinaryView* oldView, BinaryView* newView);

		bool RemoveDebuggerMemoryRegion();
		bool ReAddDebuggerMemoryRegion();

		// Re-sync the BinaryView memory regions with the backend's current memory map. Called on every
		// stop; no-ops when the map is unchanged. When the backend reports a map, mirrors it as bounded
		// regions so search only scans mapped memory; otherwise falls back to the blanket overlay (search
		// stays disabled -- see the "debugger" region gate in BinaryView::FindAll*).
		void SyncMemoryRegions();
		// Register memory regions on m_data from m_appliedMemoryRegions. Assumes any prior regions were
		// already removed. Empty map -> single blanket "debugger" region backed by m_accessor.
		void AddDebuggerMemoryRegions();
		// Remove every region we registered (blanket or per-entry) and retire the per-entry accessors.
		void RemoveDebuggerMemoryRegions();

		uint64_t GetViewFileSegmentsStart() { return m_viewStart; }

		bool ComputeExprValueAPI(const LowLevelILInstruction& instr, intx::uint512& value);
		bool ComputeExprValue(const LowLevelILInstruction& instr, intx::uint512& value);
		intx::uint512 GetValueFromComparison(const BNLowLevelILOperation op, intx::uint512 left, intx::uint512 right, size_t size);

		bool ComputeExprValueAPI(const MediumLevelILInstruction& instr, intx::uint512& value);
		bool ComputeExprValue(const MediumLevelILInstruction& instr, intx::uint512& value);
		intx::uint512 GetValueFromComparison(const BNMediumLevelILOperation op, intx::uint512 left, intx::uint512 right, size_t size);

		bool ComputeExprValueAPI(const HighLevelILInstruction& instr, intx::uint512& value);
		bool ComputeExprValue(const HighLevelILInstruction& instr, intx::uint512& value);
		intx::uint512 GetValueFromComparison(const BNHighLevelILOperation op, intx::uint512 left, intx::uint512 right, size_t size);

		bool GetVariableValueAPI(const Variable& var, uint64_t address, size_t size, intx::uint512& value);
		bool GetVariableValue(const Variable& var, uint64_t address, size_t size, intx::uint512& value);

		Ref<Settings> GetAdapterSettings();
		bool CreateDebugAdapter();

		bool DumpTargetState(const std::string& filePath);

		void SetDebuggerUICallbacks(BNDebuggerUICallbacks* cb, void* ctxt);

		bool FunctionExistsInOldView(uint64_t address);
	};
};  // namespace BinaryNinjaDebugger
