#pragma once
#include "binaryninjaapi.h"
#include "debuggerstate.h"
//#include "ui/ui.h"
#include "debuggerevent.h"
#include <queue>

// This is the controller class of the debugger. It receives the input from the UI/API, and then route them to
// the state and UI, etc. Most actions should reach here.

struct DebuggerEventCallback
{
    std::function<void(const DebuggerEvent& event)> function;
    size_t index;
};


class DebuggerController: public QObject
{
    Q_OBJECT

	DebugAdapter*  m_adapter;
    DebuggerState* m_state;
    BinaryViewRef m_data;
    BinaryViewRef m_liveView;

    bool m_hasUI;

    inline static std::vector<DebuggerController*> g_debuggerControllers;
    void DeleteController(BinaryViewRef data);

    std::atomic<size_t> m_callbackIndex = 0;
    std::vector<DebuggerEventCallback> m_eventCallbacks;
    std::queue<DebuggerEvent> m_events;
	std::recursive_mutex m_queueMutex;
	std::recursive_mutex m_callbackMutex;

    uint64_t m_lastIP = 0;
    uint64_t m_currentIP = 0;

	// A temporary workaround to ensure the status bar is only added once. A more systematic way to deal with this
	// is what we do in the collab, i.e., register context-related callbacks and manage the status bar from there.
	bool m_statusBarAdded = false;

    bool m_userRequestedBreak = false;

public:
    DebuggerController(BinaryViewRef data);

    bool hasUI() const { return m_hasUI; }

    void AddBreakpoint(uint64_t address);
    void AddBreakpoint(const ModuleNameAndOffset& address);
    void DeleteBreakpoint(uint64_t address);
    void DeleteBreakpoint(const ModuleNameAndOffset& address);

    bool Launch();
	bool Execute();
    void Restart();
    void Quit();
	// TODO: this is better renamed to Connect(), to distinguish from attaching to a running process
    void Attach();
    void Detach();
    void Pause();
    void PauseInternal();

	// Whether we can resume the execution of the target, including stepping.
	bool CanResumeTarget();

	DebugStopReason GoInternal();
	DebugStopReason StepIntoInternal();
	DebugStopReason StepOverInternal();
	DebugStopReason StepReturnInternal();
	DebugStopReason StepToInternal(const std::vector<uint64_t>& remoteAddresses);

	DebugStopReason StepIntoIL(BNFunctionGraphType il);
	DebugStopReason StepOverIL(BNFunctionGraphType il);

	DebugStopReason Go();
	DebugStopReason StepInto(BNFunctionGraphType il = NormalFunctionGraph);
	DebugStopReason StepOver(BNFunctionGraphType il = NormalFunctionGraph);
	DebugStopReason StepReturn();
	DebugStopReason StepTo(const std::vector<uint64_t>& remoteAddresses);

	// Convenience function, either launch the target process or connect to a remote, depending on the selected adapter
	void LaunchOrConnect();

	DebugThread GetActiveThread() const;
	void SetActiveThread(const DebugThread& thread);

    DebuggerState* GetState() { return m_state; }
    BinaryViewRef GetData() const { return m_data; }
    void SetData(BinaryViewRef view) { m_data = view; }
    BinaryViewRef GetLiveView() const { return m_liveView; }
    void SetLiveView(BinaryViewRef view) { m_liveView = view; }

    static DebuggerController* GetController(BinaryViewRef data);
	// Whether there already exists a controller for the data
	static bool ControllerExists(BinaryViewRef data);

    void EventHandler(const DebuggerEvent& event);

    void AddEntryBreakpoint();
    size_t RegisterEventCallback(std::function<void(const DebuggerEvent& event)> callback);
    bool RemoveEventCallback(size_t index);

    void NotifyStopped(DebugStopReason reason, void* data= nullptr);
    void NotifyError(const std::string& error, void* data = nullptr);
    void NotifyEvent(DebuggerEventType event);

    void PostDebuggerEvent(const DebuggerEvent& event);
    void Worker();

    uint64_t GetLastIP() const { return m_lastIP; }
    uint64_t GetCurrentIP() const { return m_currentIP; }

	DataBuffer ReadMemory(std::uintptr_t address, std::size_t size);
	bool WriteMemory(std::uintptr_t address, const DataBuffer& buffer);

	bool StatusBarAdded() const { return m_statusBarAdded; }
	void SetStatusBarAdded() { m_statusBarAdded = true; }

	TagTypeRef getPCTagType(BinaryViewRef data);
	TagTypeRef getBreakpointTagType(BinaryViewRef data);

	DebugAdapter* CreateDebugAdapter();

    void HandleTargetStop(DebugStopReason reason);

signals:
    void absoluteBreakpointAdded(uint64_t address);
    void relativeBreakpointAdded(const ModuleNameAndOffset& address);
    void absoluteBreakpointDeleted(uint64_t address);
    void relativeBreakpointDeleted(const ModuleNameAndOffset& address);

    void started();
    void starting();
    // stopped is emitted immediately after the target stops; the cacheUpdated() is emitted after the DebuggerState
    // gets updated, and the UI should update its content
    void stopped(DebugStopReason reason, void *data);
    void cacheUpdated(DebugStopReason reason, void *data);
    void IPChanged(uint64_t address);

    void contextChanged();
};
