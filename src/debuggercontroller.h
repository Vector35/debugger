#pragma once
#include "binaryninjaapi.h"
#include "debuggerstate.h"
#include "ui/ui.h"
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
    DebuggerUI* m_ui;
    BinaryViewRef m_data;
    BinaryViewRef m_liveView;

    bool m_hasUI;

    inline static std::vector<DebuggerController*> g_debuggerControllers;
    void DeleteController(BinaryViewRef data);

    size_t m_callbackIndex = 0;
    std::vector<DebuggerEventCallback> m_eventCallbacks;
    std::queue<DebuggerEvent> m_events;
    std::mutex m_queueMutex;

    uint64_t m_lastIP = 0;
    uint64_t m_currentIP = 0;

public:
    DebuggerController(BinaryViewRef data);

    bool hasUI() const { return m_hasUI; }

    void AddBreakpoint(uint64_t address);
    void AddBreakpoint(const ModuleNameAndOffset& address);
    void DeleteBreakpoint(uint64_t address);
    void DeleteBreakpoint(const ModuleNameAndOffset& address);

    void Run();
    void Restart();
    void Quit();
    void Exec();
    void Attach();
    void Detach();
    void Pause();
    void Go();
    void StepInto(BNFunctionGraphType il = NormalFunctionGraph);
    void StepOver(BNFunctionGraphType il = NormalFunctionGraph);
    void StepReturn();
    void StepTo(std::vector<uint64_t> remoteAddresses);

    DebugAdapter* GetAdapter() { return m_adapter; }
    DebuggerState* GetState() { return m_state; }
    BinaryViewRef GetData() const { return m_data; }
    void SetData(BinaryView* view) { m_data = view; }
    BinaryViewRef GetLiveView() const { return m_liveView; }
    void SetLiveView(BinaryView* view) { m_liveView = view; }
    DebuggerUI* GetUI() const { return m_ui; }

    static DebuggerController* GetController(BinaryViewRef data);

    void EventHandler(const DebuggerEvent& event);

    void AddEntryBreakpoint();
    size_t RegisterEventCallback(std::function<void(const DebuggerEvent& event)> callback);
    bool RemoveEventCallback(size_t index);

    void NotifyStopped(DebugStopReason reason, void* data= nullptr);
    void NotifyError(const std::string& error, void* data = nullptr);
    void NotifyEvent(const std::string& event, void* data = nullptr);

    void PostDebuggerEvent(const DebuggerEvent& event);
    void Worker();

    uint64_t GetLastIP() const { return m_lastIP; }
    uint64_t GetCurrentIP() const { return m_currentIP; }

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
