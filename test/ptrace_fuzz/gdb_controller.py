# gdb -p PID -batch -x gdb_controller.py : print the stop-channel state of the controller whose worker waits for a stop
import gdb
for t in gdb.selected_inferior().threads():
    t.switch()
    f = gdb.newest_frame()
    waiting = False
    while f is not None:
        if f.name() and 'WaitForAdapterStop' in f.name():
            waiting = True
        if waiting and f.name() and 'DebuggerController' in f.name():
            f.select()
            try:
                for expr in ('m_inAdapterWait', 'm_adapterStopPending', 'm_lastOperation', 'm_workerShouldExit'):
                    print('CTRL', f.name(), expr, '=', gdb.parse_and_eval('this->' + expr))
                raise SystemExit
            except gdb.error:
                pass
        f = f.older()
