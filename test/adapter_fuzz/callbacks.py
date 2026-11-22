"""Event callbacks whose bodies read the target."""

import time

try:
    from debugger import DebuggerEventType
except ImportError:
    from binaryninja.debugger import DebuggerEventType

READS = {
    'ip': lambda dbg: dbg.ip,
    'breakpoints': lambda dbg: len(dbg.breakpoints),
    'state': lambda dbg: (dbg.connected, dbg.running),
    'memory': lambda dbg: dbg.read_memory(dbg.ip, 8),
    'stack_pointer': lambda dbg: dbg.stack_pointer,
    'regs': lambda dbg: len(dbg.regs),
    'register': lambda dbg: dbg.get_reg_value('pc'),
    'threads': lambda dbg: [thread.tid for thread in dbg.threads],
    'modules': lambda dbg: [module.name for module in dbg.modules],
    'slow': lambda dbg: time.sleep(0.02),
    'raise': lambda dbg: (_ for _ in ()).throw(RuntimeError('callback failure')),
}

# A callback that raises on purpose is not a failure
EXPECTED_TO_RAISE = {'raise'}


def make_callback(session, read, events):
    action = READS[read]

    def callback(event):
        if session.dropped:
            return
        dbg = session.dbg
        if events == 'stop' and event.type != DebuggerEventType.TargetStoppedEventType:
            return
        try:
            action(dbg)
        except Exception as error:
            if read not in EXPECTED_TO_RAISE:
                name = DebuggerEventType(event.type).name
                session.observer.errors.append(f'{read} on {name}: {type(error).__name__}: {error}')
            raise

    return callback
