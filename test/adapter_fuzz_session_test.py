import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

import adapter_fuzz.session as session_module
import adapter_fuzz.tracking as tracking
from adapter_fuzz import GONE, Session
from adapter_fuzz.data_ops import general_registers, write_and_restore, write_outside_the_program
from adapter_fuzz.fault_ops import FaultOperations
from adapter_fuzz.lifecycle_ops import LifecycleOperations
from adapter_fuzz.operations import describe_call
from adapter_fuzz.profile import ADAPTERS
from adapter_fuzz.session import TIMING_NOTE
from adapter_fuzz.system import process_exists
from adapter_fuzz.tracking import Breakpoints, ControllerHandle, End, EndTracking, Observer, TargetProcess, ViewPool

try:
    from debugger import DebugBreakpointType, DebuggerController, DebugStopReason
except ImportError:
    from binaryninja.debugger import DebugBreakpointType, DebuggerController, DebugStopReason

MEMORY_BASE = 0x1000


class FakeController:
    def __init__(self, connected=True, running=False, active_pid=0, launch_reason=DebugStopReason.UserRequestedBreak):
        self.connected = connected
        self.running = running
        self.active_pid = active_pid
        self.launch_reason = launch_reason
        self.accepts_go = True
        self.breakpoints = set()
        self.conditions = {}
        self.hardware = set()
        self.callbacks = {}
        self.stack_pointer = MEMORY_BASE
        self.regs = {'rax': 0}
        self.ip = MEMORY_BASE + 0x80
        self.memory = bytearray(range(256))
        # Writes at or above this address are refused, as for code that an adapter treats as read-only
        self.read_only_from = MEMORY_BASE + 0x80
        # A refused write also changes the first bytes of the stack, which a controller must never do
        self.stray_write = False

    def has_breakpoint(self, address):
        return address in self.breakpoints

    def add_breakpoint(self, address):
        self.breakpoints.add(address)

    def delete_breakpoint(self, address):
        self.breakpoints.discard(address)
        self.conditions.pop(address, None)

    def enable_breakpoint(self, address):
        pass

    def disable_breakpoint(self, address):
        pass

    def set_breakpoint_condition(self, address, condition):
        if condition == 'garbage ((':
            return False
        self.conditions[address] = condition
        return True

    def get_breakpoint_condition(self, address):
        return self.conditions.get(address, '')

    def add_hardware_breakpoint(self, address, kind, size):
        self.hardware.add((address, kind, size))

    def delete_hardware_breakpoint(self, address, kind, size):
        self.hardware.discard((address, kind, size))

    def register_event_callback(self, callback):
        handle = len(self.callbacks) + 1
        self.callbacks[handle] = callback
        return handle

    def remove_event_callback(self, handle):
        del self.callbacks[handle]

    @property
    def memory_map(self):
        return [SimpleNamespace(start=MEMORY_BASE, size=len(self.memory))]

    def read_memory(self, address, size):
        offset = address - MEMORY_BASE
        if offset < 0 or offset + size > len(self.memory):
            return b''
        return bytes(self.memory[offset:offset + size])

    def write_memory(self, address, data):
        offset = address - MEMORY_BASE
        if offset < 0 or offset + len(data) > len(self.memory) or address >= self.read_only_from:
            if self.stray_write:
                self.memory[:4] = b'\xcc' * 4
            return False
        self.memory[offset:offset + len(data)] = data
        return True

    def launch_and_wait(self, timeout):
        self.connected = self.launch_reason != DebugStopReason.InternalError
        return self.launch_reason

    def go(self):
        return self.accepts_go

    def quit_and_wait(self, timeout):
        self.connected = self.running = False

    detach_and_wait = quit_and_wait


def make_session(pool=None, **controller):
    dbg = FakeController(**controller)
    session = Session(ADAPTERS[0], 0, 'helloworld', object(), dbg, pool or ViewPool())
    session.ends.was_connected = dbg.connected
    return session


def make_breakpoints():
    dbg = FakeController()
    return dbg, Breakpoints(ControllerHandle(dbg, 's0'))


@pytest.fixture
def child():
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    yield process
    process.kill()
    process.wait()


def test_a_register_is_kept_out_of_writes_by_its_whole_name_not_a_part_of_it():
    names = ['rax', 'offset', 'fsx', 'rip', 'fs', 'gs', 'rflags', 'fs_base', 'cpsr', 'tpidr_el0', 'x15']
    registers = {name: SimpleNamespace(name=name, width=64) for name in names}
    registers['ds'] = SimpleNamespace(name='ds', width=64)
    registers['wide'] = SimpleNamespace(name='wide', width=128)
    dbg = SimpleNamespace(regs=SimpleNamespace(regs=registers))
    assert [register.name for register in general_registers(dbg)] == ['rax', 'offset', 'fsx', 'x15']


def test_breakpoints_added_and_deleted_are_recorded_with_the_change_on_the_controller():
    dbg, breakpoints = make_breakpoints()
    breakpoints.add(0x1000)
    breakpoints.add(0x2000)
    breakpoints.set_enabled(0x1000, False)
    breakpoints.set_condition(0x2000, '1 == 1')
    assert breakpoints.software == {0x1000, 0x2000} and dbg.breakpoints == {0x1000, 0x2000}
    assert breakpoints.disabled == {0x1000} and breakpoints.conditions == {0x2000: '1 == 1'}
    breakpoints.delete(0x1000)
    breakpoints.delete(0x2000)
    assert not breakpoints.software and not breakpoints.disabled and not breakpoints.conditions
    assert not dbg.breakpoints


def test_a_condition_the_controller_refuses_is_not_recorded():
    dbg, breakpoints = make_breakpoints()
    breakpoints.add(0x1000)
    breakpoints.set_condition(0x1000, 'garbage ((')
    assert breakpoints.conditions == {}


def test_a_hardware_breakpoint_is_recorded_whether_or_not_the_controller_took_it():
    dbg, breakpoints = make_breakpoints()
    kind = DebugBreakpointType.BNHardwareWriteBreakpoint
    breakpoints.add_hardware(0x1000, kind, 4)
    assert breakpoints.hardware == {(0x1000, kind, 4)}
    breakpoints.delete_hardware(0x1000, kind, 4)
    assert not breakpoints.hardware and not dbg.hardware


def test_a_breakpoint_stop_may_happen_where_one_is_enabled_and_anywhere_for_a_data_breakpoint():
    dbg, breakpoints = make_breakpoints()
    breakpoints.add(0x1000)
    breakpoints.add(0x2000)
    breakpoints.set_enabled(0x2000, False)
    breakpoints.add_hardware(0x3000, DebugBreakpointType.BNHardwareExecuteBreakpoint, 1)
    assert breakpoints.stop_addresses() == {0x1000, 0x3000}
    breakpoints.add_hardware(0x4000, DebugBreakpointType.BNHardwareReadBreakpoint, 4)
    assert breakpoints.stop_addresses() is None


def test_breakpoints_are_picked_by_index_in_address_order():
    dbg, breakpoints = make_breakpoints()
    for address in (0x3000, 0x1000, 0x2000):
        breakpoints.add(address)
    assert [breakpoints.pick(index) for index in (0, 1, 2, 3, 10)] == [0x1000, 0x2000, 0x3000, 0x1000, 0x2000]


def test_a_breakpoint_the_controller_lost_is_reported_by_name_and_address():
    dbg, breakpoints = make_breakpoints()
    breakpoints.add(0x1000)
    breakpoints.verify()
    dbg.breakpoints.clear()
    with pytest.raises(AssertionError, match='s0 lost the breakpoint at 0x1000'):
        breakpoints.verify()


def test_a_condition_the_controller_lost_is_reported():
    dbg, breakpoints = make_breakpoints()
    breakpoints.add(0x1000)
    breakpoints.set_condition(0x1000, '1 == 1')
    dbg.conditions.clear()
    with pytest.raises(AssertionError, match='lost the condition'):
        breakpoints.verify()


def test_breakpoints_are_deleted_from_the_controller_on_release():
    dbg, breakpoints = make_breakpoints()
    breakpoints.add(0x1000)
    breakpoints.add_hardware(0x2000, DebugBreakpointType.BNHardwareExecuteBreakpoint, 1)
    breakpoints.release()
    assert not dbg.breakpoints and not dbg.hardware


def test_observer_records_events_and_hands_back_every_callback_it_registered():
    dbg = FakeController()
    observer = Observer(ControllerHandle(dbg, 's0'))
    observer.add(lambda event: None)
    observer.add(lambda event: None)
    assert len(dbg.callbacks) == 3
    dbg.callbacks[1](SimpleNamespace(type='stopped'))
    assert [kind for _, kind in observer.events] == ['stopped']
    observer.remove()
    assert len(dbg.callbacks) == 2
    observer.release()
    assert not dbg.callbacks


def test_observer_tells_events_before_a_moment_from_those_after_it():
    observer = Observer(ControllerHandle(FakeController(), 's0'))
    observer.events += [(1.0, 'early'), (5.0, 'late')]
    assert observer.events_after(3.0) == ['late']


def test_target_process_remembers_every_pid_and_keeps_the_last_when_none_is_reported():
    process = TargetProcess()
    process.note(10)
    process.note(0)
    assert process.pid == 10
    process.note(11)
    assert (process.pid, process.pids) == (11, {10, 11})


def test_target_process_waits_for_the_process_to_go_and_can_kill_it(child):
    process = TargetProcess()
    process.note(child.pid)
    assert not process.wait_until_gone(0.1)
    process.kill()
    child.wait(timeout=10)
    assert process.wait_until_gone(5)


def test_target_process_keeps_the_identity_from_when_a_pid_was_first_noted(child, monkeypatch):
    process = TargetProcess()
    process.note(child.pid)
    identity = process.identities[child.pid]
    assert identity is not None
    monkeypatch.setattr(tracking, 'process_identity', lambda pid: 'a later process')
    process.note(child.pid)
    assert process.identities[child.pid] == identity


def test_target_process_does_not_kill_or_signal_a_pid_that_now_belongs_to_another_process(child):
    process = TargetProcess()
    process.note(child.pid)
    process.identities[child.pid] = 'a process that is gone'
    process.kill()
    assert not process.send_signal(signal.SIGKILL)
    assert process.alive_pids() == set()
    with pytest.raises(subprocess.TimeoutExpired):
        child.wait(timeout=0.3)


def test_target_process_signals_the_process_it_noted(child):
    process = TargetProcess()
    process.note(child.pid)
    assert process.alive_pids() == {child.pid}
    assert process.send_signal(signal.SIGTERM)
    child.wait(timeout=10)


def test_target_process_does_not_kill_a_pid_whose_identity_could_not_be_read(child, monkeypatch):
    monkeypatch.setattr(tracking, 'process_identity', lambda pid: None)
    process = TargetProcess()
    process.note(child.pid)
    process.kill()
    with pytest.raises(subprocess.TimeoutExpired):
        child.wait(timeout=0.3)


def test_a_view_is_loaded_once_and_handed_out_again_only_after_it_is_given_back(monkeypatch):
    loaded = []
    monkeypatch.setattr(tracking, 'load', lambda path: loaded.append(path) or object())
    pool = ViewPool()
    first = pool.take('a')
    second = pool.take('a')
    assert first is not second and loaded == ['a', 'a']
    pool.give('a', first)
    assert pool.take('a') is first and loaded == ['a', 'a']


def test_a_launch_that_was_asked_to_fail_may_be_refused_but_any_other_refusal_is_a_failure():
    refused = make_session(connected=False, launch_reason=DebugStopReason.InternalError)
    refused.setup.bad_directory = True
    refused.launch()
    with pytest.raises(AssertionError, match='launch returned'):
        make_session(connected=False, launch_reason=DebugStopReason.InternalError).launch()


def test_a_launch_leaves_the_session_active_and_notes_the_target_process():
    session = make_session(connected=False, active_pid=4321)
    session.launch()
    assert (session.model, session.launched, session.process.pids) == ('active', True, {4321})


def test_continuing_a_stopped_target_that_the_controller_refuses_is_a_failure():
    session = make_session()
    session.dbg.accepts_go = False
    with pytest.raises(AssertionError, match='go was refused'):
        session.go()


def test_a_target_that_outlives_quit_is_a_failure_that_says_it_depends_on_timing(child, monkeypatch):
    monkeypatch.setattr(session_module, 'PROCESS_EXIT_SECONDS', 0.1)
    session = make_session(active_pid=child.pid)
    with pytest.raises(AssertionError, match='still alive') as raised:
        session.quit()
    assert TIMING_NOTE in str(raised.value)


def test_detaching_ends_the_target_so_that_it_does_not_outlive_the_example(child):
    session = make_session(active_pid=child.pid)
    session.detach()
    child.wait(timeout=10)
    assert session.ends.detaches == 1 and not process_exists(child.pid)


def test_dropping_the_controller_keeps_the_view_alive_for_the_rest_of_the_run():
    pool = ViewPool()
    session = make_session(pool=pool)
    view = session.view
    session.drop()
    assert (session.model, session.view, session.dropped) == (GONE, None, True)
    assert pool.abandoned == [view]


def test_a_part_used_after_the_session_was_dropped_fails_with_a_message_that_names_the_session():
    session = make_session()
    session.drop()
    with pytest.raises(RuntimeError, match=r's0\(helloworld\) used its controller after the controller was dropped'):
        session.breakpoints.add(0x1000)
    with pytest.raises(RuntimeError, match='after the controller was dropped'):
        session.observer.add(lambda event: None)
    with pytest.raises(RuntimeError, match='after the controller was dropped'):
        session.dbg
    assert session.state == 'idle'


def test_finishing_a_session_ends_it_hands_back_its_callbacks_and_breakpoints_and_returns_its_view():
    pool = ViewPool()
    session = make_session(pool=pool)
    session.breakpoints.add(0x1000)
    view = session.view
    session.finish()
    assert not session.dbg.connected and not session.dbg.callbacks and not session.dbg.breakpoints
    assert pool.free == {session.path: [view]} and pool.abandoned == []


def test_a_view_whose_launch_settings_changed_or_that_followed_a_failure_is_not_reused():
    changed = make_session()
    changed.setup.changed = True
    changed.finish()
    after_failure = make_session()
    after_failure.finish(reuse_view=False)
    for session in (changed, after_failure):
        assert session.pool.free == {} and len(session.pool.abandoned) == 1


def test_a_session_whose_target_was_interfered_with_has_it_killed_at_the_end(child):
    session = make_session(active_pid=child.pid)
    session.interfered = True
    session.finish()
    child.wait(timeout=10)
    assert not process_exists(child.pid)


def test_a_session_in_a_good_state_passes_every_check():
    session = make_session()
    session.breakpoints.add(0x1000)
    session.breakpoints.set_condition(0x1000, '1')
    assert session.check() is End.NONE


def test_a_failed_callback_is_reported():
    session = make_session()
    session.observer.errors.append('ip on TargetStoppedEventType: RuntimeError: x')
    with pytest.raises(AssertionError, match='callback failed'):
        session.check()


def test_a_controller_that_is_running_but_not_connected_is_reported():
    with pytest.raises(AssertionError, match='running but not connected'):
        make_session(connected=False, running=True).check()


def test_a_lost_breakpoint_is_reported_while_stopped_but_not_while_running():
    stopped = make_session()
    stopped.breakpoints.software.add(0x1000)
    with pytest.raises(AssertionError, match='lost the breakpoint at 0x1000'):
        stopped.check()
    running = make_session(running=True)
    running.breakpoints.software.add(0x1000)
    running.check()


def test_an_event_long_after_the_session_ended_is_reported_with_the_timing_note():
    session = make_session(connected=False)
    session.ends.idle_since = time.monotonic() - 10
    session.observer.events.append((time.monotonic(), 'TargetStopped'))
    with pytest.raises(AssertionError, match='arrived after the session ended') as raised:
        session.check()
    assert TIMING_NOTE in str(raised.value)


def test_an_event_within_the_grace_period_after_the_session_ended_is_not_reported():
    session = make_session(connected=False)
    session.ends.idle_since = time.monotonic()
    session.observer.events.append((time.monotonic(), 'TargetStopped'))
    session.check()


def test_a_session_that_ends_by_itself_is_told_apart_from_one_ended_by_an_operation():
    by_itself = make_session(connected=False)
    by_itself.ends.was_connected = True
    assert by_itself.check() is End.BY_ITSELF
    assert by_itself.ends.natural_ends == 1

    by_operation = make_session(connected=False)
    by_operation.ends.was_connected = True
    by_operation.ends.ask_to_end()
    assert by_operation.check() is End.BY_OPERATION
    assert by_operation.ends.natural_ends == 0


def test_a_session_that_ended_after_interference_is_told_apart_and_still_counts_as_an_end_nothing_asked_for():
    session = make_session(connected=False)
    session.ends.was_connected = True
    session.interfered = True
    assert session.check() is End.AFTER_INTERFERENCE
    assert session.ends.natural_ends == 1


def test_an_end_is_reported_once_and_a_session_that_is_still_running_reports_none():
    session = make_session(connected=False)
    session.ends.was_connected = True
    assert session.observe() is End.BY_ITSELF
    assert session.observe() is End.NONE
    running = make_session(running=True)
    assert running.observe() is End.NONE and running.ends.was_connected


def test_a_dropped_session_observes_nothing_and_asserts_nothing():
    session = make_session()
    session.drop()
    assert session.check() is End.NONE


def test_asserting_does_not_change_what_the_session_keeps_track_of():
    session = make_session(connected=False)
    session.ends.was_connected = True
    session.assert_consistent()
    assert session.ends.was_connected and session.ends.idle_since is None and session.ends.natural_ends == 0


def test_a_launch_or_restart_starts_a_run_that_nothing_has_asked_to_end_or_acted_on():
    ends = EndTracking()
    ends.ask_to_end()
    ends.interfered = True
    ends.start_run()
    assert not ends.asked_to_end and not ends.interfered


def test_ends_without_being_asked_count_detaches_and_ends_by_themselves_but_not_ends_by_operation():
    ends = EndTracking()
    assert not ends.ended_without_being_asked()
    ends.detaches = 1
    assert ends.ended_without_being_asked()
    ends = EndTracking()
    ends.ask_to_end()
    ends.was_connected = True
    ends.observe(False, 1.0)
    assert not ends.ended_without_being_asked()


def test_late_events_are_cut_off_only_after_the_session_ended():
    ends = EndTracking()
    assert ends.events_cutoff(0.5) is None
    ends.was_connected = True
    ends.observe(False, 10.0)
    assert ends.events_cutoff(0.5) == 10.5
    ends.observe(True, 11.0)
    assert ends.events_cutoff(0.5) is None


def test_a_stopped_target_without_a_stack_pointer_is_a_failure_but_one_that_ended_meanwhile_is_not():
    paused = make_session()
    paused.dbg.stack_pointer = 0
    with pytest.raises(AssertionError, match='no stack pointer while paused'):
        paused.read_stopped_state()

    class EndsWhileRead(FakeController):
        @property
        def stack_pointer(self):
            self.connected = False
            return 0

        @stack_pointer.setter
        def stack_pointer(self, value):
            pass

    session = make_session()
    session.handle = ControllerHandle(EndsWhileRead(), 's0')
    session.read_stopped_state()


def test_a_stack_that_changes_under_a_write_of_its_own_contents_is_a_failure():
    session = make_session()
    session.dbg.write_memory = lambda address, data: True
    reads = iter([bytes(16), b'x' * 16])
    session.dbg.read_memory = lambda address, size: next(reads)
    with pytest.raises(AssertionError, match='stack changed'):
        session.read_stopped_state()


def test_writing_to_the_stack_and_to_writable_code_is_read_back_and_restored():
    session = make_session()
    session.dbg.read_only_from = MEMORY_BASE + 0x100
    before = bytes(session.dbg.memory)
    write_and_restore(session, 'stack', 64, 7)
    write_and_restore(session, 'code', 8, 7)
    assert bytes(session.dbg.memory) == before


def test_a_refused_write_to_the_stack_is_a_failure_but_a_refused_write_to_code_is_not():
    session = make_session()
    session.dbg.read_only_from = 0
    write_and_restore(session, 'code', 8, 1)
    with pytest.raises(AssertionError, match='writing 8 bytes .* failed'):
        write_and_restore(session, 'stack', 8, 1)


def test_a_write_that_reads_back_differently_is_a_failure_and_is_still_undone():
    session = make_session()
    dbg = session.dbg
    before = bytes(dbg.memory)
    real_read = dbg.read_memory
    reads = []

    def read(address, size):
        reads.append(address)
        # The first read is of the original bytes, the second is of what was written
        return real_read(address, size) if len(reads) == 1 else b'?' * size

    dbg.read_memory = read
    with pytest.raises(AssertionError, match='differs from what was written'):
        write_and_restore(session, 'stack', 8, 1)
    assert bytes(dbg.memory) == before


def test_a_write_outside_the_program_that_leaves_the_stack_alone_passes_whether_or_not_it_is_refused():
    session = make_session()
    write_outside_the_program(session, 0, 8)
    write_outside_the_program(session, MEMORY_BASE + 0x10, 4)


def test_a_write_outside_the_program_that_changes_the_stack_is_a_failure():
    session = make_session()
    session.dbg.stray_write = True
    with pytest.raises(AssertionError, match='the stack changed after a write at 0x0'):
        write_outside_the_program(session, 0, 8)


def test_what_the_fake_controller_implements_exists_on_the_real_controller():
    own = {name for name, member in vars(FakeController).items()
           if not name.startswith('_') and (callable(member) or isinstance(member, property))}
    state = {name for name in vars(FakeController(connected=False))
             if name in {'connected', 'running', 'active_pid', 'stack_pointer', 'ip', 'regs'}}
    missing = sorted(name for name in own | state if not hasattr(DebuggerController, name))
    assert not missing, f'FakeController has what DebuggerController lacks: {missing}'


def test_an_operation_is_logged_by_its_name_and_arguments():
    def read_stopped_target():
        pass

    assert describe_call(read_stopped_target, {'index': 3, 'kind': 'ones'}) == "read stopped target index=3 kind='ones'"


def test_operations_are_named_for_what_they_do_not_after_something_else():
    assert hasattr(FaultOperations, 'send_signal') and not hasattr(FaultOperations, 'signal_target')
    assert hasattr(LifecycleOperations, 'read_stopped_target')
    assert hasattr(Session, 'read_stopped_state')
