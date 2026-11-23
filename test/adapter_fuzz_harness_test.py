import faulthandler
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

import adapter_fuzz.machine as machine_module
from adapter_fuzz import GONE, AdapterMachine, machine_for
import adapter_fuzz.campaign as campaign_module
import adapter_fuzz.recording as recording
from adapter_fuzz.campaign import Campaign
from adapter_fuzz.failures import Failure, describe_crash, failure_key, unfinished_example
from adapter_fuzz.lock import CampaignBusy, CampaignLock
from adapter_fuzz.profile import ADAPTERS, host_profiles, unavailable_reason
from adapter_fuzz.recording import Operation
from adapter_fuzz.report import format_step
from adapter_fuzz.settings import LENGTHS, SettingsError, from_environment
from adapter_fuzz.shrink import shrink
from adapter_fuzz.system import (available_signals, descendants, kill_process, open_pipe_count, process_exists,
                                 process_identity)
from adapter_fuzz.tracking import End, TargetProcess

SEGFAULT_OUTPUT = '''Fatal Python error: Segmentation fault

Current thread 0x00007ff8 (most recent call first):
  File "/work/adapter_fuzz/session.py", line 120 in launch
  File "/work/adapter_fuzz/lifecycle_ops.py", line 33 in launch
  File "/work/adapter_fuzz/recording.py", line 80 in guarded
  File "/work/adapter_fuzz/recording.py", line 70 in perform

Thread 0x00007ff9 (most recent call first):
  File "/usr/lib/python3/threading.py", line 100 in wait
'''

HANG_OUTPUT = '''Timeout (0:03:00)!
Thread 0x00007ff8 (most recent call first):
  File "/work/adapter_fuzz/session.py", line 120 in launch
'''


def step(rule, **arguments):
    return {'rule': rule, 'args': arguments}


def record(message, where='check_sessions', kind='AssertionError', steps=()):
    return {'where': where, 'kind': kind, 'message': message, 'steps': list(steps)}


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    monkeypatch.setenv('ADAPTER_FUZZ_DIR', str(tmp_path))
    return Campaign('LLDB', 'adapter_fuzz.machine:AdapterMachine')


@pytest.fixture
def machine():
    instance = machine_for(ADAPTERS[0])()
    yield instance
    faulthandler.cancel_dump_traceback_later()


def test_failures_that_differ_only_in_numbers_and_session_names_share_a_key():
    first = record('s0(helloworld) lost the breakpoint at 0x1000 after 3 steps')
    second = record('s2(getcwd) lost the breakpoint at 0xdead0010 after 12 steps')
    assert failure_key(first) == failure_key(second)


def test_failures_that_say_different_things_have_different_keys():
    assert failure_key(record('lost the breakpoint at 0x1000')) != failure_key(record('lost the condition at 0x1000'))
    assert failure_key(record('lost it')) != failure_key(record('lost it', where='check_nothing_is_left'))


def test_crash_is_named_by_signal_and_the_frames_of_the_crashing_thread(campaign):
    campaign.add_crash(-11, {'steps': [step('launch')], 'warm_up': False}, SEGFAULT_OUTPUT)
    [failure] = campaign.failures.values()
    assert failure.key == 'crash: Segmentation fault: launch,launch,guarded'
    assert failure.steps == [step('launch')]


def test_hang_is_named_as_a_hang_and_keyed_by_the_operation_that_hung(campaign):
    campaign.add_crash(1, {'steps': [step('go'), step('pause')], 'warm_up': False}, HANG_OUTPUT)
    [failure] = campaign.failures.values()
    assert failure.key == 'crash: hang: while running pause'


def test_the_same_failure_is_counted_and_keeps_its_shortest_steps(campaign):
    campaign.add_recorded({**record('x'), 'steps': [step('a'), step('b'), step('c')], 'traceback': '', 'history': []})
    campaign.add_recorded({**record('x'), 'steps': [step('b')], 'traceback': '', 'history': []})
    campaign.add_recorded({**record('x'), 'steps': [step('a'), step('b')], 'traceback': '', 'history': []})
    [failure] = campaign.failures.values()
    assert (failure.count, failure.steps) == (3, [step('b')])


def test_unfinished_example_is_the_one_that_started_and_never_ended():
    log = [{'example': 1, 'start': True, 'warm_up': False}, {'example': 1, 'step': step('launch')},
           {'example': 1, 'end': True, 'warm_up': False, 'failed': False},
           {'example': 2, 'start': True, 'warm_up': False}, {'example': 2, 'step': step('go', which=1)},
           {'example': 2, 'target': 1}]
    assert unfinished_example(log) == {'steps': [{**step('go', which=1), 'session': 1}], 'warm_up': False}
    assert unfinished_example(log[:3]) is None


def test_shrinking_keeps_only_the_steps_the_failure_needs(campaign, monkeypatch):
    steps = [step('go'), step('launch'), step('pause'), step('step'), step('quit'), step('go'), step('detach')]
    key = 'AssertionError'

    def replay(candidate):
        rules = [candidate_step['rule'] for candidate_step in candidate]
        return key if 'launch' in rules and 'quit' in rules[rules.index('launch'):] else None

    monkeypatch.setattr(campaign, 'replay', replay)
    failure = Failure(key=key, kind=key, message='', where='', steps=steps)
    campaign.shrink(failure)
    assert [shrunk['rule'] for shrunk in failure.steps] == ['launch', 'quit']
    assert failure.reproducible


def test_shrinking_simplifies_numbers_that_the_failure_does_not_need(campaign, monkeypatch):
    steps = [step('add_breakpoint', kind='function', index=37, which=5), step('select_thread', index=9)]
    key = 'AssertionError'

    def replay(candidate):
        needed = any(s['rule'] == 'select_thread' and s['args']['index'] == 9 for s in candidate)
        return key if needed else None

    monkeypatch.setattr(campaign, 'replay', replay)
    failure = Failure(key=key, kind=key, message='', where='', steps=steps)
    campaign.shrink(failure)
    assert failure.steps == [step('select_thread', index=9)]


def test_a_failure_that_does_not_reproduce_keeps_its_steps_and_is_marked(campaign, monkeypatch):
    monkeypatch.setattr(campaign, 'replay', lambda candidate: None)
    failure = Failure(key='k', kind='k', message='', where='', steps=[step('go'), step('pause')])
    campaign.shrink(failure)
    assert failure.reproducible is False
    assert len(failure.steps) == 2


def test_a_step_is_printed_with_its_session_and_without_the_index_that_chose_it():
    assert format_step({**step('step', which=2, into=True), 'session': 1}) == 's1.step(into=True)'
    assert format_step(step('start', program='loop')) == "start(program='loop')"


def test_a_second_campaign_is_refused_while_the_first_holds_the_lock(tmp_path, monkeypatch):
    monkeypatch.setenv('ADAPTER_FUZZ_LOCK', str(tmp_path / 'lock'))
    monkeypatch.delenv('ADAPTER_FUZZ_ALLOW_PARALLEL', raising=False)
    with CampaignLock():
        with pytest.raises(CampaignBusy, match=str(os.getpid())):
            with CampaignLock():
                pass
    with CampaignLock():
        pass


def test_open_pipe_count_sees_a_pipe_open_and_close():
    before = open_pipe_count()
    if before is None:
        pytest.skip('pipes cannot be counted on this host')
    read, write = os.pipe()
    try:
        assert open_pipe_count() == before + 2
    finally:
        os.close(read)
        os.close(write)
    assert open_pipe_count() == before


def test_process_helpers_follow_a_child_from_running_to_killed():
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        assert process_exists(child.pid)
        assert child.pid in descendants(os.getpid())
        assert kill_process(child.pid, process_identity(child.pid))
        child.wait(timeout=10)
        assert not process_exists(child.pid)
    finally:
        child.kill()
        child.wait()


def test_a_process_identity_is_stable_for_a_live_process_and_gone_with_it():
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        identity = process_identity(child.pid)
        assert identity is not None
        assert process_identity(child.pid) == identity
    finally:
        child.kill()
        child.wait()
    assert process_identity(child.pid) is None


def test_a_process_is_not_signalled_when_its_identity_differs_or_is_unknown():
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        identity = process_identity(child.pid)
        assert not kill_process(child.pid, identity + 'x' if isinstance(identity, str) else identity + 1)
        assert not kill_process(child.pid, None)
        with pytest.raises(subprocess.TimeoutExpired):
            child.wait(timeout=0.3)
    finally:
        child.kill()
        child.wait()


def test_only_sigterm_is_sent_on_windows_and_unknown_signals_are_dropped():
    assert 'SIGTERM' in available_signals(['SIGTERM', 'SIGNOSUCH'])
    assert 'SIGNOSUCH' not in available_signals(['SIGTERM', 'SIGNOSUCH'])
    if os.name == 'nt':
        assert available_signals(['SIGTERM', 'SIGINT']) == ['SIGTERM']


def test_profiles_are_limited_to_the_host_platform():
    assert all(profile in ADAPTERS for profile in host_profiles())
    assert len({profile.name for profile in ADAPTERS}) == len(ADAPTERS)


def test_a_missing_test_program_is_named_instead_of_replaced():
    reason = unavailable_reason(ADAPTERS[0], ['no_such_program'])
    assert 'no_such_program' in reason


def test_a_failing_operation_is_recorded_and_ends_the_example_quietly(machine):
    ran = []

    def broken(self):
        raise AssertionError('boom')

    machine.perform(Operation('broken', broken, 1, None, {}, False), {})
    machine.perform(Operation('later', lambda self: ran.append(True), 1, None, {}, False), {})
    assert isinstance(machine.failure, AssertionError)
    assert ran == []


def test_a_dropped_controller_whose_target_survives_is_reported_and_the_target_killed(machine, monkeypatch):
    monkeypatch.setattr(machine_module, 'PROCESS_EXIT_SECONDS', 0.1)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        process = TargetProcess()
        process.note(child.pid)
        machine.sessions.append(SimpleNamespace(model=GONE, process=process))
        with pytest.raises(AssertionError, match='outlived their dropped controller'):
            machine.check_dropped_targets()
        child.wait(timeout=10)
    finally:
        child.kill()
        child.wait()


def test_a_dropped_controllers_reused_pid_is_neither_reported_nor_killed(machine, monkeypatch):
    monkeypatch.setattr(machine_module, 'PROCESS_EXIT_SECONDS', 0.1)
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        process = TargetProcess()
        process.note(child.pid)
        # The noted process is gone and an unrelated one holds its pid
        process.identities[child.pid] = 'a process that is gone'
        machine.sessions.append(SimpleNamespace(model=GONE, process=process))
        machine.check_dropped_targets()
        with pytest.raises(subprocess.TimeoutExpired):
            child.wait(timeout=0.3)
    finally:
        child.kill()
        child.wait()


def test_a_pipe_kept_after_the_example_is_reported(machine, monkeypatch):
    if open_pipe_count() is None:
        pytest.skip('pipes cannot be counted on this host')
    monkeypatch.setattr(machine_module, 'PIPE_SETTLE_SECONDS', 0.1)
    type(machine).warmed = True
    machine.check_nothing_is_left()
    read, write = os.pipe()
    try:
        with pytest.raises(AssertionError, match='opened 2 pipes'):
            machine.check_nothing_is_left()
    finally:
        os.close(read)
        os.close(write)


def test_settings_default_to_the_ci_length_with_three_sessions():
    settings = from_environment({})
    assert (settings.length, settings.examples, settings.steps) == (
        'ci', LENGTHS['ci']['examples'], LENGTHS['ci']['steps'])
    assert (settings.sessions, settings.patience, settings.seed, settings.shrink_budget) == (3, 1.0, 0, 25)
    assert (settings.directory, settings.report, settings.parallel) == (None, None, False)


def test_the_length_sets_examples_and_steps_and_an_explicit_example_count_wins():
    assert from_environment({'ADAPTER_FUZZ_LENGTH': 'long'}).steps == LENGTHS['long']['steps']
    long = from_environment({'ADAPTER_FUZZ_LENGTH': 'long', 'ADAPTER_FUZZ_EXAMPLES': '7'})
    assert (long.examples, long.steps) == (7, LENGTHS['long']['steps'])


def test_an_empty_variable_counts_as_unset():
    assert from_environment({'ADAPTER_FUZZ_SESSIONS': ''}).sessions == 3


def test_every_setting_is_read_from_its_variable(tmp_path):
    settings = from_environment({
        'ADAPTER_FUZZ_SESSIONS': '2', 'ADAPTER_FUZZ_PATIENCE': '2.5', 'ADAPTER_FUZZ_SEED': '-4',
        'ADAPTER_FUZZ_SHRINK': '0', 'ADAPTER_FUZZ_DIR': str(tmp_path / 'd'), 'ADAPTER_FUZZ_REPORT': str(tmp_path / 'r'),
        'ADAPTER_FUZZ_ALLOW_PARALLEL': '1', 'ADAPTER_FUZZ_LOCK': str(tmp_path / 'l')})
    assert (settings.sessions, settings.patience, settings.seed, settings.shrink_budget) == (2, 2.5, -4, 0)
    assert (settings.directory, settings.report, settings.parallel, settings.lock) == (
        tmp_path / 'd', tmp_path / 'r', True, tmp_path / 'l')


@pytest.mark.parametrize('name, value', [
    ('ADAPTER_FUZZ_LENGTH', 'profile'), ('ADAPTER_FUZZ_SESSIONS', 'three'),
    ('ADAPTER_FUZZ_SESSIONS', '0'), ('ADAPTER_FUZZ_PATIENCE', '0'), ('ADAPTER_FUZZ_PATIENCE', 'inf'),
    ('ADAPTER_FUZZ_PATIENCE', 'fast'), ('ADAPTER_FUZZ_EXAMPLES', '0'), ('ADAPTER_FUZZ_EXAMPLES', '1.5'),
    ('ADAPTER_FUZZ_SEED', 'x'), ('ADAPTER_FUZZ_SHRINK', '-1'), ('ADAPTER_FUZZ_ALLOW_PARALLEL', 'yes')])
def test_a_bad_setting_fails_with_a_message_naming_its_variable(name, value):
    with pytest.raises(SettingsError, match=f'{name} must be .*{value!r}'):
        from_environment({name: value})


def test_the_lock_takes_its_path_and_parallel_flag_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv('ADAPTER_FUZZ_LOCK', str(tmp_path / 'lock'))
    monkeypatch.setenv('ADAPTER_FUZZ_ALLOW_PARALLEL', '1')
    with CampaignLock():
        with CampaignLock():
            pass
    assert CampaignLock().path == tmp_path / 'lock'


def test_a_worker_writes_its_records_in_the_directory_the_environment_names(tmp_path, monkeypatch):
    monkeypatch.setenv(recording.WORKER_DIRECTORY, str(tmp_path))
    recording.append('log', {'example': 1})
    recording.append('failures', {'example': 2})
    files = recording.worker_files()
    assert (files.log.read_text(), files.failures.read_text()) == ('{"example": 1}\n', '{"example": 2}\n')
    assert {path.name for path in tmp_path.iterdir()} == {'log.jsonl', 'failures.jsonl'}


def test_a_process_that_is_not_a_worker_records_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv(recording.WORKER_DIRECTORY, raising=False)
    monkeypatch.chdir(tmp_path)
    recording.append('log', {'example': 1})
    assert recording.worker_files() is None
    assert list(tmp_path.iterdir()) == []


def test_the_worker_files_are_four_paths_in_one_directory(tmp_path):
    files = recording.WorkerFiles(tmp_path)
    paths = {files.log, files.failures, files.crash, files.output}
    assert len(paths) == 4
    assert {path.parent for path in paths} == {tmp_path}
    assert files.environment() == {recording.WORKER_DIRECTORY: str(tmp_path)}


@pytest.fixture
def start_worker(campaign, monkeypatch):
    seen = []

    def run(command, env, **keywords):
        seen.append(env)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(campaign_module.subprocess, 'run', run)
    monkeypatch.delenv('BN_DISABLE_USER_SETTINGS', raising=False)

    def start():
        worker = campaign.start_worker('run', [], timeout=1)
        return seen[-1], worker

    return start


def test_a_worker_cannot_change_the_users_debugger_settings(start_worker):
    environment, _ = start_worker()
    assert environment['BN_DISABLE_USER_SETTINGS'] == 'true'


def test_an_explicit_choice_about_user_settings_reaches_the_worker(start_worker, monkeypatch):
    monkeypatch.setenv('BN_DISABLE_USER_SETTINGS', 'false')
    environment, _ = start_worker()
    assert environment['BN_DISABLE_USER_SETTINGS'] == 'false'


def test_a_worker_is_told_its_directory_and_the_files_are_in_it(start_worker, campaign):
    environment, worker = start_worker()
    assert environment[recording.WORKER_DIRECTORY] == str(worker.files.directory)
    assert worker.files.directory.parent == campaign.directory


def run_pytest_with_the_fuzz_conftest(directory, *options):
    shutil.copy(os.path.join(os.path.dirname(__file__), 'conftest.py'), directory)
    (directory / 'sample_test.py').write_text('import pytest\n\n@pytest.mark.fuzz\ndef test_campaign():\n    pass\n\n'
                                              'def test_quick():\n    pass\n')
    return subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '-rs', *options],
                          cwd=directory, capture_output=True, text=True).stdout


def test_a_fuzz_campaign_is_skipped_with_the_option_to_run_it_unless_the_option_is_given(tmp_path):
    output = run_pytest_with_the_fuzz_conftest(tmp_path)
    assert '1 passed, 1 skipped' in output
    assert 'pass --fuzz to run it' in output


def test_a_fuzz_campaign_runs_when_the_option_is_given(tmp_path):
    assert '2 passed' in run_pytest_with_the_fuzz_conftest(tmp_path, '--fuzz')


def test_a_crash_is_described_once(campaign, monkeypatch):
    calls = []

    def counted(text, returncode):
        calls.append(returncode)
        return describe_crash(text, returncode)

    monkeypatch.setattr(campaign_module, 'describe_crash', counted)
    campaign.add_crash(-11, {'steps': [step('launch')], 'warm_up': False}, SEGFAULT_OUTPUT)
    assert calls == [-11]


def test_shrinking_stops_at_the_replay_budget():
    replays = []

    def replay(candidate):
        replays.append(candidate)
        # Needs the first and last step, which takes many replays to find out
        rules = [candidate_step['rule'] for candidate_step in candidate]
        return 'k' if '0' in rules and '15' in rules else None

    shrunk = shrink([step(str(number)) for number in range(16)], 'k', replay, budget=5)
    assert (len(replays), shrunk.replays) == (5, 5)
    assert shrunk.reproducible


def test_a_failure_that_does_not_reproduce_is_not_shrunk_and_costs_one_replay():
    steps = [step('go'), step('pause')]
    shrunk = shrink(steps, 'k', lambda candidate: None, budget=25)
    assert (shrunk.reproducible, shrunk.steps, shrunk.replays) == (False, steps, 1)


def test_a_true_argument_is_simplified_to_false_and_a_number_to_zero_when_the_failure_does_not_need_them():
    shrunk = shrink([step('step', into=True, count=3)], 'k', lambda candidate: 'k', budget=25)
    assert shrunk.steps == [step('step', into=False, count=0)]

def test_a_warm_up_session_that_fails_to_start_raises_an_error_that_says_why():
    class Broken(AdapterMachine):
        def starting_session(self):
            raise ValueError('no such program')

    broken = machine_for(ADAPTERS[0], Broken)
    with pytest.raises(RuntimeError, match='warm-up session failed to start: ValueError: no such program'):
        broken.warm_up()
    assert not broken.warmed


def test_a_pipe_leak_message_says_it_depends_on_timing(machine, monkeypatch):
    if open_pipe_count() is None:
        pytest.skip('pipes cannot be counted on this host')
    monkeypatch.setattr(machine_module, 'PIPE_SETTLE_SECONDS', 0.1)
    type(machine).warmed = True
    read, write = os.pipe()
    try:
        with pytest.raises(AssertionError, match='ADAPTER_FUZZ_PATIENCE=2'):
            machine.check_nothing_is_left()
    finally:
        os.close(read)
        os.close(write)


def test_the_machine_tells_the_hook_how_each_session_ended_and_nothing_for_one_still_going(machine):
    ended = []
    machine.session_ended = lambda session, end: ended.append((session.name, end))
    machine.sessions = [SimpleNamespace(name=name, model='active', state='idle', check=lambda end=end: end)
                        for name, end in [('a', End.NONE), ('b', End.BY_ITSELF), ('c', End.BY_OPERATION)]]
    machine.check_sessions()
    assert ended == [('b', End.BY_ITSELF), ('c', End.BY_OPERATION)]
