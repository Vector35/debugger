#!/usr/bin/env python3
"""Randomized stress driver for the ptrace adapter. Runs many session.py processes
and reports hangs, crashes (signals) and invariant violations with a reproducer line.

env: PTRACE_TEST_BUILD_DIR (contains progs), BN_USER_DIRECTORY / PYTHONPATH as for debugger_test.py
usage: fuzz.py [--seconds N] [--jobs J] [--modes a,b] [--seed S]
"""
import argparse, os, random, subprocess, sys, time, concurrent.futures as cf

MODES = ['loop', 'threads', 'bploop', 'stepthreads', 'churnloop', 'sigthread', 'forkthreads', 'multiload', 'dlcycle',
         'execloop', 'cloneproc', 'flood', 'sleeper', 'frames', 'stepover', 'recurse', 'forkbp', 'sighandler',
         'bpthreads', 'markerthreads', 'execthread', 'spawnbp', 'vforkbp', 'syscalls', 'sig', 'sigchld',
         'sigtrap_raise', 'sigtrap_kill', 'sigtrap_instruction', 'sigtrap_unhandled', 'abort', 'lastwords', 'execpad',
         'execbp', 'cloneshared', 'forkbp2', 'watch', 'watchthread', 'detachbp', 'dl', 'dlrebase', 'leaderexit']

p = argparse.ArgumentParser()
p.add_argument('--seconds', type=int, default=300)
p.add_argument('--jobs', type=int, default=4)
p.add_argument('--modes', default=','.join(MODES))
p.add_argument('--seed', type=int, default=int(time.time()))
p.add_argument('--nops', type=int, default=40)
p.add_argument('--flag-prob', type=float, default=0.35, help='chance of each of --signals/--attach/--hammer')
a = p.parse_args()
progs = os.path.join(os.environ['PTRACE_TEST_BUILD_DIR'], 'progs')
here = os.path.dirname(os.path.abspath(__file__))
modes = a.modes.split(',')
rng = random.Random(a.seed)
deadline = time.time() + a.seconds
results = {}


def run(seed, mode, pause, flags):
    cmd = [sys.executable, os.path.join(here, 'session.py'), progs, mode, str(seed), str(a.nops)] + ([] if pause else ['--no-pause']) + flags
    try:
        pr = subprocess.run(cmd, capture_output=True, text=True, timeout=int(300 * float(os.environ.get('FUZZ_TIME_SCALE', '1'))))
        save = os.environ.get('FUZZ_SAVE_DIR')
        if save and pr.returncode != 0:
            os.makedirs(save, exist_ok=True)
            with open(os.path.join(save, f'{cmd[4]}-{cmd[5]}.log'), 'w') as f:
                f.write(' '.join(cmd) + '\n' + pr.stdout + '\n--- stderr ---\n' + pr.stderr)
        return cmd, pr.returncode, pr.stdout[-6000:], pr.stderr[-2000:]
    except subprocess.TimeoutExpired as e:
        return cmd, 'TIMEOUT', (e.stdout or b'')[-3000:], ''


n = bad = 0
with cf.ThreadPoolExecutor(a.jobs) as ex:
    futs = set()
    while time.time() < deadline or futs:
        while time.time() < deadline and len(futs) < a.jobs:
            futs.add(ex.submit(run, rng.randrange(1 << 30), rng.choice(modes), rng.random() < 0.7, [f for f in ('--signals', '--attach', '--hammer') if rng.random() < a.flag_prob]))
        done, futs = cf.wait(futs, timeout=1, return_when=cf.FIRST_COMPLETED)
        for f in done:
            cmd, rc, out, err = f.result()
            n += 1
            if rc != 0:
                bad += 1
                print(f'=== rc={rc} reproduce: {" ".join(cmd[1:])}')
                print('\n'.join(l for l in out.splitlines() if l.startswith(('FINDING', 'OPS', '  File', 'Thread', 'Current')))[:3000])
                sys.stdout.flush()
print(f'{n} sessions, {bad} failing (base seed {a.seed})')
sys.exit(1 if bad else 0)
