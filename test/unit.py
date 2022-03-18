#!/usr/bin/env python3
#
# unit tests for debugger

import os
import sys
import time
import platform
import threading
import traceback
import subprocess

from binaryninja import BinaryView, BinaryViewType, LowLevelILOperation
from binaryninja.debugger import DebuggerController, DebugStopReason


# --------------------------------------------------------------------------
# UTILITIES
# --------------------------------------------------------------------------

def shellout(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdout, stderr) = process.communicate()
    stdout = stdout.decode("utf-8")
    stderr = stderr.decode("utf-8")
    #print('stdout: -%s-' % stdout)
    #print('stderr: -%s-' % stderr)
    process.wait()
    return (stdout, stderr)


# 'helloworld' -> '.\binaries\Windows-x64\helloworld.exe' (windows)
# 'helloworld' -> './binaries/Darwin/arm64/helloworld' (linux, android)
def testbin_to_fpath(testbin, arch=None, os_str=None):
    if arch is None:
        arch = platform.machine()

    if os_str is None:
        os_str = platform.system()

    if os_str == 'Windows' and not testbin.endswith('.exe'):
        testbin = testbin + '.exe'

    path = os.path.join('binaries', f'{os_str}-{arch}', testbin)
    if '~' in path:
        path = os.expanduser(path)
    path = os.path.abspath(path)
    return path


def break_into(dbg):
    print('sending break')
    dbg.pause()


def is_wow64(fpath):
    if 'x86' not in fpath:
        return False
    a, b = platform.architecture()
    return a == '64bit' and b.startswith('Windows')


def assert_equality(a, b):
    if a == b:
        return
    print('EXPECTED EQUALITY!')
    print('  actual: %s' % a)
    print('expected: %s' % b)
    traceback.print_stack()
    sys.exit(-1)


def expect_bad_instruction(reason):
    # :/ I cannot induce a bad instruction exception on these OS's!
    # TODO: add android
    # It seems to me that we ALWAYS get an AccessViolation when there is an illegal instruction
    if platform.system() in ['Windows', 'Linux']:
        expected = DebugStopReason.AccessViolation
    else:
        expected = DebugStopReason.IllegalInstruction

    assert_equality(reason, expected)


def assert_general_error(func):
    raised = False
    try:
        func()
    except DebugAdapter.GeneralError:
        raised = True
    assert raised


def test_one_arch(current_arch):
    #--------------------------------------------------------------------------
    # TESTS
    #--------------------------------------------------------------------------

    # repeat DebugController use tests
    fpath = testbin_to_fpath('helloworld', current_arch)
    bv = BinaryViewType.get_view_of_file(fpath)

    def thread_task():
        dbg = DebuggerController(bv)
        dbg.cmd_line = 'segfault'
        if not dbg.launch():
            print(f'fail to launch {fpath}')
            sys.exit(-1)

        # continue execution to the entry point, and check the stop reason
        reason = dbg.go()
        assert_equality(reason, DebugStopReason.Breakpoint)
        reason = dbg.step_into()
        assert_equality(reason, DebugStopReason.SingleStep)
        reason = dbg.step_into()
        assert_equality(reason, DebugStopReason.SingleStep)
        reason = dbg.step_into()
        assert_equality(reason, DebugStopReason.SingleStep)
        # go until executing done
        reason = dbg.go()
        assert_equality(reason, DebugStopReason.ProcessExited)

        dbg.destroy()

    # Do the same thing for 10 times
    n = 10
    for i in range(n):
        print('testing %s %d/%d' % (fpath, i+1, n))
        thread_task()

    # return code tests
    fpath = testbin_to_fpath('exitcode', current_arch)
    bv = BinaryViewType.get_view_of_file(fpath)

    # some systems return byte, or low byte of 32-bit code and others return 32-bit code
    testvals = [('-11',[245,4294967285]), ('-1',[4294967295,255]), ('-3',[4294967293,253]), ('0',[0]), ('3',[3]), ('7',[7]), ('123',[123])]
    for (arg, expected) in testvals:
        print('testing %s %s' % (fpath, arg))
        dbg = DebuggerController(bv)
        dbg.cmd_line = arg

        if not dbg.launch():
            print(f'fail to launch {fpath}')
            sys.exit(-1)

        dbg.go()
        reason = dbg.go()
        assert_equality(reason, DebugStopReason.ProcessExited)
        exit_code = dbg.exit_code
        if exit_code not in expected:
            raise Exception('expected return code %d to be in %s' % (exit_code, expected))

    # exception test
    fpath = testbin_to_fpath('do_exception', current_arch)
    bv = BinaryViewType.get_view_of_file(fpath)
    dbg = DebuggerController(bv)

    # segfault
    dbg.cmd_line = 'segfault'
    if not dbg.launch():
        print(f'fail to launch {fpath}')
        sys.exit(-1)
    dbg.go()
    reason = dbg.go()
    assert_equality(reason, DebugStopReason.AccessViolation)
    dbg.quit()

    # illegal instruction
    dbg.cmd_line = 'illegalinstr'
    if not dbg.launch():
        print(f'fail to launch {fpath}')
        sys.exit(-1)
    dbg.go()
    reason = dbg.go()
    expect_bad_instruction(reason)
    dbg.quit()

    # breakpoint, single step, exited
    dbg.cmd_line = 'fakearg'
    if not dbg.launch():
        print(f'fail to launch {fpath}')
        sys.exit(-1)
    reason = dbg.go()
    assert_equality(reason, DebugStopReason.Breakpoint)
    reason = dbg.step_into()
    assert_equality(reason, DebugStopReason.SingleStep)
    reason = dbg.step_into()
    assert_equality(reason, DebugStopReason.SingleStep)
    reason = dbg.go()
    assert_equality(reason, DebugStopReason.ProcessExited)

    # divzero
    # divide-by-zero does not cause an exception on arm64, so this test is meaningless. Skip it.
    if not current_arch == 'arm64':
        dbg.cmd_line = 'divzero'
        if not dbg.launch():
            print(f'fail to launch {fpath}')
            sys.exit(-1)
        dbg.go()
        reason = dbg.go()
        assert_equality(reason, DebugStopReason.Calculation)

    # assembler x86/x64 tests
    if current_arch == 'x86_64':
        fpath = testbin_to_fpath('asmtest', 'x86_64')
        print(f'testing {fpath}')
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        if not dbg.launch():
            print(f'fail to launch {fpath}')
            sys.exit(-1)

        entry = dbg.live_view.entry_point
        ip = dbg.ip
        loader = ip != entry
        if loader:
            print('entrypoint is the program, no library or loader')
        else:
            print('loader detected, gonna step a few times for fun')

        # a few steps in the loader
        if loader:
            reason = dbg.step_into()
            assert_equality(reason, DebugStopReason.SingleStep)
            reason = dbg.step_into()
            assert_equality(reason, DebugStopReason.SingleStep)
            # go to entry
            dbg.go()
            assert_equality(dbg.ip, entry)

        # TODO: we can use BN to disassemble the binary and find out how long is the instruction
        # step into nop
        dbg.step_into()
        assert_equality(dbg.ip, entry+1)
        # step into call, return
        dbg.step_into()
        dbg.step_into()
        # back
        assert_equality(dbg.ip, entry+6)
        dbg.step_into()
        # step into call, return
        dbg.step_into()
        dbg.step_into()
        # back
        assert_equality(dbg.ip, entry+12)

        reason = dbg.go()
        assert_equality(reason, DebugStopReason.ProcessExited)

        print('PASS!')

    # helloworld, no threads
    fpath = testbin_to_fpath('helloworld', current_arch)
    bv = BinaryViewType.get_view_of_file(fpath)
    dbg = DebuggerController(bv)
    if not dbg.launch():
        print(f'fail to launch {fpath}')
        sys.exit(-1)

    arch_name = bv.arch.name
    if arch_name == 'x86':
        (bits, xip, xax, xbx) = (32, 'eip', 'eax', 'ebx')
        (testval_a, testval_b) = (0xDEADBEEF, 0xCAFEBABE)
    elif arch_name == 'x86_64':
        (bits, xip, xax, xbx) = (64, 'rip', 'rax', 'rbx')
        (testval_a, testval_b) = (0xAAAAAAAADEADBEEF, 0xBBBBBBBBCAFEBABE)
    elif arch_name == 'aarch64':
        (bits, xip, xax, xbx) = (64, 'pc', 'x0', 'x1')
        (testval_a, testval_b) = (0xAAAAAAAADEADBEEF, 0xBBBBBBBBCAFEBABE)

    print('%s: 0x%X' % (xip, dbg.ip))

    # breakpoint set/clear should fail at 0
    if dbg.add_breakpoint(0):
        print('expected add breakpoint failure at 0')
        sys.exit(-1)

    if dbg.delete_breakpoint(0):
        print('expected remove breakpoint failure at 0')
        sys.exit(-1)

    # breakpoint set/clear should succeed at entrypoint
    entry = dbg.live_view.entry_point
    print('clearing breakpoint at 0x%X' % entry)
    dbg.delete_breakpoint(entry)
    print('setting breakpoint at 0x%X' % entry)
    dbg.add_breakpoint(entry)

    # proceed to breakpoint
    print('going')
    reason = dbg.go()
    assert_equality(reason, DebugStopReason.Breakpoint)

    assert_equality(dbg.ip, entry)

    # single step until it wasn't over a call
    instr_len = 0
    while 1:
        pc = dbg.ip
        data = dbg.read_memory(pc, 15)
        assert_equality(len(data), 15)

        reason = dbg.step_into()
        assert_equality(reason, DebugStopReason.SingleStep)

        arch = dbg.live_view.arch
        llil = arch.get_low_level_il_from_bytes(bytes(data), pc)
        if llil.operation in [LowLevelILOperation.LLIL_CALL, LowLevelILOperation.LLIL_JUMP]:
            continue

        instr_len = dbg.live_view.get_instruction_length(pc)
        break

    addr2 = dbg.ip
    print('%s: 0x%X' % (xip, addr2))
    assert_equality(pc + instr_len, addr2)

    print('registers read/write')
    rax = dbg.get_reg_value(xax)
    rbx = dbg.get_reg_value(xbx)

    dbg.set_reg_value(xax, testval_a)
    assert_equality(dbg.get_reg_value(xax), testval_a)
    dbg.set_reg_value(xbx, testval_b)
    assert_equality(dbg.get_reg_value(xbx), testval_b)

    dbg.set_reg_value(xax, rax)
    assert_equality(dbg.get_reg_value(xax), rax)
    dbg.set_reg_value(xbx, rbx)
    assert_equality(dbg.get_reg_value(xbx), rbx)

    print('mem read/write')
    addr = dbg.ip
    data = dbg.read_memory(addr, 256)
    assert_equality(dbg.write_memory(0, b'heheHAHAherherHARHAR'), False)
    data2 = b'\xAA' * 256
    dbg.write_memory(addr, data2)

    assert_equality(len(dbg.read_memory(0, 256)), 0)
    assert_equality(dbg.read_memory(addr, 256), data2)
    dbg.write_memory(addr, data)
    assert_equality(dbg.read_memory(addr, 256), data)

    print('quiting')
    dbg.quit()
    dbg = None

    # helloworlds with threads
    fpath = testbin_to_fpath('helloworld_thread', current_arch)
    bv = BinaryViewType.get_view_of_file(fpath)
    dbg = DebuggerController(bv)
    if not dbg.launch():
        print(f'fail to launch {fpath}')
        sys.exit(-1)

    print('scheduling break in 1 second')
    threading.Timer(1, break_into, [dbg]).start()
    print('going')
    reason = dbg.go()
    reason = dbg.go()

    # print('switching to bad thread')
    # assert_general_error(lambda: adapter.thread_select(999))

    print('asking for threads')
    if platform.system() == 'Windows':
        # main thread at WaitForMultipleObjects() + 4 created threads + debugger thread
        nthreads_expected = 9
    else:
        # main thread at pthread_join() + 4 created threads
        nthreads_expected = 5

    threads = dbg.threads
    assert_equality(len(threads), nthreads_expected)

    tid_active = dbg.active_thread
    addrs = []
    for thread in threads:
        addr = thread.rip
        addrs.append(addr)
        seltxt = '<--' if thread == tid_active else ''
        print('thread %02d: 0x%016X %s' % (thread.tid, addr, seltxt))

    if not is_wow64(fpath):
        # on wow64, wow64cpu!TurboDispatchJumpAddressEnd+0x544 becomes common thread jump from point
        assert addrs[0] != addrs[1] # thread at WaitForMultipleObjects()/pthread_join() should be different

    # Wait for the thread that stops the target finish, before we resume the target again
    time.sleep(1)

    # run for one second
    print('scheduling break in 1 second')
    threading.Timer(1, break_into, [dbg]).start()
    print('going')
    dbg.go()

    # print('switching to bad thread')
    # assert_general_error(lambda: adapter.thread_select(999))

    print('checking for %d threads' % nthreads_expected)
    threads = dbg.threads
    assert_equality(len(threads), nthreads_expected)
    # ensure the eip/rip are in different locations (that the continue actually continued)
    addrs2 = []
    for thread in threads:
        addr = thread.rip
        addrs2.append(addr)

    if not is_wow64(fpath):
        print('checking that at least one thread progressed')
        if not list(filter(lambda x: not x, [addrs[i] == addrs2[i] for i in range(len(addrs))])):
            print('did any threads progress?')
            print('addrs: ', list(map(hex, addrs)))
            print('addrs2: ', list(map(hex, addrs2)))
            assert False
    print('done')
    dbg.quit()
    pass


#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
#
if __name__ == '__main__':
    arg = sys.argv[1] if sys.argv[1:] else None

    # one-off tests
    if arg == 'oneoff':
        fpath = testbin_to_fpath('helloworld_thread')
        print(fpath)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        # launch the target, and execute to the entry point
        dbg.launch()
        dbg.go()
        print(dbg.modules)
        dbg.quit()
        sys.exit(0)

    # attaching test
    if arg == 'attaching':
        pid = None
        # TODO: we definitely need to simplify code like this
        if platform.system() == 'Windows':
            fpath = testbin_to_fpath('helloworld_loop')
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_CONSOLE = 0x00000010
            cmds = [fpath]
            print('cmds:', cmds)
            pid = subprocess.Popen(cmds, creationflags=CREATE_NEW_CONSOLE).pid
        elif platform.system() in ['Darwin', 'linux']:
            fpath = testbin_to_fpath('helloworld_loop')
            cmds = [fpath]
            print('cmds:', cmds)
            pid = subprocess.Popen(cmds).pid
        else:
            print('attaching test not yet implemented on %s' % platform.system())

        print('created process with pid: %d\n' % pid)
        bv = BinaryViewType.get_view_of_file(fpath)
        dbg = DebuggerController(bv)
        print('attaching')
        dbg.attach(pid)
        for i in range(4):
            print('scheduling break into in 2 seconds')
            threading.Timer(2, break_into, [dbg]).start()
            # print the first 8 register values
            print('some registers:')
            for (idx, reg) in enumerate(dbg.regs):
                print('%d: %s (%d bits): 0x%X' % (idx, reg.name, reg.width, reg.value))
                if idx > 8:
                    break

            print('pausing a sec')
            time.sleep(1)
            print('continuing')
            reason = dbg.go()

        print('quiting')
        dbg.quit()
        dbg = None
        sys.exit(-1)

    test_archs = []
    if platform.system() == 'Darwin':
        if platform.machine() == 'arm64':
            test_archs.append('arm64')
        # test_archs.append('x86_64')
    elif platform.system() in ['Linux', 'Windows']:
        test_archs.append('x86_64')
        test_archs.append('x86')

    for current_arch in test_archs:
        print('testing arch %s' % current_arch)
        test_one_arch(current_arch)
        print('tested arch %s' % current_arch)

    print('TESTS PASSED!')
    sys.exit(0)
