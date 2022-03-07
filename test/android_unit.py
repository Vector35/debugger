#!/usr/bin/env python3
#
# Android unit tests for debugger

import os
import re
import sys
import time
import platform
import threading
import traceback
import subprocess

from binaryninja import BinaryView, BinaryViewType, LowLevelILOperation
from binaryninja.debugger import DebuggerController, DebugStopReason


def invoke_adb_gdb_listen(testbin_args, port=31337):
    global testbin

    if '_armv7-' in testbin: gdbserver = 'gdbserver_armv7'
    elif '_aarch64-' in testbin: gdbserver = 'gdbserver_aarch64'
    else: raise Exception('cannot determine gdbserver architecture from %s' % testbin)

    cmdline = []
    cmdline.append('adb')
    cmdline.append('shell')
    cmdline.append('/data/local/tmp/%s :%d /data/local/tmp/%s' % (gdbserver, port, testbin))
    cmdline.extend(testbin_args)

    print('invoke_adb() executing: %s' % ' '.join(cmdline))
    shellout(cmdline)
    print('invoke_adb() done')


def android_test_setup(testbin_args=[]):
    global testbin

    # send file to phone
    fpath = testbin_to_fpath()
    shellout(['adb', 'push', fpath, '/data/local/tmp'])

    # launch adb
    threading.Thread(target=invoke_adb_gdb_listen, args=[testbin_args]).start()

    # connect to adb
    time.sleep(.25)
    adapter = gdb.DebugAdapterGdb()
    adapter.connect('localhost', 31337)
    entry = confirm_initial_module(adapter)

    return (adapter, entry)


if __name__ == '__main__':
    #--------------------------------------------------------------------------
    # {ARMV7,AARCH64}-ANDROID TESTS
    #--------------------------------------------------------------------------

    # helloworld armv7, no threads
    for tb in testbins:
        if not tb.startswith('helloworld_'): continue
        if not '_armv7-' in tb: continue
        if '_thread' in tb: continue
        print('testing %s' % tb)
        testbin = tb

        (adapter, entry) = android_test_setup()

        print('pc: 0x%X' % adapter.reg_read('pc'))

        # breakpoint set/clear should fail at 0
        print('breakpoint failures')
        try:
            adapter.breakpoint_clear(0)
        except DebugAdapter.BreakpointClearError:
            pass

        try:
            adapter.breakpoint_set(0)
        except DebugAdapter.BreakpointSetError:
            pass

        # breakpoint set/clear should succeed at entrypoint
        print('setting breakpoint at 0x%X' % entry)
        adapter.breakpoint_set(entry)
        print('clearing breakpoint at 0x%X' % entry)
        adapter.breakpoint_clear(entry)
        print('setting breakpoint at 0x%X' % entry)
        adapter.breakpoint_set(entry)

        # proceed to breakpoint
        print('going')
        (reason, info) = adapter.go()
        assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
        pc = adapter.reg_read('pc')
        print('pc: 0x%X' % pc)
        assert_equality(pc, entry)

        # single step
        data = adapter.mem_read(pc, 15)
        assert_equality(len(data), 15)
        (asmstr, asmlen) = utils.disasm1(data, 0, 'armv7')
        adapter.breakpoint_clear(entry)
        (reason, info) = adapter.step_into()
        assert_equality(reason, DebugAdapter.STOP_REASON.SINGLE_STEP)
        pc2 = adapter.reg_read('pc')
        print('pc2: 0x%X' % pc2)
        assert_equality(pc + asmlen, pc2)

        print('registers')
        for (ridx,rname) in enumerate(adapter.reg_list()):
            width = adapter.reg_bits(rname)
        #print('%d: %s (%d bits)' % (ridx, rname, width))
        assert_equality(adapter.reg_bits('r0'), 32)
        assert_equality(adapter.reg_bits('r4'), 32)
        assert_general_error(lambda: adapter.reg_bits('rzx'))

        print('registers read/write')
        r0 = adapter.reg_read('r0')
        r4 = adapter.reg_read('r4')
        assert_general_error(lambda: adapter.reg_read('rzx'))
        adapter.reg_write('r0', 0xDEADBEEF)
        assert_equality(adapter.reg_read('r0'), 0xDEADBEEF)
        adapter.reg_write('r4', 0xCAFEBABE)
        assert_general_error(lambda: adapter.reg_read('rzx'))
        assert_equality(adapter.reg_read('r4'), 0xCAFEBABE)
        adapter.reg_write('r0', r0)
        assert_equality(adapter.reg_read('r0'), r0)
        adapter.reg_write('r4', r4)
        assert_equality(adapter.reg_read('r4'), r4)

        print('mem read/write')
        addr = adapter.reg_read('pc')
        data = adapter.mem_read(addr, 256)
        assert_general_error(lambda: adapter.mem_write(0, b'heheHAHAherherHARHAR'))
        data2 = b'\xAA' * 256
        adapter.mem_write(addr, data2)
        assert_general_error(lambda: adapter.mem_read(0, 256))
        assert_equality(adapter.mem_read(addr, 256), data2)
        adapter.mem_write(addr, data)
        assert_equality(adapter.mem_read(addr, 256), data)

        print('quiting')
        adapter.quit()
        adapter = None

    # helloworld with threads
    # architectures: armv7, aarch64
    for tb in testbins:
        if not tb.startswith('helloworld_thread_'): continue
        if not (('_armv7-' in tb) or ('_aarch64-' in tb)): continue
        print('testing %s' % tb)
        testbin = tb

        (adapter, entry) = android_test_setup()

        print('pc: 0x%X' % adapter.reg_read('pc'))
        print('scheduling break in 1 seconds')
        threading.Timer(.3, break_into, [adapter]).start()
        print('going')
        adapter.go()
        print('back')
        print('switching to bad thread')
        assert_general_error(lambda: adapter.thread_select(999))
        print('asking for threads')
        tids = adapter.thread_list()
        assert_equality(len(tids), 5)
        tid_active = adapter.thread_selected()
        pcs = []
        for tid in tids:
            adapter.thread_select(tid)
            pc = adapter.reg_read('pc')
            pcs.append(pc)
            seltxt = '<--' if tid == tid_active else ''
            print('thread %02d: pc=0x%016X %s' % (tid, pc, seltxt))
        assert pcs[0] != pcs[1] # thread at WaitForMultipleObjects()/pthread_join() should be different
        print('switching to bad thread')
        assert_general_error(lambda: adapter.thread_select(999))
        secs = 1
        print('scheduling break in %d second(s)' % secs)
        threading.Timer(secs, break_into, [adapter]).start()
        print('going')
        adapter.go()
        print('back')
        print('checking for %d threads' % 5)
        assert_equality(len(adapter.thread_list()), 5)
        # ensure the pc's are in different locations (that the continue actually continued)
        pcs2 = []
        for tid in tids:
            adapter.thread_select(tid)
            pcs2.append(adapter.reg_read('pc'))
        print('checking that at least one thread progressed')
        #print(' pcs: ', pcs)
        #print('pcs2: ', pcs2)
        if list(filter(lambda x: not x, [pcs[i]==pcs2[i] for i in range(len(pcs))])) == []:
            print('did any threads progress?')
            print(' pcs:  ', pcs)
            print('pcs2:  ', pcs2)
            assert False
        print('done')
        adapter.quit()

    # exception test
    for tb in testbins:
        if not tb.startswith('do_exception'): continue
        if not '-android' in tb: continue
        print('testing %s' % tb)
        testbin = tb


        # segfault
        (adapter, entry) = android_test_setup(['segfault'])
        (reason, extra) = go_initial(adapter)
        assert_equality(reason, DebugAdapter.STOP_REASON.ACCESS_VIOLATION)
        adapter.quit()

        # illegal instruction
        (adapter, entry) = android_test_setup(['illegalinstr'])
        (reason, extra) = go_initial(adapter)
        expect_bad_instruction(reason)
        adapter.quit()

        # breakpoint, single step, exited
        (adapter, entry) = android_test_setup(['fakearg'])
        entry = confirm_initial_module(adapter)
        adapter.breakpoint_set(entry)
        (reason, extra) = go_initial(adapter)
        assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
        adapter.breakpoint_clear(entry)
        #print('rip: ', adapter.reg_read('rip'))
        (reason, extra) = adapter.step_into()
        #print('rip: ', adapter.reg_read('rip'))
        expect_single_step(reason)

        (reason, extra) = adapter.step_into()
        #print('rip: ', adapter.reg_read('rip'))
        expect_single_step(reason)

        (reason, extra) = adapter.go()
        assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
        adapter.quit()

    # divzero
    # https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/divide-and-conquer
    # ARMv7-A - divide by zero always returns a zero result.
    # ARMv7-R - the SCTLR.DZ bit controls whether you get a zero result or a Undefined Instruction exception when you attempt to divide by zero (the default is to return zero).
    # ARMv7-M -  the CCR.DIV_0_TRP bit controls whether an exception is generated. If this occurs, it will cause a UsageFault and the UFSR.DIVBYZERO bit will indicate the reason for the fault.

    #(adapter, entry) = android_test_setup(['divzero'])
    #if 'aarch64' in tb:
    #	# aarch64 compiled binaries divide by 0 just fine, return "inf" *shrug*
    #	assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
    #else:
    #	assert_equality(reason, DebugAdapter.STOP_REASON.CALCULATION)
    #adapter.quit()

    # assembler test
    # architectures: armv7, aarch64
    for tb in filter(lambda x: x.startswith('asmtest_armv7') or x.startswith('asmtest_aarch64'), testbins):
        print('testing %s' % tb)
        testbin = tb

        (adapter, entry) = android_test_setup()

        loader = adapter.reg_read('pc') != entry
        if loader:
            print('entrypoint is the program, no library or loader')
        else:
            print('loader detected, gonna step a few times for fun')

        # a few steps in the loader
        if loader:
            (reason, extra) = adapter.step_into()
            expect_single_step(reason)

        # set bp entry
        print('setting entry breakpoint at 0x%X' % entry)
        adapter.breakpoint_set(entry)

        # few more steps
        if loader:
            (reason, extra) = adapter.step_into()
            expect_single_step(reason)

        # go to entry
        adapter.go()
        assert_equality(adapter.reg_read('pc'), entry)
        adapter.breakpoint_clear(entry)
        # step into nop
        adapter.step_into()
        assert_equality(adapter.reg_read('pc'), entry+4)
        # step into call, return
        adapter.step_into()
        adapter.step_into()
        # back
        assert_equality(adapter.reg_read('pc'), entry+8)
        adapter.step_into()
        # step into call, return
        adapter.step_into()
        adapter.step_into()
        # back
        assert_equality(adapter.reg_read('pc'), entry+16)

        (reason, extra) = adapter.go()
        assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)

        adapter.quit()

    # helloworld aarch64, no threads
    for tb in testbins:
        if not tb.startswith('helloworld_'): continue
        if not '_aarch64-' in tb: continue
        if '_thread' in tb: continue
        print('testing %s' % tb)
        testbin = tb

        (adapter, entry) = android_test_setup()

        print('pc: 0x%X' % adapter.reg_read('pc'))

        # breakpoint set/clear should fail at 0
        print('breakpoint failures')
        try:
            adapter.breakpoint_clear(0)
        except DebugAdapter.BreakpointClearError:
            pass

        try:
            adapter.breakpoint_set(0)
        except DebugAdapter.BreakpointSetError:
            pass

        # breakpoint set/clear should succeed at entrypoint
        print('setting breakpoint at 0x%X' % entry)
        adapter.breakpoint_set(entry)
        print('clearing breakpoint at 0x%X' % entry)
        adapter.breakpoint_clear(entry)
        print('setting breakpoint at 0x%X' % entry)
        adapter.breakpoint_set(entry)

        # proceed to breakpoint
        print('going')
        (reason, info) = adapter.go()
        assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
        pc = adapter.reg_read('pc')
        print('pc: 0x%X' % pc)
        assert_equality(pc, entry)

        # single step
        data = adapter.mem_read(pc, 15)
        assert_equality(len(data), 15)
        (asmstr, asmlen) = utils.disasm1(data, 0, 'armv7')
        adapter.breakpoint_clear(entry)
        (reason, info) = adapter.step_into()
        expect_single_step(reason)
        pc2 = adapter.reg_read('pc')
        print('pc2: 0x%X' % pc2)
        assert_equality(pc + asmlen, pc2)

        print('registers')
        for (ridx,rname) in enumerate(adapter.reg_list()):
            width = adapter.reg_bits(rname)
        #print('%d: %s (%d bits)' % (ridx, rname, width))
        assert_equality(adapter.reg_bits('x0'), 64)
        assert_equality(adapter.reg_bits('x4'), 64)
        assert_general_error(lambda: adapter.reg_bits('rzx'))

        print('registers read/write')
        x0 = adapter.reg_read('x0')
        x4 = adapter.reg_read('x4')
        assert_general_error(lambda: adapter.reg_read('rzx'))
        adapter.reg_write('x0', 0xDEADBEEF)
        assert_equality(adapter.reg_read('x0'), 0xDEADBEEF)
        adapter.reg_write('x4', 0xCAFEBABE)
        assert_general_error(lambda: adapter.reg_read('rzx'))
        assert_equality(adapter.reg_read('x4'), 0xCAFEBABE)
        adapter.reg_write('x0', x0)
        assert_equality(adapter.reg_read('x0'), x0)
        adapter.reg_write('x4', x4)
        assert_equality(adapter.reg_read('x4'), x4)

        print('mem read/write')
        addr = adapter.reg_read('pc')
        data = adapter.mem_read(addr, 256)
        assert_general_error(lambda: adapter.mem_write(0, b'heheHAHAherherHARHAR'))
        data2 = b'\xAA' * 256
        adapter.mem_write(addr, data2)
        assert_general_error(lambda: adapter.mem_read(0, 256))
        assert_equality(adapter.mem_read(addr, 256), data2)
        adapter.mem_write(addr, data)
        assert_equality(adapter.mem_read(addr, 256), data)

        if not '_loop' in tb:
            print('going')
            (reason, extra) = adapter.go()
            assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)

        print('quiting')
        adapter.quit()
        adapter = None
