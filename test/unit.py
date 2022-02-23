#!/usr/bin/env python3
#
# unit tests for debugger

import os
import re
import sys
import time
import platform
import threading
import traceback
import subprocess

from struct import unpack

import colorama

sys.path.append('..')
from binaryninja.debugger import *

# globals
adapter = None
testbin = None

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

def parse_image(fpath):
    load_addr = None
    entry_offs = None

    print('finding entrypoint for %s' % fpath)
    with open(fpath, 'rb') as fp:
        data = fp.read()

    # little endian macho
    if data[0:4] == b'\xCF\xFA\xED\xFE':
        assert_equality(data[4:8], b'\x07\x00\x00\x01') # CPU_TYPE_X86_X64
        ncmds = unpack('<I', data[16:20])[0]
        #print('ncmds: %d' % ncmds)
        vmaddr = None
        entryoff1 = None # offset given by COMMAND entry_point_command (priority)
        entryoff2 = None # offset of __text section inside __TEXT segment
        offs = 0x20
        for i in range(ncmds):
            cmd = unpack('<I', data[offs:offs+4])[0]
            cmdsize = unpack('<I', data[offs+4:offs+8])[0]
            if cmd == 0x19: # segment_command_64
                if data[offs+8:offs+16] == b'\x5F\x5F\x54\x45\x58\x54\x00\x00': # __TEXT
                    vmaddr = unpack('<Q', data[offs+24:offs+32])[0]
                    print('vmaddr: %X' % vmaddr)

                    nsects = unpack('<I', data[offs+64:offs+68])[0]
                    #print('segment __TEXT nsects: %d' % nsects)

                    # advance past command to first section
                    o_scn = offs + 0x48
                    for i in range(nsects):
                        name = data[o_scn+0:o_scn+16]
                        #print('__TEXT section %d: %s' % (i, name))
                        if name == b'__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                            entryoff2 = unpack('<I', data[o_scn+0x30:o_scn+0x34])[0]
                            break;
                        o_scn += 0x50

                    if entryoff2 == None:
                        raise Exception('couldn\'t locate section __text in segment __TEXT in %s' % fpath)
            if cmd == 0x80000028: # entry_point_command
                entryoff = unpack('<I', data[offs+8:offs+12])[0]
            #print('entryoff: %X' % entryoff)
            offs += cmdsize
        if not vmaddr:
            raise Exception('couldn\'t locate segment_command_64 (where __TEXT loads) in %s' % fpath)
        if entryoff1 == None and entryoff2 == None:
            raise Exception('couldn\'t locate entry_point_command in macho (where main is)' % fpath)

        load_addr = vmaddr
        entry_offs = entryoff1 or entryoff2

    # PE
    elif data[0:2] == b'\x4d\x5a':
        e_lfanew = unpack('<I', data[0x3C:0x40])[0]
        if data[e_lfanew:e_lfanew+6] == b'\x50\x45\x00\x00\x64\x86':
            # x86_64
            entryoff = unpack('<I', data[e_lfanew+0x28:e_lfanew+0x2C])[0]
            vmaddr = unpack('<Q', data[e_lfanew+0x30:e_lfanew+0x38])[0]
        elif data[e_lfanew:e_lfanew+6] == b'\x50\x45\x00\x00\x4c\x01':
            # x86
            entryoff = unpack('<I', data[e_lfanew+0x28:e_lfanew+0x2C])[0]
            vmaddr = unpack('<I', data[e_lfanew+0x34:e_lfanew+0x38])[0]

        load_addr = vmaddr
        entry_offs = entryoff

    # ELF
    elif data[0:4] == b'\x7FELF':
        if data[4] == 1: # EI_CLASS 32-bit
            assert_equality(data[5], 1) # EI_DATA little endian
            assert data[0x10:0x12] in [b'\x02\x00', b'\x03\x00'] # e_type ET_EXEC or ET_DYN (pie)
            #assert_equality(data[0x12:0x14], b'\x3E\x00' # e_machine EM_X86_64)
            e_entry = unpack('<I', data[0x18:0x1C])[0]
            e_phoff = unpack('<I', data[0x1C:0x20])[0]
            e_phentsize = unpack('<H', data[0x2A:0x2C])[0]
            e_phnum = unpack('<H', data[0x2C:0x2E])[0]
            print('e_entry:0x%X e_phoff:0x%X e_phentsize:0x%X e_phnum:0x%X' %
                  (e_entry, e_phoff, e_phentsize, e_phnum))

            # find first PT_LOAD
            p_vaddr = None
            offs = e_phoff
            for i in range(e_phnum):
                p_type = unpack('<I', data[offs:offs+4])[0]
                #print('at offset 0x%X p_type:0x%X' % (offs, p_type))
                if p_type == 1:
                    p_vaddr = unpack('<I', data[offs+8:offs+12])[0]
                    break
                offs += e_phentsize
            if p_vaddr == None:
                raise Exception('couldnt locate a single PT_LOAD program header')

            load_addr = p_vaddr
            entry_offs = e_entry - p_vaddr

        elif data[4] == 2: # EI_CLASS 64-bit
            assert_equality(data[5], 1) # EI_DATA little endian

            assert data[0x10:0x12] in [b'\x02\x00', b'\x03\x00'] # e_type ET_EXEC or ET_DYN (pie)
            #assert_equality(data[0x12:0x14], b'\x3E\x00' # e_machine EM_X86_64)
            e_entry = unpack('<Q', data[0x18:0x20])[0]
            e_phoff = unpack('<Q', data[0x20:0x28])[0]
            e_phentsize = unpack('<H', data[0x36:0x38])[0]
            e_phnum = unpack('<H', data[0x38:0x3a])[0]
            print('e_entry:0x%X e_phoff:0x%X e_phentsize:0x%X e_phnum:0x%X' %
                  (e_entry, e_phoff, e_phentsize, e_phnum))

            # find first PT_LOAD
            p_vaddr = None
            offs = e_phoff
            for i in range(e_phnum):
                p_type = unpack('<I', data[offs:offs+4])[0]
                #print('at offset 0x%X p_type:0x%X' % (offs, p_type))
                if p_type == 1:
                    p_vaddr = unpack('<Q', data[offs+16:offs+24])[0]
                    break
                offs += e_phentsize
            if p_vaddr == None:
                raise Exception('couldnt locate a single PT_LOAD program header')

            load_addr = p_vaddr
            entry_offs = e_entry - p_vaddr

        else:
            raise Exception('expected e_ident[EI_CLASS] to be 1 or 2, got: %d' % data[4])
    else:
        raise Exception('unrecognized file type')

    print('(file) load addr: 0x%X' % load_addr)
    print('(file) entry offset: 0x%X' % entry_offs)
    return (load_addr, entry_offs)

# 'helloworld' -> '.\testbins\helloworld.exe' (windows)
# 'helloworld' -> './testbins/helloworld' (linux, android)
def testbin_to_fpath():
    global testbin
    if testbin.endswith('-win') or testbin.endswith('-windows'):
        testbin = testbin + '.exe'
    tmp =  os.path.join('testbins', testbin)
    if '~' in tmp:
        tmp = os.expanduser(tmp)
    tmp = os.path.abspath(tmp)
    return tmp

# 'helloworld_armv7-android' -> '/data/local/tmp/helloworld_armv7-android'
def testbin_to_mpath():
    global testbin
    m = re.match(r'^.*_(.*)-(.*)$', testbin)
    (mach, os_) = m.group(1, 2)
    if os_ == 'android':
        return '/data/local/tmp/' + testbin
    else:
        return testbin_to_fpath()

def break_into(adapter):
    print('sending break')
    adapter.break_into()

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

def is_wow64():
    global testbin
    if not 'x86' in testbin: return False
    (a,b) = platform.architecture()
    return a=='64bit' and b.startswith('Windows')

def go_initial(adapter):
    global testbin
    if is_wow64():
        (reason, info) = adapter.go()
        assert_equality((reason, info), (DebugAdapter.STOP_REASON.UNKNOWN, 0x4000001f))
    return adapter.go()

def assert_equality(a, b):
    if a == b: return
    utils.red('EXPECTED EQUALITY!')
    utils.red('  actual: %s' % a)
    utils.red('expected: %s' % b)
    traceback.print_stack()
    sys.exit(-1)

# let there be a single check for single-step
# (abstract away OS-exceptional cases)
def expect_single_step(reason):
    global testbin

    if 'macos' in testbin:
        expected = DebugAdapter.STOP_REASON.BREAKPOINT
    else:
        expected = DebugAdapter.STOP_REASON.SINGLE_STEP

    assert_equality(reason, expected)

def expect_bad_instruction(reason):
    global testbin

    # :/ I cannot induce a bad instruction exception on these OS's!
    if 'macos' in testbin or 'windows' in testbin or 'android' in testbin:
        expected = DebugAdapter.STOP_REASON.ACCESS_VIOLATION
    else:
        expected = DebugAdapter.STOP_REASON.ILLEGAL_INSTRUCTION

    assert_equality(reason, expected)

def assert_general_error(func):
    raised = False
    try:
        func()
    except DebugAdapter.GeneralError:
        raised = True
    assert raised

# determines the entrypoint from the
def confirm_initial_module(adapter):
    global testbin

    fpath = testbin_to_fpath()
    mpath = testbin_to_mpath()

    module2addr = adapter.mem_modules()
    #print('module2addr: ', ' '.join(['%s:%X' % (i[0],i[1]) for i in module2addr.items()]))
    #print('      mpath: ', mpath)

    if not mpath in module2addr:
        mpath = os.path.basename(mpath)
        assert mpath in module2addr

    (load_addr, entry_offs) = parse_image(fpath)
    print('  load_addr: 0x%X' % load_addr)
    if '_pie' in testbin:
        # pie: override file's load address with runtime load address
        load_addr = module2addr[mpath]
    else:
        # non-pie: file's load address should match runtime load address
        assert_equality(module2addr[mpath], load_addr)

    return load_addr + entry_offs

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

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
#
# if __name__ == '__main__':
#     colorama.init()
#     arg = sys.argv[1] if sys.argv[1:] else None
#
#     # one-off tests
#     if arg == 'oneoff':
#         fpath = testbin_to_fpath('helloworld_thread')
#         adapter = DebugAdapter.get_adapter_for_current_system()
#         adapter.exec(fpath)
#         print(adapter.mem_modules())
#         print(type(adapter) == dbgeng.DebugAdapterDbgeng)
#         sys.exit(0)
#
#     # attaching test
#     if arg == 'attaching':
#         pid = None
#         if platform.system() == 'Windows':
#             testbin = 'helloworld_loop_x64-windows'
#             fpath = testbin_to_fpath()
#             DETACHED_PROCESS = 0x00000008
#             CREATE_NEW_CONSOLE = 0x00000010
#             cmds = [fpath]
#             print('cmds:', cmds)
#             pid = subprocess.Popen(cmds, creationflags=CREATE_NEW_CONSOLE).pid
#         else:
#             print('attaching test not yet implemented on %s' % platform.system())
#         print('created process with pid: %d\n' % pid)
#         adapter = DebugAdapter.get_adapter_for_current_system()
#         print('attaching')
#         adapter.attach(pid)
#         for i in range(4):
#             print('scheduling break into in 2 seconds')
#             threading.Timer(2, break_into, [adapter]).start()
#             print('some registers:')
#             for (ridx,rname) in enumerate(adapter.reg_list()):
#                 width = adapter.reg_bits(rname)
#                 print('%d: %s (%d bits): 0x%X' % (ridx, rname, width, adapter.reg_read(rname)))
#                 if ridx > 8: break
#             print('pausing a sec')
#             time.sleep(1)
#             print('continuing')
#             (reason, extra) = adapter.go()
#         print('quiting')
#         adapter.quit()
#         adapter = None
#         sys.exit(-1)
#
#     # otherwise test all executables built in the testbins dir
#     testbins = []
#     for fname in os.listdir('testbins'):
#         fpath = os.path.join('testbins', fname)
#         if platform.system() == 'Windows':
#             if fpath.endswith('.exe'):
#                 testbins.append(fname)
#         elif os.access(fpath, os.X_OK):
#             testbins.append(fname)
#     print('collected the following tests:\n', testbins)
#
#     #--------------------------------------------------------------------------
#     # x86/x64 TESTS
#     #--------------------------------------------------------------------------
#
#     # repeat adapter use tests
#     for tb in filter(lambda x: x.startswith('helloworld_x64'), testbins):
#         testbin = tb
#         fpath = testbin_to_fpath()
#
#         def thread_task():
#             adapter = DebugAdapter.get_adapter_for_current_system()
#
#             adapter.exec(fpath, ['segfault'])
#             # set initial breakpoint
#             entry = confirm_initial_module(adapter)
#             adapter.breakpoint_set(entry)
#             # go to breakpoint
#             (reason, extra) = go_initial(adapter)
#             assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
#             # clear, single step a few times
#             adapter.breakpoint_clear(entry)
#             (reason, extra) = adapter.step_into()
#             expect_single_step(reason)
#             (reason, extra) = adapter.step_into()
#             expect_single_step(reason)
#             (reason, extra) = adapter.step_into()
#             expect_single_step(reason)
#             # go until executing done
#             (reason, extra) = adapter.go()
#             assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#
#             adapter.quit()
#             adapter = None
#
#         for i in range(10):
#             utils.green('testing %s %d/10' % (fpath, i+1))
#             t = threading.Thread(target=thread_task)
#             t.start()
#             t.join()
#
#     # return code tests
#     for tb in [x for x in testbins if x.startswith('exitcode')]:
#         testbin = tb
#
#         fpath = testbin_to_fpath()
#
#         # some systems return byte, or low byte of 32-bit code and otheres return 32-bit code
#         testvals = [('-11',[245,4294967285]), ('-1',[4294967295,255]), ('-3',[4294967293,253]), ('0',[0]), ('3',[3]), ('7',[7]), ('123',[123])]
#         for (arg, expected) in testvals:
#             adapter = DebugAdapter.get_adapter_for_current_system()
#
#             utils.green('testing %s %s' % (tb, arg))
#             adapter.exec(fpath, [arg])
#             (reason, extra) = go_initial(adapter)
#             assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#             if not extra in expected:
#                 raise Exception('expected return code %d to be in %s' % (extra, expected))
#
#     # exception test
#     for tb in testbins:
#         if not tb.startswith('do_exception'): continue
#         if not ('x86' in tb) or ('x64' in tb): continue
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#         adapter = DebugAdapter.get_adapter_for_current_system()
#         fpath = testbin_to_fpath()
#
#         # segfault
#         adapter.exec(fpath, ['segfault'])
#         (reason, extra) = go_initial(adapter)
#         assert_equality(reason, DebugAdapter.STOP_REASON.ACCESS_VIOLATION)
#         adapter.quit()
#
#         # illegal instruction
#         adapter.exec(fpath, ['illegalinstr'])
#         (reason, extra) = go_initial(adapter)
#         expect_bad_instruction(reason)
#         adapter.quit()
#
#         # breakpoint, single step, exited
#         adapter.exec(fpath, ['fakearg'])
#         entry = confirm_initial_module(adapter)
#         adapter.breakpoint_set(entry)
#         (reason, extra) = go_initial(adapter)
#         assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
#         adapter.breakpoint_clear(entry)
#         #print('rip: ', adapter.reg_read('rip'))
#         (reason, extra) = adapter.step_into()
#         #print('rip: ', adapter.reg_read('rip'))
#         expect_single_step(reason)
#
#         (reason, extra) = adapter.step_into()
#         #print('rip: ', adapter.reg_read('rip'))
#         expect_single_step(reason)
#
#         (reason, extra) = adapter.go()
#         assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#         adapter.quit()
#
#         # divzero
#         adapter.exec(fpath, ['divzero'])
#         (reason, extra) = go_initial(adapter)
#         assert_equality(reason, DebugAdapter.STOP_REASON.CALCULATION)
#         adapter.quit()
#
#     # assembler x86/x64 tests
#     for tb in testbins:
#         if not (tb.startswith('asmtest_x64') or tb.startswith('asmtest_x86')): continue
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#         # parse entrypoint information
#         fpath = testbin_to_fpath()
#         (load_addr, entry_offs) = parse_image(fpath)
#         entry = load_addr + entry_offs
#
#         # tester and testee run on same machine
#         adapter = DebugAdapter.get_adapter_for_current_system()
#         adapter.exec(fpath, '')
#
#         xip = 'eip' if 'x86' in tb else 'rip'
#
#         loader = adapter.reg_read(xip) != entry
#         if loader: print('entrypoint is the program, no library or loader')
#         else: print('loader detected, gonna step a few times for fun')
#
#         # a few steps in the loader
#         if loader:
#             (reason, extra) = adapter.step_into()
#             expect_single_step(reason)
#
#         # set bp entry
#         print('setting entry breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#
#         # few more steps
#         if loader:
#             (reason, extra) = adapter.step_into()
#             expect_single_step(reason)
#
#         # go to entry
#         (reason, extra) = go_initial(adapter)
#         assert_equality(adapter.reg_read(xip), entry)
#         adapter.breakpoint_clear(entry)
#         # step into nop
#         adapter.step_into()
#         assert_equality(adapter.reg_read(xip), entry+1)
#         # step into call, return
#         adapter.step_into()
#         adapter.step_into()
#         # back
#         assert_equality(adapter.reg_read(xip), entry+6)
#         adapter.step_into()
#         # step into call, return
#         adapter.step_into()
#         adapter.step_into()
#         # back
#         assert_equality(adapter.reg_read(xip), entry+12)
#
#         (reason, extra) = adapter.go()
#         assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#
#         adapter.quit()
#         print('PASS!')
#
#     # helloworld x86/x64, no threads
#     for tb in testbins:
#         if not tb.startswith('helloworld_'): continue
#         if not ('_x64-' in tb or '_x86-' in tb): continue
#         if '_thread' in tb: continue
#         utils.green('hellworld x86/x64, no threads, testing %s' % tb)
#         testbin = tb
#
#         # tester and testee run on same machine
#         adapter = DebugAdapter.get_adapter_for_current_system()
#         fpath = testbin_to_fpath()
#         adapter.exec(fpath, '')
#         entry = confirm_initial_module(adapter)
#
#         if '_x86-' in tb:
#             (bits, xip, xax, xbx) = (32, 'eip', 'eax', 'ebx')
#             (testval_a, testval_b) = (0xDEADBEEF, 0xCAFEBABE)
#         else:
#             (bits, xip, xax, xbx) = (64, 'rip', 'rax', 'rbx')
#             (testval_a, testval_b) = (0xAAAAAAAADEADBEEF, 0xBBBBBBBBCAFEBABE)
#
#         print('%s: 0x%X' % (xip, adapter.reg_read(xip)))
#
#         # breakpoint set/clear should fail at 0
#         print('expect breakpoint clear failure at 0')
#         try:
#             adapter.breakpoint_clear(0)
#         except DebugAdapter.BreakpointClearError:
#             pass
#
#         print('expect breakpoint set failure at 0')
#         try:
#             adapter.breakpoint_set(0)
#         except DebugAdapter.BreakpointSetError:
#             pass
#
#         # breakpoint set/clear should succeed at entrypoint
#         print('setting breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#         print('clearing breakpoint at 0x%X' % entry)
#         adapter.breakpoint_clear(entry)
#         print('setting breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#
#         # proceed to breakpoint
#         print('going')
#         (reason, extra) = go_initial(adapter)
#         assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
#
#         assert_equality(adapter.reg_read(xip), entry)
#         adapter.breakpoint_clear(entry)
#
#         # single step until it wasn't over a call
#         while 1:
#             addr = adapter.reg_read(xip)
#             data = adapter.mem_read(addr, 15)
#             assert_equality(len(data), 15)
#             (asmstr, asmlen) = utils.disasm1(data, 0)
#             print('%s: 0x%X %s' % (xip, addr, asmstr))
#
#             (reason, info) = adapter.step_into()
#             expect_single_step(reason)
#             if asmstr.startswith('call'): continue
#             if asmstr.startswith('jmp'): continue
#             break
#
#         addr2 = adapter.reg_read(xip)
#         print('%s: 0x%X' % (xip, addr2))
#         assert_equality(addr + asmlen, addr2)
#
#         print('registers')
#         for (ridx,rname) in enumerate(adapter.reg_list()):
#             width = adapter.reg_bits(rname)
#         #print('%d: %s (%d bits)' % (ridx, rname, width))
#         assert_equality(adapter.reg_bits(xax), bits)
#         assert_equality(adapter.reg_bits(xbx), bits)
#         assert_general_error(lambda: adapter.reg_bits('rzx'))
#
#         print('registers read/write')
#         rax = adapter.reg_read(xax)
#         rbx = adapter.reg_read(xbx)
#         assert_general_error(lambda: adapter.reg_read('rzx'))
#         adapter.reg_write(xax, testval_a)
#         assert_equality(adapter.reg_read(xax), testval_a)
#         adapter.reg_write(xbx, testval_b)
#         assert_general_error(lambda: adapter.reg_read('rzx'))
#         assert_equality(adapter.reg_read(xbx), testval_b)
#         adapter.reg_write(xax, rax)
#         assert_equality(adapter.reg_read(xax), rax)
#         adapter.reg_write(xbx, rbx)
#         assert_equality(adapter.reg_read(xbx), rbx)
#
#         print('mem read/write')
#         addr = adapter.reg_read(xip)
#         data = adapter.mem_read(addr, 256)
#         assert_general_error(lambda: adapter.mem_write(0, b'heheHAHAherherHARHAR'))
#         data2 = b'\xAA' * 256
#         adapter.mem_write(addr, data2)
#         assert_general_error(lambda: adapter.mem_read(0, 256))
#         assert_equality(adapter.mem_read(addr, 256), data2)
#         adapter.mem_write(addr, data)
#         assert_equality(adapter.mem_read(addr, 256), data)
#
#         print('quiting')
#         adapter.quit()
#         adapter = None
#
#     # helloworlds x86/x64 with threads
#     for tb in testbins:
#         if not tb.startswith('helloworld_thread'): continue
#         if not ('_x86-' in tb or '_x64-' in tb): continue
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#         # for x64 machine, tester and testee run on same machine
#         adapter = DebugAdapter.get_adapter_for_current_system()
#         fpath = testbin_to_fpath()
#         adapter.exec(fpath, '')
#         entry = confirm_initial_module(adapter)
#
#         if '_x86-' in tb: xip = 'eip'
#         else: xip = 'rip'
#
#         print('scheduling break in 1 second')
#         threading.Timer(1, break_into, [adapter]).start()
#         print('going')
#         (reason, extra) = go_initial(adapter)
#         print('back')
#         print('switching to bad thread')
#         assert_general_error(lambda: adapter.thread_select(999))
#         print('asking for threads')
#         if platform.system() == 'Windows':
#             # main thread at WaitForMultipleObjects() + 4 created threads + debugger thread
#             nthreads_expected = 6
#         else:
#             # main thread at pthread_join() + 4 created threads
#             nthreads_expected = 5
#         tids = adapter.thread_list()
#         if len(tids) != nthreads_expected:
#             print('expected %d threads, but len(tids) is %d' % (nthreads_expected, len(tids)))
#             assert False
#         tid_active = adapter.thread_selected()
#         addrs = []
#         for tid in tids:
#             adapter.thread_select(tid)
#             addr = adapter.reg_read(xip)
#             addrs.append(addr)
#             seltxt = '<--' if tid == tid_active else ''
#             print('thread %02d: %s=0x%016X %s' % (tid, xip, addr, seltxt))
#
#         if not is_wow64():
#             # on wow64, wow64cpu!TurboDispatchJumpAddressEnd+0x544 becomes common thread jump from point
#             assert addrs[0] != addrs[1] # thread at WaitForMultipleObjects()/pthread_join() should be different
#         print('switching to bad thread')
#         assert_general_error(lambda: adapter.thread_select(999))
#         secs = 1
#         print('scheduling break in %d second(s)' % secs)
#         threading.Timer(secs, break_into, [adapter]).start()
#         print('going')
#         adapter.go()
#         print('back')
#         print('checking for %d threads' % nthreads_expected)
#         assert_equality(len(adapter.thread_list()), nthreads_expected)
#         # ensure the eip/rip are in different locations (that the continue actually continued)
#         addrs2 = []
#         for tid in tids:
#             adapter.thread_select(tid)
#             addr2 = adapter.reg_read(xip)
#             addrs2.append(addr2)
#         if not is_wow64():
#             print('checking that at least one thread progressed')
#             if list(filter(lambda x: not x, [addrs[i]==addrs2[i] for i in range(len(addrs))])) == []:
#                 print('did any threads progress?')
#                 print('addrs: ', map(hex,addrs))
#                 print('addrs2:  ', map(hex,addrs2))
#                 assert False
#         print('done')
#         adapter.quit()
#
#     #--------------------------------------------------------------------------
#     # {ARMV7,AARCH64}-ANDROID TESTS
#     #--------------------------------------------------------------------------
#
#     # helloworld armv7, no threads
#     for tb in testbins:
#         if not tb.startswith('helloworld_'): continue
#         if not '_armv7-' in tb: continue
#         if '_thread' in tb: continue
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#         (adapter, entry) = android_test_setup()
#
#         print('pc: 0x%X' % adapter.reg_read('pc'))
#
#         # breakpoint set/clear should fail at 0
#         print('breakpoint failures')
#         try:
#             adapter.breakpoint_clear(0)
#         except DebugAdapter.BreakpointClearError:
#             pass
#
#         try:
#             adapter.breakpoint_set(0)
#         except DebugAdapter.BreakpointSetError:
#             pass
#
#         # breakpoint set/clear should succeed at entrypoint
#         print('setting breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#         print('clearing breakpoint at 0x%X' % entry)
#         adapter.breakpoint_clear(entry)
#         print('setting breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#
#         # proceed to breakpoint
#         print('going')
#         (reason, info) = adapter.go()
#         assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
#         pc = adapter.reg_read('pc')
#         print('pc: 0x%X' % pc)
#         assert_equality(pc, entry)
#
#         # single step
#         data = adapter.mem_read(pc, 15)
#         assert_equality(len(data), 15)
#         (asmstr, asmlen) = utils.disasm1(data, 0, 'armv7')
#         adapter.breakpoint_clear(entry)
#         (reason, info) = adapter.step_into()
#         assert_equality(reason, DebugAdapter.STOP_REASON.SINGLE_STEP)
#         pc2 = adapter.reg_read('pc')
#         print('pc2: 0x%X' % pc2)
#         assert_equality(pc + asmlen, pc2)
#
#         print('registers')
#         for (ridx,rname) in enumerate(adapter.reg_list()):
#             width = adapter.reg_bits(rname)
#         #print('%d: %s (%d bits)' % (ridx, rname, width))
#         assert_equality(adapter.reg_bits('r0'), 32)
#         assert_equality(adapter.reg_bits('r4'), 32)
#         assert_general_error(lambda: adapter.reg_bits('rzx'))
#
#         print('registers read/write')
#         r0 = adapter.reg_read('r0')
#         r4 = adapter.reg_read('r4')
#         assert_general_error(lambda: adapter.reg_read('rzx'))
#         adapter.reg_write('r0', 0xDEADBEEF)
#         assert_equality(adapter.reg_read('r0'), 0xDEADBEEF)
#         adapter.reg_write('r4', 0xCAFEBABE)
#         assert_general_error(lambda: adapter.reg_read('rzx'))
#         assert_equality(adapter.reg_read('r4'), 0xCAFEBABE)
#         adapter.reg_write('r0', r0)
#         assert_equality(adapter.reg_read('r0'), r0)
#         adapter.reg_write('r4', r4)
#         assert_equality(adapter.reg_read('r4'), r4)
#
#         print('mem read/write')
#         addr = adapter.reg_read('pc')
#         data = adapter.mem_read(addr, 256)
#         assert_general_error(lambda: adapter.mem_write(0, b'heheHAHAherherHARHAR'))
#         data2 = b'\xAA' * 256
#         adapter.mem_write(addr, data2)
#         assert_general_error(lambda: adapter.mem_read(0, 256))
#         assert_equality(adapter.mem_read(addr, 256), data2)
#         adapter.mem_write(addr, data)
#         assert_equality(adapter.mem_read(addr, 256), data)
#
#         print('quiting')
#         adapter.quit()
#         adapter = None
#
#     # helloworld with threads
#     # architectures: armv7, aarch64
#     for tb in testbins:
#         if not tb.startswith('helloworld_thread_'): continue
#         if not (('_armv7-' in tb) or ('_aarch64-' in tb)): continue
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#         (adapter, entry) = android_test_setup()
#
#         print('pc: 0x%X' % adapter.reg_read('pc'))
#         print('scheduling break in 1 seconds')
#         threading.Timer(.3, break_into, [adapter]).start()
#         print('going')
#         adapter.go()
#         print('back')
#         print('switching to bad thread')
#         assert_general_error(lambda: adapter.thread_select(999))
#         print('asking for threads')
#         tids = adapter.thread_list()
#         assert_equality(len(tids), 5)
#         tid_active = adapter.thread_selected()
#         pcs = []
#         for tid in tids:
#             adapter.thread_select(tid)
#             pc = adapter.reg_read('pc')
#             pcs.append(pc)
#             seltxt = '<--' if tid == tid_active else ''
#             print('thread %02d: pc=0x%016X %s' % (tid, pc, seltxt))
#         assert pcs[0] != pcs[1] # thread at WaitForMultipleObjects()/pthread_join() should be different
#         print('switching to bad thread')
#         assert_general_error(lambda: adapter.thread_select(999))
#         secs = 1
#         print('scheduling break in %d second(s)' % secs)
#         threading.Timer(secs, break_into, [adapter]).start()
#         print('going')
#         adapter.go()
#         print('back')
#         print('checking for %d threads' % 5)
#         assert_equality(len(adapter.thread_list()), 5)
#         # ensure the pc's are in different locations (that the continue actually continued)
#         pcs2 = []
#         for tid in tids:
#             adapter.thread_select(tid)
#             pcs2.append(adapter.reg_read('pc'))
#         print('checking that at least one thread progressed')
#         #print(' pcs: ', pcs)
#         #print('pcs2: ', pcs2)
#         if list(filter(lambda x: not x, [pcs[i]==pcs2[i] for i in range(len(pcs))])) == []:
#             print('did any threads progress?')
#             print(' pcs:  ', pcs)
#             print('pcs2:  ', pcs2)
#             assert False
#         print('done')
#         adapter.quit()
#
#     # exception test
#     for tb in testbins:
#         if not tb.startswith('do_exception'): continue
#         if not '-android' in tb: continue
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#
#         # segfault
#         (adapter, entry) = android_test_setup(['segfault'])
#         (reason, extra) = go_initial(adapter)
#         assert_equality(reason, DebugAdapter.STOP_REASON.ACCESS_VIOLATION)
#         adapter.quit()
#
#         # illegal instruction
#         (adapter, entry) = android_test_setup(['illegalinstr'])
#         (reason, extra) = go_initial(adapter)
#         expect_bad_instruction(reason)
#         adapter.quit()
#
#         # breakpoint, single step, exited
#         (adapter, entry) = android_test_setup(['fakearg'])
#         entry = confirm_initial_module(adapter)
#         adapter.breakpoint_set(entry)
#         (reason, extra) = go_initial(adapter)
#         assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
#         adapter.breakpoint_clear(entry)
#         #print('rip: ', adapter.reg_read('rip'))
#         (reason, extra) = adapter.step_into()
#         #print('rip: ', adapter.reg_read('rip'))
#         expect_single_step(reason)
#
#         (reason, extra) = adapter.step_into()
#         #print('rip: ', adapter.reg_read('rip'))
#         expect_single_step(reason)
#
#         (reason, extra) = adapter.go()
#         assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#         adapter.quit()
#
#     # divzero
#     # https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/divide-and-conquer
#     # ARMv7-A - divide by zero always returns a zero result.
#     # ARMv7-R - the SCTLR.DZ bit controls whether you get a zero result or a Undefined Instruction exception when you attempt to divide by zero (the default is to return zero).
#     # ARMv7-M -  the CCR.DIV_0_TRP bit controls whether an exception is generated. If this occurs, it will cause a UsageFault and the UFSR.DIVBYZERO bit will indicate the reason for the fault.
#
#     #(adapter, entry) = android_test_setup(['divzero'])
#     #if 'aarch64' in tb:
#     #	# aarch64 compiled binaries divide by 0 just fine, return "inf" *shrug*
#     #	assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#     #else:
#     #	assert_equality(reason, DebugAdapter.STOP_REASON.CALCULATION)
#     #adapter.quit()
#
#     # assembler test
#     # architectures: armv7, aarch64
#     for tb in filter(lambda x: x.startswith('asmtest_armv7') or x.startswith('asmtest_aarch64'), testbins):
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#         (adapter, entry) = android_test_setup()
#
#         loader = adapter.reg_read('pc') != entry
#         if loader:
#             print('entrypoint is the program, no library or loader')
#         else:
#             print('loader detected, gonna step a few times for fun')
#
#         # a few steps in the loader
#         if loader:
#             (reason, extra) = adapter.step_into()
#             expect_single_step(reason)
#
#         # set bp entry
#         print('setting entry breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#
#         # few more steps
#         if loader:
#             (reason, extra) = adapter.step_into()
#             expect_single_step(reason)
#
#         # go to entry
#         adapter.go()
#         assert_equality(adapter.reg_read('pc'), entry)
#         adapter.breakpoint_clear(entry)
#         # step into nop
#         adapter.step_into()
#         assert_equality(adapter.reg_read('pc'), entry+4)
#         # step into call, return
#         adapter.step_into()
#         adapter.step_into()
#         # back
#         assert_equality(adapter.reg_read('pc'), entry+8)
#         adapter.step_into()
#         # step into call, return
#         adapter.step_into()
#         adapter.step_into()
#         # back
#         assert_equality(adapter.reg_read('pc'), entry+16)
#
#         (reason, extra) = adapter.go()
#         assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#
#         adapter.quit()
#
#     # helloworld aarch64, no threads
#     for tb in testbins:
#         if not tb.startswith('helloworld_'): continue
#         if not '_aarch64-' in tb: continue
#         if '_thread' in tb: continue
#         utils.green('testing %s' % tb)
#         testbin = tb
#
#         (adapter, entry) = android_test_setup()
#
#         print('pc: 0x%X' % adapter.reg_read('pc'))
#
#         # breakpoint set/clear should fail at 0
#         print('breakpoint failures')
#         try:
#             adapter.breakpoint_clear(0)
#         except DebugAdapter.BreakpointClearError:
#             pass
#
#         try:
#             adapter.breakpoint_set(0)
#         except DebugAdapter.BreakpointSetError:
#             pass
#
#         # breakpoint set/clear should succeed at entrypoint
#         print('setting breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#         print('clearing breakpoint at 0x%X' % entry)
#         adapter.breakpoint_clear(entry)
#         print('setting breakpoint at 0x%X' % entry)
#         adapter.breakpoint_set(entry)
#
#         # proceed to breakpoint
#         print('going')
#         (reason, info) = adapter.go()
#         assert_equality(reason, DebugAdapter.STOP_REASON.BREAKPOINT)
#         pc = adapter.reg_read('pc')
#         print('pc: 0x%X' % pc)
#         assert_equality(pc, entry)
#
#         # single step
#         data = adapter.mem_read(pc, 15)
#         assert_equality(len(data), 15)
#         (asmstr, asmlen) = utils.disasm1(data, 0, 'armv7')
#         adapter.breakpoint_clear(entry)
#         (reason, info) = adapter.step_into()
#         expect_single_step(reason)
#         pc2 = adapter.reg_read('pc')
#         print('pc2: 0x%X' % pc2)
#         assert_equality(pc + asmlen, pc2)
#
#         print('registers')
#         for (ridx,rname) in enumerate(adapter.reg_list()):
#             width = adapter.reg_bits(rname)
#         #print('%d: %s (%d bits)' % (ridx, rname, width))
#         assert_equality(adapter.reg_bits('x0'), 64)
#         assert_equality(adapter.reg_bits('x4'), 64)
#         assert_general_error(lambda: adapter.reg_bits('rzx'))
#
#         print('registers read/write')
#         x0 = adapter.reg_read('x0')
#         x4 = adapter.reg_read('x4')
#         assert_general_error(lambda: adapter.reg_read('rzx'))
#         adapter.reg_write('x0', 0xDEADBEEF)
#         assert_equality(adapter.reg_read('x0'), 0xDEADBEEF)
#         adapter.reg_write('x4', 0xCAFEBABE)
#         assert_general_error(lambda: adapter.reg_read('rzx'))
#         assert_equality(adapter.reg_read('x4'), 0xCAFEBABE)
#         adapter.reg_write('x0', x0)
#         assert_equality(adapter.reg_read('x0'), x0)
#         adapter.reg_write('x4', x4)
#         assert_equality(adapter.reg_read('x4'), x4)
#
#         print('mem read/write')
#         addr = adapter.reg_read('pc')
#         data = adapter.mem_read(addr, 256)
#         assert_general_error(lambda: adapter.mem_write(0, b'heheHAHAherherHARHAR'))
#         data2 = b'\xAA' * 256
#         adapter.mem_write(addr, data2)
#         assert_general_error(lambda: adapter.mem_read(0, 256))
#         assert_equality(adapter.mem_read(addr, 256), data2)
#         adapter.mem_write(addr, data)
#         assert_equality(adapter.mem_read(addr, 256), data)
#
#         if not '_loop' in tb:
#             print('going')
#             (reason, extra) = adapter.go()
#             assert_equality(reason, DebugAdapter.STOP_REASON.PROCESS_EXITED)
#
#         print('quiting')
#         adapter.quit()
#         adapter = None

    print('TESTS PASSED!')
