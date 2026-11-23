"""Register and memory operations on a stopped target."""

from .draws import booleans, integers, one_of

from .common import INDEX
from .operations import OperationModule, is_active, session_operation

# Registers that a write may not read back from or that the program cannot survive being written, even briefly. Most
# are matched by exact name, so that a register that only contains one of them in its name (`offset`) is still written.
SPECIAL_REGISTERS = {'pc', 'ip', 'sp', 'fp', 'lr', 'rip', 'rsp', 'rbp', 'eip', 'esp', 'ebp', 'xzr', 'wzr', 'zr',
                     'cs', 'ds', 'es', 'fs', 'gs', 'ss'}
# Flag, status, segment base and thread-pointer registers go by a part of the name, since each architecture has several
SPECIAL_FRAGMENTS = ('flags', 'psr', 'base', 'nzcv', 'fpcr', 'fpsr', 'tpidr')

VALUE_KINDS = ['zero', 'one', 'ones', 'plus_one', 'pattern']
WRITE_SIZES = [1, 3, 8, 64, 4096]
HOSTILE_ACCESSES = ['null', 'high', 'zero_size', 'huge', 'cross_end', 'wrap']
HUGE_READ = 16 * 1024 * 1024
# Accesses that cannot land on memory the program uses, so a write needs no undoing
UNUSED_ADDRESSES = {'null', 'high', 'zero_size', 'wrap'}


def general_registers(dbg):
    registers = []
    # Read the dictionary behind DebugRegisters, so that this does not depend on iterating it (iterate_registers does)
    for register in dbg.regs.regs.values():
        name = register.name.lower()
        if name in SPECIAL_REGISTERS or any(fragment in name for fragment in SPECIAL_FRAGMENTS):
            continue
        if register.width in (32, 64):
            registers.append(register)
    return registers


def register_value(kind, original, width):
    mask = (1 << width) - 1
    return {'zero': 0, 'one': 1, 'ones': mask, 'plus_one': (original + 1) & mask,
            'pattern': 0x5a5a5a5a5a5a5a5a & mask}[kind]


def region_of(dbg, address):
    for region in dbg.memory_map:
        if region.start <= address < region.start + region.size:
            return region
    return None


def write_and_restore(session, place, size, seed):
    """Writes a pattern to the stack or the code, checks that it reads back, and puts the original bytes back."""
    dbg = session.dbg
    address = dbg.stack_pointer if place == 'stack' else dbg.ip
    region = region_of(dbg, address)
    if region is not None:
        size = min(size, region.start + region.size - address)
    if size <= 0 or address == 0:
        return
    original = dbg.read_memory(address, size)
    if len(original) != size:
        return
    pattern = bytes((seed + offset) % 256 for offset in range(size))
    if not dbg.write_memory(address, pattern):
        if place == 'stack':
            raise AssertionError(f'{session}: writing {size} bytes at {address:#x} failed')
        # Code may be read-only to an adapter
        return
    try:
        if dbg.read_memory(address, size) != pattern:
            raise AssertionError(f'{session}: memory at {address:#x} differs from what was written')
    finally:
        dbg.write_memory(address, original)
    if dbg.read_memory(address, size) != original:
        raise AssertionError(f'{session}: memory at {address:#x} was not restored')


def write_outside_the_program(session, address, size):
    """Writes where the program has no memory. The adapter may refuse, but a write touches only the bytes it names,
    so the stack must be as it was whether or not the write succeeded."""
    dbg = session.dbg
    stack = dbg.stack_pointer
    stack_before = dbg.read_memory(stack, 16)
    dbg.write_memory(address, b'\xcc' * size)
    if dbg.read_memory(stack, 16) != stack_before:
        raise AssertionError(f'{session}: the stack changed after a write at {address:#x}')


class DataOperations(OperationModule):
    @session_operation(is_active, paused=True, weight=2, index=INDEX, kind=one_of(VALUE_KINDS))
    def write_register(self, session, index, kind):
        registers = general_registers(session.dbg)
        if not registers:
            return
        register = registers[index % len(registers)]
        original = session.dbg.get_reg_value(register.name)
        value = register_value(kind, original, register.width)
        session.dbg.set_reg_value(register.name, value)
        try:
            if session.dbg.get_reg_value(register.name) != value:
                read_back = session.dbg.get_reg_value(register.name)
                raise AssertionError(f'{session}: {register.name} reads {read_back:#x} after writing {value:#x}')
        finally:
            session.dbg.set_reg_value(register.name, original)
        if session.dbg.get_reg_value(register.name) != original:
            raise AssertionError(f'{session}: {register.name} was not restored')

    @session_operation(is_active, paused=True, weight=2, place=one_of(['stack', 'code']),
                       size=one_of(WRITE_SIZES), seed=integers(0, 255))
    def write_memory(self, session, place, size, seed):
        write_and_restore(session, place, size, seed)

    @session_operation(is_active, paused=True, weight=2, access=one_of(HOSTILE_ACCESSES), write=booleans())
    def touch_hostile_memory(self, session, access, write):
        dbg = session.dbg
        stack = dbg.stack_pointer
        region = region_of(dbg, stack)
        end = region.start + region.size if region is not None else stack + 4096
        address, size = {'null': (0, 8), 'high': (0xffffffffffff0000, 16), 'zero_size': (stack, 0),
                         'huge': (stack, HUGE_READ), 'cross_end': (end - 8, 32), 'wrap': (2 ** 64 - 8, 32)}[access]
        if write and access in UNUSED_ADDRESSES:
            write_outside_the_program(session, address, min(size, 64))
        elif write:
            return
        else:
            data = dbg.read_memory(address, size)
            if len(data) > size:
                raise AssertionError(f'{session}: read {len(data)} bytes when asked for {size}')

    @session_operation(is_active, paused=True)
    def list_modules_and_regions(self, session):
        for module in session.dbg.modules:
            if not module.name:
                raise AssertionError(f'{session}: a module has no name')
        for region in session.dbg.memory_map:
            if region.size <= 0:
                raise AssertionError(f'{session}: the region at {region.start:#x} has no size')

    @session_operation(is_active, paused=True)
    def iterate_registers(self, session):
        if next(iter(session.dbg.regs), None) is None:
            raise AssertionError(f'{session}: iterating the registers yields None')
