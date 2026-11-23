"""Operations on software and hardware breakpoints."""

from .draws import booleans, one_of

try:
    from debugger import DebugBreakpointType
except ImportError:
    from binaryninja.debugger import DebugBreakpointType

from .common import INDEX
from .operations import OperationModule, is_launched, is_live, is_unlaunched, session_operation

ADDRESS_KINDS = ['entry', 'function', 'instruction', 'unmapped', 'null']
CONDITIONS = ['', '1', '0', '1 == 1', 'garbage ((']
HARDWARE_TYPES = [DebugBreakpointType.BNHardwareExecuteBreakpoint, DebugBreakpointType.BNHardwareReadBreakpoint,
                  DebugBreakpointType.BNHardwareWriteBreakpoint, DebugBreakpointType.BNHardwareAccessBreakpoint]
UNMAPPED_ADDRESS = 0xdead0000


def resolve_address(session, kind, index):
    """An address of the given kind in the program the session debugs. `index` chooses among the candidates."""
    if kind == 'null':
        return 0
    if kind == 'unmapped':
        return UNMAPPED_ADDRESS + 16 * index
    data = session.dbg.data
    if data is None:
        data = session.view
    if kind == 'entry':
        return data.entry_point
    functions = sorted(data.functions, key=lambda function: function.start)
    if not functions:
        return data.entry_point
    function = functions[index % len(functions)]
    if kind == 'function':
        return function.start
    # Only instruction boundaries: a breakpoint inside an instruction would corrupt the program
    instructions = [address for _, address in function.instructions]
    return instructions[index % len(instructions)] if instructions else function.start


class BreakpointOperations(OperationModule):
    @session_operation(is_launched, weight=2, kind=one_of(ADDRESS_KINDS), index=INDEX)
    def add_breakpoint(self, session, kind, index):
        session.breakpoints.add(resolve_address(session, kind, index))

    @session_operation(lambda s: is_live(s) and s.breakpoints.software, index=INDEX)
    def delete_breakpoint(self, session, index):
        session.breakpoints.delete(session.breakpoints.pick(index))

    @session_operation(lambda s: is_live(s) and s.breakpoints.software)
    def clear_breakpoints(self, session):
        session.breakpoints.clear()

    @session_operation(lambda s: is_live(s) and s.breakpoints.software, index=INDEX, enable=booleans())
    def enable_breakpoint(self, session, index, enable):
        session.breakpoints.set_enabled(session.breakpoints.pick(index), enable)

    @session_operation(lambda s: is_live(s) and s.breakpoints.software, index=INDEX,
                       condition=one_of(CONDITIONS))
    def set_breakpoint_condition(self, session, index, condition):
        session.breakpoints.set_condition(session.breakpoints.pick(index), condition)

    @session_operation(is_launched, kind=one_of(['entry', 'function', 'instruction']), index=INDEX,
                       breakpoint_type=one_of(HARDWARE_TYPES), size=one_of([1, 2, 4, 8]))
    def add_hardware_breakpoint(self, session, kind, index, breakpoint_type, size):
        session.breakpoints.add_hardware(resolve_address(session, kind, index), breakpoint_type, size)

    @session_operation(lambda s: is_live(s) and s.breakpoints.hardware, index=INDEX)
    def delete_hardware_breakpoint(self, session, index):
        session.breakpoints.delete_hardware(*session.breakpoints.pick_hardware(index))

    @session_operation(is_unlaunched, kind=one_of(['entry', 'function']), index=INDEX)
    def add_breakpoint_before_launch(self, session, kind, index):
        address = resolve_address(session, kind, index)
        session.dbg.add_breakpoint(address)
        # Not added to the model: whether a breakpoint set before launch is kept is what is being checked, and what
        # an operation may do next must not depend on the answer
        if not session.dbg.has_breakpoint(address):
            raise AssertionError(
                f'{session}: the breakpoint at {address:#x} set before the session was launched is not there')
