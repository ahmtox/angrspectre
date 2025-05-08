import sys
import os

# Setup paths to use local angr
from angrspectre.config import setup_paths
setup_paths()

# Import angr directly (this will use the local version because of sys.path modification)
import angr
import claripy

from angrspectre.utils.utils import describeAst

import logging
l = logging.getLogger(name=__name__)

def armBoundsChecks(proj,state):
    state.register_plugin('oob', OOBState(proj))
    assert len(state.oob.inbounds_intervals) > 0
    state.oob.arm(state)
    assert state.oob.armed()

class OOBState(angr.SimStatePlugin):
    """
    State tracking for crudely marking what is determined 'in-bounds'.
    If you 'arm' it, it reports any potential memory read/write to any area not marked 'in-bounds'.

    This 'in-bounds' determination is not used by the SpectreOOB checker (which
    relies on uninitialized memory for the initial 'secret' determination, then a
    form of taint tracking), but it is used by the OOB concretization strategy below
    (which both OOB and SpectreOOB checking rely on). However, the SpectreOOB checker doesn't
    need/want the OOB state to be 'armed'.
    """

    def __init__(self, proj=None, inbounds_intervals=None, armed=False):
        """
        Either 'proj' or 'inbounds_intervals' must not be None. Initial inbounds intervals
        will be taken from 'proj', or else from the explicit 'inbounds_intervals' if 'proj' is None.
        """
        super().__init__()
        if proj is None:
            self.inbounds_intervals = inbounds_intervals
        else:
            self.inbounds_intervals = [(obj.min_addr, obj.max_addr) for obj in proj.loader.all_objects]
              # this is an overapproximation of what is in-bounds: everything that is mapped is in-bounds.
              # the analysis then tells us if we can leak the value of things that are "not mapped".
              # of course, we separately need to account for when more memory is allocated, for instance
              # malloc() or when the stack is expanded (??)
        self._armed = armed
        self.violation = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return OOBState(inbounds_intervals=self.inbounds_intervals, armed=self._armed)

    def arm(self, state):
        """
        Setup hooks and breakpoints to perform bounds tracking.
        Also set up concretization to ensure addresses are always made to be OOB when possible.
        """
        state.inspect.b('mem_read',  when=angr.BP_AFTER, condition=_read_can_be_oob, action=detected_oob_read)
        state.inspect.b('mem_write', when=angr.BP_AFTER, condition=_write_can_be_oob, action=detected_oob_write)

        state.memory.read_strategies.insert(0, OOBStrategy())
        state.memory.write_strategies.insert(0, OOBStrategy())

        state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)

        state.inspect.b('address_concretization', when=angr.BP_AFTER, condition=concretization_succeeded, action=log_concretization)

        self._armed = True

    def armed(self):
        """
        Has arm() been called?
        """
        return self._armed

# Call during a breakpoint callback on 'mem_read'
def _read_can_be_oob(state):
    addr = state.inspect.mem_read_address
    length = state.inspect.mem_read_length
    return can_be_oob(state, addr, length)

# Call during a breakpoint callback on 'mem_write'
def _write_can_be_oob(state):
    addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    return can_be_oob(state, addr, length)

def can_be_oob(state, addr, length):
    l.debug("checking if {} can be oob".format(addr))
    inbounds_intervals = state.oob.inbounds_intervals + [get_stack_interval(state)]
    oob_constraints = [claripy.Or(addr < mn, addr+length > mx) for (mn,mx) in inbounds_intervals]
    if state.solver.satisfiable(extra_constraints=oob_constraints): return True  # there is a solution to current constraints such that the access is OOB
    return False  # operation must be inbounds

def get_stack_interval(state):
    sp = state.regs.rsp
    end_of_stack = 0x7fffffffffffffff  # this is an assumption, but I think a good one for ELF programs
    return (sp, end_of_stack)

# Call during a breakpoint callback on 'address_concretization'
def concretization_succeeded(state):
    return state.inspect.address_concretization_result is not None

# Call during a breakpoint callback on 'address_concretization'
def log_concretization(state):
    raw = describeAst(state.inspect.address_concretization_expr)
    concretized = "[{}]".format(', '.join(describeAst(x) for x in state.inspect.address_concretization_result))
    l.debug("instr {}: concretized {} to {}".format(hex(state.addr), raw, concretized))

def detected_oob_read(state):
    print("\n!!!!!!!! OUT-OF-BOUNDS READ !!!!!!!!\n  Address {}\n  Value {}\n  x={}\n  constraints were {}\n".format(
        state.inspect.mem_read_address, state.inspect.mem_read_expr, state.globals['arg'], state.solver.constraints))
    state.oob.violation = (state.inspect.mem_read_address, state.inspect.mem_read_expr)

def detected_oob_write(state):
    print("\n!!!!!!!! OUT-OF-BOUNDS WRITE !!!!!!!!\n  Address {}\n  Value {}\n  x={}\n  constraints were {}\n".format(
        state.inspect.mem_write_address, state.inspect.mem_write_expr, state.globals['arg'], state.solver.constraints))
    state.oob.violation = (state.inspect.mem_write_address, state.inspect.mem_write_expr)

class OOBStrategy(angr.concretization_strategies.SimConcretizationStrategy):
    """
    Concretization strategy which attempts to resolve every address to
    somewhere *outside* of bounds (as determined by the OOBState state
    plugin). See notes on superclass (and other subclasses) for more info on
    what's happening here.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _concretize(self, memory, addr):
        """
        Attempts to resolve the address to a value *outside* all of the in-bounds
        intervals if possible.
        Else, defers to fallback strategies.
        """
        try:
            constraints = [memory.state.solver.Or(addr < mn, addr >= mx) for (mn, mx) in memory.state.oob.inbounds_intervals]
            return [ self._any(memory, addr, extra_constraints=constraints) ]
        except angr.errors.SimUnsatError:
            # no solution
            return None

class OOBViolationFilter(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique (which you can use on your SimulationManager if you want)
    which puts all states with OOB violations in a special stash 'oob_violation'
    """
    def __init__(self):
       super().__init__()

    def filter(self, simgr, state, **kwargs):
        if state.oob.violation: return 'oob_violation'
        return simgr.filter(state, **kwargs)
