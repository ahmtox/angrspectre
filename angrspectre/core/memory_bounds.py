"""
Memory bounds tracking and violation detection for symbolic execution.
"""
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

def setup_bounds_checking(proj, state):
    """Set up state for memory bounds checking"""
    state.register_plugin('bounds_tracker', MemoryBoundsTracker(proj))
    assert len(state.bounds_tracker.valid_regions) > 0
    state.bounds_tracker.enable(state)
    assert state.bounds_tracker.enabled()

class MemoryBoundsTracker(angr.SimStatePlugin):
    """
    Tracks valid memory regions and detects out-of-bounds memory accesses.
    
    This plugin marks memory regions as valid/invalid and reports accesses to 
    invalid memory. It also provides concretization strategies to help find
    out-of-bounds accesses.
    """

    def __init__(self, proj=None, valid_regions=None, enabled=False):
        """
        Initialize with either a project (to auto-detect valid memory regions)
        or explicitly provided regions.
        """
        super().__init__()
        if proj is None:
            self.valid_regions = valid_regions
        else:
            # Use project's memory objects to determine valid regions
            self.valid_regions = [(obj.min_addr, obj.max_addr) for obj in proj.loader.all_objects]
        self._enabled = enabled
        self.violation = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return MemoryBoundsTracker(valid_regions=self.valid_regions, enabled=self._enabled)

    def enable(self, state):
        """
        Enable bounds checking on the state, setting up breakpoints and
        concretization strategies for memory accesses.
        """
        state.inspect.b('mem_read',  when=angr.BP_AFTER, condition=_check_read_bounds, action=handle_invalid_read)
        state.inspect.b('mem_write', when=angr.BP_AFTER, condition=_check_write_bounds, action=handle_invalid_write)

        state.memory.read_strategies.insert(0, BoundaryAccessStrategy())
        state.memory.write_strategies.insert(0, BoundaryAccessStrategy())

        state.options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)

        state.inspect.b('address_concretization', when=angr.BP_AFTER, 
                        condition=check_concretization_success, 
                        action=log_concretization)

        self._enabled = True

    def enabled(self):
        """Check if bounds checking is enabled"""
        return self._enabled

# Utility functions for memory access inspection
def _check_read_bounds(state):
    addr = state.inspect.mem_read_address
    length = state.inspect.mem_read_length
    return can_access_out_of_bounds(state, addr, length)

def _check_write_bounds(state):
    addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    return can_access_out_of_bounds(state, addr, length)

def can_access_out_of_bounds(state, addr, length):
    """Check if a memory access could be out of bounds"""
    l.debug(f"Checking if address {addr} can be out of bounds")
    
    # Consider both valid memory regions and stack
    valid_regions = state.bounds_tracker.valid_regions + [get_stack_boundary(state)]
    
    # An access is out of bounds if it's outside all valid regions
    out_of_bounds_constraints = [claripy.Or(addr < start, addr+length > end) 
                               for (start, end) in valid_regions]
    
    # If we can satisfy these constraints, the access could be out of bounds
    return state.solver.satisfiable(extra_constraints=out_of_bounds_constraints)

def get_stack_boundary(state):
    """Get the valid stack memory region boundary"""
    stack_start = state.regs.rsp
    stack_end = 0x7fffffffffffffff  # Upper bound for stack in typical ELF programs
    return (stack_start, stack_end)

# Concretization-related functions
def check_concretization_success(state):
    """Check if an address was successfully concretized"""
    return state.inspect.address_concretization_result is not None

def log_concretization(state):
    """Log information about concretized addresses"""
    original = describeAst(state.inspect.address_concretization_expr)
    result = "[{}]".format(', '.join(describeAst(x) for x in state.inspect.address_concretization_result))
    l.debug(f"At {hex(state.addr)}: concretized {original} to {result}")

# Violation handlers
def handle_invalid_read(state):
    """Handle detection of an out-of-bounds read"""
    print(f"\n!!!!!!!! OUT-OF-BOUNDS READ !!!!!!!!\n"
          f"  Address {state.inspect.mem_read_address}\n"
          f"  Value {state.inspect.mem_read_expr}\n"
          f"  x={state.globals['arg']}\n"
          f"  constraints were {state.solver.constraints}\n")
    state.bounds_tracker.violation = (state.inspect.mem_read_address, state.inspect.mem_read_expr)

def handle_invalid_write(state):
    """Handle detection of an out-of-bounds write"""
    print(f"\n!!!!!!!! OUT-OF-BOUNDS WRITE !!!!!!!!\n"
          f"  Address {state.inspect.mem_write_address}\n"
          f"  Value {state.inspect.mem_write_expr}\n"
          f"  x={state.globals['arg']}\n"
          f"  constraints were {state.solver.constraints}\n")
    state.bounds_tracker.violation = (state.inspect.mem_write_address, state.inspect.mem_write_expr)

class BoundaryAccessStrategy(angr.concretization_strategies.SimConcretizationStrategy):
    """
    Concretization strategy that tries to find addresses outside valid memory regions.
    
    This helps discover potential out-of-bounds accesses during symbolic execution.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _concretize(self, memory, addr):
        """Try to find a value for addr that is outside valid memory regions"""
        try:
            # Create constraints that force the address outside all valid regions
            constraints = [memory.state.solver.Or(addr < start, addr >= end) 
                          for (start, end) in memory.state.bounds_tracker.valid_regions]
            
            return [self._any(memory, addr, extra_constraints=constraints)]
        except angr.errors.SimUnsatError:
            # No solution possible - address must be in-bounds
            return None

class MemoryViolationFilter(angr.exploration_techniques.ExplorationTechnique):
    """
    Exploration technique that separates states with memory violations.
    
    States with detected memory violations are moved to 'memory_violation' stash.
    """
    def __init__(self):
       super().__init__()

    def filter(self, simgr, state, **kwargs):
        if state.bounds_tracker.violation:
            return 'memory_violation'
        return simgr.filter(state, **kwargs)