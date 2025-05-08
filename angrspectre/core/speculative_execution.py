"""
Implements speculative execution functionality for analyzing Spectre vulnerabilities.
Extends angr's execution engine to model speculative behavior and track mispredictions.
"""
import os
import sys
import collections
import logging

# Setup paths to use local angr
from angrspectre.config import setup_paths
setup_paths()

# Standard imports
import angr
import pyvex
import claripy
from angr.errors import SimReliftException, UnsupportedIRStmtError, SimStatementError, SimUninitializedAccessError
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE
from angr.state_plugins.sim_action_object import SimActionObject
from angr.state_plugins.sim_action import SimActionData
from angr.engines import vex

l = logging.getLogger(name=__name__)

from angrspectre.utils.utils import isDefinitelyEqual_Solver, isDefinitelyNotEqual_Solver, describeAst

def enable_speculative_execution(proj, state, window_size=250, misforwarding=False):
    """
    Configures an angr project and state for speculative execution analysis.
    
    Args:
        proj: The angr project
        state: The initial state 
        window_size: Speculative execution window size in instructions
        misforwarding: Whether to model store-to-load forwarding mispredictions
    """
    proj.engines.register_plugin('specvex', SpeculativeExecutionEngine())
    proj.engines.order = ['specvex' if x=='vex' else x for x in proj.engines.order]
    if proj.engines.has_plugin('vex'):
        proj.engines.release_plugin('vex')

    state.register_plugin('spec', SpeculativeState(window_size))
    state.spec.initialize(state, misforwarding=misforwarding)
    assert state.spec.ins_executed == 0

class SpeculativeExecutionEngine(angr.SimEngineVEX):
    """
    Execution engine that models speculative execution with mispredictions.
    Extends SimEngineVEX to add branch misprediction and store-to-load forwarding.
    """

    def lift(self, **kwargs):
        """
        Lifts instructions with special handling for loads.
        Ensures instructions containing loads are marked as block boundaries.
        """
        firsttry = super().lift(**kwargs)
        # Find all load instructions
        def is_load(stmt):
            return (type(stmt) == pyvex.IRStmt.WrTmp and 
                   type(stmt.data) == pyvex.IRExpr.Load) or type(stmt) == pyvex.IRStmt.LoadG
            
        # Get addresses of all instructions with loads
        stops = [find_next_instruction(firsttry, stmt) for stmt in firsttry.statements if is_load(stmt)]
        stops = list(set(addr for (addr, _) in stops if addr is not None))
        
        if stops:
            l.debug(f"Adding load-based stop points: {[hex(stop) for stop in stops]}")
            extra_stop_points = kwargs.pop('extra_stop_points', [])
            if extra_stop_points is None:
                extra_stop_points = []
            extra_stop_points.extend(stops)
            return super().lift(extra_stop_points=extra_stop_points, **kwargs)
        else:
            return firsttry

    def _handle_statement(self, state, successors, stmt):
        """
        Handles VEX statements with speculative execution modeling.
        Forks execution paths on branches to represent both predicted and mispredicted paths.
        """
        # Handle instruction markers
        if type(stmt) == pyvex.IRStmt.IMark:
            ins_addr = stmt.addr + stmt.delta
            state.scratch.ins_addr = ins_addr

            # Check for self-modifying code
            for subaddr in range(stmt.len):
                if subaddr + stmt.addr in state.scratch.dirty_addrs:
                    raise SimReliftException(state)
            state._inspect('instruction', BP_AFTER)

            state.scratch.num_insns += 1
            state._inspect('instruction', BP_BEFORE, instruction=ins_addr)

            # Abort if in mispredicted path
            if state.spec.mispredicted:
                return False

        # Handle loads with possible forwarding misprediction
        if state.spec.hook_loads and type(stmt) == pyvex.IRStmt.WrTmp and type(stmt.data) == pyvex.IRExpr.Load:
            self._handle_load_with_forwarding(state, successors, stmt)
            return True

        if state.spec.hook_loads and type(stmt) == pyvex.IRStmt.LoadG:
            self._handle_loadg_with_forwarding(state, successors, stmt)
            return True

        # Handle all other standard statements
        try:
            stmt_handler = self.stmt_handlers[stmt.tag_int]
        except IndexError:
            l.error(f"Unsupported statement type {type(stmt)}")
            if angr.options.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
                raise UnsupportedIRStmtError(f"Unsupported statement type {type(stmt)}")
            state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')
            return None
        else:
            exit_data = stmt_handler(self, state, stmt)

        # Handle branch/exit points
        if exit_data is not None:
            target, guard, jumpkind = exit_data
            
            l.debug(f"Time {state.spec.ins_executed}: forking for conditional branch to {target} with guard {guard}")

            # In speculative execution, we explore both branch outcomes 
            branch_cond = guard
            not_branch_cond = claripy.Not(branch_cond)

            exit_state = None
            cont_state = None

            # Check if we have a predetermined path to follow
            if hasattr(state.spectre, 'takepath') and state.spectre.takepath:
                npath = state.spectre.takepath.popleft()
                if npath == '1':
                    exit_state = state
                elif npath == '0':
                    cont_state = state
            else:
                # Fork state for both branch outcomes
                exit_state = state.copy()
                cont_state = state

            # Handle taken branch path
            if exit_state is not None:
                exit_state.spec.path.append('1')
                if not state.solver.is_true(branch_cond):
                    exit_state.spec.conditionals.append(branch_cond)
                successors.add_successor(exit_state, target, guard, jumpkind, add_guard=False,
                                        exit_stmt_idx=state.scratch.stmt_idx, exit_ins_addr=state.scratch.ins_addr)
                                        
            # Handle not-taken branch path
            if cont_state is not None:
                cont_state.spec.path.append('0')
                if not state.solver.is_true(not_branch_cond):
                    cont_state.spec.conditionals.append(not_branch_cond)
                return True
            else:
                return False

        return True

    def _handle_load_with_forwarding(self, state, successors, stmt):
        """
        Handles load operations with possible store forwarding misprediction.
        Can fork execution when multiple forwarding options exist.
        """
        load = stmt.data
        with state.history.subscribe_actions() as data_deps:
            state._inspect('expr', BP_BEFORE, expr=load)
            load_size_bits = pyvex.const.get_type_size(load.type)
            load_size_bytes = load_size_bits // state.arch.byte_width
            
            with state.history.subscribe_actions() as addr_actions:
                addr = self.handle_expression(state, load.addr)
                
            if angr.options.UNINITIALIZED_ACCESS_AWARENESS in state.options:
                if getattr(addr._model_vsa, 'uninitialized', False):
                    raise SimUninitializedAccessError('addr', addr)
                    
            if angr.options.DO_LOADS not in state.options:
                results = [(state, state.solver.Unconstrained(f"load_expr_{state.scratch.ins_addr:#x}_{state.scratch.stmt_idx}", load_size_bits))]
            else:
                results = execute_load_with_forwarding(state, addr, load_size_bytes, load_endness=load.endness)

            # Process all potential load results
            for (l_state, l_value) in results:
                if load.type.startswith('Ity_F'):
                    l_value = l_value.raw_to_fp()
                    
                if angr.options.TRACK_MEMORY_ACTIONS in l_state.options:
                    addr_ao = SimActionObject(addr, deps=addr_actions, state=l_state)
                    r = SimActionData(l_state, l_state.memory.id, SimActionData.READ, addr=addr_ao, size=load_size_bits, data=l_value)
                    l_state.history.add_action(r)
                    
                if angr.options.SIMPLIFY_EXPRS in l_state.options:
                    l_value = state.solver.simplify(l_value)
                    
                if l_state.solver.symbolic(l_value) and angr.options.CONCRETIZE in l_state.options:
                    concrete_value = l_state.solver.BVV(l_state.solver.eval(l_value), len(l_value))
                    l_state.add_constraints(l_value == concrete_value)
                    l_value = concrete_value
                    
                l_state._inspect('expr', BP_AFTER, expr=load, expr_result=l_value)
                l_state.scratch.store_tmp(stmt.tmp, l_value, deps=data_deps)

                # For forked states, we need to finish executing the current instruction
                if l_state is not state:
                    (next_instr_addr, next_instr_idx) = find_next_instruction(state.scratch.irsb, stmt)
                    self._handle_irsb(l_state, successors, l_state.scratch.irsb, 
                                     state.scratch.stmt_idx+1, 
                                     next_instr_idx-1 if next_instr_idx is not None else None, None)

                    # Add the forked state as a successor
                    l.debug(f"Time {state.spec.ins_executed}: forking for forwarding on load from {addr}")
                    target = next_instr_addr if next_instr_addr is not None else self.handle_expression(l_state, l_state.scratch.irsb.next) 
                    jumpkind = 'Ijk_Boring'
                    guard = claripy.BVV(1, 1)  # Always True
                    successors.add_successor(l_state, target, guard, jumpkind, add_guard=False,
                                           exit_stmt_idx=None, exit_ins_addr=None)

    def _handle_loadg_with_forwarding(self, state, successors, stmt):
        """
        Handles conditional loads (LoadG) with possible forwarding misprediction.
        Similar to regular loads but with guarded semantics.
        """
        with state.history.subscribe_actions() as addr_deps:
            addr = self.handle_expression(state, stmt.addr)
        with state.history.subscribe_actions() as alt_deps:
            alt = self.handle_expression(state, stmt.alt)
        with state.history.subscribe_actions() as guard_deps:
            guard = self.handle_expression(state, stmt.guard)
            
        if guard is not None and state.solver.satisfiable(extra_constraints=[claripy.Not(guard)]):
            raise ValueError("Not implemented: conditional load with condition that could be false")

        read_type, converted_type = stmt.cvt_types
        read_size_bits = pyvex.const.get_type_size(read_type)
        converted_size_bits = pyvex.const.get_type_size(converted_type)
        read_size = read_size_bits // state.arch.byte_width

        results = execute_load_with_forwarding(state, addr, read_size, load_endness=stmt.end)

        for (l_state, l_value) in results:
            # Handle type conversion
            if read_size_bits == converted_size_bits:
                converted_expr = l_value
            elif "S" in stmt.cvt:
                converted_expr = l_value.sign_extend(converted_size_bits - read_size_bits)
            elif "U" in stmt.cvt:
                converted_expr = l_value.zero_extend()
            else:
                raise SimStatementError(f"Unrecognized IRLoadGOp {stmt.cvt}!")
                
            l_value = l_state.solver.If(guard != 0, converted_expr, alt)
            l_state.scratch.store_tmp(stmt.dst, l_value, deps=addr_deps + alt_deps + guard_deps)
            
            if angr.options.TRACK_MEMORY_ACTIONS in l_state.options:
                data_ao = SimActionObject(converted_expr)
                alt_ao = SimActionObject(alt, deps=alt_deps, state=l_state)
                addr_ao = SimActionObject(addr, deps=addr_deps, state=l_state)
                guard_ao = SimActionObject(guard, deps=guard_deps, state=l_state)
                size_ao = SimActionObject(converted_size_bits)
                r = SimActionData(l_state, l_state.memory.id, SimActionData.READ, addr=addr_ao, 
                                 data=data_ao, condition=guard_ao, size=size_ao, fallback=alt_ao)
                l_state.history.add_action(r)

            # Handle forked states
            if l_state is not state:
                (next_instr_addr, next_instr_idx) = find_next_instruction(state.scratch.irsb, stmt)
                self._handle_irsb(l_state, successors, l_state.scratch.irsb, 
                                 state.scratch.stmt_idx+1, 
                                 next_instr_idx-1 if next_instr_idx is not None else None, None)

                l.debug(f"Time {state.spec.ins_executed}: forking for forwarding on conditional load from {addr}")
                target = next_instr_addr if next_instr_addr is not None else self.handle_expression(l_state, l_state.scratch.irsb.next)
                jumpkind = 'Ijk_Boring'
                guard = claripy.BVV(1, 1)  # Always True
                successors.add_successor(l_state, target, guard, jumpkind, add_guard=False,
                                       exit_stmt_idx=None, exit_ins_addr=None)

def find_next_instruction(irsb, stmt):
    """
    Finds the address and statement index of the next instruction after stmt.
    
    Args:
        irsb: VEX IR basic block
        stmt: Current statement
    
    Returns:
        (addr, stmt_idx) tuple for next instruction, or (None, None) if at end
    """
    found_current = False
    
    for (idx, s) in enumerate(irsb.statements):
        if found_current and type(s) == pyvex.stmt.IMark:
            return (s.addr, idx)
        if s is stmt:
            found_current = True
            
    if found_current:
        # Statement was found but no IMark follows - this was the last instruction
        return (None, None)
    else:
        raise ValueError(f"Statement {stmt} not found in IRSB {irsb}")

class SpeculativeState(angr.SimStatePlugin):
    """
    Tracks and manages speculative execution state.
    
    Attributes:
        _window_size: Max instructions in speculation window
        ins_executed: Number of instructions executed
        conditionals: Queue of branch conditions that haven't retired
        stores: Queue of stores that haven't retired
        hook_loads: Whether load hooks are active
        mispredicted: Whether state is on a mispredicted path
        path: Execution path history through branches ('0'=not-taken, '1'=taken)
    """

    def __init__(self, window_size, ins=0, conditionals=None, stores=None, 
                 hook_loads=False, mispredicted=False, path=None):
        super().__init__()
        self._window_size = window_size
        self.ins_executed = ins
        self.conditionals = conditionals if conditionals is not None else TimedQueue(ins)
        self.stores = stores if stores is not None else TimedQueue(ins)
        self.hook_loads = hook_loads
        self.mispredicted = mispredicted
        self.path = path if path is not None else []

    def initialize(self, state, misforwarding=False):
        """
        Sets up hooks and plugins for speculative execution.
        
        Args:
            state: The angr state to initialize
            misforwarding: Whether to model store forwarding mispredictions
        """
        state.inspect.b('instruction', when=BP_BEFORE, action=update_speculative_state)
        state.inspect.b('statement', when=BP_BEFORE, action=handle_memory_barriers)
        
        if misforwarding:
            state.register_plugin('store_hook', StoreForwardingController())
            self.hook_loads = True

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return SpeculativeState(
            window_size=self._window_size,
            ins=self.ins_executed,
            conditionals=self.conditionals.copy(),
            stores=self.stores.copy(),
            hook_loads=self.hook_loads,
            mispredicted=self.mispredicted,
            path=self.path.copy()
        )

    def tick(self):
        """Updates instruction count and timing for speculative tracking."""
        self.ins_executed += 1
        self.conditionals.tick()
        self.stores.tick()

    def is_poisoned(self):
        """Checks if state has misforwarded store-to-load data."""
        def is_entry_poisoned(entry):
            (_, _, _, _, _, poisoned) = entry
            return poisoned
        return any(is_entry_poisoned(e) for e in self.stores.get_all_oldest_first())

class TimedQueue:
    """
    Queue that tracks when entries were added, based on instruction count.
    Used to model how long entries remain in flight during speculation.
    """
    def __init__(self, ins_executed=0, q=None):
        self.ins_executed = ins_executed
        self.q = collections.deque() if q is None else q

    def copy(self):
        return TimedQueue(ins_executed=self.ins_executed, q=self.q.copy())

    def tick(self):
        """Update instruction counter."""
        self.ins_executed += 1

    def append(self, thing):
        """Add an item with current timestamp."""
        self.q.append((thing, self.ins_executed))

    def age_of_oldest(self):
        """Get age (in instructions) of oldest entry."""
        if self.q:
            (_, when_added) = self.q[0]
            return self.ins_executed - when_added
        else:
            return None

    def pop_oldest(self):
        """Remove and return the oldest entry."""
        (thing, _) = self.q.popleft()
        return thing

    def pop_all(self):
        """Generator that pops and yields all entries."""
        while self.q:
            (thing, _) = self.q.popleft()
            yield thing

    def get_at(self, i):
        """Get the i-th entry (0 = oldest)."""
        return self.q[i]

    def update_at(self, i, transform_func):
        """Apply a function to update the i-th entry."""
        (thing, time) = self.q[i]
        self.q[i] = (transform_func(thing), time)

    def get_all_oldest_first(self):
        """Yield all entries from oldest to newest without removing them."""
        for (thing, _) in self.q:
            yield thing

def update_speculative_state(state):
    """
    Updates speculative execution state for each instruction.
    Retires old branch conditions and stores that exit the speculation window.
    """
    # Update instruction counter 
    state.spec.tick()

    # Check if oldest branch condition is ready to retire
    age = state.spec.conditionals.age_of_oldest()
    while age and age > state.spec._window_size:
        cond = state.spec.conditionals.pop_oldest()
        l.debug(f"Time {state.spec.ins_executed}: committing deferred branch condition (age {age}): {cond}")
        state.add_constraints(cond)
        
        # If constraints now unsatisfiable, this was a misprediction
        if angr.sim_options.LAZY_SOLVES not in state.options and not state.solver.satisfiable():
            l.debug(f"Time {state.spec.ins_executed}: killing mispredicted path: constraints not satisfiable")
            state.spec.mispredicted = True
            return
            
        age = state.spec.conditionals.age_of_oldest()

    # Check if oldest store is ready to retire
    age = state.spec.stores.age_of_oldest()
    while age and age > state.spec._window_size:
        commit_store(state, state.spec.stores.pop_oldest())
        if state.spec.mispredicted:
            return
        age = state.spec.stores.age_of_oldest()

def handle_memory_barriers(state):
    """
    Handles memory fence operations by retiring all speculative operations.
    """
    stmt = state.scratch.irsb.statements[state.inspect.statement]
    if type(stmt) == pyvex.stmt.MBE and stmt.event == "Imbe_Fence":
        l.debug(f"Time {state.spec.ins_executed}: fence encountered, retiring all in-flight operations")
        
        # Retire all branch conditions
        state.add_constraints(*list(state.spec.conditionals.pop_all()))
        
        # Check satisfiability after adding all constraints
        if angr.sim_options.LAZY_SOLVES not in state.options and not state.solver.satisfiable():
            l.debug(f"Time {state.spec.ins_executed}: killing mispredicted path after fence")
            state.spec.mispredicted = True
            return
            
        # Retire all stores
        for store in state.spec.stores.pop_all():
            commit_store(state, store)
            if state.spec.mispredicted:
                return

def commit_store(state, store):
    """
    Performs a store operation that has reached retirement.
    
    Args:
        state: Current program state
        store: Store operation tuple containing (addr, value, condition, endness, action, poisoned)
    """
    (addr, value, cond, endness, action, poisoned) = store
    if poisoned:
        l.debug(f"Time {state.spec.ins_executed}: killing path due to incorrect forwarding")
        state.spec.mispredicted = True
    else:
        state.memory.store(addr, value, condition=cond, endness=endness, action=action)

class StoreForwardingController(angr.SimStatePlugin):
    """
    Controls store operations to enable modeling of forwarding mispredictions.
    Instead of immediately executing stores, they are queued for later retirement.
    """
    def do_store(self, state, addr, expr, condition, endness, action):
        """
        Captures store operations for speculative handling.
        
        Args:
            state: Current program state
            addr: Store address
            expr: Value being stored
            condition: Optional condition for store
            endness: Memory endianness
            action: SimAction for tracking
        """
        l.debug(f"Time {state.spec.ins_executed}: deferring store of {describeAst(expr)} to {describeAst(addr)}")
        state.spec.stores.append((addr, expr, condition, endness, action, False))
        
        # Trigger inspection points for memory writes
        # The store will execute again when it retires, but inspection is useful now
        state._inspect('mem_write', BP_BEFORE,
            mem_write_address=addr,
            mem_write_length=len(expr) // 8,
            mem_write_expr=expr,
            mem_write_condition=condition
        )
        state._inspect('mem_write', BP_AFTER)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return StoreForwardingController()

def execute_load_with_forwarding(state, load_addr, load_size_bytes, load_endness):
    """
    Executes a load operation with possible store forwarding.
    Handles multiple outcomes when forwarding is ambiguous.
    
    Args:
        state: Current program state
        load_addr: Address to load from
        load_size_bytes: Size of the load
        load_endness: Memory endianness
        
    Returns:
        List of (state, value) pairs for different possible load outcomes
    """
    l.debug(f"Time {state.spec.ins_executed}: handling load from {load_addr}")
    
    result_pairs = []
    
    # Always consider the case of loading directly from memory (no forwarding)
    memory_value = state.memory.load(load_addr, load_size_bytes, endness=load_endness)
    result_pairs.append((state, memory_value))
    
    # Track our current idea of the correct state
    current_state = state
    current_value = memory_value
    
    # Keep track of states where load doesn't overlap with specific stores
    non_overlapping_states = []
    
    # Check all in-flight stores for possible forwarding
    stores = list(enumerate(state.spec.stores.get_all_oldest_first()))
    
    for (store_idx, (s_addr, s_value, s_cond, s_endness, _, _)) in stores:
        l.debug(f"  - checking for overlap with store of {describeAst(s_value)} to {describeAst(s_addr)}")
        s_size_bytes = len(s_value) // 8
        
        # Check if load could overlap with this store
        addresses_overlap = check_overlap(load_addr, load_size_bytes, s_addr, s_size_bytes)
        
        if not current_state.solver.satisfiable(extra_constraints=[addresses_overlap]):
            # Load definitely doesn't overlap this store
            continue

        # Check store conditions
        if s_cond is not None and current_state.solver.satisfiable(extra_constraints=[claripy.Not(s_cond)]):
            raise ValueError("Not implemented: conditional store where condition could be False")
            
        # Check for symbolic sizes
        if current_state.solver.symbolic(load_size_bytes) or current_state.solver.symbolic(s_size_bytes):
            # Currently only handling concrete sizes
            continue

        # If load is larger than store, only consider full overlaps
        if load_size_bytes > s_size_bytes:
            continue

        # Check for partial overlap possibility
        if current_state.solver.satisfiable(extra_constraints=[claripy.Not(addresses_overlap)]):
            # Load might or might not overlap with this store
            # Create a state for the non-overlapping case
            non_overlap_state = current_state.copy()
            non_overlapping_states.append(non_overlap_state)
            result_pairs.append((non_overlap_state, current_value))
            
            # Constrain current state to assume overlap
            current_state.add_constraints(addresses_overlap)

        # Add constraints to non-overlapping states
        for s in non_overlapping_states:
            s.add_constraints(claripy.Not(addresses_overlap))

        # Handle the case where load and store overlap
        
        # Check for misaligned overlaps
        if isDefinitelyNotEqual_Solver(current_state, load_addr, s_addr):
            continue
        elif not isDefinitelyEqual_Solver(current_state, load_addr, s_addr):
            # Only consider aligned loads/stores
            current_state.add_constraints(load_addr == s_addr)

        # Create a new state that forwards from this store
        forwarding_state = current_state.copy()
        
        # Mark current state as poisoned - it will be killed when store retires
        current_state.spec.stores.update_at(store_idx, mark_poisoned)
        
        # Update current state to the forwarded one
        current_state = forwarding_state
        
        # Add the forwarded state to results
        forwarded_value = extract_value_from_store(
            load_size_bytes, s_value, s_size_bytes, load_endness, s_endness)
        result_pairs.append((forwarding_state, forwarded_value))
        
    if len(result_pairs) == 1:
        l.debug(f"  - final result: single value {result_pairs[0][1]}")
    else:
        l.debug(f"  - final results: {len(result_pairs)} possible values")
        
    return result_pairs

def check_overlap(addr_a, size_a, addr_b, size_b):
    """
    Creates a symbolic constraint for whether two memory regions overlap.
    
    Args:
        addr_a, size_a: First memory region
        addr_b, size_b: Second memory region
        
    Returns:
        Symbolic constraint that is true when regions overlap
    """
    a_end = addr_a + size_a
    b_end = addr_b + size_b
    return claripy.And(a_end > addr_b, addr_a < b_end)

def mark_poisoned(store):
    """
    Marks a store operation as poisoned, indicating that any state using
    this store's value is on a mispredicted path.
    """
    (addr, value, cond, endness, action, _) = store
    return (addr, value, cond, endness, action, True)

def extract_value_from_store(load_size, stored_value, store_size, load_endness, store_endness):
    """
    Extracts the correct bytes when loading from a stored value.
    Handles cases where load size differs from store size.
    
    Args:
        load_size: Size of load in bytes
        stored_value: Value from store operation
        store_size: Size of store in bytes
        load_endness: Endianness of load
        store_endness: Endianness of store
        
    Returns:
        Value that should be loaded
    """
    if load_endness != store_endness:
        raise ValueError("Not implemented: load and store with different endianness")
        
    if len(stored_value) != store_size * 8:
        raise ValueError(f"Expected stored value of {store_size} bytes, got {len(stored_value)} bits")
        
    if load_size == store_size:
        return stored_value

    # Extract appropriate bytes from the stored value
    return stored_value.get_bytes(0, load_size)