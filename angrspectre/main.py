"""
Pitchfork: A Spectre vulnerability detector built on angr

This module provides the core functionality of Pitchfork, including state
construction, test case definitions, and simulation management.
"""
import os
import sys
import logging
import time
import textwrap
from tabulate import tabulate
from collections import defaultdict, OrderedDict

# Setup paths to use local angr
from config import setup_paths
setup_paths()

# Standard imports - these will use the local angr due to sys.path manipulation
import angr
import claripy

# Import your modules with standard imports
from angrspectre.core.speculative_execution import enable_speculative_execution
from angrspectre.core.memory_bounds import setup_bounds_checking, MemoryViolationFilter
from angrspectre.core.vulnerability_detector import setup_oob_detection, setup_secret_detection, VulnerabilityFilter
from angrspectre.core.symbolic_operation_monitor import SymbolicOperationMonitor
from angrspectre.core.memory_model import create_public_value, create_sensitive_value, create_pointer_to, create_generic_pointer, create_public_array, create_sensitive_array, create_array, create_struct

l = logging.getLogger(name=__name__)

try:
    import monkeyhex
except ImportError:
    pass

# Configure logging
def configure_logging(verbose=False):
    """Configure logging levels based on verbosity"""
    logging.getLogger('spectre').setLevel(logging.INFO if verbose else logging.WARNING)
    logging.getLogger('oob').setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger('stubs').setLevel(logging.INFO if verbose else logging.WARNING)
    logging.getLogger(__name__).setLevel(logging.INFO)

#------------------------------------------------------------------------------
# STATE AND PROJECT CONSTRUCTION HELPERS
#------------------------------------------------------------------------------

class TestMetrics:
    def __init__(self):
        self.start_time = None
        self.execution_time = 0
        self.max_active_states = 0
        self.finished_states = 0
        self.violations = 0
        self.max_bbs = 0
        self.max_constraints = 0
        self.paths_explored = 0
        self.violation_addresses = set()
        
    def start(self):
        self.start_time = time.process_time()
        
    def end(self):
        if self.start_time is not None:
            self.execution_time = time.process_time() - self.start_time
            
    def update_from_simgr(self, simgr):
        active_count = len(simgr.active) if 'active' in simgr.stashes else 0
        if active_count > self.max_active_states:
            self.max_active_states = active_count
            
        if 'deadended' in simgr.stashes:
            self.finished_states = len(simgr.deadended)
            
        if 'spectre_violation' in simgr.stashes:
            violations = len(simgr.spectre_violation)
            self.violations = violations
            # Track violation addresses
            for state in simgr.spectre_violation:
                if state.spectre.violation:
                    _, addr, _, _ = state.spectre.violation
                    self.violation_addresses.add(hex(addr))
                    
        if active_count > 0:
            max_bbs = max(len(s.history.bbl_addrs) for s in simgr.active)
            if max_bbs > self.max_bbs:
                self.max_bbs = max_bbs
                
            max_constraints = max(len(s.solver.constraints) for s in simgr.active)
            if max_constraints > self.max_constraints:
                self.max_constraints = max_constraints
                
        # Count each step as exploring a new path
        self.paths_explored += 1

def getAddressOfSymbol(proj, symbolname):
    """Get the address of a named symbol in the project"""
    symb = proj.loader.find_symbol(symbolname)
    if symb is None:
        raise ValueError(f"symbol name {symbolname} not found")
    return symb.rebased_addr

def funcEntryState(proj, funcname, args):
    """
    Get a state ready to enter the given function, with each argument
    as a fully unconstrained 64-bit value.
    
    Args:
        proj: The angr project
        funcname: Name of the function to enter
        args: List of (name, val) pairs where:
            - name: Either None for default naming or custom name for the argument
            - val: An AbstractValue denoting the structure of the argument
    
    Returns:
        Initialized entry state for the function
    """
    funcaddr = getAddressOfSymbol(proj, funcname)
    argnames = list("arg{}".format(i) if name is None else name for (i, (name, _)) in enumerate(args))
    argBVSs = list(claripy.BVS(name, val.bits) for (name, (_, val)) in zip(argnames, args))
    state = proj.factory.call_state(funcaddr, *argBVSs)
    state.globals['args'] = {argname:(argBVS, val) for (argname, (_, val), argBVS) in zip(argnames, args, argBVSs)}
    state.register_plugin('irop_hook', SymbolicOperationMonitor())
    return state

def getArgBVS(state, argname):
    """Get the BVS for a named argument"""
    return state.globals['args'][argname][0]

def addSecretObject(proj, state, symbol, length):
    """
    In the given state, mark the given symbol with the given length (in bytes) as secret.
    """
    secretaddr = getAddressOfSymbol(proj, symbol)
    prevSecrets = state.globals.get('otherSecrets', [])
    state.globals['otherSecrets'] = [(secretaddr, secretaddr+length)] + prevSecrets

#------------------------------------------------------------------------------
# PROJECT LOADERS
#------------------------------------------------------------------------------

def newSpectreV1TestcasesProject():
    """Load the Spectre V1 testcases project"""
    return angr.Project('testcases/other_spectre/spectrev1')

def forwardingTestcasesProject():
    """Load the forwarding testcases project"""
    return angr.Project('testcases/other_spectre/forwarding')

#------------------------------------------------------------------------------
# KOCHER TEST CASES
#------------------------------------------------------------------------------

def kocher(s):
    """
    Get project and state for a Kocher test case
    
    Args:
        s: String like "01" or "12" for the test case number
    
    Returns:
        Tuple of (project, state)
    """
    proj = angr.Project('testcases/kocher/'+s+'.o')
    funcname = "victim_function_v"+s
    
    # Configure state based on test case
    if s == '10':
        state = funcEntryState(proj, funcname, [(None, create_public_value()), (None, create_public_value(bits=8))])
    elif s == '12':
        state = funcEntryState(proj, funcname, [(None, create_public_value()), (None, create_public_value())])
    elif s == '09':
        state = funcEntryState(proj, funcname, [(None, create_public_value()), (None, create_generic_pointer())])
    elif s == '15':
        state = funcEntryState(proj, funcname, [(None, create_generic_pointer())])
    else:
        state = funcEntryState(proj, funcname, [(None, create_public_value())])
    return (proj, state)

def kocher11(s):
    """
    Get project and state for Kocher test case 11 variants
    
    Args:
        s: One of 'gcc', 'ker', or 'sub' for the variant
    
    Returns:
        Tuple of (project, state)
    """
    proj = angr.Project('testcases/kocher/11'+s+'.o')
    state = funcEntryState(proj, "victim_function_v11", [(None, create_public_value())])
    return (proj, state)

#------------------------------------------------------------------------------
# FORWARDING TEST CASES
#------------------------------------------------------------------------------

def create_forwarding_example(example_num, args):
    """Helper to create forwarding examples with consistent setup"""
    proj = forwardingTestcasesProject()
    state = funcEntryState(proj, f"example_{example_num}", args)
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

def forwarding_example_1():
    return create_forwarding_example(1, [
        ("idx", create_public_value(bits=64)),
        ("val", create_public_value(bits=8)),
        ("idx2", create_public_value(bits=64))
    ])

def forwarding_example_2():
    return create_forwarding_example(2, [
        ("idx", create_public_value(bits=64))
    ])

def forwarding_example_3():
    return create_forwarding_example(3, [
        ("idx", create_public_value(bits=64)),
        ("mask", create_public_value(bits=8))
    ])

def forwarding_example_4():
    return create_forwarding_example(4, [])

def forwarding_example_5():
    return create_forwarding_example(5, [
        ("idx", create_public_value(bits=64)),
        ("val", create_public_value(bits=8)),
        ("idx2", create_public_value(bits=64))
    ])

#------------------------------------------------------------------------------
# SPECTRE V1 TEST CASES
#------------------------------------------------------------------------------

def _typicalSpectrev1Case(casename):
    """Helper for creating standard Spectre v1 test cases"""
    proj = newSpectreV1TestcasesProject()
    state = funcEntryState(proj, casename, [ ("idx", create_public_value(bits=64)) ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

# Dictionary of special case handlers
SPECTRE_SPECIAL_CASES = {}  # We'll handle special cases directly

# Generate functions for all Spectre v1 cases
def spectrev1_case_factory(case_num):
    """Create a function to generate project and state for a Spectre v1 case"""
    case_name = f"case_{case_num}"
    
    # Use special case if available, otherwise use typical case
    if case_name in SPECTRE_SPECIAL_CASES:
        proj = newSpectreV1TestcasesProject()
        state = SPECTRE_SPECIAL_CASES[case_name]()
        addSecretObject(proj, state, 'secretarray', 16)
        return lambda: (proj, state)
    else:
        return lambda: _typicalSpectrev1Case(case_name)

# Define functions for each case
spectrev1_case_1 = spectrev1_case_factory("1")
spectrev1_case_2 = spectrev1_case_factory("2")
spectrev1_case_3 = spectrev1_case_factory("3")
spectrev1_case_4 = spectrev1_case_factory("4")
spectrev1_case_5 = spectrev1_case_factory("5")
spectrev1_case_6 = spectrev1_case_factory("6")
spectrev1_case_7 = spectrev1_case_factory("7")
spectrev1_case_8 = spectrev1_case_factory("8")
spectrev1_case_9 = spectrev1_case_factory("9")
def spectrev1_case_10():
    proj = newSpectreV1TestcasesProject()
    state = funcEntryState(proj, "case_10", [
        ("idx", create_public_value(bits=64)),
        ("val", create_public_value(bits=8))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)


spectrev1_case_11gcc = lambda: _typicalSpectrev1Case("case_11gcc")
spectrev1_case_11ker = lambda: _typicalSpectrev1Case("case_11ker")
spectrev1_case_11sub = lambda: _typicalSpectrev1Case("case_11sub")
def spectrev1_case_12():
    proj = newSpectreV1TestcasesProject()
    state = funcEntryState(proj, "case_12", [
        ("idx", create_public_value(bits=64)),
        ("val", create_public_value(bits=8))
    ])
    addSecretObject(proj, state, 'secretarray', 16)
    return (proj, state)

spectrev1_case_13 = lambda: _typicalSpectrev1Case("case_13")
spectrev1_case_14 = lambda: _typicalSpectrev1Case("case_14")

#------------------------------------------------------------------------------
# SIMULATION MANAGEMENT
#------------------------------------------------------------------------------

def getSimgr(proj, state, spec=True, window=None, misforwarding=False):
    """
    Create a simulation manager for the given project and state.
    
    Args:
        proj: The angr project
        state: The initial state
        spec: Whether to enable speculative execution
        window: Size of speculative window (~ROB) in x86 instructions
        misforwarding: Whether to enable misforwarding features
        
    Returns:
        Configured simulation manager
    """
    if spec:
        if window is not None: 
            enable_speculative_execution(proj, state, window, misforwarding=misforwarding)
        else: 
            enable_speculative_execution(proj, state, misforwarding=misforwarding)
            
    simgr = proj.factory.simgr(state, save_unsat=False)
    
    if state.has_plugin('bounds_tracker'):
        simgr.use_technique(MemoryViolationFilter())
    if state.has_plugin('spectre'):
        simgr.use_technique(VulnerabilityFilter())
        
    return simgr

def runSimgr(simgr, **kwargs):
    """Run the simulation manager with timing and state reporting"""
    if not hasattr(simgr, 'metrics'):
        simgr.metrics = TestMetrics()
    
    simgr.metrics.start()
    simgr.run(step_func=describeActiveStates, **kwargs)
    simgr.metrics.end()
    
    print(f"running time: {simgr.metrics.execution_time:.6f}")
    return simgr

def describeActiveStates(simgr):
    """Log information about active states in the simulation manager and update metrics"""
    active_count = len(simgr.active) if 'active' in simgr.stashes else 0
    
    # Update metrics if available
    if hasattr(simgr, 'metrics'):
        simgr.metrics.update_from_simgr(simgr)
    
    # Create log message as before
    if active_count == 0:
        logstring = "no active states"
    elif active_count == 1:
        logstring = f"1 active state, at {hex(simgr.active[0].addr)}"
    elif active_count <= 8:
        logstring = f"{active_count} active states, at {[hex(s.addr) for s in simgr.active]}"
    else:
        unique_addrs = len(set(s.addr for s in simgr.active))
        logstring = f"{active_count} active states, at {unique_addrs} unique addresses"
    
    # Add deadended states info
    if 'deadended' in simgr.stashes and len(simgr.deadended) > 0:
        deadend_count = len(simgr.deadended)
        logstring += f"; {deadend_count} state{'s' if deadend_count > 1 else ''} finished"
            
    # Add violation info
    if 'spectre_violation' in simgr.stashes and len(simgr.spectre_violation) > 0:
        violation_count = len(simgr.spectre_violation)
        logstring += f"; {violation_count} Spectre violation{'s' if violation_count > 1 else ''}"
    
    # Add state details
    if active_count > 0:
        max_bbs = max(len(s.history.bbl_addrs) for s in simgr.active)
        max_constraints = max(len(s.solver.constraints) for s in simgr.active)
        logstring += f". Max bbs is {max_bbs}, max #constraints is {max_constraints}"
    
    l.info(logstring)
    return simgr

#------------------------------------------------------------------------------
# SIMULATION DRIVER
#------------------------------------------------------------------------------

def _spectreSimgr(getProjState, getProjStateArgs, funcname, checks, spec=True, window=None, 
                  misforwarding=False, run=True, whitelist=None, trace=False, takepath=[]):
    """
    Create and run a simulation manager for the given function.
    
    Args:
        getProjState: Function to produce (proj, state)
        getProjStateArgs: Arguments for getProjState
        funcname: Name of the function (for logging)
        checks: 'OOB' or 'explicit' check type
        spec: Enable speculative execution
        window: Size of speculative window
        misforwarding: Enable misforwarding features
        run: Run the simulation manager before returning
        whitelist: Whitelist for explicit checks
        trace: Enable tracing
        takepath: Path to take for explicit checks
        
    Returns:
        Simulation manager
    """
    l.info(f"Running {funcname} {'with' if spec else 'without'} speculative execution")
    proj, state = getProjState(*getProjStateArgs)
    
    if checks == 'OOB': 
        setup_oob_detection(proj, state)
    elif checks == 'explicit': 
        setup_secret_detection(proj, state, whitelist, trace, takepath)
    else: 
        raise ValueError(f"Expected `checks` to be either 'OOB' or 'explicit', got {checks}")
        
    simgr = getSimgr(proj, state, spec=spec, window=window, misforwarding=misforwarding)
    simgr.metrics = TestMetrics()
    
    if run: 
        return runSimgr(simgr)
    else: 
        return simgr

#------------------------------------------------------------------------------
# TEST RUNNERS - SINGLE CASES
#------------------------------------------------------------------------------

# Create test case runners
def create_simgr_runner(test_function, test_name, check_type="explicit"):
    """Create a simulation manager runner for a test function"""
    def runner(**kwargs):
        return _spectreSimgr(test_function, [], test_name, check_type, **kwargs)
    return runner

# Kocher test cases
def kocherSimgr(s, **kwargs):
    """Run Kocher test case"""
    return _spectreSimgr(kocher, [s], f"Kocher test case {s}", "OOB", **kwargs)

def kocher11Simgr(s, **kwargs):
    """Run Kocher test case 11 variant"""
    return _spectreSimgr(kocher11, [s], f"Kocher test case 11{s}", "OOB", **kwargs)

# Spectre v1 test cases - create functions programmatically
spectrev1case1Simgr = create_simgr_runner(spectrev1_case_1, "Spectre v1 case 1")
spectrev1case2Simgr = create_simgr_runner(spectrev1_case_2, "Spectre v1 case 2")
spectrev1case3Simgr = create_simgr_runner(spectrev1_case_3, "Spectre v1 case 3")
spectrev1case4Simgr = create_simgr_runner(spectrev1_case_4, "Spectre v1 case 4")
spectrev1case5Simgr = create_simgr_runner(spectrev1_case_5, "Spectre v1 case 5")
spectrev1case6Simgr = create_simgr_runner(spectrev1_case_6, "Spectre v1 case 6")
spectrev1case7Simgr = create_simgr_runner(spectrev1_case_7, "Spectre v1 case 7")
spectrev1case8Simgr = create_simgr_runner(spectrev1_case_8, "Spectre v1 case 8")
spectrev1case9Simgr = create_simgr_runner(spectrev1_case_9, "Spectre v1 case 9")
spectrev1case10Simgr = create_simgr_runner(spectrev1_case_10, "Spectre v1 case 10")
spectrev1case11gccSimgr = create_simgr_runner(spectrev1_case_11gcc, "Spectre v1 case 11gcc")
spectrev1case11kerSimgr = create_simgr_runner(spectrev1_case_11ker, "Spectre v1 case 11ker")
spectrev1case11subSimgr = create_simgr_runner(spectrev1_case_11sub, "Spectre v1 case 11sub")
spectrev1case12Simgr = create_simgr_runner(spectrev1_case_12, "Spectre v1 case 12")
spectrev1case13Simgr = create_simgr_runner(spectrev1_case_13, "Spectre v1 case 13")
spectrev1case14Simgr = create_simgr_runner(spectrev1_case_14, "Spectre v1 case 14")

# Forwarding test cases
forwarding1Simgr = create_simgr_runner(forwarding_example_1, "forwarding example 1")
forwarding2Simgr = create_simgr_runner(forwarding_example_2, "forwarding example 2")
forwarding3Simgr = create_simgr_runner(forwarding_example_3, "forwarding example 3")

def forwarding4Simgr(**kwargs):
    # Default to window size 20, override with caller's value if provided
    window = kwargs.pop('window', 20)
    return _spectreSimgr(forwarding_example_4, [], "forwarding example 4", "explicit", window=window, **kwargs)

forwarding5Simgr = create_simgr_runner(forwarding_example_5, "forwarding example 5")

#------------------------------------------------------------------------------
# TEST RUNNERS - BATCH CASES
#------------------------------------------------------------------------------

def unionDicts(dicta, dictb):
    """Combine two dictionaries"""
    return {**dicta, **dictb}

def runallKocher(**kwargs):
    """Run all Kocher test cases"""
    # Note: Order matters due to some global state effects, see comment in original
    return unionDicts(
        {s: kocherSimgr(s, **kwargs) for s in ['01','02','03','05','07','04','06','08','09','10','12','13','14','15']},
        {('11'+s): kocher11Simgr(s, **kwargs) for s in ['gcc','ker','sub']}
    )

def runallSpectrev1(**kwargs):
    """Run all Spectre v1 test cases"""
    return {
        "01": spectrev1case1Simgr(**kwargs),
        "02": spectrev1case2Simgr(**kwargs),
        "03": spectrev1case3Simgr(**kwargs),
        "04": spectrev1case4Simgr(**kwargs),
        "05": spectrev1case5Simgr(**kwargs),
        "06": spectrev1case6Simgr(**kwargs),
        "07": spectrev1case7Simgr(**kwargs),
        "08": spectrev1case8Simgr(**kwargs),
        "09": spectrev1case9Simgr(**kwargs),
        "10": spectrev1case10Simgr(**kwargs),
        "11gcc": spectrev1case11gccSimgr(**kwargs),
        "11ker": spectrev1case11kerSimgr(**kwargs),
        "11sub": spectrev1case11subSimgr(**kwargs),
        "12": spectrev1case12Simgr(**kwargs),
        "13": spectrev1case13Simgr(**kwargs),
        "14": spectrev1case14Simgr(**kwargs)
    }

def runallForwarding(**kwargs):
    """Run all forwarding test cases"""
    return {
        "1": forwarding1Simgr(**kwargs),
        "2": forwarding2Simgr(**kwargs),
        "3": forwarding3Simgr(**kwargs),
        "4": forwarding4Simgr(**kwargs),
        "5": forwarding5Simgr(**kwargs)
    }

#------------------------------------------------------------------------------
# RESULTS ANALYSIS AND REPORTING
#------------------------------------------------------------------------------

def violationDetected(simgr):
    """Check if a Spectre violation was detected in the simulation manager"""
    return 'spectre_violation' in simgr.stashes and len(simgr.spectre_violation) > 0

def kocher_testResult(s, kocher_notspec, kocher_spec):
    """Analyze Kocher test results"""
    spec_metrics = getattr(kocher_spec[s], 'metrics', None)
    notspec_metrics = getattr(kocher_notspec[s], 'metrics', None)
    
    # Define which test cases are expected to have violations without speculation
    # These are identified in kocher_analysis.txt
    expected_violations_without_spec = {'04', '09', '14', '15', '11gcc'}
    
    if s == '08':
        # Test case '08' should not report violations (uses cmov instruction)
        result = ("PASS (correctly found no violations)" if not violationDetected(kocher_spec[s])
                 else "FAIL: detected a violation when not expected")
    elif s in expected_violations_without_spec:
        # These are expected to have violations even without speculation
        result = ("PASS (correctly detected expected non-speculative violation)" if violationDetected(kocher_notspec[s])
                 else "FAIL: missed expected non-speculative violation")
    else:
        # Regular cases - should have violations only with speculation
        result = ("FAIL: detected unexpected non-speculative violation" if violationDetected(kocher_notspec[s])
                 else "FAIL: no speculative violation detected" if not violationDetected(kocher_spec[s])
                 else "PASS (correctly detected speculative violation)")
    
    return {
        'result': result,
        'metrics': spec_metrics,
        'notspec_metrics': notspec_metrics
    }
    
def spectrev1_testResult(s, spectrev1_notspec, spectrev1_spec):
    """Analyze Spectre v1 test results"""
    spec_metrics = getattr(spectrev1_spec[s], 'metrics', None)
    notspec_metrics = getattr(spectrev1_notspec[s], 'metrics', None)
    
    if s == '08':
        # Test case '08' should not report violations (uses cmov instruction)
        result = ("FAIL: detected a violation without speculative execution" if violationDetected(spectrev1_notspec[s])
                 else "FAIL: detected a violation, expected no violation" if violationDetected(spectrev1_spec[s])
                 else "PASS")
    else:
        result = ("FAIL: detected a violation without speculative execution" if violationDetected(spectrev1_notspec[s])
                 else "FAIL: no violation detected" if not violationDetected(spectrev1_spec[s])
                 else "PASS")
    
    return {
        'result': result,
        'metrics': spec_metrics,
        'notspec_metrics': notspec_metrics
    }

def forwarding_testResult(s, forwarding_notspec, forwarding_forwarding):
    """Analyze forwarding test results"""
    spec_metrics = getattr(forwarding_forwarding[s], 'metrics', None)
    notspec_metrics = getattr(forwarding_notspec[s], 'metrics', None)
    
    result = ("FAIL: detected a violation without speculative execution" if violationDetected(forwarding_notspec[s])
             else "FAIL: no violation detected" if not violationDetected(forwarding_forwarding[s])
             else "PASS")
    
    return {
        'result': result,
        'metrics': spec_metrics,
        'notspec_metrics': notspec_metrics
    }

#------------------------------------------------------------------------------
# MAIN TESTING FUNCTION
#------------------------------------------------------------------------------

def display_test_results(results, title=None):
    """Display test results in a nice tabular format"""
    if not results:
        print("No test results to display.")
        return
    
    if title:
        print(f"\n===== {title} =====\n")
    
    # Create result tables per test suite
    for suite_name, suite_results in results.items():
        print(f"\n{suite_name}:")
        
        # Convert to tabular format
        table_data = []
        headers = ["Test Case", "Result", "Time (s)", "Violations", "Max States", 
                  "Max BBs", "Max Constraints", "Paths", "Violation Addrs"]
        
        for test_name, test_data in suite_results.items():
            if isinstance(test_data, str):
                # Simple result string (old format)
                row = [test_name, test_data, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]
            else:
                # Enhanced result with metrics
                result = test_data.get('result', '')
                metrics = test_data.get('metrics', None)
                
                if metrics:
                    row = [
                        test_name,
                        result,
                        f"{metrics.execution_time:.4f}",
                        metrics.violations,
                        metrics.max_active_states,
                        metrics.max_bbs,
                        metrics.max_constraints,
                        metrics.paths_explored,
                        ", ".join(metrics.violation_addresses) if metrics.violation_addresses else "None"
                    ]
                else:
                    row = [test_name, result, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]
            
            table_data.append(row)
        
        # Print the table
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

def alltests(kocher=True, spectrev1=True, forwarding=True):
    """
    Run all selected test suites and report results with metrics
    """
    if not kocher and not spectrev1 and not forwarding:
        raise ValueError("no tests specified")
    
    # Set logging levels for tests
    configure_logging(verbose=False)
    
    # Run selected test suites
    results = {}
    
    if kocher:
        kocher_notspec = runallKocher(spec=False)
        kocher_spec = runallKocher(spec=True)
        results["Kocher tests"] = {k: kocher_testResult(k, kocher_notspec, kocher_spec) 
                                  for k in kocher_spec.keys()}
    
    if spectrev1:
        spectrev1_notspec = runallSpectrev1(spec=False)
        spectrev1_spec = runallSpectrev1(spec=True)
        results["Spectrev1 tests"] = {k: spectrev1_testResult(k, spectrev1_notspec, spectrev1_spec) 
                                    for k in spectrev1_spec.keys()}    
    
    if forwarding:
        forwarding_notspec = runallForwarding(spec=False)
        forwarding_forwarding = runallForwarding(spec=True, misforwarding=True)
        results["Forwarding tests"] = {k: forwarding_testResult(k, forwarding_notspec, forwarding_forwarding) 
                                     for k in forwarding_forwarding.keys()}
    
    # Display results
    display_test_results(results, "SPECTRE VULNERABILITY DETECTION RESULTS")

#------------------------------------------------------------------------------
# ENTRY POINT
#------------------------------------------------------------------------------

if __name__ == '__main__':
    alltests()  # Run regular tests
    # alltests(kocher=True, spectrev1=False, forwarding=False)