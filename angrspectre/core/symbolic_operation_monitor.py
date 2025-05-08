"""
Monitors symbolic operations during execution to track data flows
and prevent leakage of sensitive information.
"""
import sys
import os

# Setup paths to use local angr
from angrspectre.config import setup_paths
setup_paths()

import angr
from angrspectre.core.secret_tracking import contains_secret_data, create_sensitive_symbol

import logging
l = logging.getLogger(__name__)

class SymbolicOperationMonitor(angr.SimStatePlugin):
    """
    Monitors operations during symbolic execution to identify and handle
    potentially sensitive data flows.
    """
    def do_op(self, state, operation, arguments):
        """
        Processes an operation with its arguments to determine if sensitive data is involved.
        
        Args:
            state: Current symbolic execution state
            operation: The operation being performed
            arguments: Operation arguments (claripy AST objects)
            
        Returns:
            Replacement value if sensitive data is involved, None otherwise
        """
        # If any argument contains secret data, replace with a new unconstrained secret
        if any(contains_secret_data(arg) for arg in arguments):
            return create_sensitive_symbol(state, "secret", operation._output_size_bits)
        return None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        """Create a copy of this plugin instance"""
        return SymbolicOperationMonitor()