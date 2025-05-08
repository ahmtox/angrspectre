"""
Tools for tracking secret/sensitive data during symbolic execution.
"""
import sys
import os

# Setup paths to use local angr
from angrspectre.config import setup_paths
setup_paths()

import angr
import claripy

class SecretDataMarker(claripy.Annotation):
    """
    Annotation that marks symbolic values containing sensitive/secret data.
    Used to track secret data flow through program execution.
    """
    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        src_annotations = list(src.annotations)
        if len(src_annotations) == 0: 
            return None
        elif len(src_annotations) == 1: 
            return src_annotations[0]
        else: 
            raise ValueError(f"Multiple annotations found: {src_annotations}")

def create_sensitive_symbol(state, name, bits):
    """
    Creates an unconstrained symbol marked as secret/sensitive.
    
    Args:
        state: The angr state
        name: Name for the symbol
        bits: Symbol size in bits
        
    Returns:
        A symbolic value annotated as sensitive
    """
    return state.solver.Unconstrained(
        name, 
        bits, 
        key=(f"secret_{name}",), 
        eternal=False, 
        annotations=(SecretDataMarker(),)
    )

def contains_secret_data(ast):
    """
    Check if an AST contains any secret/sensitive data.
    
    Returns True if either this AST or any of its leaf nodes are marked as sensitive.
    """
    return _has_secret_marker(ast) or any(_has_secret_marker(leaf) for leaf in ast.leaf_asts())

def _has_secret_marker(ast):
    """Check if this AST is directly marked as sensitive."""
    return any(isinstance(a, SecretDataMarker) for a in ast.annotations)