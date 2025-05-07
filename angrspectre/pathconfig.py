import sys
import os

def setup_paths():
    """Configure Python paths to use local angr installation"""
    # Add parent dir to path
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
        
    # Add local angr directory to beginning of path
    angr_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'angr')
    if os.path.exists(angr_path) and angr_path not in sys.path:
        sys.path.insert(0, angr_path)