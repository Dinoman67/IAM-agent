"""Demo 2 runner: Security Kernel Interception of Invariant Violation (Safety Block)."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from main import run_safety_block_demo

if __name__ == "__main__":
    exit_code = run_safety_block_demo()
    sys.exit(exit_code)
