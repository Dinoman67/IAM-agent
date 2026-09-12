"""Demo 3 runner: Deterministic Rollback on Post-Apply Verification Failure."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from main import run_rollback_demo

if __name__ == "__main__":
    exit_code = run_rollback_demo()
    sys.exit(exit_code)
