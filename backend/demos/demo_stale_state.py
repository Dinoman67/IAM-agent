"""Demo 4 runner: Optimistic Concurrency Stale State Detection & Replan."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from main import run_stale_state_demo

if __name__ == "__main__":
    exit_code = run_stale_state_demo()
    sys.exit(exit_code)
