"""Demo runner: Provider mismatch protection preventing cross-cloud contamination."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from main import run_provider_mismatch_demo

if __name__ == "__main__":
    exit_code = run_provider_mismatch_demo()
    sys.exit(exit_code)
