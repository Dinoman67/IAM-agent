"""Demo 3 runner: Security Kernel blocking cross-provider mismatch."""

import sys
from main import run_provider_mismatch_demo

if __name__ == "__main__":
    exit_code = run_provider_mismatch_demo()
    sys.exit(exit_code)
