"""Demo 2 runner: Safe escalation on unsupported GCP simulation."""

import sys
from main import run_unsupported_gcp_demo

if __name__ == "__main__":
    exit_code = run_unsupported_gcp_demo()
    sys.exit(exit_code)
