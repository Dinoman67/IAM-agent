"""Demo 1 runner: AWS Least-Privilege Mitigation with Cryptographic Dependency Discovery."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from main import run_aws_demo

if __name__ == "__main__":
    exit_code = run_aws_demo(use_mock=True)
    sys.exit(exit_code)
