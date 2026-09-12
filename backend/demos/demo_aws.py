"""Demo 1 runner: AWS Least-Privilege Mitigation with Cryptographic Dependency Discovery."""

import sys
from main import run_aws_demo

if __name__ == "__main__":
    exit_code = run_aws_demo()
    sys.exit(exit_code)
