#!/usr/bin/env python
"""
AWS Resource Enumeration Tool

This is a thin wrapper that loads the aws_enum package from the same directory.
Use 'python -m aws_enum' for the standard invocation.

Usage:
    ./aws-enum.py <command> [options]
    python -m aws_enum <command> [options]
"""

import sys
from pathlib import Path

# Add the script's directory to path so aws_enum package can be found
script_dir = Path(__file__).parent
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))

from aws_enum import main  # noqa: E402 - path manipulation must come first

if __name__ == "__main__":
    main()
