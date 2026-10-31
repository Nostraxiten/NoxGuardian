"""Shim for direct invocation: python audit_runner.py"""

import sys
from noxguardian.audit_runner import main, run_audit

__all__ = ["main", "run_audit"]

if __name__ == "__main__":
    sys.exit(main())
