#!/usr/bin/env python3
"""
Thin entrypoint so the project can be run as:

    python scripts/run_demo.py
    python scripts/run_demo.py --dry-run
    python -m aerodrift.daemon --dry-run
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aerodrift.daemon import main  # noqa: E402

if __name__ == "__main__":
    main()
