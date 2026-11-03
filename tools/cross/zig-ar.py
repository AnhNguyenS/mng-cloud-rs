#!/usr/bin/env python3
"""ar wrapper for the Zig-provided archiver."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    return subprocess.call([sys.executable, "-m", "ziglang", "ar", *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
