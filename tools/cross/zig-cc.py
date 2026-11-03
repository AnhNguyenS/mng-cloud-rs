#!/usr/bin/env python3
"""cc wrapper that compiles C for the Rust ARMv7 musl target with Zig.

The cc crate appends `--target=arm-unknown-linux-musleabihf`, which Zig 0.16
does not accept. Strip it and select the canonical Zig triple ourselves.
"""

from __future__ import annotations

import os
import subprocess
import sys

TARGET = os.environ.get("MNG_ZIG_TARGET", "arm-linux-musleabihf")


def main() -> int:
    args = [arg for arg in sys.argv[1:] if not arg.startswith("--target=")]
    command = [
        sys.executable,
        "-m",
        "ziglang",
        "cc",
        "-target",
        TARGET,
        *args,
    ]
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
