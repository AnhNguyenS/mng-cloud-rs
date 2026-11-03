#!/bin/sh
# Cross-build the static ARMv7 mngd binary with Zig's C compiler. Zig supplies
# SQLite's C headers and libc, so the build machine does not need a separate
# ARM cross toolchain.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export CC_armv7_unknown_linux_musleabihf="$ROOT/tools/cross/zig-cc.sh"
export AR_armv7_unknown_linux_musleabihf="$ROOT/tools/cross/zig-ar.sh"
exec cargo build -p mngd --release --target armv7-unknown-linux-musleabihf "$@"
