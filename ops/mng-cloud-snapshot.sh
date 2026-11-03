#!/bin/sh
# Publish a consistent, read-only SQLite snapshot for mngd.
#
# The PHP application keeps the live database in WAL mode and owns the
# directory. mngd therefore never opens the live file: a root timer copies it
# through SQLite's online backup API into tmpfs and atomically replaces the
# snapshot mngd reads. The snapshot lives in /run, so the refresh does not wear
# the eMMC/SD card and survives only until reboot (the timer recreates it).
set -eu

SOURCE=${MNG_SNAPSHOT_SOURCE:-/var/lib/mng-cloud/mng-cloud.sqlite}
DIR=${MNG_SNAPSHOT_DIR:-/run/mng-cloud-snapshot}
TARGET="$DIR/mng-cloud.sqlite"
TMP="$DIR/.mng-cloud.sqlite.next"

if [ ! -f "$SOURCE" ]; then
    echo "snapshot: source database not found: $SOURCE" >&2
    exit 1
fi

install -d -m 0755 -o root -g root "$DIR"
rm -f "$TMP"
trap 'rm -f "$TMP"' EXIT INT TERM

# `.timeout` keeps a writer from failing the copy immediately; `.backup` uses
# SQLite's online backup API and restarts if the source changes mid-copy.
sqlite3 "$SOURCE" ".timeout 5000" ".backup '$TMP'"

# The source runs in WAL mode. Publish a rollback-journal database so a
# read-only reader never needs to create a -shm file, even without immutable=1.
sqlite3 "$TMP" "PRAGMA journal_mode=DELETE;" >/dev/null

CHECK=$(sqlite3 "$TMP" "PRAGMA quick_check;")
if [ "$CHECK" != "ok" ]; then
    echo "snapshot: quick_check failed: $CHECK" >&2
    exit 1
fi

chown mng:mng "$TMP"
chmod 0440 "$TMP"
mv -f "$TMP" "$TARGET"
trap - EXIT INT TERM
