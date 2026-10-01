#!/bin/bash
# ladder.sh — run the FULL criteria ladder: every rung named, each via
# ladder_rung.sh (fresh prep + complete applicable suite).  The matching rig
# must already be up (scripts/rig.sh <configuration>).  Name the rungs in
# descending node order so each transition is a cheap shrink (prep tears down
# the extras).
#
# Usage: scripts/ladder.sh <configuration> [configuration ...]
#   e.g. scripts/ladder.sh 32/disk/caw/mpath 16/disk/caw/mpath 8/disk/caw/mpath
# Exit 0 iff every rung had zero FAILs.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
[ $# -ge 1 ] || { echo "usage: ladder.sh <configuration> [configuration ...]"; exit 2; }
for cfg in "$@"; do
    python3 tools/configuration.py parse "$cfg" >/dev/null || exit 2
done
rc=0
for cfg in "$@"; do
    echo "=== ladder: rung $cfg start $(date -u +%FT%TZ) ==="
    scripts/ladder_rung.sh "$cfg" || rc=1
done
echo "=== ladder [$*] complete rc=$rc $(date -u +%FT%TZ) ==="
exit "$rc"
