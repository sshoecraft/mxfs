#!/bin/bash
# ladder.sh — run the FULL criteria ladder for one deployment condition:
# every rung (default 32 16 8 4 2 1), each via ladder_rung.sh (fresh prep +
# complete applicable suite).  The matching rig must already be up
# (scripts/rig.sh <rig> 32).  Descending order makes each transition a
# cheap shrink (prep tears down the extras).
#
# Usage: scripts/ladder.sh <caw|cawd|cawp|tcp> [N ...]
# Exit 0 iff every rung had zero FAILs.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
COND="${1:?usage: ladder.sh <caw|cawd|cawp|tcp> [N ...]}"
shift || true
RUNGS=("$@")
[ "${#RUNGS[@]}" -gt 0 ] || RUNGS=(32 16 8 4 2 1)
rc=0
for N in "${RUNGS[@]}"; do
    echo "=== ladder[$COND]: rung $N start $(date -u +%FT%TZ) ==="
    scripts/ladder_rung.sh "$N" "$COND" || rc=1
done
echo "=== ladder[$COND] complete rc=$rc $(date -u +%FT%TZ) ==="
exit "$rc"
