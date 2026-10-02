#!/bin/bash
# repro_agstrand_dir_lost_update.sh — laps of ag_strand_repair followed by the
# cold audit, on one rig group, until the audit finds a corrupt directory.
#
# WHY.  Wave 1 of the parallel revalidation (run 20260930T173640Z-g8) left
# /.agstrand.<tag> with two lost directory updates, both on shortform
# directories: children created by other nodes inside a directory that rank 1's
# `rm -rf` had already removed and freed (their '..' dangles, no entry names
# them), and an entry that survived the rm of the inode it named.  The same
# board run alone on the idle host came back CLEAN once, which proves nothing
# either way.  This lap isolates the workload that made the damage: prep, the
# ag_strand_repair round shape (every node mkdirs into fresh shared parents
# while rank 1 removes the parent three rounds back), then chk_clean's cold
# audit of the unmounted image.
#
# A lap that audits CORRUPT stops the loop: the group's LUN image is copied
# before anything re-formats it, and the audit's node is left unmounted, which
# is what chk_clean does to keep the proof.
#
# chk_clean without alloc_witness before it grades the release INDETERMINATE by
# design; the lap reads the audit's own verdict (CLEAN / CORRUPT), not the
# release claim.
#
# Usage: tests/repro_agstrand_dir_lost_update.sh <configuration> <group> <laps>
#   e.g. tests/repro_agstrand_dir_lost_update.sh 8/net/mesh/direct g8 5
# Exit 0 iff every lap audited CLEAN; 1 at the first CORRUPT; 2 on a lap that
# could not produce a verdict.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
CONFIG=${1:?configuration}
GROUP=${2:?group}
LAPS=${3:?laps}
OUT="$REPO/tests/evidence/repro_agstrand_$(date -u +%Y%m%dT%H%M%SZ)-$GROUP"
mkdir -p "$OUT"
NODES=$("$REPO/tools/mxfs_lab.sh" group "$GROUP") || exit 2
echo "repro: $CONFIG on $GROUP, $LAPS laps, evidence $OUT"

verdict_of() {  # <since iso> -> the audit's own verdict from chk_clean's cell, if written since
    python3 - "$REPO/data/criteria.json" "$CONFIG" "$1" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
for e in d["criteria"]:
    if e.get("id") == "chk_clean":
        cell = (e.get("per_config") or {}).get(sys.argv[2]) or {}
        # a cell older than this lap is some earlier run's verdict, not this lap's
        if str(cell.get("iso", "")) < sys.argv[3]:
            print("STALE")
            break
        m = re.search(r"verdict=([A-Z]+)", str(cell.get("measured", "")))
        print(m.group(1) if m else "NONE")
PY
}

for lap in $(seq 1 "$LAPS"); do
    t0=$(date +%s); since=$(date -u +%FT%TZ)
    # A filtered run forces a prep only when prep_cluster is the whole filter,
    # so the fresh format is its own invocation.
    "$REPO/run.sh" "$CONFIG" --group "$GROUP" prep_cluster > "$OUT/lap$lap.prep.log" 2>&1 \
        || { echo "lap $lap: prep failed — see $OUT/lap$lap.prep.log"; exit 2; }
    "$REPO/run.sh" "$CONFIG" --group "$GROUP" ag_strand_repair chk_clean > "$OUT/lap$lap.log" 2>&1
    rc=$?
    v=$(verdict_of "$since")
    strand=$(grep -aE '(PASS|FAIL) +ag_strand_repair' "$OUT/lap$lap.log" | tail -1 | tr -s ' ')
    echo "lap $lap rc=$rc wall=$(( $(date +%s) - t0 ))s audit=$v ag_strand_repair=[$strand]"
    case "$v" in
        CLEAN) ;;
        CORRUPT)
            # the group's pool LUN: the next run on it formats it
            lun=$("$REPO/tools/lun_pool.sh" lookup --nodes "$(tr ' ' ',' <<<"$NODES")" | sed -n 's/.* id=\([0-9]*\) .*/\1/p')
            if snap=$([ -n "$lun" ] && "$REPO/tools/lun_pool.sh" snapshot "$lun" "$GROUP-repro-corrupt-lap$lap"); then
                echo "image kept: $snap (sha256 $(sha256sum "$snap" | cut -c1-16))"
            else
                echo "image NOT kept: no pool LUN bound to [$NODES]"
            fi
            exit 1 ;;
        *) echo "lap $lap produced no audit verdict — see $OUT/lap$lap.log"; exit 2 ;;
    esac
done
exit 0
