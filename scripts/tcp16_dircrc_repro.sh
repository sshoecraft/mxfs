#!/bin/bash
# tcp16_dircrc_repro.sh — RULE-4 repro driver for the tcp/16 stale-dir-read
# defect (P-SFDIR-STALE-RMW -> P-DIRCRC-RETRY-FAIL payload-in-dirblock,
# first seen sweep81 run_id 20260725T105522Z, ccloop c7ee71c6 sess2).
#
# One iteration = fresh FORCE_PREP at 16/tcp with dirwr=1 armed at module
# load, dmesg -w streamers on every node (defeats the ring-roll that ate
# sess8's GRANT/REL pairs), then the exact failing 11-cell sequence.
# On ANY cell FAIL or any P-marker hit, collects all 16 streams +
# run output into tests/logs/tcp16_forensics_r<iter>/ (persistent, RULE 3).
#
# Usage: scripts/tcp16_dircrc_repro.sh <iter-label>
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
S="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
IT="${1:?usage: tcp16_dircrc_repro.sh <iter-label>}"
FDIR="$REPO/tests/logs/tcp16_forensics_r${IT}"
N=16
CELLS="precond_readiness cache_coherency strong_consistency posix_multi mmap_coherency zero_silent_loss dlm_fairness dlm_membership scaling_curve dlm_scaling rsync_paired"

cd "$REPO"
unset RULE0_CALIBRATE

echo "=== iter $IT: fresh prep (dirwr=1 at load) ==="
MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS='dirwr=1' ./run.sh $N tcp prep_cluster 2>&1 | tail -3 || exit 1

echo "=== arming streamers on all $N nodes ==="
for i in $(seq 1 $N); do
    ( timeout 15 "$S" test$i "$PASS" "dmesg -C; pkill -f 'dmesg -w' 2>/dev/null; rm -f /root/dmesg_stream.log; nohup dmesg -w -T > /root/dmesg_stream.log 2>&1 & echo ARMED" >/dev/null 2>&1 ) &
done
wait

echo "=== running failing cell sequence ==="
OUT="$FDIR.runlog"
./run.sh $N tcp $CELLS 2>&1 | tee "$OUT" | grep -E '^  (PASS|FAIL)|prep'
FAILS=$(grep -c '^  FAIL' "$OUT" || true)

echo "=== scanning nodes for P-markers ==="
HITS=0
for i in $(seq 1 $N); do
    c=$(timeout 15 "$S" test$i "$PASS" "grep -c 'P-SFDIR-STALE-RMW\|P-DIRCRC-RETRY-FAIL\|P31-FACEA\|P38-POSTREL-ZOMBIE' /root/dmesg_stream.log 2>/dev/null" 2>/dev/null | tr -dc 0-9)
    [ -n "$c" ] && [ "$c" -gt 0 ] && { echo "  test$i: $c marker hits"; HITS=$((HITS+c)); }
done

if [ "$FAILS" -gt 0 ] || [ "$HITS" -gt 0 ]; then
    echo "=== FIRE (fails=$FAILS marker_hits=$HITS) — collecting to $FDIR ==="
    mkdir -p "$FDIR"
    for i in $(seq 1 $N); do
        ( timeout 40 "$S" test$i "$PASS" "pkill -f 'dmesg -w' 2>/dev/null; cat /root/dmesg_stream.log 2>/dev/null" > "$FDIR/dmesg_test$i" 2>/dev/null ) &
    done
    wait
    mv "$OUT" "$FDIR/runlog"
    echo "REPRO_FIRE iter=$IT fails=$FAILS hits=$HITS"
    exit 42
fi
echo "REPRO_CLEAN iter=$IT"
exit 0
