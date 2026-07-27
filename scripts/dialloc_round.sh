#!/bin/bash
# dialloc_round.sh — one fully-instrumented fresh-FS churn round for the
# ccloop-4dd7 dialloc/liveness campaign.
#
# Does, in order:
#   1. MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster   (fresh mkfs every round)
#   2. per-node probe params: iwr=1 (P28-IWR write decisions), watch_ino=131
#      (dlmtr transition ring on the deterministic hot dir)
#   3. LIVE journalctl -kf streams from clyde into $LOGDIR/<tag>_testN.live
#      — the runtime journal wraps in <2 min at full probe volume
#      (RuntimeMaxUse=400M), so post-hoc capture keeps losing the failure
#      window (lost round-5 and b55r2 test1-side evidence).  A live stream
#      cannot rotate away.
#   4. agi_wedge_repro.sh DUR WORKERS
#   5. stream teardown + per-node verification (corruption signatures,
#      probe families, mount state)
#
# Usage: LOGDIR=/src/mxfs/tests/logs/... TAG=b55r3 scripts/dialloc_round.sh [DUR] [WORKERS]
# Exit: 0 clean round, 42 escalation, 1 infra failure.
set -u
cd /src/mxfs
DUR=${1:-180}
WORKERS=${2:-24}
TAG=${TAG:?set TAG}
LOGDIR=${LOGDIR:?set LOGDIR}
PASS=${MXFS_PASS:-/tmp/.mxfs_pass}
SSH=/src/mxfs/tools/mxfs_sshpass.sh
mkdir -p "$LOGDIR"

MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster > "$LOGDIR/${TAG}_prep.log" 2>&1
grep -q "prep_cluster OK" "$LOGDIR/${TAG}_prep.log" || { echo "PREP FAIL"; tail -3 "$LOGDIR/${TAG}_prep.log"; exit 1; }

for n in test1 test2; do
    "$SSH" "$n" "$PASS" "echo 1 > /sys/module/mxfs/parameters/iwr; echo 131 > /sys/module/mxfs/parameters/watch_ino" >/dev/null 2>&1
done

# Live streams (line-buffered; kill at round end).
declare -a SPIDS=()
for n in test1 test2; do
    "$SSH" "$n" "$PASS" "journalctl -kf --no-pager -o short-precise" > "$LOGDIR/${TAG}_${n}.live" 2>/dev/null &
    SPIDS+=($!)
done
sleep 2

N1=test1 N2=test2 MXFS_PASS="$PASS" scripts/agi_wedge_repro.sh "$DUR" "$WORKERS" \
    > "$LOGDIR/${TAG}_round.log" 2>&1
rrc=$?

sleep 3
kill "${SPIDS[@]}" 2>/dev/null; wait 2>/dev/null

esc=0
grep -q "ESCALATION" "$LOGDIR/${TAG}_round.log" && esc=42
for n in test1 test2; do
    L="$LOGDIR/${TAG}_${n}.live"
    sig=$(grep -cE 'Corruption|Internal error|unrecoverable|Shutting down' "$L" 2>/dev/null)
    bstuck=$(grep -c 'P-BUFLOCK-STUCK' "$L" 2>/dev/null)
    aorph=$(grep -c 'P-ACQ-ORPHAN' "$L" 2>/dev/null)
    esk=$(grep -c 'inobt-already-free' "$L" 2>/dev/null)
    freewr=$(grep -c 'P28-IWR-FREEWR' "$L" 2>/dev/null)
    mounts=$("$SSH" "$n" "$PASS" 'mount | grep -c " type mxfs "' 2>/dev/null | tail -1)
    echo "$n: sig=$sig BUFSTUCK=$bstuck ACQORPH=$aorph ESTALE-SKIP=$esk FREEWR=$freewr mounts=$mounts lines=$(wc -l < "$L" 2>/dev/null)"
    [ "${sig:-1}" -ne 0 ] && esc=42
done
tail -2 "$LOGDIR/${TAG}_round.log"
exit $esc
