#!/bin/bash
# suite_cycle_run.sh — one clean-cycle full-suite iteration for flake hunting.
#
#   usage: suite_cycle_run.sh <N> <dlm> [logfile]
#
# Destroys+starts test1..testN (fresh boot = fresh kernel ring, no cross-run
# residue), waits for SSH on all nodes, then runs the full `run.sh N dlm`
# suite with MXFS_EXTRA_MODARGS preserved from the environment (default
# 'watch_ino=1' — the sess10 probe-scope sentinel; dir_reuse/fence arm the
# real storm-dir ino per round themselves).
#
# RULE 0: healthy 4/tcp suite wall is ~11-13 min; the 1100s cap makes a hung
# suite a FAIL, not a wait.
set -u
N="${1:?usage: suite_cycle_run.sh <N> <dlm> [logfile] [test ...]}"
DLM="${2:?usage: suite_cycle_run.sh <N> <dlm> [logfile] [test ...]}"
LOG="${3:-/tmp/suite_cycle_run.log}"
shift; shift; [ $# -gt 0 ] && shift
ONLY=("$@")	# optional explicit test subset passed to run.sh
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-/tmp/.mxfs_pass}"
# MXFS_WATCH_ARM=0 → unarmed r8-parity iteration: impossible-ino watch
# silences the whole storm-probe family (incl. legacy ino<=256 scope) and
# the tests skip per-round arming.  Default 1 = armed.
ARM="${MXFS_WATCH_ARM:-1}"
if [ "$ARM" = 0 ]; then
    MODARGS="${MXFS_EXTRA_MODARGS:-watch_ino=999999999999}"
    export MXFS_TEST_ENV="MXFS_WATCH_ARM=0"
else
    MODARGS="${MXFS_EXTRA_MODARGS:-watch_ino=1}"
fi

{
    echo "=== suite_cycle_run $(date -u +%FT%TZ) N=$N dlm=$DLM modargs='$MODARGS' build=$(modinfo "$REPO/mxfs.ko" 2>/dev/null | awk '/^srcversion/{print $2}') ==="
    for k in $(seq 1 "$N"); do virsh -c qemu:///system destroy "test$k" >/dev/null 2>&1 & done; wait
    sleep 2
    for k in $(seq 1 "$N"); do virsh -c qemu:///system start "test$k" >/dev/null 2>&1 & done; wait
    deadline=$(( SECONDS + 180 ))
    up=0
    while [ "$SECONDS" -lt "$deadline" ]; do
        up=0
        for k in $(seq 1 "$N"); do
            timeout 6 "$SSH" "test$k" "$PASS" true >/dev/null 2>&1 && up=$((up + 1))
        done
        [ "$up" -eq "$N" ] && break
        sleep 5
    done
    if [ "$up" -ne "$N" ]; then
        echo "CYCLE FAIL: only $up/$N nodes reachable after 180s"
        exit 1
    fi
    echo "--- cycle OK: $N nodes up ---"
    cd "$REPO"
    MXFS_EXTRA_MODARGS="$MODARGS" timeout 1100 ./run.sh "$N" "$DLM" ${ONLY[@]+"${ONLY[@]}"}
    rc=$?
    # Archive every node's current-boot kernel log BEFORE the next cycle
    # destroys it (virsh destroy skips the journald flush — this is how the
    # r8 forensics were nearly lost).  ~1-3MB gz per node per run.
    kd="/tmp/suite_kernlogs_$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$kd"
    for k in $(seq 1 "$N"); do
        timeout 60 "$SSH" "test$k" "$PASS" \
            "journalctl -k -b 0 --no-pager 2>/dev/null | gzip -c" \
            > "$kd/test$k.kern.gz" 2>/dev/null &
    done
    wait
    echo "--- kernlogs: $kd ---"
    echo "=== suite exit rc=$rc $(date -u +%FT%TZ) ==="
} >> "$LOG" 2>&1
