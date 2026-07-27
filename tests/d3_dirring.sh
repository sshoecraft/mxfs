#!/bin/bash
# d3_dirring.sh — D3 (32/caw durable data loss) provenance-capture laps
# (ccloop c7ee71c6 sess14).  sess13 proved the tight recipe reproduces the
# co-resident stale clobber ~1/1 with dir tracing OFF (printk at the write
# path suppresses the µs-wide race), so v0.11.118 records every dir-metadata
# + inode-cluster write submission in the memory-only P172-WRTR ring
# (pal/linux/xfs_buf.c).  Each lap here: churn storm -> tree removal ->
# cache_coherency.  On a REAL coherency FAIL (failed>0 in measured, not the
# interference states:FAIL shape) it immediately pokes mxfs.dirring_dump=1
# on every node, harvests dmesg to tests/logs/d3ring_<ts>/, and stops with
# the evidence in place.  Analyze with tests/d3_ring_analyze.py.
#
# Usage:  tests/d3_dirring.sh [laps]        (default 4)
# Precondition: 32/caw cluster prepped at the P172 build (v0.11.118+),
# dirwr=0 everywhere (KEEP 0 — dirwr>=1 hides the race).

set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
PASS="${MXFS_PASS:-$("$REPO/tools/mxfs_secrets.sh" passfile)}"
LAPS="${1:-4}"
STORM_SECS=120

poke_and_harvest() {   # $1 = destination dir
    local dest="$1"
    mkdir -p "$dest"
    echo "--- poking dirring_dump + harvesting dmesg on all 32 nodes -> $dest"
    for i in $(seq 1 32); do
        (timeout 25 "$SSH" "test$i" "$PASS" \
            'echo 1 > /sys/module/mxfs/parameters/dirring_dump 2>/dev/null; sleep 2; dmesg' \
            > "$dest/test$i.dmesg" 2>/dev/null </dev/null) &
    done
    wait
    # one-line sanity: ring line counts per node
    for i in $(seq 1 32); do
        printf 'test%-2s P172=%s P26=%s P171=%s\n' "$i" \
            "$(grep -c 'P172-WRTR ' "$dest/test$i.dmesg" 2>/dev/null)" \
            "$(grep -c 'P26-IGET-FAIL' "$dest/test$i.dmesg" 2>/dev/null)" \
            "$(grep -c 'P171-SFNULL' "$dest/test$i.dmesg" 2>/dev/null)"
    done | tee "$dest/harvest_summary.txt"
    jq -r '.categories[].tests[] | select(.name=="cache_coherency") | .runs["32/caw"]' \
        "$REPO/criteria.json" > "$dest/criteria_row.json" 2>/dev/null
}

for lap in $(seq 1 "$LAPS"); do
    echo "=== D3 lap $lap/$LAPS $(date -u +%H:%M:%S) ==="

    # 1. churn storm (ino-reuse minefield builder) — runs STORM_SECS then dies
    "$REPO/tests/wedge_load.sh" start "$STORM_SECS"
    sleep $((STORM_SECS + 10))
    "$REPO/tests/wedge_load.sh" stop >/dev/null 2>&1

    # 2. remove the churn tree (frees the churned inos for reuse)
    timeout 120 "$SSH" test1 "$PASS" 'rm -rf /mnt/shared/.wedgeload' </dev/null

    # 3. cache_coherency (budget enforced inside run.sh; RULE 0)
    out=$("$REPO/run.sh" 32 caw cache_coherency 2>&1 | grep -E '  (PASS|FAIL)')
    echo "$out"

    # 4. REAL-failure discrimination.  sess14 lesson: the aggregate measured
    #    can show failed=0 even on a REAL 22-node coherency loss (the count
    #    comes from rank1's view) — so ALSO treat any per-node check-name in
    #    the reason (rv/cv/cwr/uv ...) as a real hit.
    failed=$(jq -r '.categories[].tests[] | select(.name=="cache_coherency")
                    | .runs["32/caw"].measured' "$REPO/criteria.json" 2>/dev/null \
             | grep -o 'failed=[0-9]*' | cut -d= -f2)
    failed="${failed:-0}"
    reason=$(jq -r '.categories[].tests[] | select(.name=="cache_coherency")
                    | .runs["32/caw"].reason' "$REPO/criteria.json" 2>/dev/null)
    if [ "$failed" = 0 ] && echo "$reason" | grep -qE ':FAIL:(rv|cv|cwr|uv) '; then
        failed=$(echo "$reason" | grep -oE 'test[0-9]+:FAIL' | wc -l)
        echo "--- reason-derived real coherency FAIL on $failed node(s)"
    fi

    # 5. node-reachability sweep (a vanished node mid-lap = D4 panic watch)
    unreach=0
    for i in $(seq 1 32); do
        timeout 8 "$SSH" "test$i" "$PASS" 'echo UP' </dev/null 2>/dev/null \
            | grep -q UP || { echo "UNREACHABLE test$i"; unreach=$((unreach+1)); }
    done

    # sess14: NO_TERMINAL_RECORD / BARRIER_TIMEOUT in the measured field is
    # WEDGE evidence (lap-4 2026-07-26: one node parked in the pre-CAW
    # cancel_work_sync deadlock → 31 barrier-parks → all-32 no-record),
    # NOT interference — capture it too, with a distinct exit code.
    wedge=0
    measured=$(jq -r '.categories[].tests[] | select(.name=="cache_coherency")
                      | .runs["32/caw"].measured' "$REPO/criteria.json" 2>/dev/null)
    case "$measured" in *NO_TERMINAL_RECORD*|*BARRIER_TIMEOUT*) wedge=1;; esac

    if [ "$failed" != 0 ] || [ "$unreach" != 0 ] || [ "$wedge" != 0 ]; then
        ts=$(date -u +%Y%m%d_%H%M%S)
        dest="$REPO/tests/logs/d3ring_$ts"
        echo "=== HIT lap $lap: failed=$failed unreachable=$unreach wedge=$wedge — capturing"
        echo "$out" > /tmp/d3_rows.$$ 2>/dev/null || true
        poke_and_harvest "$dest"
        mv /tmp/d3_rows.$$ "$dest/run_rows.txt" 2>/dev/null || true
        echo "=== evidence in $dest — next: tests/d3_ring_analyze.py $dest"
        [ "$failed" != 0 ] || [ "$unreach" != 0 ] && exit 3
        exit 4
    fi
    echo "--- lap $lap clean (failed=0, all reachable) — continuing"
done
echo "=== $LAPS laps, no hit ==="
exit 0
