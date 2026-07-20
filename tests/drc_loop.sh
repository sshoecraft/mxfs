#!/bin/bash
# drc_loop.sh — run dir_reuse_coherency 2/tcp N times, aggregate per-iteration
# PASS/FAIL, fence-fire (P-CLMERGE-DEADINCARN), and REAL fs-corruption/shutdown
# (excludes the benign "DLM shutdown complete" teardown line).  run.sh's prep
# asserts the build srcversion on every node, so all iters run the local .ko.
#
# RULE 0 budget: each iter = prep(mkfs/mount/load ~20s) + test(~284s) ~= 306s;
# N iters => ~N*330s wall.  drc_cap2.sh overwrites tests/_cap/<host>.log each
# run, so this snapshots fence counts + failing logs immediately after each iter.
#
# Usage: tests/drc_loop.sh <iters>
set -u
cd /src/mxfs
N="${1:?usage: drc_loop.sh <iters>}"
CAPDIR=/src/mxfs/tests/_cap
SUM=$CAPDIR/loop_summary.txt
mkdir -p "$CAPDIR"
: > "$SUM"
pass=0; fail=0
corr_re='EFSCORRUPTED|EFSBADCRC|Internal error|force shutdown|has been shut down|Corruption of in-memory|metadata I/O error|bad CRC'
for i in $(seq 1 "$N"); do
    echo "=== iter $i/$N @ $(date -u +%T) build=$(modinfo mxfs.ko 2>/dev/null|awk '/srcversion/{print $2}') ===" | tee -a "$SUM"
    out=$(timeout 520 bash tests/drc_cap2.sh 2>&1)
    res=$(echo "$out" | grep -E "PASS|FAIL" | grep dir_reuse | head -1)
    ft1=$(grep -c "P-CLMERGE-DEADINCARN" "$CAPDIR/test1.log" 2>/dev/null)
    ft2=$(grep -c "P-CLMERGE-DEADINCARN" "$CAPDIR/test2.log" 2>/dev/null)
    rt1=$(grep -c "P-CLMERGE restored" "$CAPDIR/test1.log" 2>/dev/null)
    rt2=$(grep -c "P-CLMERGE restored" "$CAPDIR/test2.log" 2>/dev/null)
    dc1=$(grep -c "P-DATACLOBBER-SKIP" "$CAPDIR/test1.log" 2>/dev/null)
    dc2=$(grep -c "P-DATACLOBBER-SKIP" "$CAPDIR/test2.log" 2>/dev/null)
    corr=$(grep -hcE "$corr_re" "$CAPDIR"/test1.log "$CAPDIR"/test2.log 2>/dev/null | paste -sd+ | bc 2>/dev/null)
    if echo "$res" | grep -q PASS; then pass=$((pass+1)); st=PASS; else fail=$((fail+1)); st=FAIL; fi
    echo "  iter $i: $st | dataclobber-skip(t1=$dc1 t2=$dc2) | deadincarn(t1=$ft1 t2=$ft2) | corrupt=$corr" | tee -a "$SUM"
    [ -n "$res" ] && echo "    res: $res" | tee -a "$SUM"
    if [ "$st" = FAIL ]; then
        cp "$CAPDIR/test1.log" "$CAPDIR/fail_${i}_test1.log" 2>/dev/null
        cp "$CAPDIR/test2.log" "$CAPDIR/fail_${i}_test2.log" 2>/dev/null
        echo "    (FAIL logs snapshotted: fail_${i}_test{1,2}.log)" | tee -a "$SUM"
    fi
done
echo "=== DONE: pass=$pass fail=$fail / $N @ $(date -u +%T) ===" | tee -a "$SUM"
