#!/bin/bash
# drc_catch3.sh [MAXRUNS] — instrumented (dirwr=1 + DRC_STREAM NFS capture) reboot+run
# dir_reuse 8/tcp until a FAIL.  Clears the stale /root/drc_* markers each run (the
# sess27 contamination), streams every node's dmesg to NFS (/src/mxfs/tests/tcp/drc_cap,
# immune to ring rotation), and on FAIL extracts the decisive grown-dir probes for the
# fail round: P68-GROWREL-VERIFY (does disk reflect in-core after release?), P-DIRIFLUSH
# (which flush reverts the extent map), P68-MAPDIVERGE (divergent daddr alloc).
set -u
MAX="${1:-8}"
MODARGS="dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dirwr=1"
SCR=/tmp/claude-1000/-src-mxfs/efdc16a7-85d5-4b89-985f-6934a7de0517/scratchpad
mkdir -p "$SCR"
SSH=/src/mxfs/tools/mxfs_sshpass.sh
STREAMDIR=/src/mxfs/tests/tcp/drc_cap; mkdir -p "$STREAMDIR"
echo "=== catch3 MAX=$MAX modargs=[$MODARGS] $(date -u) ===" | tee "$SCR/catch3.log"
for run in $(seq 1 "$MAX"); do
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system destroy test$n >/dev/null 2>&1; done
    sleep 5
    for n in 1 2 3 4 5 6 7 8; do virsh -c qemu:///system start test$n >/dev/null 2>&1; done
    for w in $(seq 1 30); do up=0; for n in 1 2 3 4 5 6 7 8; do timeout 5 $SSH test$n /tmp/.mxfs_pass true >/dev/null 2>&1 && up=$((up+1)); done; [ "$up" = 8 ] && break; sleep 3; done
    # clear stale markers + NFS streams (sess27: failrounds.txt persisted across reboots)
    for n in 1 2 3 4 5 6 7 8; do timeout 8 $SSH test$n /tmp/.mxfs_pass 'rm -f /root/drc_failrounds.txt /root/drc_*.dmesg 2>/dev/null' >/dev/null 2>&1; done
    rm -f "$STREAMDIR"/stream_rank*.log 2>/dev/null
    t0=$(date +%s)
    MXFS_EXTRA_MODARGS="$MODARGS" MXFS_TEST_ENV="DRC_STREAM=1 DRC_ROUNDS=16" \
        timeout 590 /src/mxfs/run.sh 8 tcp dir_reuse_coherency > "$SCR/c3_run${run}.log" 2>&1
    t1=$(date +%s)
    if grep -q "PASS  dir_reuse_coherency" "$SCR/c3_run${run}.log"; then
        echo "run $run: PASS wall=$((t1-t0))s" | tee -a "$SCR/catch3.log"
        continue
    fi
    echo "run $run: FAIL wall=$((t1-t0))s — capturing" | tee -a "$SCR/catch3.log"
    FR=$(timeout 15 $SSH test1 /tmp/.mxfs_pass "head -1 /root/drc_failrounds.txt 2>/dev/null")
    RND=$(echo "$FR" | grep -oE "round=[0-9]+" | head -1 | cut -d= -f2)
    echo "fail marker: $FR  (round=$RND)" | tee -a "$SCR/catch3.log"
    # per-rank readdir counts from the streams
    echo "--- per-rank RDMISS (round $RND) ---" | tee -a "$SCR/catch3.log"
    grep -h "drc-RDMISS round=$RND " "$STREAMDIR"/stream_rank*.log 2>/dev/null | grep -oE "rank=[0-9]+ readdir=[0-9]+" | sort -u | tee -a "$SCR/catch3.log"
    echo "--- GROWREL-VERIFY STALE-DISK count (ino=131) per rank ---" | tee -a "$SCR/catch3.log"
    for r in 1 2 3 4 5 6 7 8; do
        f="$STREAMDIR/stream_rank${r}.log"; [ -s "$f" ] || continue
        st=$(grep "P68-GROWREL-VERIFY ino=131" "$f" 2>/dev/null | grep -c "STALE")
        du=$(grep "P68-GROWREL-VERIFY ino=131" "$f" 2>/dev/null | grep -c "DURABLE")
        df=$(grep -c "P68-DIRINODE-DURABLE-FAIL ino=131" "$f" 2>/dev/null)
        md=$(grep -c "P68-MAPDIVERGE ino=131" "$f" 2>/dev/null)
        echo "rank$r: GROWREL-STALE=$st GROWREL-DURABLE=$du DURABLE-FAIL=$df MAPDIVERGE=$md" | tee -a "$SCR/catch3.log"
    done
    echo "streams in $STREAMDIR" | tee -a "$SCR/catch3.log"
    break
done
echo "=== catch3 done ===" | tee -a "$SCR/catch3.log"
