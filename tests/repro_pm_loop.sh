#!/bin/bash
# repro_pm_loop.sh — run posix_multi manually on test1/test2 N times without
# reformatting the cluster, cleaning the test dir between runs.  Reports per-run
# pass/fail + the RESULT reason for each node, to characterize flakiness.
# Usage: tests/repro_pm_loop.sh [iters] [test-script-name]
set -u
ITERS="${1:-5}"
TEST="${2:-posix_multi}"
P=/tmp/.mxfs_pass
S=/src/mxfs/tools/mxfs_sshpass.sh
BROKER=192.168.1.149
LOGD=/src/mxfs/.testlogs
mkdir -p "$LOGD"

for k in $(seq 1 "$ITERS"); do
    PFX="mxfs/coord/reproloop/${TEST}_${k}"
    timeout 5 mosquitto_sub -h $BROKER -t "$PFX/#" --remove-retained -W 2 >/dev/null 2>&1
    # clean the test's dir on test1 (covers .posix_multi etc.)
    timeout 20 bash $S test1 $P "rm -rf /mnt/shared/.${TEST} /mnt/shared/.posix_multi; sync" >/dev/null 2>&1
    t0=$(date +%s.%N)
    timeout 150 bash $S test1 $P "MXFS_NODES=2 MXFS_RANK=1 MXFS_DLM=tcp MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$PFX COORD_TIMEOUT=60 bash /src/mxfs/tests/suite/${TEST}.sh /mnt/shared" >"$LOGD/rl_t1.out" 2>&1 &
    timeout 150 bash $S test2 $P "MXFS_NODES=2 MXFS_RANK=2 MXFS_DLM=tcp MXFS_COORD_BROKER=$BROKER MXFS_COORD_PREFIX=$PFX COORD_TIMEOUT=60 bash /src/mxfs/tests/suite/${TEST}.sh /mnt/shared" >"$LOGD/rl_t2.out" 2>&1 &
    wait
    t1=$(date +%s.%N)
    r1=$(grep -E '^RESULT:' "$LOGD/rl_t1.out" | tail -1)
    r2=$(grep -E '^RESULT:' "$LOGD/rl_t2.out" | tail -1)
    s1=$(awk '{print $2}' <<<"$r1"); s2=$(awk '{print $2}' <<<"$r2")
    [ "$s1" = PASS ] && [ "$s2" = PASS ] && AGG=PASS || AGG=FAIL
    printf "iter %d: %s (%.1fs)  t1=%s t2=%s\n" "$k" "$AGG" "$(echo "$t1-$t0"|bc)" "${s1:-NONE}" "${s2:-NONE}"
    if [ "$AGG" != PASS ]; then
        echo "   t1 reason: $(sed -n 's/.*reason=//p' <<<"$r1")"
        echo "   t2 reason: $(sed -n 's/.*reason=//p' <<<"$r2")"
    fi
done
