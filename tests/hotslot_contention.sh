#!/bin/bash
# hotslot_contention.sh — D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B, sess379.
#
# ISOLATES the mechanism found by mass_umount_stall_probe.sh away from unmount.
#
# What that probe established:
#   - 32 nodes unmounting SIMULTANEOUSLY: 60.5 / 121 / 181.5 s per node, every
#     one blocked in statx() -> mxfs_dlm_ilock_begin -> the cached-grant
#     ownership verify -> SCSI READ(16)+FUA of the ROOT DIRECTORY's CAW slot,
#     and all 35 timeouts fleet-wide named THE SAME LBA with DID_TIME_OUT.
#   - the SAME 32 nodes unmounting 3 s apart: 0.04-0.09 s per node, zero
#     timeouts.
#   - the teardown work itself, once reached, takes ~0.5 s.
#
# So the cost is the CONCURRENCY of what the nodes do on the shared LUN, not
# unmount.  This test asks the narrow question that follows: is N-way
# concurrent probing of ONE hot slot enough on its own to starve the LUN?
#
# It does nothing but `stat` the mount point on every node at once — no
# unmount, no writes, no membership change.  Every node's statx takes the same
# path into the same root-inode slot.
#
#   PASS  = concurrent stat of the mount root stays inside BUDGET_MS.  The
#           hot-slot probe is not, on its own, the starvation mechanism, and
#           the mass-unmount stall needs something else in the mix.
#   FAIL  = it reproduces without any unmount at all: the verify's per-serve
#           slot probe on a shared hot inode is an O(N) cluster-wide
#           serialization point, which makes this a general metadata-path
#           defect, not an unmount-path one.
#
# Usage: tests/hotslot_contention.sh [N] [SECONDS] [BUDGET_MS]
#   N          fleet size, currently prepped and mounted (default 32)
#   SECONDS    duration of the concurrent stat storm (default 30)
#   BUDGET_MS  worst-case per-stat budget (default 200; native XFS stat of a
#              cached directory is microseconds, this is a very loose 2x-native)
#
# Leaves the fleet mounted and untouched.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:-32}"
SECS="${2:-30}"
BUDGET_MS="${3:-200}"
MNT=/mnt/shared

OUT=$(mktemp -d)
T0=$(date -u +%FT%TZ)
echo "=== hotslot_contention: N=$N dur=${SECS}s budget=${BUDGET_MS}ms/stat @ $T0 ==="
echo "--- evidence dir: $OUT"

notmounted=""
for i in $(seq 1 "$N"); do
    ( m=$("$SSH" "test$i" "mountpoint -q $MNT && echo Y || echo N" 2>/dev/null | tr -d ' \r\n')
      echo "$m" > "$OUT/pre.test$i" ) &
done
wait
for i in $(seq 1 "$N"); do
    [ "$(cat "$OUT/pre.test$i" 2>/dev/null)" = "Y" ] || notmounted="$notmounted test$i"
done
[ -n "$notmounted" ] && { echo "ABORT: not mounted:$notmounted"; exit 2; }
echo "precondition OK: all $N nodes mounted"

for i in $(seq 1 "$N"); do
    "$SSH" "test$i" "dmesg --clear" >/dev/null 2>&1 &
done
wait

# The storm.  Each node loops `stat` on the mount root for SECS seconds and
# reports count + worst single-call latency, measured on the node in ns.
echo "--- $N nodes stat'ing $MNT concurrently for ${SECS}s"
for i in $(seq 1 "$N"); do
    ( "$SSH" "test$i" "
        end=\$(( \$(date +%s) + $SECS )); n=0; worst=0; tot=0
        while [ \$(date +%s) -lt \$end ]; do
            a=\$(date +%s%N); stat -c %i $MNT >/dev/null 2>&1; b=\$(date +%s%N)
            d=\$(( (b - a) / 1000000 ))
            n=\$((n+1)); tot=\$((tot+d))
            [ \$d -gt \$worst ] && worst=\$d
        done
        echo \"STATS n=\$n worst_ms=\$worst mean_ms=\$(( tot / (n>0?n:1) ))\"" \
      > "$OUT/stat.test$i" 2>&1 ) &
done
wait

echo
echo "=== per-node stat latency (budget ${BUDGET_MS}ms) ==="
: > "$OUT/lat"
for i in $(seq 1 "$N"); do
    l=$(grep -o 'STATS n=[0-9]* worst_ms=[0-9]* mean_ms=[0-9]*' "$OUT/stat.test$i" 2>/dev/null | tail -1)
    n=$(echo "$l" | sed -n 's/.*n=\([0-9]*\).*/\1/p')
    w=$(echo "$l" | sed -n 's/.*worst_ms=\([0-9]*\).*/\1/p')
    m=$(echo "$l" | sed -n 's/.*mean_ms=\([0-9]*\).*/\1/p')
    [ -n "$w" ] || { n=0; w=-1; m=-1; }
    printf '%s test%s %s %s\n' "$w" "$i" "$n" "$m" >> "$OUT/lat"
done
sort -grk1 "$OUT/lat" | awk -v b="$BUDGET_MS" '
    { printf "  %-8s worst=%7sms mean=%5sms stats=%-7s %s\n", $2, $1, $4, $3, ($1 > b ? "OVER-BUDGET" : "ok");
      if ($1 > b) over++; if ($1 > mx) mx = $1; ops += $3 }
    END { printf "  ---- worst=%sms over_budget=%d/%d total_stats=%d\n", mx, over+0, NR, ops }'
NOVER=$(awk -v b="$BUDGET_MS" '$1 > b' "$OUT/lat" | wc -l)
MAXW=$(sort -grk1 "$OUT/lat" | head -1 | awk '{print $1}')

echo
echo "--- DLM / transport markers from the storm"
for i in $(seq 1 "$N"); do
    "$SSH" "test$i" "dmesg 2>/dev/null | grep -E 'P302-FUA-READ-DEADLINE|P303-VERIFY-BREAKER|P-FUA-READ-RETRY|P-FUA-READ-ERR|P108-REACQUIRE|P106-STALE-EX|P139-LOCKTOTAL|P34-ACQ-SLOW|P73-WAITSTALL'" \
        > "$OUT/marks.test$i" 2>/dev/null &
done
wait
for m in P302-FUA-READ-DEADLINE P303-VERIFY-BREAKER P-FUA-READ-RETRY P-FUA-READ-ERR P108-REACQUIRE P106-STALE-EX P139-LOCKTOTAL P34-ACQ-SLOW P73-WAITSTALL; do
    printf '  %-26s %s\n' "$m" "$(cat "$OUT"/marks.test* 2>/dev/null | grep -c "$m")"
done
echo "--- distinct FUA-retry LBAs:"
cat "$OUT"/marks.test* 2>/dev/null | grep -o 'lba=[0-9]*' | sort | uniq -c | sed 's/^/  /'

echo
if [ "$NOVER" -eq 0 ]; then
    echo "=== hotslot_contention PASS — worst stat ${MAXW}ms across $N nodes ==="
    echo "evidence: $OUT"
    exit 0
fi
echo "=== hotslot_contention FAIL — $NOVER/$N node(s) over ${BUDGET_MS}ms, worst=${MAXW}ms ==="
echo "evidence: $OUT"
exit 1
