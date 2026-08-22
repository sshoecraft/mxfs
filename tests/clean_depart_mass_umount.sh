#!/bin/bash
# clean_depart_mass_umount.sh — #92 D-CLEAN-RELEASE-TREATED-AS-DEATH-
# PHANTOM-RECOVERY-526 verification (sess344 GPT ruling, landed 0.13.0).
#
# Reproduces the sess342 trigger: with the whole fleet mounted, mass-unmount
# every node except one survivor concurrently.  Each departing node's
# disklock slot goes FLAG_EMPTY (clean release); before 0.13.0 the peers'
# monitors had no EMPTY arm and declared the LIVE-but-released slots dead
# ("no longer responding"), fenced them, and latched phantom recovery
# (P163-RECOVERY-PENDING livelock, rc=-116).
#
# PASS (all must hold):
#   1. zero "no longer responding" on EVERY node since T0 (no node died —
#      any death declaration is a false death),
#   2. zero P163-RECOVERY-PENDING on the survivor since T0,
#   3. >=1 P163-CLEAN-DEPART* on the survivor (positive evidence the new
#      clean-departure arms did the retire, not some silent path),
#   4. survivor still writable after the storm (not shut down/withdrawn).
#
# Topology: fleet freshly prepped + mounted (post prep_cluster).  Leaves
# only the survivor mounted.
#
# Usage: tests/clean_depart_mass_umount.sh [N] [survivor]
#   N         fleet size currently prepped (default 32)
#   survivor  node that keeps its mount (default test1)
#
# RULE 0 budget: 31-way umount ~100s (sess342 measured; the serialize is
# ledgered separately as #93) + 120s observe window + sweeps ~40s = 260s;
# budget 330s.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

N="${1:-32}"
SURV="${2:-test1}"
MNT=/mnt/shared
OBSERVE_S="${OBSERVE_S:-120}"

T0=$(date -u +%FT%TZ)
echo "=== clean_depart_mass_umount: N=$N survivor=$SURV @ $T0 ==="

# 0. Preconditions: survivor mounted and writable.
ok=$("$SSH" "$SURV" "mountpoint -q $MNT && echo seed > $MNT/.cdmu_seed && sync $MNT/.cdmu_seed 2>/dev/null && echo W_OK" 2>/dev/null | tr -d ' \r\n')
[ "$ok" = "W_OK" ] || { echo "FAIL: survivor $SURV not mounted/writable (fleet not prepped?)"; exit 1; }

# 1. Mass-unmount every node except the survivor (parallel, bounded per
#    RULE 2c).
echo "--- mass-unmounting $((N-1)) nodes (all except $SURV)"
UM_T0=$SECONDS
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$SURV" ] && continue
    "$SSH" "$h" "timeout 150 umount $MNT" >/dev/null 2>&1 &
done
wait
UM_WALL=$((SECONDS - UM_T0))
still=""
for i in $(seq 1 "$N"); do
    h="test$i"
    [ "$h" = "$SURV" ] && continue
    m=$("$SSH" "$h" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
    [ "$m" = "Y" ] && still="$still $h"
done
if [ -n "$still" ]; then
    echo "FAIL: still mounted after mass umount:$still (wall=${UM_WALL}s)"
    exit 1
fi
echo "all $((N-1)) nodes unmounted in ${UM_WALL}s"

# 2. Observe window: longer than the death-confirm window (~62s) so any
#    false death that WOULD fire has fired before we assert.
echo "--- observing ${OBSERVE_S}s (death-confirm window is ~62s)"
sleep "$OBSERVE_S"

# 3. Cluster-wide false-death sweep + survivor latch sweep.
td=$(mktemp -d)
for i in $(seq 1 "$N"); do
    h="test$i"
    "$SSH" "$h" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -E 'no longer responding|P163-RECOVERY-PENDING|P163-CLEAN-DEPART|P164-DEAD-REJECT|Filesystem has been shut down|MXFS.*withdraw' " > "$td/$h" 2>/dev/null &
done
wait

fail=0
fd_total=0
for i in $(seq 1 "$N"); do
    h="test$i"
    fd=$(grep -c "no longer responding" "$td/$h" 2>/dev/null); fd=${fd:-0}
    if [ "$fd" -gt 0 ]; then
        echo "FAIL: $h declared $fd false death(s):"
        grep "no longer responding" "$td/$h" | head -5
        fd_total=$((fd_total + fd)); fail=1
    fi
done
[ "$fd_total" -eq 0 ] && echo "PASS-1: zero false-death declarations across all $N nodes"

rp=$(grep -c "P163-RECOVERY-PENDING" "$td/$SURV" 2>/dev/null); rp=${rp:-0}
if [ "$rp" -gt 0 ]; then
    echo "FAIL: survivor latched P163-RECOVERY-PENDING x$rp:"
    grep "P163-RECOVERY-PENDING" "$td/$SURV" | head -5
    fail=1
else
    echo "PASS-2: zero P163-RECOVERY-PENDING on survivor"
fi

cd_n=$(grep -c "P163-CLEAN-DEPART" "$td/$SURV" 2>/dev/null); cd_n=${cd_n:-0}
if [ "$cd_n" -lt 1 ]; then
    echo "FAIL: survivor logged no P163-CLEAN-DEPART (expected the new arms to retire $((N-1)) released slots)"
    fail=1
else
    echo "PASS-3: survivor P163-CLEAN-DEPART x$cd_n:"
    grep "P163-CLEAN-DEPART" "$td/$SURV" | head -8
fi

# 4. Survivor health after the storm.
hw=$("$SSH" "$SURV" "mountpoint -q $MNT && echo post > $MNT/.cdmu_post && sync $MNT/.cdmu_post 2>/dev/null && echo W_OK" 2>/dev/null | tr -d ' \r\n')
sd=$(grep -cE "Filesystem has been shut down|MXFS.*withdraw" "$td/$SURV" 2>/dev/null); sd=${sd:-0}
if [ "$hw" = "W_OK" ] && [ "$sd" -eq 0 ]; then
    echo "PASS-4: survivor still mounted+writable, no shutdown/withdraw"
else
    echo "FAIL: survivor health — write=$hw shutdown/withdraw-lines=$sd"
    grep -E "Filesystem has been shut down|withdraw" "$td/$SURV" | head -5
    fail=1
fi

rm -rf "$td"
if [ "$fail" -eq 0 ]; then
    echo "=== clean_depart_mass_umount PASS (umount wall=${UM_WALL}s) ==="
    exit 0
fi
echo "=== clean_depart_mass_umount FAIL ==="
exit 1
