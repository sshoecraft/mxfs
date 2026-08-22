#!/bin/bash
# sbclean_fence_idle.sh — #94 D-IDLE-SLICE-WSKIP-REFUSAL-AG-QUARANTINE-0130
# closure test (sess351 GPT ruling; fix landed 0.13.1 sess352).
#
# Reproduces the sess350 natural incident deliberately: an ACTIVE-then-IDLE
# node's journal slice ends up containing ONLY lazy counter-only SB
# transactions (log covering).  Fencing that node used to make the elected
# replayer refuse the slice as "torn" (P227-FR-TORN-UNPUBLISHED) and
# quarantine AG 0 cluster-wide (P241-RECOV-TERMINAL).  With the 0.13.1
# clean-skip classifier the replayer must instead CLEAN-SKIP those
# transactions and publish recovery normally.
#
# Choreography:
#   1. Victim V does brief FS activity (dirties SB counters), then idles
#      IDLE_WAIT s so XFS log covering leaves only counter-only SB txns in
#      its slice.
#   2. virsh suspend V past the death threshold (~65s observed sess350).
#      Peers fence V; the elected replayer replays V's slice.
#   3. Asserts (all nodes, since T0), while V is still suspended:
#      P1: >=1 P227-FR-SBCOUNTER-CLEANSKIP on the replayer
#      P2: "foreign replay of slot S complete (sbclean_skips=K)" with K>=1
#      P3: ZERO P227-FR-TORN-UNPUBLISHED, ZERO P227-FR-ATOMIC-SKIP,
#          ZERO P241-RECOV-TERMINAL anywhere
#      P4: victim hb slot NOT left in RECOVERY_GUARD (flags=3) — no freeze
#      P5: zero shutdown/withdraw on the 31 live nodes
#   4. Resume V (it self-fences on SLOT_TAKEOVER — expected, not asserted
#      against), power-cycle it, rejoin via prep_node.sh caw:
#      P6: V remounts and reports active_count=N.
#
# Usage: tests/sbclean_fence_idle.sh [V] [OBS] [N]
#   V    victim node / libvirt domain (default test2)
#   OBS  node for slotdump reads + health (default test1; != V)
#   N    cluster size (default 32)
#
# RULE 0 budget: activity 10s + idle 90s + fence wait ~70s + replay poll
# <=60s + sweep 15s + resume/cycle/boot/rejoin ~120s + converge 15s ~= 380s.
# External timeout: 480s.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"

V="${1:-test2}"
OBS="${2:-test1}"
N="${3:-32}"
DEV=/dev/mapper/mpatha
MNT=/mnt/shared
DUMP="/src/mxfs/tools/caw_slotdump"
VIRSH="sudo virsh -c qemu:///system"
IDLE_WAIT="${IDLE_WAIT:-90}"

fail=0
td=$(mktemp -d)
echo "=== sbclean_fence_idle: V=$V OBS=$OBS N=$N idle=${IDLE_WAIT}s ==="

# 0. Preconditions.
for h in "$V" "$OBS"; do
    m=$("$SSH" "$h" "mountpoint -q $MNT && echo Y" 2>/dev/null | tr -d ' \r\n')
    [ "$m" = "Y" ] || { echo "FAIL: $h not mounted"; exit 1; }
done
$VIRSH domstate "$V" 2>/dev/null | grep -q running || {
    echo "FAIL: libvirt domain $V not running"; exit 1; }

# 1. Activity on V: dirty the SB counters (alloc+free), then idle so log
#    covering reduces V's slice to counter-only SB transactions.
echo "--- activity on $V, then idle ${IDLE_WAIT}s for log covering"
"$SSH" "$V" "mkdir -p $MNT/.sbclean_$V && for i in \$(seq 1 20); do dd if=/dev/zero of=$MNT/.sbclean_$V/f\$i bs=1M count=2 conv=fsync 2>/dev/null; done && rm -f $MNT/.sbclean_$V/f* && sync" >/dev/null 2>&1 \
    || { echo "FAIL: activity phase on $V"; exit 1; }
sleep "$IDLE_WAIT"

# 2. Suspend V past the death threshold; poll for the replay outcome.
T0=$(date -u +%FT%TZ)
echo "--- T0=$T0; suspending $V"
$VIRSH suspend "$V" >/dev/null || { echo "FAIL: virsh suspend $V"; exit 1; }
SUSP_T0=$SECONDS

sweep() {  # $1 = grep -E pattern, $2 = outdir prefix; scans all N except V
    local pat="$1" pfx="$2" i h
    for i in $(seq 1 "$N"); do
        h="test$i"
        [ "$h" = "$V" ] && continue
        "$SSH" "$h" "journalctl -k --since '$T0' --no-pager 2>/dev/null | grep -E '$pat'" > "$td/$pfx.$h" 2>/dev/null &
    done
    wait
}

echo "--- waiting for fence + foreign replay (poll from t+60s, cap t+240s)"
sleep 60
outcome=""
while [ $((SECONDS - SUSP_T0)) -lt 240 ]; do
    sweep 'foreign replay of slot .* complete|P227-FR-TORN-UNPUBLISHED|P241-RECOV-TERMINAL' rp
    if grep -l . "$td"/rp.test* >/dev/null 2>&1; then
        outcome=found; break
    fi
    sleep 10
done
FENCE_WALL=$((SECONDS - SUSP_T0))
if [ -z "$outcome" ]; then
    echo "FAIL: no replay outcome (complete/TORN/P241) on any node within ${FENCE_WALL}s of suspend"
    fail=1
fi

# 3. Asserts while V is still down.
sweep 'P227-FR-SBCOUNTER-CLEANSKIP|P227-FR-TORN-UNPUBLISHED|P227-FR-ATOMIC-SKIP|P241-RECOV-TERMINAL|P227-TOKENSUM|foreign replay of slot .* complete|Filesystem has been shut down|MXFS.*withdraw' as
cat "$td"/as.test* > "$td/all" 2>/dev/null

cleanskip=$(grep -c 'P227-FR-SBCOUNTER-CLEANSKIP' "$td/all"); cleanskip=${cleanskip:-0}
if [ "$cleanskip" -ge 1 ]; then
    echo "PASS-1: P227-FR-SBCOUNTER-CLEANSKIP x$cleanskip"
    grep 'P227-FR-SBCOUNTER-CLEANSKIP' "$td/all" | head -3
else
    echo "FAIL: zero P227-FR-SBCOUNTER-CLEANSKIP since $T0"
    fail=1
fi

comp=$(grep -E 'foreign replay of slot [0-9]+ complete' "$td/all" | head -1)
VSLOT=$(echo "$comp" | sed -nE 's/.*foreign replay of slot ([0-9]+) complete.*/\1/p')
K=$(echo "$comp" | sed -nE 's/.*sbclean_skips=([0-9]+).*/\1/p')
if [ -n "$comp" ] && [ "${K:-0}" -ge 1 ]; then
    echo "PASS-2: replay complete, slot=$VSLOT sbclean_skips=$K"
    echo "  $comp"
else
    echo "FAIL: no replay-complete with sbclean_skips>=1 (line: '${comp:-none}')"
    fail=1
fi

torn=$(grep -c 'P227-FR-TORN-UNPUBLISHED' "$td/all")
askip=$(grep -c 'P227-FR-ATOMIC-SKIP' "$td/all")
p241=$(grep -c 'P241-RECOV-TERMINAL' "$td/all")
if [ "${torn:-0}" -eq 0 ] && [ "${askip:-0}" -eq 0 ] && [ "${p241:-0}" -eq 0 ]; then
    echo "PASS-3: zero TORN-UNPUBLISHED / ATOMIC-SKIP / P241-RECOV-TERMINAL"
else
    echo "FAIL: torn=$torn atomic_skip=$askip p241=$p241"
    grep -E 'P227-FR-TORN-UNPUBLISHED|P227-FR-ATOMIC-SKIP|P241-RECOV-TERMINAL' "$td/all" | head -5
    fail=1
fi
echo "--- TOKENSUM evidence:"
grep 'P227-TOKENSUM' "$td/all" | head -3

# P4: the GUARD is DESIGNED to persist from IMAGES_REPLAYED until
# recovery_complete's CAW authority purge + flush + sector zero finish
# (measured 10s at 32 nodes, sess354).  Poll up to 45s from now for the
# slot to leave RECOVERY_GUARD; only a freeze that OUTLIVES that window
# is the #94 quarantine symptom.
if [ -n "${VSLOT:-}" ]; then
    p4dl=$((SECONDS + 45)); fl=""; row=""; st="?"
    while [ "$SECONDS" -lt "$p4dl" ]; do
        dump=$("$SSH" "$OBS" "$DUMP $DEV" 2>/dev/null)
        echo "$dump" | grep -q 'heartbeat slots' || { st=noread; sleep 5; continue; }
        row=$(echo "$dump" | grep "^hb\[0*$VSLOT\]")
        if [ -z "$row" ]; then
            # slotdump omits all-zero records: sector zeroed = recovery
            # PUBLISHED (CONSUMABLE) — the strongest form of "not frozen".
            st=zeroed; break
        fi
        fl=$(echo "$row" | sed -nE 's/.*flags=([0-9]+).*/\1/p')
        if [ -n "$fl" ] && [ "$fl" != "3" ]; then st="flags=$fl"; break; fi
        st=guard; sleep 5
    done
    if [ "$st" = "zeroed" ] || [ "${st#flags=}" != "$st" ]; then
        echo "PASS-4: victim slot $VSLOT not frozen ($st)${row:+: $row}"
    else
        echo "FAIL: victim slot $VSLOT state=$st after 45s (guard = RECOVERY_GUARD freeze): $row"
        fail=1
    fi
else
    echo "SKIP-4: no victim slot known (PASS-2 failed)"
fi

sd=$(grep -cE 'Filesystem has been shut down|MXFS.*withdraw' "$td/all")
if [ "${sd:-0}" -eq 0 ]; then
    echo "PASS-5: zero shutdown/withdraw on the $((N-1)) live nodes"
else
    echo "FAIL: $sd shutdown/withdraw lines on live nodes:"
    grep -E 'Filesystem has been shut down|MXFS.*withdraw' "$td/all" | head -5
    fail=1
fi

# 4. Resume V (expected to self-fence), then power-cycle + rejoin.
echo "--- resuming $V (self-fence expected), then power-cycle + rejoin"
$VIRSH resume "$V" >/dev/null || echo "WARN: virsh resume $V failed"
sleep 5
$VIRSH destroy "$V" >/dev/null 2>&1
sleep 2
$VIRSH start "$V" >/dev/null 2>&1 || { echo "FAIL: virsh start $V"; fail=1; }

dl=$((SECONDS + 180)); up=0
while [ "$SECONDS" -lt "$dl" ]; do
    timeout 8 "$SSH" "$V" "echo SSH_UP" 2>/dev/null | grep -q SSH_UP && { up=1; break; }
    sleep 3
done
if [ "$up" -eq 1 ]; then
    timeout 70 "$SSH" "$V" "
        mountpoint -q /src || { mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; }
        iscsiadm -m discovery -t st -p 192.168.120.1:3260 >/dev/null 2>&1
        iscsiadm -m discovery -t st -p 192.168.120.2:3260 >/dev/null 2>&1
        iscsiadm -m node --login >/dev/null 2>&1
        iscsiadm -m session --rescan >/dev/null 2>&1
        multipath >/dev/null 2>&1" >/dev/null 2>&1
    dl=$((SECONDS + 90)); devup=0
    while [ "$SECONDS" -lt "$dl" ]; do
        timeout 8 "$SSH" "$V" "[ -e $DEV ] && mountpoint -q /src && echo DEV_UP" 2>/dev/null | grep -q DEV_UP && { devup=1; break; }
        timeout 20 "$SSH" "$V" "multipath >/dev/null 2>&1" >/dev/null 2>&1
        sleep 3
    done
    if [ "$devup" -eq 1 ]; then
        KO_MD5=$(md5sum "$REPO/mxfs.ko" 2>/dev/null | awk '{print $1}')
        out=$(timeout 120 "$SSH" "$V" "MXFS_DEV='$DEV' MXFS_KO_MD5='$KO_MD5' bash /src/mxfs/tests/setup/prep_node.sh caw" 2>&1)
        if echo "$out" | grep -q NODE_PREP_OK; then
            sleep 10
            ac=$("$SSH" "$V" "dmesg | awk '/DLM initialized/{m=\"\"} /MXFS-MEMBERSHIP/{m=\$0} END{print m}'" 2>/dev/null | grep -oE 'active_count=[0-9]+' | cut -d= -f2)
            if [ "${ac:-0}" = "$N" ]; then
                echo "PASS-6: $V rejoined, active_count=$ac"
            else
                echo "FAIL: $V rejoined but active_count=${ac:-none} (want $N)"
                fail=1
            fi
        else
            echo "FAIL: $V prep_node rejoin: $(echo "$out" | tail -3)"
            fail=1
        fi
    else
        echo "FAIL: $DEV never appeared on rebooted $V"
        fail=1
    fi
else
    echo "FAIL: $V no ssh within 180s of power cycle"
    fail=1
fi

rm -rf "$td"
if [ "$fail" -eq 0 ]; then
    echo "=== sbclean_fence_idle PASS (fence+replay window ${FENCE_WALL}s) ==="
    exit 0
fi
echo "=== sbclean_fence_idle FAIL ==="
exit 1
