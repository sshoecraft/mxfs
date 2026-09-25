#!/bin/bash
# ghost_slot_restart_probe.sh — both nodes of the two-node TCP rig come back
# onto a LUN that still carries the ACTIVE heartbeat records of incarnations
# that died in earlier boots (crash leftovers), with no mkfs and no operator
# action, and the harness measures what the joiners do about those records:
# whether the heartbeat monitor declares them dead, what the fence of each
# classifies, whether their slices are recovered, whether a bootstrap node
# emerges, and whether the mounts complete.
#
# Why: tests/cluster_restart_nomkfs.sh s557/s558 (0.75.68/0.75.69) hung both
# mounts in D state for good; the boot journals showed four stale ACTIVE slots
# auto-monitored at mount and never declared dead 21 minutes later
# (dlm/disklock.c check_dead required the slot to have been seen live), so no
# recovery ran, no bootstrap node existed, and every ledger-page request
# parked.  This probe is the deterministic arm for that shape: the LUN as the
# hung laps left it (slots 0-3 dead ACTIVE), or any LUN after both VMs are
# destroyed with mounts in flight.
#
# Shape: (VM_RESTART=1: virsh destroy + start both, wait for boot) -> deploy
# the tree's mxfs.ko as /root/mxfs.ko.prep on both -> concurrent insmod+mount
# with no mkfs, bound JOIN_BOUND -> capture each node's kernel journal since
# its own MARK -> count the probes -> verdict.
#
# the budget rule (derived): boot ~30-60 s per VM (parallel); dead window 31 x 2 s =
# 62 s before the monitor can declare a frozen record dead; fence certify
# ~30 s healthy, or RECOVERY_BLOCKED at fence_blocked_after_ms (120 s) when
# no proof exists; slice replay seconds.  Healthy join ~100-130 s; bound
# 300 s (JOIN_BOUND).  Whole probe bound ~420 s.
#
# Usage: tests/ghost_slot_restart_probe.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, MXFS_MODARGS (default
#        target_cache_protected=1 force_transport=1), VM_RESTART=1 (default 1),
#        JOIN_BOUND (default 300).
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
KO=/root/mxfs.ko.prep
JOIN_BOUND=${JOIN_BOUND:-300}
VM_RESTART=${VM_RESTART:-1}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_ghost_$LABEL
mkdir -p "$OUT"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== ghost_slot_restart_probe label=$LABEL A=$A B=$B sv=$SV join_bound=${JOIN_BOUND}s vm_restart=$VM_RESTART $(date -u +%FT%TZ) ==="
s0=$(date +%s)

if [ "$VM_RESTART" = 1 ]; then
    for n in $A $B; do
        timeout 30 virsh -c qemu:///system destroy "$n" > /dev/null 2>&1
        timeout 30 virsh -c qemu:///system start "$n" > /dev/null 2>&1
    done
    for n in $A $B; do
        w=0
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 30 ]; do
            w=$((w+1)); sleep 5
        done
        echo "STAGE boot-wait node=$n polls=$w"
    done
    echo "STAGE vm-restart wall=$(( $(date +%s) - s0 ))s"
fi

# deploy the tree build (the source tree reaches the nodes over NFS, mounted
# the way run.sh mounts it; a fresh boot has no /src); refuse to measure a
# different build
MD5=$(md5sum mxfs.ko | cut -c1-32)
for n in $A $B; do
    value_now_into got "$n" 150 "$OUT/rv_got_1.txt" '^[0-9a-f]{32}$' "got on $n" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32"
    ck "$n runs the tree build (md5)" "$got" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy fails=$fails"; exit 2; }

# the slot table before the join (plain reads; recov_forge's FUA READ is
# refused by the QNAP)
rs 60 "$A" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV" > "$OUT/hb_before.txt"
echo "STAGE hb-before: $(grep -c 'flags=ACTIVE' "$OUT/hb_before.txt") ACTIVE record(s)"
grep -a 'flags=ACTIVE' "$OUT/hb_before.txt" | sed 's/^/    /' | cut -c1-110

join() {  # <node> <tag>
    rs $((JOIN_BOUND + 60)) "$1" "M=\$(date +%s); echo MARK=\$M; lsmod | grep -q '^mxfs ' || insmod $KO dyndbg=+p $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; R=\$?; echo MOUNT_RC=\$R; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/$2_join.txt"
}
s=$(date +%s)
join "$A" A &
join "$B" B &
wait
arc=$(field "$OUT/A_join.txt" MOUNT_RC); brc=$(field "$OUT/B_join.txt" MOUNT_RC)
echo "STAGE join A rc=$arc wall=$(field "$OUT/A_join.txt" WALL_MS)ms B rc=$brc wall=$(field "$OUT/B_join.txt" WALL_MS)ms total=$(( $(date +%s) - s ))s"

# the journals since each node's own MARK, and the table after
for n in $A $B; do
    t=$([ "$n" = "$A" ] && echo A || echo B)
    m=$(field "$OUT/${t}_join.txt" MARK)
    rs 30 "$n" "journalctl -k --since @$m --no-pager 2>/dev/null | cut -c1-600" > "$OUT/${t}_journal.txt"
done
rs 60 "$A" "python3 /src/mxfs/tools/disklock_hb_dump.py $MXFS_DEV" > "$OUT/hb_after.txt"

cnt() { grep -ac "$2" "$OUT/$1_journal.txt"; }
for t in A B; do
    n=$([ "$t" = A ] && echo "$A" || echo "$B")
    echo "--- $n ($t) probes since MARK"
    for pat in 'P-HB-GHOST-DEAD' 'no longer responding' 'P163-RECOVERY-PENDING' 'P236-FENCEKIND' 'P304-FENCE-RETRY' 'P238-FENCE-BLOCKED' 'P238-FENCE-ABSENT' 'P-RBLK' 'P163-RECOVERED' 'foreign replay of slot' 'P-TAUTH-ORPHAN-SWEEP' 'P-TAUTH-TAKEOVER' 'P-TAUTH-PAGE-PARKED' 'lock request failed after' 'shutting down filesystem' 'BUG:\|Oops\|WARNING:'; do
        printf '    %-28s %s\n' "$pat" "$(cnt $t "$pat")"
    done
    grep -ao 'P236-FENCEKIND[^—]*' "$OUT/${t}_journal.txt" | sort | uniq -c | sed 's/^/    /' | cut -c1-160
    grep -ao 'P-HB-GHOST-DEAD[^—]*' "$OUT/${t}_journal.txt" | sed 's/^/    /' | cut -c1-120
    grep -ao 'P-TAUTH-ORPHAN-SWEEP[^—]*\|P-DEPART-WORK-ORPHAN-SWEEP[^—]*' "$OUT/${t}_journal.txt" | sed 's/^/    /' | cut -c1-160
    ck "$n mounted inside ${JOIN_BOUND}s" "$(grep -ao 'MOUNTED\|NOT_MOUNTED' "$OUT/${t}_join.txt" | tail -1)" "MOUNTED"
    ck "$n: zero 'lock request failed after'" "$(cnt $t 'lock request failed after')" "0"
    ck "$n: zero shutdown / BUG / Oops" "$(( $(cnt $t 'shutting down filesystem') + $(cnt $t 'BUG:\|Oops') ))" "0"
done
echo "STAGE hb-after: $(grep -c 'flags=ACTIVE' "$OUT/hb_after.txt") ACTIVE record(s)"
grep -a 'flags=ACTIVE' "$OUT/hb_after.txt" | sed 's/^/    /' | cut -c1-110
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"; fi
exit $fails
