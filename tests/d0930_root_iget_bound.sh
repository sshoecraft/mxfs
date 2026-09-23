#!/bin/bash
# d0930_root_iget_bound.sh — the mount's root iget must FAIL CLOSED when AG 0's
# authority stays unreachable, never loop in D state.  Two-node TCP rig.
#
# Why: D-0930 — the DLM answers an acquire that outlived its retry budget with
# EAGAIN, the untrusted-iget bracket passed it through, and xfs_iget retried
# any EAGAIN forever with an uninterruptible delay: the mount sat in D state
# for good (s556-s559c), unkillable, the device held, only a host reset ending
# it.  0.75.72 bounds the bracket (mxfs.untrusted_aglock_budgets, then EIO).
# The shape that produced it — a crash-restart pile-up leaving AG 0's ledger
# page with no reachable authority — is resolved by the recovery fixes since
# 0.75.70, so this arm forces the bracket's answer instead:
# mxfs.untrusted_aglock_inject_eagain (0.75.78, TEST ONLY) answers the next N
# untrusted-iget AG acquires with EAGAIN without asking the DLM.
#
# Shape: leave both nodes -> deploy the tree build -> B joins normally (so A's
# mount is multi-node; a single-node mount skips the bracket) -> A insmods with
# untrusted_aglock_budgets=2 untrusted_aglock_inject_eagain=100 and mounts:
# the mount must return NON-ZERO to userspace, the journal must carry
# P-IMAP-UNTRUSTED-AGLOCK-INJECT, P-IMAP-UNTRUSTED-AGLOCK-GIVEUP budgets=2
# and 'Failed to read root inode', no mount process may be left in D state,
# and rmmod must succeed -> A insmods normally and mounts: MOUNTED (the failed
# attempt unwound cleanly) -> leave both.
#
# the budget rule (derived): leave <= 20 s per node; deploy <= 20 s; B join <= 60 s
# (healthy 1-5 s; up to ~130 s only on a LUN with dead slots, which this arm
# does not expect); A negative mount: the injected answers cost no DLM wait,
# so the mount fails in the barrier + iget overhead, <= 60 s; A positive join
# <= 60 s; leaves <= 40 s.  Whole harness bound 300 s.
#
# Usage: tests/d0930_root_iget_bound.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default: A's live
#        mxfs mount's device, else the MXFS_TRANSPORT rig default, via
#        mxfs_dev_resolve — no rig's device path is assumed), MXFS_MODARGS
#        (default target_cache_protected=1 force_transport=1), BUDGETS
#        (default 2), MXFS_FAULT_UMOUNT_SRC=<node>:deploy (capture-contract
#        verification only: a real `umount -l /src` on <node> right before
#        the module copy; the lap must then ABORT, never reach a verdict).
#
# Every capture a verdict is taken from crosses tests/lib/rig.sh's boundary
# (rsx + capture_require in the parent shell) before it is counted.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
BUDGETS=${BUDGETS:-2}
KO=/root/mxfs.ko.prep
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0930_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/cnt/capture_require/ensure_src_or_abort/mxfs_dev_resolve (tests/lib/rig.sh)
. "$(dirname "$0")/lib/rig.sh"
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
fault_before() { # <stage>
    case ${MXFS_FAULT_UMOUNT_SRC:-} in
        *:"$1") echo "STAGE FAULT: unmounting /src on ${MXFS_FAULT_UMOUNT_SRC%%:*} before $1"; rs 30 "${MXFS_FAULT_UMOUNT_SRC%%:*}" "umount -l /src; mountpoint -q /src && echo STILL || echo GONE" | tail -1 ;;
    esac
}
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0930_root_iget_bound label=$LABEL A=$A B=$B sv=$SV budgets=$BUDGETS $(date -u +%FT%TZ) ==="
s0=$(date +%s)

# the LUN as MXFS uses it: A's live mount if it has one, else the transport's
# rig default (both nodes may already be unmounted when this starts)
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
echo "STAGE device=$MXFS_DEV"

# leave <node> <tag>: acquires only.  The two leaves run in parallel, so the
# caller validates $OUT/<tag>_leave.txt after `wait` (an exit inside a
# backgrounded function does not stop the harness).
leave() {  # <node> <tag>
    rsx 70 "$1" "mountpoint -q $MNT && timeout 40 umount $MNT; echo UMOUNT_RC=\$?; for i in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null; lsmod | grep -q '^mxfs' || break; sleep 2; done; lsmod | grep -q '^mxfs' && echo STILL_LOADED || echo UNLOADED" > "$OUT/$2_leave.txt"
}
leave_require() {  # <tag> <node>
    capture_require "$OUT/$1_leave.txt" '^(UNLOADED|STILL_LOADED)$' "$1: the departure of $2"
}
join() {  # <node> <tag> <modargs> <bound>
    rsx $(( $4 + 30 )) "$1" "M=\$(date +%s); echo MARK=\$M; lsmod | grep -q '^mxfs ' || insmod $KO $3; echo INSMOD_RC=\$?; T0=\$(date +%s%N); timeout $4 mount -t mxfs $MXFS_DEV $MNT; R=\$?; echo MOUNT_RC=\$R; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED; echo DSTATE_MOUNTS=\$(ps -o stat= -C mount 2>/dev/null | grep -c '^D')" > "$OUT/$2_join.txt"
    capture_require "$OUT/$2_join.txt" '^(MOUNTED|NOT_MOUNTED)$' "$2: the mount on $1"
    capture_require "$OUT/$2_join.txt" '^MARK=[0-9]+$' "$2: the clock mark of the mount on $1"
    capture_require "$OUT/$2_join.txt" '^DSTATE_MOUNTS=[0-9]+$' "$2: the D-state census on $1"
}
journal() {  # <node> <tag>
    local m; m=$(field "$OUT/$2_join.txt" MARK)
    rsx 30 "$1" "journalctl -k --since @$m --no-pager 2>/dev/null | cut -c1-400" > "$OUT/$2_journal.txt"
    capture_require "$OUT/$2_journal.txt" 'kernel: ' "$2: the kernel journal on $1 across its mount"
}

leave "$A" A0 & leave "$B" B0 & wait
leave_require A0 "$A"; leave_require B0 "$B"
echo "STAGE leave0 A=$(grep -ao 'UNLOADED\|STILL_LOADED' "$OUT/A0_leave.txt" | tail -1) B=$(grep -ao 'UNLOADED\|STILL_LOADED' "$OUT/B0_leave.txt" | tail -1) wall=$(( $(date +%s) - s0 ))s"

MD5=$(md5sum mxfs.ko | cut -c1-32)
ensure_src_or_abort "$A" "$B"
for n in $A $B; do
    fault_before deploy
    rsx 60 "$n" "cp /src/mxfs/mxfs.ko $KO && md5sum $KO | cut -c1-32" > "$OUT/${n}_md5.txt"
    capture_require "$OUT/${n}_md5.txt" '^[0-9a-f]{32}$' "the module copy on $n"
    ck "$n runs the tree build (md5)" "$(head -1 "$OUT/${n}_md5.txt")" "$MD5"
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL deploy fails=$fails"; exit 2; }

# B joins normally: A's mount below must be a multi-node mount.
s=$(date +%s)
join "$B" B1 "$MODARGS" 60
echo "STAGE B-join rc=$(field "$OUT/B1_join.txt" MOUNT_RC) wall=$(field "$OUT/B1_join.txt" WALL_MS)ms total=$(( $(date +%s) - s ))s"
ck "$B mounted (the peer that makes A's mount multi-node)" "$(grep -ao 'MOUNTED\|NOT_MOUNTED' "$OUT/B1_join.txt" | tail -1)" "MOUNTED"
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL B did not mount fails=$fails"; exit 2; }

# A: the negative arm.  Every untrusted-iget AG acquire answers EAGAIN.
s=$(date +%s)
join "$A" A1 "$MODARGS untrusted_aglock_budgets=$BUDGETS untrusted_aglock_inject_eagain=100" 120
journal "$A" A1
arc=$(field "$OUT/A1_join.txt" MOUNT_RC); awall=$(field "$OUT/A1_join.txt" WALL_MS)
echo "STAGE A-negative rc=$arc wall=${awall}ms total=$(( $(date +%s) - s ))s"
ck "$A negative mount returned to userspace non-zero" "$([ -n "$arc" ] && [ "$arc" != 0 ] && echo yes || echo no)" "yes"
ck "$A negative mount NOT_MOUNTED" "$(grep -ao 'MOUNTED\|NOT_MOUNTED' "$OUT/A1_join.txt" | tail -1)" "NOT_MOUNTED"
ck "$A negative mount inside 60 s" "$([ -n "$awall" ] && [ "$awall" -lt 60000 ] && echo yes || echo no)" "yes"
ck "$A no mount process left in D state" "$(field "$OUT/A1_join.txt" DSTATE_MOUNTS)" "0"
ck "$A P-IMAP-UNTRUSTED-AGLOCK-INJECT fired" "$([ "$(cnt "$OUT/A1_journal.txt" 'P-IMAP-UNTRUSTED-AGLOCK-INJECT')" -ge 1 ] && echo yes || echo no)" "yes"
ck "$A P-IMAP-UNTRUSTED-AGLOCK-GIVEUP budgets=$BUDGETS" "$(cnt "$OUT/A1_journal.txt" "P-IMAP-UNTRUSTED-AGLOCK-GIVEUP.*budgets=$BUDGETS ")" "1"
ck "$A 'Failed to read root inode'" "$([ "$(cnt "$OUT/A1_journal.txt" 'Failed to read root inode')" -ge 1 ] && echo yes || echo no)" "yes"
ck "$A zero 'lock request failed after'" "$(cnt "$OUT/A1_journal.txt" 'lock request failed after')" "0"
ck "$A zero shutdown / BUG / Oops" "$(( $(cnt "$OUT/A1_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/A1_journal.txt" 'BUG:\|Oops') ))" "0"
grep -ao 'P-IMAP-UNTRUSTED-AGLOCK-GIVEUP[^—]*\|Failed to read root inode[^"]*' "$OUT/A1_journal.txt" | head -3 | sed 's/^/    /' | cut -c1-160

# A must be able to unload (no D-state holder) and then join normally.
leave "$A" A2
leave_require A2 "$A"
ck "$A module unloaded after the failed mount" "$(grep -ao 'UNLOADED\|STILL_LOADED' "$OUT/A2_leave.txt" | tail -1)" "UNLOADED"
s=$(date +%s)
join "$A" A3 "$MODARGS" 60
journal "$A" A3
echo "STAGE A-positive rc=$(field "$OUT/A3_join.txt" MOUNT_RC) wall=$(field "$OUT/A3_join.txt" WALL_MS)ms total=$(( $(date +%s) - s ))s"
ck "$A mounted normally after the failed attempt" "$(grep -ao 'MOUNTED\|NOT_MOUNTED' "$OUT/A3_join.txt" | tail -1)" "MOUNTED"
ck "$A positive join: zero 'lock request failed after'" "$(cnt "$OUT/A3_journal.txt" 'lock request failed after')" "0"

leave "$A" A4 & leave "$B" B4 & wait
leave_require A4 "$A"; leave_require B4 "$B"
ck "$A left cleanly" "$(grep -ao 'UNLOADED\|STILL_LOADED' "$OUT/A4_leave.txt" | tail -1)" "UNLOADED"
ck "$B left cleanly" "$(grep -ao 'UNLOADED\|STILL_LOADED' "$OUT/B4_leave.txt" | tail -1)" "UNLOADED"
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=$(( $(date +%s) - s0 ))s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(( $(date +%s) - s0 ))s evidence=$OUT"; fi
exit $fails
