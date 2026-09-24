#!/bin/bash
#
# concurrent_umount_lease.sh — a peer's GOODBYE delivered while this node's
# DLM teardown is past the lease stop must not reach a freed lease context.
#
# 0.89.84 oopsed in tests/packaged_round.sh: both nodes unmounted at once,
# test3's teardown freed the lease context and only later stopped the peer
# transport, and test4's GOODBYE made test3's peer receive thread call
# mxfs_lease_unregister_node on the freed context.  SLUB's freelist pointer
# sits at offset 0x1000 of that 8 KiB object, where node_count is, so the
# shift of nodes[] ran with a length of ~35 GB (memmove oops in mxfs-worker).
#
# The window between the lease stop and the peer shutdown is milliseconds,
# so the victim's teardown is held open there with the one-shot knob
# dbg_teardown_lease_hold_ms, and the peer unmounts inside the hold:
#
#   1. a fresh 2/tcp cluster (./run.sh 2 tcp prep_cluster, test1 + test2)
#   2. arm the hold on the victim, unmount the victim in the background
#   3. when the victim logs P-DBG-TEARDOWN-LEASE-HOLD, unmount the peer
#   4. both unmounts must finish; the victim's log must show the GOODBYE
#      received during the hold and no P-LEASE-COUNT-INSANE, BUG or Oops
#
# P-LEASE-COUNT-INSANE is the detector: mxfs_lease_unregister_node refuses a
# node_count outside 0..MXFS_MAX_NODES, which only a freed context produces,
# so the unfixed ordering shows it on every run whatever sign the garbage
# count has, instead of oopsing about half the time.
#
# Budgets: prep_cluster measured 39 s on the QNAP LUN (run.sh enforces it);
# a clean 2-node TCP unmount measured 35-80 s with the peer mounted, doubled
# -> UMOUNT_S=160; the hold is HOLD_MS (default 20 s) on top of the
# victim's unmount.
#
# Usage: tests/concurrent_umount_lease.sh [victim] [peer] [hold_ms]
#   Exit 0 only if both unmounts finished and the victim logged the GOODBYE
#   inside the hold without the detector firing.
#   Evidence: tests/evidence/concurrent_umount_lease/<stamp>/.
#
set -u

V="${1:-test1}"
P="${2:-test2}"
HOLD_MS="${3:-20000}"
UMOUNT_S=160
MNT=/mnt/shared
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SSH="$HERE/tools/mxfs_sshpass.sh"
EV="$HERE/tests/evidence/concurrent_umount_lease/$(date +%Y%m%dT%H%M%S)"
mkdir -p "$EV"
exec > >(tee -a "$EV/run.log") 2>&1
say() { echo "[$(date +%T)] $*"; }
fail() { say "FAIL: $*"; say "RESULT FAIL"; exit 1; }
on() { local h=$1 t=$2; shift 2; timeout "$t" "$SSH" "$h" "$@" 2>&1 | grep --line-buffered -v -E "^Warning: Permanently|^$|Unauthorized access|authorized user, disconnect"; return "${PIPESTATUS[0]}"; }

say "victim=$V peer=$P hold_ms=$HOLD_MS evidence=$EV"
say "build: $(modinfo -F srcversion "$HERE/mxfs.ko")"

# --- 1. fresh cluster
(cd "$HERE" && ./run.sh 2 tcp prep_cluster) > "$EV/prep_cluster.log" 2>&1 || { tail -20 "$EV/prep_cluster.log"; fail "prep_cluster"; }
for h in $V $P; do
    on $h 20 "grep -c ' $MNT mxfs ' /proc/mounts; cat /sys/module/mxfs/srcversion" > "$EV/mounted_$h.log"
    [ "$(head -1 "$EV/mounted_$h.log")" = 1 ] || fail "$h is not mounted after prep_cluster"
done
say "both mounted, srcversion $(tail -1 "$EV/mounted_$V.log")"
on $V 10 "dmesg -C" >/dev/null

# --- 2. hold the victim's teardown past the lease stop
on $V 10 "echo $HOLD_MS > /sys/module/mxfs/parameters/dbg_teardown_lease_hold_ms" || fail "arming the hold"
T0=$(date +%s)
on $V $UMOUNT_S "timeout $((UMOUNT_S - 10)) umount $MNT; echo umount_rc=\$?" > "$EV/umount_$V.log" 2>&1 &
VPID=$!

# --- 3. the peer unmounts inside the hold
held=0
while [ $(( $(date +%s) - T0 )) -lt $UMOUNT_S ]; do
    on $V 10 "dmesg | grep -q P-DBG-TEARDOWN-LEASE-HOLD" && { held=1; break; }
    kill -0 $VPID 2>/dev/null || break
    sleep 1
done
[ $held = 1 ] || { wait $VPID; fail "the victim never reached the hold (umount_$V.log: $(tr '\n' ' ' < "$EV/umount_$V.log"))"; }
say "victim held after the lease stop at +$(( $(date +%s) - T0 )) s; unmounting $P"
on $P $UMOUNT_S "timeout $((UMOUNT_S - 10)) umount $MNT; echo umount_rc=\$?" > "$EV/umount_$P.log" 2>&1
wait $VPID
say "unmounts done at +$(( $(date +%s) - T0 )) s"

# --- 4. verdict
on $V 20 "dmesg" > "$EV/dmesg_$V.log"
on $P 20 "dmesg | tail -300" > "$EV/dmesg_$P.log"
grep -h -E "P-DBG-TEARDOWN-LEASE-HOLD|P-GOODBYE-RX|P-GOODBYE-SENT|P-LEASE-COUNT-INSANE|BUG:|Oops|DLM shutdown complete" "$EV/dmesg_$V.log" | cut -c1-200
v=PASS
grep -q "umount_rc=0" "$EV/umount_$V.log" || { say "victim unmount: $(tr '\n' ' ' < "$EV/umount_$V.log")"; v=FAIL; }
grep -q "umount_rc=0" "$EV/umount_$P.log" || { say "peer unmount: $(tr '\n' ' ' < "$EV/umount_$P.log")"; v=FAIL; }
grep -q -E "P-LEASE-COUNT-INSANE|BUG:|Oops" "$EV/dmesg_$V.log" && { say "the victim touched a dead lease context or oopsed"; v=FAIL; }
# the run tests nothing unless the GOODBYE landed inside the hold
awk '/P-DBG-TEARDOWN-LEASE-HOLD/ {h=1} h && /P-GOODBYE-RX/ {g=1} END {exit !g}' "$EV/dmesg_$V.log" \
    || { say "no GOODBYE from $P reached $V during the hold — the window was not exercised"; v=FAIL; }
say "RESULT $v"
[ $v = PASS ]
