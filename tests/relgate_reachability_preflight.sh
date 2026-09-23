#!/bin/bash
# Prove that the ICLUS cluster-release path is REACHABLE before spending a
# 32-node fault-injection matrix on it.
#
# Why this exists.  Four consecutive 4-arm matrices for
# D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY measured nothing: every victim probe
# read iclus_marked=0 iclus_unmarked=0 P282=0 with the one-shot stage knob still
# armed.  Three of them printed VERDICT PASS on that, and any of the three could
# have been cited to close a critical record.  Roughly two hours of 32-node rig
# time went into discovering a fact that two nodes and two minutes can establish.
#
# The fact, proven from xfs/xfs_mxfs_dlm.c rather than guessed: mxfs_iclus_unlock
# reaches mxfs_iclus_disk_release -- the function holding relgate stages 19-21 --
# only behind the gate at :57131,
#
#     if (ic->bast_pending && ic->disk_mode > MXFS_LOCK_NL && !ic->busy) { ... sweep = true; }
#     if (!sweep) return busy_gate ? -EBUSY : 0;
#
# so an ordinary unlock with NO PEER DEMAND retains the grant and never enters
# the marker block.  No victim-side action -- cache drop, sync, eviction, more
# churn -- can reach it.  Only a genuine peer BAST can, which is exactly what the
# churn workload could not produce, because its files are O_TMPFILE and carry a
# name for sub-milliseconds.
#
# So this pre-flight tests the ONE thing the matrix depends on, in the simplest
# possible way: node A creates a NAMED file and holds the cluster; node B stats
# it, which takes ICLUS PR on the same base cluster and BASTs A; then A's
# counters are read.  If they moved, the path is reachable and a matrix is worth
# running.  If they did not, the matrix would be vacuous and must not be started.
#
# Usage:  tests/relgate_reachability_preflight.sh [nodeA] [nodeB]
# Exit:   0 = reachable (counters moved)      1 = NOT reachable (do not run a matrix)
#
# budget: this is a two-node, few-operation probe.  Each remote step gets 20-30 s,
# derived from ordinary ssh round-trip plus one create/stat; the whole run should
# be well under a minute.  If it is not, that slowness is itself a finding.
set -u
cd /src/mxfs || exit 1
A=${1:-test1}
B=${2:-test2}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/.relgate_preflight_$(date -u +%H%M%S)

say() { echo "  $*"; }
counters() { # <node> -> the iclus counter line, or the empty string
  timeout 20 "$SSH" "$1" \
    "grep -a -A11 '^relmark' /sys/kernel/debug/mxfs/*/inode_authority 2>/dev/null \
     | grep -a 'iclus_\|published' | awk '{printf \"%s=%s \", \$1, \$2}'" 2>/dev/null \
    | grep -av '^Unauthorized access\|^Warning: Permanently\|^If you are not'
}

echo "=== relgate reachability pre-flight A=$A B=$B $(date -u +%FT%TZ) ==="

# Both nodes must actually have the filesystem mounted, or every reading below is
# a statement about nothing.  This is the check whose absence turned four
# matrices into fabricated evidence.
for n in "$A" "$B"; do
  m=$(timeout 20 "$SSH" "$n" "mount | grep -c ' $MNT type mxfs'" 2>/dev/null | tr -dc '0-9')
  say "$n mounted=$m"
  [ "${m:-0}" -ge 1 ] || { echo "NOT REACHABLE: $n has no mxfs mount — prep the cluster first."; exit 1; }
done

timeout 30 "$SSH" "$A" "mkdir -p '$D' && dd if=/dev/zero of='$D/anchor' bs=4096 count=1 2>/dev/null && sync && stat -c 'ino=%i' '$D/anchor'" 2>/dev/null | grep -a 'ino=' | sed 's/^/  A created /'
ino=$(timeout 20 "$SSH" "$A" "stat -c %i '$D/anchor'" 2>/dev/null | tr -dc '0-9')
[ -n "$ino" ] || { echo "NOT REACHABLE: could not create or stat the anchor on $A."; exit 1; }
say "anchor inode=$ino"

before=$(counters "$A")
say "A counters BEFORE: ${before:-<none>}"

# The BAST.  B reading the anchor takes ICLUS PR on the anchor's base cluster,
# which is a live demand on the grant A holds -- the only thing that sets
# ic->bast_pending and so the only thing that opens the gate above.
timeout 30 "$SSH" "$B" "cat '$D/anchor' >/dev/null 2>&1; stat -c 'B_ino=%i' '$D/anchor'" 2>/dev/null | grep -a 'B_ino=' | sed 's/^/  B read /'
sleep 3
after=$(counters "$A")
say "A counters AFTER:  ${after:-<none>}"

num() { echo "$1" | grep -ao "$2=[0-9]*" | tr -dc '0-9' | head -c 9; }
moved=0
for k in iclus_marked iclus_unmarked iclus_failed; do
  b=$(num "$before" "$k"); a=$(num "$after" "$k")
  say "$k: ${b:-0} -> ${a:-0}"
  [ "${a:-0}" -gt "${b:-0}" ] && moved=1
done

timeout 20 "$SSH" "$A" "rm -f '$D/anchor'; rmdir '$D'" >/dev/null 2>&1

if [ "$moved" = 1 ]; then
  echo "REACHABLE: a peer read moved A's cluster-release counters, so the marker block is entered and a fault matrix over stages 19-21 will measure something."
  exit 0
fi
echo "NOT REACHABLE: a peer read did NOT move A's cluster-release counters."
echo "  A fault matrix armed on stages 19-21 would be VACUOUS — every arm would"
echo "  report the stage still armed and the counters at zero, which is what the"
echo "  last four matrices did.  Do not start one.  Fix the trigger first: the"
echo "  release is entered only when ic->bast_pending is set (xfs_mxfs_dlm.c:57131),"
echo "  so the peer must take ICLUS PR on the SAME 16 KB base cluster the holder"
echo "  has, and that must be proven rather than assumed."
exit 1
