#!/bin/bash
# node_responsive — this node can still fork, schedule, and USE the mount,
# within a bounded time.
#
# WHY THIS EXISTS (ccloop c7ee71c6 sess21)
#   During the 32/tcp wedge, test31 was:
#     virsh domstate -> running
#     ping           -> replies, 0.12 ms, 0% packet loss
#     ssh            -> NOTHING; sshd could not fork
#   A CPU had been soft-locked for 522 s inside mxfs_ici_lock's unbounded
#   spin_trylock loop, and the node was holding AG grants it could never
#   release.  Every ssh-based probe in the harness returned empty and was read
#   as "clean", and the evidence existed ONLY on the libvirt serial console
#   (/var/log/libvirt/qemu/<vm>-serial.log) — not in any dmesg the harness
#   could collect.
#
#   Liveness that stops at ping is worthless for this failure mode: a kernel
#   answers ICMP from softirq context long after every task is stuck.
#
# The real detection is structural: a node this wedged cannot run this script,
# so it yields NO_TERMINAL_RECORD and the runner scores it as a failure.  What
# this script adds is an explicit, fast, named check with a tight budget, so
# the board says "node_responsive FAILED on testN" instead of leaving the
# operator to infer a wedge from a timeout somewhere else.
SUITE_TEST_NAME=node_responsive
MNT="${1:-/mnt/shared}"; NODES="${MXFS_NODES:-1}"

fails=0; detail=""

# 1. Can we fork and reap a child?  (The soft-locked node could not.)
if ! out=$( (echo alive) 2>/dev/null ) || [ "$out" != alive ]; then
    fails=$((fails + 1)); detail="${detail}fork;"
fi

# 2. Is the filesystem serviceable — not merely mounted?  statfs goes into the
#    filesystem, so a wedged DLM/AG path shows up here rather than passing a
#    string check against /proc/mounts.
if ! timeout 15 stat -f -c %T "$MNT" >/dev/null 2>&1; then
    fails=$((fails + 1)); detail="${detail}statfs;"
fi

# 3. Can we complete a trivial metadata round-trip?  This is the smallest
#    operation that actually needs the cluster lock machinery to function.
W="$MNT/.node_responsive.$(hostname).$$"
if ! timeout 20 mkdir -p "$W" 2>/dev/null; then
    fails=$((fails + 1)); detail="${detail}mkdir;"
else
    timeout 20 rmdir "$W" 2>/dev/null || { fails=$((fails + 1)); detail="${detail}rmdir;"; }
fi

# 4. Are any of OUR OWN tasks STUCK in uninterruptible sleep?  D-state on a
#    kernel thread is how a drain wedge presents before it becomes a lockup.
#    mxfs-worker in msleep is the normal heartbeat and is excluded.
#
#    PERSISTENCE, not presence (ccloop c7ee71c6 sess25).  This was a single
#    instantaneous `ps` snapshot, which measures LOAD, not a wedge: a momentary
#    D-state is what every ordinary blocking I/O looks like.  Worse, this very
#    script manufactures the condition it then flagged — step 3 above has all
#    N ranks mkdir+rmdir into ONE shared mount simultaneously, so some of them
#    are necessarily in the DLM/CAW wait at the instant of the snapshot.
#    Measured: 20 of 32 nodes FAILed with exactly dstate=1 each right after a
#    dirent_durability storm, and 3 of 32 still did on a fully QUIESCED
#    cluster; a re-sample 25 s later found ZERO D-state tasks anywhere.  One
#    stuck task on most nodes is the signature of ordinary concurrent I/O.  A
#    real wedge is the opposite shape — MANY tasks on ONE node (test27 had 21)
#    with UNCHANGED PIDs over many minutes.
#
#    So: sample twice and fail only on a task that is STILL in D state, by PID,
#    after the dwell.  This is strictly MORE specific, not a weaker bar — it
#    keeps 100% of the true-positive rate for the failure mode this check
#    exists for (an unchanged-PID wedge trivially survives a 10 s dwell) while
#    removing a false positive that fires on a healthy busy cluster.  A task
#    blocked for 10 s straight is itself a RULE 0 problem, so the assertion
#    still bites.  Costs nothing when nothing is in D state.
DWELL="${MXFS_DSTATE_DWELL_S:-10}"
dsnap() { ps -eo stat=,pid=,comm= 2>/dev/null | awk '$1 ~ /^D/ && $3 != "mxfs-worker" {print $2}'; }

first=$(dsnap)
dstuck=0; dwho=""
if [ -n "$first" ]; then
    sleep "$DWELL"
    for p in $first; do
        # Same PID still in D after the dwell => genuinely stuck, not busy.
        st=$(cut -d' ' -f3 "/proc/$p/stat" 2>/dev/null)
        [ "$st" = D ] || continue
        dstuck=$((dstuck + 1))
        [ -n "$dwho" ] && dwho="$dwho,"
        dwho="$dwho$p:$(cat /proc/$p/comm 2>/dev/null):$(cat /proc/$p/wchan 2>/dev/null)"
    done
fi
[ "$dstuck" -gt 0 ] && { fails=$((fails + 1)); detail="${detail}dstate=$dstuck[$dwho];"; }

st=PASS; reason=""
[ "$fails" -gt 0 ] && { st=FAIL; reason="unresponsive: ${detail%;}"; }
echo "RESULT: $st | test=node_responsive | nodes=$NODES | measured=checks=4 failed=$fails dstate=$dstuck | reason=$reason"
[ "$st" = PASS ]
