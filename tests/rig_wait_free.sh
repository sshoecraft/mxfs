#!/bin/bash
# Block until the rig is actually free, then return.
#
# Why this exists.  Chains here gate on the PREVIOUS chain's "DONE" line, and
# that is not the same thing as the rig being available.  On 2026-09-03 three
# chains gated that way all woke within 30 s of one chain's DONE and collided:
# a board instance left over from an earlier session won the run lock, two
# freshly-launched chains hit "ERROR: another run.sh holds /tmp/mxfs_run.lock"
# and burned themselves to a hard FAIL in one second each, and a LAB build
# chain started `make modules` in the tree WHILE that board's preps were
# insmod'ing /src/mxfs/mxfs.ko over NFS -- which would have split the board's
# srcversion across the fleet and silently corrupted a run being collected as
# closure evidence for a critical record.  The relink was killed with seconds
# to spare.
#
# The run lock is the real resource, so wait on the run lock.  A chain that
# fails fast on a held lock wastes its whole launch; a chain that waits simply
# starts a few minutes later.
#
# Usage:  tests/rig_wait_free.sh [timeout_s]        # default 7200
# Exit:   0 = rig free (the caller may now take the lock)
#         1 = still busy when the timeout expired (caller should NOT proceed)
#
# the budget rule note: the timeout here is a DEADLOCK backstop, not a performance
# budget -- it bounds how long a queued chain waits for its predecessor, and
# the predecessors it waits on carry their own derived budgets.  It is
# deliberately longer than the longest chain (the 10-lap NDR streak, ~2 h).
set -u
LOCK=/tmp/mxfs_run.lock
DEADLINE=$(( $(date +%s) + ${1:-7200} ))

holders() {
    # Every process holding an fd on the lock file, found by walking /proc
    # directly.  Deliberately NOT `pgrep -f` and NOT `ps aux`: both read
    # /proc/<pid>/cmdline for every process, which takes that process's
    # mmap_lock, and one task wedged holding its own mmap_lock makes the scan
    # hang unkillably.  That has taken this host down before.  Reading the fd
    # symlinks and comm is safe even when tasks are wedged.
    local d p t
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        for t in "$d"/fd/*; do
            case "$(readlink "$t" 2>/dev/null)" in
                */mxfs_run.lock) echo "$p:$(cat "$d/comm" 2>/dev/null)"; break ;;
            esac
        done
    done 2>/dev/null
}

building() {
    # A `make` relinking mxfs.ko is exclusive with any rig run for the same
    # reason: the preps ship the tree's module to the nodes.
    local d
    for d in /proc/[0-9]*; do
        case "$(cat "$d/comm" 2>/dev/null)" in
            make) return 0 ;;
        esac
    done
    return 1
}

while :; do
    h=$(holders)
    b=no; building && b=yes
    if [ -z "$h" ] && [ "$b" = no ]; then
        echo "rig_wait_free: free at $(date -u +%FT%TZ)"
        exit 0
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "rig_wait_free: STILL BUSY at the deadline — refusing to proceed."
        # Summarise rather than dump: a killed run.sh's whole ssh fan-out
        # inherits fd 9, so the raw list runs to hundreds of lines of
        # sshpass/timeout children that say nothing the count does not.
        echo "  lock holders: $(echo "$h" | grep -c .) process(es); by name: $(echo "$h" | cut -d: -f2 | sort | uniq -c | tr '\n' ' ')"
        echo "  first few: $(echo "$h" | head -3 | tr '\n' ' ')"
        echo "  build running: $b"
        echo "  Proceeding anyway would either stomp a live run's cluster or"
        echo "  relink the module its preps are shipping.  Diagnose the holder."
        exit 1
    fi
    sleep 20
done
