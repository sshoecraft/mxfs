#!/bin/bash
# runlock.sh — who may touch which rig nodes right now.  Sourced by run.sh,
# scripts/rig.sh and scripts/rig_groups.sh; defines functions only.
#
# Three kinds of lock, all flock(2) on files in /tmp, held on an open fd until
# the holding process exits (a crash releases them; nothing to clean up):
#
#   /tmp/mxfs_run.lock          the rig as a whole.  A run over test1..testN
#                               takes it EXCLUSIVE, as it always has: it may
#                               power-cycle or tear down any rig VM outside its
#                               set, and it cleans the shared broker namespace.
#                               A rig-group run takes it SHARED, so any number
#                               of group runs coexist while a whole-rig run, or
#                               a rewiring of every node, is refused.
#   /tmp/mxfs_node.<node>.lock  one node.  A group run takes every node of its
#                               group, so two runs can never share a node.
#   /tmp/mxfs_config.<slug>.lock  one configuration.  Its board column and its
#                               stale-marker heal belong to one run at a time.
#
# Each file's content names the holder (pid, time, what), for the refusal.

RUNLOCK=/tmp/mxfs_run.lock

runlock_holder() {  # <file> -> the holder line it records, or "unknown"
    local h
    h=$(head -1 "$1" 2>/dev/null)
    echo "${h:-unknown}"
}

runlock_take() {  # <file> <shared|exclusive> <what> -> 0 if taken; the fd stays open
    local file=$1 mode=$2 what=$3 fd flag=-x
    [ "$mode" = shared ] && flag=-s
    exec {fd}>>"$file" || return 1
    if ! flock -n $flag "$fd"; then
        exec {fd}>&-
        return 1
    fi
    # Only an exclusive holder rewrites the holder line: shared holders
    # append, so the file names every group run holding the rig.
    if [ "$mode" = exclusive ]; then
        : > "$file"
    fi
    echo "$$ $(date -u +%FT%TZ) $what" >> "$file"
    return 0
}

runlock_rig_free() {  # -> 0 iff no run of any kind holds the rig lock right now
    local fd
    exec {fd}>>"$RUNLOCK" || return 1
    if flock -n -x "$fd"; then
        exec {fd}>&-
        return 0
    fi
    exec {fd}>&-
    return 1
}

runlock_nodes() {  # <what> <node>... -> 0 iff every node's lock is taken
    local what=$1 n; shift
    for n in "$@"; do
        runlock_take "/tmp/mxfs_node.$n.lock" exclusive "$what" || {
            echo "ERROR: $n is held by another run: $(runlock_holder "/tmp/mxfs_node.$n.lock")"
            return 1
        }
    done
    return 0
}

runlock_config() {  # <slug> <what> -> 0 iff the configuration's lock is taken
    runlock_take "/tmp/mxfs_config.$1.lock" exclusive "$2" || {
        echo "ERROR: configuration $1 is held by another run: $(runlock_holder "/tmp/mxfs_config.$1.lock")"
        return 1
    }
}
