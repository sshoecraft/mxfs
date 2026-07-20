#!/bin/bash
# tests/suite/coord.sh — agnostic multi-node coordination primitive.
#
# Sourced by coordinated FS tests (coord-class barrier/ordered/fault).  Backed
# by MQTT (an external broker), so coordination NEVER touches the filesystem
# under test — the old on-FS .mxfs_barriers/ scheme coordinated the test of the
# FS *using* the FS, which masks/poisons coherency bugs.  A test still references
# only its mount point + these opaque coord_* calls; the harness owns broker
# address, per-run topic namespace, and this node's identity (passed via env).
#
# Harness-provided environment (run.sh sets these before launching the test):
#   MXFS_COORD_BROKER  MQTT broker host           (default 192.168.1.149)
#   MXFS_COORD_PREFIX  per-run+test topic prefix  (unique; harness clears it)
#   MXFS_RANK          this node's rank, 1..N
#   MXFS_NODES         participating node count N
#   COORD_TIMEOUT      max wait for any rendezvous (default 120s)
#
# All state lives in RETAINED topics under $MXFS_COORD_PREFIX, so the protocol
# is director-free and race-free: a late subscriber still receives every prior
# publish.  The harness clears the prefix (mosquitto_sub --remove-retained)
# before and after the run, so retained messages never leak across runs.

: "${MXFS_COORD_BROKER:=192.168.1.149}"
: "${MXFS_COORD_PREFIX:=mxfs/coord/default}"
: "${MXFS_RANK:=1}"
: "${MXFS_NODES:=1}"
: "${COORD_TIMEOUT:=120}"
: "${COORD_POLL:=2}"           # per-poll subscribe window (seconds)

COORD_B="$MXFS_COORD_BROKER"

# coord_enabled — true when real multi-node coordination is in play.
coord_enabled() { [ "${MXFS_NODES:-1}" -ge 2 ]; }

# coord_barrier <tag> — rendezvous: every node must reach <tag> before any
# proceeds.  Publishes its own rank (retained), then polls until it has seen
# all N ranks.  No-op (success) on a single node.  Returns 1 on timeout.
coord_barrier() {
    local tag="$1"
    coord_enabled || return 0
    local base="$MXFS_COORD_PREFIX/bar/$tag"
    mosquitto_pub -h "$COORD_B" -t "$base/r/$MXFS_RANK" -m 1 -r -q 1 2>/dev/null
    # sess14(ccloop): exit the instant all NODES ranks have published their
    # retained marker, rather than blocking a fixed COORD_POLL window every
    # poll.  -C $MXFS_NODES disconnects after that many messages arrive; on
    # subscribe the broker delivers every already-retained marker immediately,
    # and any rank that publishes later is delivered live to this subscriber,
    # so the count reaches NODES the moment the last node arrives.  -W is the
    # max-wait cap (TIMEOUT).  Barrier tags are unique per round and the test
    # namespace is cleared per-run, so no stale markers can satisfy this early.
    # This removed ~2s/barrier (~10s/round) of pure polling latency that was
    # masquerading as MXFS slowness (single-node FS ops are ~0.45s/round).
    # sess2 (a9a03929) BARRIER DUP FIX: -C counts MESSAGES, not DISTINCT
    # RANKS.  A duplicate delivery (QoS-1 redelivery, live+retained overlap)
    # released the barrier one arrival EARLY — PROVEN run58: rank3's r9
    # create-start at t=241.15 while rank1 was still inside its r8 rm-rf
    # (rm-done t=242.42), so the create wave raced the rm in the shared dir
    # every round (P15-REL-ABORT / 5-way dir-EX contention).  Fast path
    # keeps the instant -C exit but verifies DISTINCT topics; on a dup
    # shortfall it falls back to short re-polls of the retained set until
    # all N ranks are genuinely present.
    local deadline=$(( $(date +%s) + COORD_TIMEOUT ))
    local uniq cnt
    cnt=$(timeout $(( COORD_TIMEOUT + 3 )) mosquitto_sub -h "$COORD_B" \
            -t "$base/r/+" -C "$MXFS_NODES" -W "$COORD_TIMEOUT" -v -q 1 2>/dev/null \
          | awk '{print $1}' | sort -u | grep -c .)
    [ "$cnt" -ge "$MXFS_NODES" ] && return 0
    echo "coord_barrier '$tag' dup-shortfall (uniq $cnt/$MXFS_NODES) — re-polling" >&2
    while :; do
        uniq=$(timeout 5 mosquitto_sub -h "$COORD_B" -t "$base/r/+" \
                -W 1 -v -q 1 2>/dev/null | awk '{print $1}' | sort -u | grep -c .)
        [ "$uniq" -ge "$MXFS_NODES" ] && return 0
        [ "$(date +%s)" -ge "$deadline" ] && break
    done
    echo "coord_barrier '$tag' TIMEOUT (saw ${uniq:-0}/$MXFS_NODES on rank $MXFS_RANK)" >&2
    return 1
}

# coord_put <key> <value> — publish a value (retained) for peers to read.
coord_put() {
    mosquitto_pub -h "$COORD_B" -t "$MXFS_COORD_PREFIX/kv/$1" -m "$2" -r -q 1 2>/dev/null
}

# coord_get <key> [timeout] — read a value a peer published.  Blocks (up to
# timeout) until the value exists; echoes it.  Returns 1 on timeout.
coord_get() {
    local key="$1" to="${2:-$COORD_TIMEOUT}" val
    val=$(timeout $(( to + 3 )) mosquitto_sub -h "$COORD_B" \
            -t "$MXFS_COORD_PREFIX/kv/$key" -C 1 -W "$to" -q 1 2>/dev/null)
    [ -n "$val" ] || { echo "coord_get '$key' TIMEOUT" >&2; return 1; }
    printf '%s\n' "$val"
}

# coord_signal <event> [value] — fire a one-shot event (retained).
coord_signal() {
    mosquitto_pub -h "$COORD_B" -t "$MXFS_COORD_PREFIX/sig/$1" -m "${2:-1}" -r -q 1 2>/dev/null
}

# coord_wait <event> [timeout] — block until <event> fired.  Returns 1 on timeout.
coord_wait() {
    local evt="$1" to="${2:-$COORD_TIMEOUT}" v
    v=$(timeout $(( to + 3 )) mosquitto_sub -h "$COORD_B" \
            -t "$MXFS_COORD_PREFIX/sig/$evt" -C 1 -W "$to" -q 1 2>/dev/null)
    [ -n "$v" ] || { echo "coord_wait '$evt' TIMEOUT" >&2; return 1; }
    return 0
}

# coord_done <status> — report this node's final status (retained) for the
# harness to aggregate.  (The harness primarily aggregates the parsed RESULT
# line; this is a belt-and-suspenders channel.)
coord_done() {
    mosquitto_pub -h "$COORD_B" -t "$MXFS_COORD_PREFIX/done/$MXFS_RANK" -m "${1:-UNKNOWN}" -r -q 1 2>/dev/null
}

# coord_check_abort — bounded (~0.3s) poll for a peer-broadcast fatal abort
# (a kernel-level hang, forced shutdown, etc.).  On success echoes the
# broadcaster's reason string and returns 0; otherwise returns 1 with no
# output.  Built on the same retained sig/ channel as coord_signal/
# coord_wait, just non-blocking so it can be polled from inside another
# wait loop instead of committing to a single event.
#
# sess1 (ccloop 0220f43f) RULE-4 PROVEN: mosquitto_sub's -W only accepts
# INTEGER seconds (a fractional value like "0.3" silently truncates to 0
# via its atoi-style parse); -W 0 returns near-instantly but UNRELIABLY
# misses even an already-retained message (measured: 0/1 delivered across
# reps, vs 10/10 delivered using an outer `timeout`).  Dropping -W and
# instead bounding the whole call with the outer `timeout` (which DOES
# accept fractional seconds) keeps retained-message delivery reliable
# (measured 10/10 hits, ~50ms) while cutting the empty-case poll floor
# from ~1.0s to ~0.3s — this call sits in coord_barrier_or_abort's watch
# loop and was measured adding ~2.2s/round of pure poll padding (4-5
# barrier calls/round) to dir_reuse_coherency@32/cawp, the difference
# between 7 and 8 rounds fitting the 100s pace budget.
coord_check_abort() {
    coord_enabled || return 1
    local v
    v=$(timeout 0.3 mosquitto_sub -h "$COORD_B" \
            -t "$MXFS_COORD_PREFIX/sig/abort" -C 1 -q 1 2>/dev/null)
    [ -n "$v" ] || return 1
    printf '%s\n' "$v"
}

# coord_signal_abort <reason> — broadcast a fatal, run-ending condition
# discovered by THIS node (a kernel-level hang, a forced shutdown, etc.) so
# every peer stops cooperating and reports its own terminal state at once,
# instead of each independently burning a full COORD_TIMEOUT on every
# remaining barrier.  Proven costly 2026-07-11 (run61b): one node's rm
# hung D-state in the kernel and was never coming back; the other 31 nodes
# had no way to learn that, so they cycled through ~2 hours of repeated
# 120s barrier timeouts, one per remaining round, before the outer per-run
# timeout finally killed everything with zero RESULT lines printed by any
# of the 32 nodes — a single hung syscall read back as an undifferentiated
# nodes_pass=0/32.
coord_signal_abort() {
    coord_signal "abort" "${1:-unspecified}"
}

# coord_barrier_or_abort <tag> — like coord_barrier, but also polls for a
# peer-broadcast abort while waiting and returns immediately (status 2,
# printing the abort reason) the instant one appears, instead of riding out
# the full barrier timeout.  Runs the real barrier wait in the background
# so this node's abort-poll cadence is independent of coord_barrier's own
# internal timing; does not otherwise touch coord_barrier's (carefully
# tuned, see its own comments) internals.
#
# sess1 (ccloop 0220f43f) RULE-4: a FIRST decoupled-watcher attempt had the
# background subshell independently poll `kill -0 "$bpid"` to know when to
# stop — REVERTED, live-reproduced: caused a full cluster-wide hang
# (NO_TERMINAL_RECORD=32) on cache_coherency/dlm_fairness/
# crash_consistency/posix_multi (dir_reuse_coherency, with much longer
# gaps between barrier calls, stayed healthy).  Root cause: a PID-reuse
# TOCTOU — the foreground reaps bpid via `wait` while a SEPARATE process
# independently checks `kill -0 "$bpid"`; once reaped, that PID number can
# be recycled by any concurrent fork, and the watcher then mistakes an
# unrelated process for the still-running barrier and loops forever.
#
# THIS version's watcher never references bpid at all -- it just polls for
# abort in a plain loop until the FOREGROUND explicitly kills it (after
# `wait "$bpid"` returns), so there is no cross-process PID check to race.
# The foreground's own wait is signal-driven (not polling), so normal
# completion has zero poll-loop tail latency, only the abort path pays
# coord_check_abort's ~0.3s poll floor (paid once, in the background,
# never blocking normal completion).  Validated: isolated rapid-fire
# repeat test (no hang/zombie growth over 200 calls), 2-node and 32-node
# dir_reuse_coherency (proven fix for the 7-vs-8-round pace boundary),
# then a full 32-node regression batch (cache_coherency/dlm_fairness/
# crash_consistency/posix_multi/dir_reuse_coherency) before trusting it.
coord_barrier_or_abort() {
    local tag="$1" reason rc abf
    coord_enabled || return 0
    coord_barrier "$tag" >/dev/null 2>&1 &
    local bpid=$!
    abf=$(mktemp "/tmp/.coord_abort.XXXXXX")
    ( while true; do
          if reason=$(coord_check_abort); then
              printf '%s\n' "$reason" > "$abf"
              exit 0
          fi
      done ) &
    local apid=$!
    wait "$bpid" 2>/dev/null; rc=$?
    kill "$apid" 2>/dev/null
    wait "$apid" 2>/dev/null
    if [ -s "$abf" ]; then
        reason=$(cat "$abf")
        rm -f "$abf"
        printf '%s\n' "$reason"
        return 2
    fi
    rm -f "$abf"
    return "$rc"
}
