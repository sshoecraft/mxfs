#!/bin/bash
# withdraw_recovery_test.sh — deterministic verification of the D2 fix
# (sess9 ccloop c7ee71c6): a member whose FS force-shuts down mid-workload
# must be treated as DEAD by the cluster — WITHDRAWN stamp → prompt peer
# detection → fence → elected foreign-slice replay → purge — and the shared
# namespace must come out CONSISTENT (no dangling dirent → freed-inode, the
# proven drc@16 r13 tear).
#
# Reproduces the incident shape exactly: creator populates a dir, a DIFFERENT
# node starts rm -rf of it and force-shuts-down mid-flight WITHOUT flushing
# its log (xfs_io shutdown, GOING_FLAGS default = no log flush) — leaving
# committed-but-partially-destaged unlink transactions only in its slice.
#
# PASS requires ALL of:
#   1. victim stamped WITHDRAWN (P163-WITHDRAW-STAMP in victim dmesg)
#   2. >=1 survivor saw it promptly (P163-WITHDRAW-SEEN)
#   3. a survivor was elected and completed replay (P163-RECOVERY-COMPLETE)
#   4. other survivors ran their deferred purge (P163-RECOVERED) or the
#      elected node was the only other member
#   5. NO dangling dirents afterward: from 2 survivor nodes, every name a
#      readdir of the dir lists must be lookup-able ([ -e ]), and every
#      present file must be readable
#   6. no NEW force-shutdowns on any survivor during the episode
#
# Run from clyde with the cluster already prepped+mounted (run.sh prep).
# Usage: tests/withdraw_recovery_test.sh [N] [victim] [creator]
set -u
N="${1:-16}"
VICTIM="${2:-test1}"
# creator must be an in-cluster node != victim; test6 was hardcoded when the
# smallest rig was 16 nodes and silently populated a bare mountpoint at N<6
CREATOR="${3:-test$N}"
[ "$CREATOR" = "$VICTIM" ] && { echo "creator==victim ($CREATOR) — need N>=2 or explicit args" >&2; exit 2; }
SSH=/src/mxfs/tools/mxfs_sshpass.sh
MNT=/mnt/shared
D="$MNT/.withdraw_t"
NF=64

say() { echo "[withdraw_t] $*"; }
fail() { echo "[withdraw_t] FAIL: $*"; echo "WITHDRAW_RECOVERY_FAIL"; exit 1; }

# sess11: MXFS_NODE_LIST-aware (physrig runs name nodes by IP, not testN)
if [ -n "${MXFS_NODE_LIST:-}" ]; then
    nodes=$(echo "$MXFS_NODE_LIST" | tr ',' ' ')
else
    nodes=""
    for i in $(seq 1 "$N"); do nodes="$nodes test$i"; done
fi
survivors=$(echo "$nodes" | tr ' ' '\n' | sed '/^$/d' | grep -v "^${VICTIM}$" | tr '\n' ' ')
# observer: first survivor (was hardcoded test2 — wrong fleet under MXFS_NODE_LIST)
OBS=$(echo "$survivors" | awk '{print $1}')

# --- Phase 0: sanity — all mounted, note baseline shutdown counts -----------
for h in $nodes; do
    m=$("$SSH" "$h" x "mount | grep -c ' type mxfs'" 2>/dev/null | tail -1)
    [ "$m" = "1" ] || fail "$h not mounted (got '$m')"
done
declare -A SD0
for h in $nodes; do
    SD0[$h]=$("$SSH" "$h" x "dmesg | grep -c 'Shutting down filesystem'" 2>/dev/null | tail -1)
done
say "baseline OK ($N mounted)"

# --- Phase 1: creator populates ---------------------------------------------
"$SSH" "$CREATOR" x "mkdir -p $D && for i in \$(seq 1 $NF); do printf 'WDRT %04d\n' \$i > $D/wf\$i; done && sync && ls $D | wc -l" 2>/dev/null | tail -1 | grep -q "^$NF\$" \
    || fail "creator populate ($CREATOR) did not produce $NF files"
say "populated $NF files from $CREATOR"

# --- Phase 2: cold cross-node baseline check --------------------------------
c=$("$SSH" "$OBS" x "ls $D | wc -l" 2>/dev/null | tail -1)
[ "$c" = "$NF" ] || fail "baseline cross-node readdir: $OBS sees $c/$NF"
say "cross-node baseline OK"

# --- Phase 3: victim starts rm -rf, then force-shutdown mid-flight ----------
# Injection: mxfs.dbg_dialloc_shutdown=1 makes the victim's next create fire
# a DIRTY trans_cancel → EFSCORRUPTED → force shutdown, mid-transaction with
# committed-but-unreplayed rm work in its journal slice — the incident's tear
# precondition, one better than GOINGDOWN (xfs_io/GOINGDOWN also ENOTTYs on
# this fork's file fds; the dbg param is the supported injector).
"$SSH" "$VICTIM" x "nohup sh -c 'rm -rf $D' >/dev/null 2>&1 & sleep 0.3; echo 1 > /sys/module/mxfs/parameters/dbg_dialloc_shutdown; timeout 10 touch $MNT/.wdrt_trigger >/dev/null 2>&1; echo INJECTED" 2>/dev/null | grep -q INJECTED \
    || fail "shutdown injection on $VICTIM did not run"
inject_ts=$(date +%s)
say "injected dirty-cancel force-shutdown on $VICTIM mid-rm"

# --- Phase 4: wait for the recovery chain (stamp ~1s, detect <=4s, replay
# sub-second-to-a-few-s).  The COMPLETE banner prints only after the
# disklock_purge_node zeroing pass, which is media-latency-bound: ~4s on the
# VM/SCST rig but ~31s measured on the QNAP physrig — a fixed 30s harvest
# missed it there (sess11).  Poll for completion on any survivor (budget 90s,
# derived: zeroing ≈ slot-records × per-write RTT; QNAP worst measured 31s,
# x2 headroom + detection), keep a floor of 30s settle for the deferred
# purges the completion broadcast releases.
poll_start=$(date +%s)
while :; do
    complete=0
    for h in $survivors; do
        cpl=$("$SSH" "$h" x "dmesg | grep -c 'P163-RECOVERY-COMPLETE'" 2>/dev/null | tail -1)
        complete=$((complete + ${cpl:-0}))
    done
    [ "$complete" -ge 1 ] && break
    [ $(( $(date +%s) - poll_start )) -ge 90 ] && break
    sleep 3
done
elapsed_poll=$(( $(date +%s) - poll_start ))
[ "$elapsed_poll" -lt 30 ] && sleep $(( 30 - elapsed_poll ))

vst=$("$SSH" "$VICTIM" x "dmesg | grep -c 'P163-WITHDRAW-STAMP'" 2>/dev/null | tail -1)
[ "${vst:-0}" -ge 1 ] || fail "victim never stamped WITHDRAWN (P163-WITHDRAW-STAMP=0)"
say "1/6 victim stamped WITHDRAWN"

seen=0; complete=0; recovered=0; elected_host=""
for h in $survivors; do
    s=$("$SSH" "$h" x "dmesg | grep -c 'P163-WITHDRAW-SEEN'" 2>/dev/null | tail -1)
    cpl=$("$SSH" "$h" x "dmesg | grep -c 'P163-RECOVERY-COMPLETE'" 2>/dev/null | tail -1)
    rcv=$("$SSH" "$h" x "dmesg | grep -c 'P163-RECOVERED'" 2>/dev/null | tail -1)
    seen=$((seen + ${s:-0})); complete=$((complete + ${cpl:-0})); recovered=$((recovered + ${rcv:-0}))
    [ "${cpl:-0}" -ge 1 ] && elected_host="$h"
done
[ "$seen" -ge 1 ] || fail "no survivor saw the WITHDRAWN stamp (P163-WITHDRAW-SEEN=0 cluster-wide)"
say "2/6 stamp seen by survivors (count=$seen)"
[ "$complete" -ge 1 ] || fail "no elected survivor completed replay (P163-RECOVERY-COMPLETE=0)"
say "3/6 elected replay complete on $elected_host"
if [ "$N" -gt 2 ]; then
    [ "$recovered" -ge 1 ] || fail "no deferred local purge ran on non-elected survivors (P163-RECOVERED=0)"
fi
say "4/6 deferred purges ran (P163-RECOVERED count=$recovered)"

# --- Phase 5: namespace consistency from two survivors ----------------------
# The rm was mid-flight: the dir may exist with a subset, or be gone.  Either
# is consistent.  What is FORBIDDEN is a listed name that fails lookup
# (dangling dirent → freed inode) or an unreadable present file.
for h in "$OBS" "$CREATOR"; do
    [ "$h" = "$VICTIM" ] && continue
    out=$("$SSH" "$h" x "
        dangle=0; unread=0; listed=0
        if [ -d $D ]; then
            for f in \$(ls $D 2>/dev/null); do
                listed=\$((listed+1))
                if [ ! -e $D/\$f ]; then dangle=\$((dangle+1)); echo DANGLE:\$f >&2
                elif ! cat $D/\$f >/dev/null 2>&1; then unread=\$((unread+1)); echo UNREAD:\$f >&2; fi
            done
        fi
        echo RESULT listed=\$listed dangle=\$dangle unread=\$unread" 2>/dev/null | grep RESULT | tail -1)
    say "consistency($h): $out"
    echo "$out" | grep -q 'dangle=0 unread=0' || fail "namespace inconsistent on $h: $out"
done
say "5/6 no dangling dirents, all present files readable"

# --- Phase 6: survivors healthy — no new shutdowns; cluster still writable --
for h in $survivors; do
    sd1=$("$SSH" "$h" x "dmesg | grep -c 'Shutting down filesystem'" 2>/dev/null | tail -1)
    [ "${sd1:-0}" -le "${SD0[$h]:-0}" ] || fail "survivor $h force-shut down during the episode ($sd1 > ${SD0[$h]})"
done
"$SSH" "$OBS" x "echo post-recovery-write > $MNT/.wdrt_probe && cat $MNT/.wdrt_probe && rm -f $MNT/.wdrt_probe" 2>/dev/null | grep -q post-recovery-write \
    || fail "cluster not writable after recovery"
say "6/6 survivors healthy and cluster writable"

elapsed=$(( $(date +%s) - inject_ts ))
say "PASS (episode ${elapsed}s incl. 30s settle)"
echo "WITHDRAW_RECOVERY_PASS"
