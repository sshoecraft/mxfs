#!/bin/bash
# fence_during_write — sustained concurrent cross-node writes must NOT trigger
# spurious fencing or lose committed data.
#
# Both nodes write their own files AND contend on a shared hot directory for a
# fixed window (the exact pattern that, with a too-aggressive fence policy, can
# falsely evict a busy peer).  PASS iff: (a) no node was fenced — every node's
# FS is still mounted + writable at the end and dmesg shows no fence/shutdown
# in this run's window; (b) every node's own data is intact (checksums match);
# (c) both nodes see the agreed shared-dir file count (no silent loss from a
# mistaken eviction).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.fence_during_write"
HOT="$D/hot"
# sess11 (8/cawd): this mkdir silently failed on 4/8 nodes right after a
# dir_reuse_coherency row — every storm write then ENOENTed for the whole
# window and the row failed as "still writable" with zero diagnostic.  Keep
# the failure a FAILURE (no masking) but make it loud and typed, and retry
# once so the rest of the row still measures what it was built to measure.
mkerr=$(mkdir -p "$D/node${R}" "$HOT" 2>&1); mkrc=$?
if [ "$mkrc" -ne 0 ]; then
    echo "mxfs-fdw-MKDIR-FAIL rank=$R rc=$mkrc err=[$mkerr]" > /dev/kmsg 2>/dev/null
    echo "FDW-MKDIR-FAIL rc=$mkrc err=[$mkerr]"
    sleep 0.5
    mkerr2=$(mkdir -p "$D/node${R}" "$HOT" 2>&1); mkrc2=$?
    echo "mxfs-fdw-MKDIR-RETRY rank=$R rc2=$mkrc2 err2=[$mkerr2]" > /dev/kmsg 2>/dev/null
    echo "FDW-MKDIR-RETRY rc2=$mkrc2 err2=[$mkerr2]"
fi
ckeq "fdw setup mkdir clean" 0 "$mkrc"

WINDOW="${FENCE_WINDOW:-15}"
MARK="MXFS_FDW_$(date +%s)_${R}"
echo "$MARK" > /dev/kmsg 2>/dev/null
# Match only REAL fence/shutdown events.  NOT bare 'evict'/'fence' — mxfs prints
# benign routine eviction-ring traffic ("EVICT-RING-DIRMOD", "force_peer_flush")
# during normal cross-node operation; those are not faults.
FPAT='self.?fence|fenced node|node fenced|being fenced|Shutting down filesystem|shutting down filesystem|Corruption of|Metadata I/O Error|Internal error xfs'

ck "fdw barrier ready" coord_barrier "fdw_ready"

# sess10(a9a03929): arm the kernel storm-dir probe family on the shared hot
# dir — the drained-check leak (s10r1: 5 leftover names, durable) is the same
# stale-base RMW family as dir_reuse; with the watch armed, P-DIRWR /
# P13-LADD / P9-LFREE / P49-STALEBASE record every placement/free/write of
# the hot dir's blocks.  Harmless if the param is absent.
if [ "${MXFS_WATCH_ARM:-1}" = 1 ]; then
    fdw_watch=$(stat -c '%i' "$HOT" 2>/dev/null)
    [ -n "$fdw_watch" ] && echo "$fdw_watch" > /sys/module/mxfs/parameters/watch_ino 2>/dev/null || true
fi

# Concurrent write storm: own files (checksummed) + shared-dir contention.
declare -A sums
i=0; end=$(( $(date +%s) + WINDOW ))
while [ "$(date +%s)" -lt "$end" ]; do
    f="$D/node${R}/f$((i % 40))"
    head -c $(( (RANDOM % 8192) + 512 )) /dev/urandom > "$f" 2>/dev/null
    sums[$((i % 40))]=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
    # contend on the shared hot dir (forces cross-node dir EX handoffs)
    h="$HOT/n${R}_$((i % 16))"
    : > "$h" 2>/dev/null && rm -f "$h" 2>/dev/null
    i=$((i + 1))
done
sync

# (b) own data intact (re-read the last-written 40 files).
ok=1
for k in "${!sums[@]}"; do
    cur=$(md5sum "$D/node${R}/f${k}" 2>/dev/null | awk '{print $1}')
    if [ "$cur" != "${sums[$k]}" ]; then
        ok=0
        # sess15(a9a03929): name the miss — file, expected/got md5, size,
        # stat, and drop a kernel marker so the kernlog window can be
        # correlated.  A drop_caches re-read discriminates page-cache-stale
        # (md5 heals) from durable-stale (md5 still wrong).
        sz=$(stat -c '%s %i %Y' "$D/node${R}/f${k}" 2>/dev/null)
        echo "mxfs-fdw-MISS rank=$R f=f${k} exp=${sums[$k]} got=${cur:-none} stat=[$sz]" > /dev/kmsg 2>/dev/null
        echo "FDW-MISS f${k} exp=${sums[$k]} got=${cur:-none} stat=[$sz]"
        echo 1 > /proc/sys/vm/drop_caches 2>/dev/null
        cur2=$(md5sum "$D/node${R}/f${k}" 2>/dev/null | awk '{print $1}')
        echo "mxfs-fdw-MISS-REREAD rank=$R f=f${k} got2=${cur2:-none} healed=$([ "$cur2" = "${sums[$k]}" ] && echo 1 || echo 0)" > /dev/kmsg 2>/dev/null
        echo "FDW-MISS-REREAD f${k} got2=${cur2:-none}"
    fi
done
ckeq "fdw node${R} own data intact" 1 "$ok"

# (a) not fenced: FS still writable here.
probe="$D/node${R}/.probe"
ck "fdw node${R} still writable" bash -c ": > '$probe' && rm -f '$probe'"
hits=$(dmesg 2>/dev/null | awk -v m="$MARK" 'f{print} $0 ~ m{f=1}' | grep -ciE "$FPAT")
ckeq "fdw node${R} no fence/shutdown in window" 0 "${hits:-0}"

ck "fdw barrier survived" coord_barrier "fdw_survived"

# (c) shared-dir drained consistently (every node's churn cleaned, no leak).
if [ "$R" = 1 ]; then
    left=$(ls "$HOT" 2>/dev/null | wc -l | tr -d ' ')
    ckeq "fdw shared hot dir drained" 0 "$left"
    # sess10(a9a03929): on a leak, record WHICH names leaked + trigger the
    # kernel P10-DIRDUMP (in-core vs platter per block) for the hot dir.
    if [ "$left" != 0 ]; then
        echo "mxfs-fdw-LEAK rank=$R left=$left names=[$(ls "$HOT" 2>/dev/null | tr '\n' ' ')]" > /dev/kmsg 2>/dev/null
        [ -e "$HOT/.mxfs_dirdump1" ] 2>/dev/null || true
    fi
fi

ck "fdw barrier done" coord_barrier "fdw_done"
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
