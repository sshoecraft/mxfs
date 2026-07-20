#!/bin/bash
# dir_add_visibility — long-lived shared-dir dirent-ADD visibility.
#
# The gap this covers (ccloop 72513a13 sess9): every other suite dir test
# (posix_multi, dir_reuse_coherency, cache_coherency) creates its working
# dir FRESH each run/round, so per-inode DLM state starts clean and the
# TCP-transport staleness debt that accumulates on an AGING dir inode never
# gets exercised.  Measured on 8/tcp (posix_multi pre-wipe run B, dir ino
# 4195264 at epoch ~60): after an 8-node ln wave, 7/8 nodes' lookups missed
# ALL peers' fresh adds — P65-EPOCH-ADOPT printed grant_epoch 26 ahead of
# valid_epoch with adopt=0 (TCP epoch gate is observe-only; the P63 one-shot
# bit is the only adopt trigger and is documented lossy).
#
# Shape: ONE dir created once (round 1) and never removed.  Each round every
# node creates one unique file (add-only — no removals, so no same-inode mv
# degeneracy can invert the assertions), syncs, barriers, then EVERY node
# asserts EVERY name from ALL rounds so far is visible (count + per-name
# stat of the current round's names).  A stale base shows up as a specific
# (round, name, victim) triple within seconds.
#
# Rounds default high enough to age the dir's epoch well past the run-B
# failure point (8 nodes x 24 rounds = 192 EX handoffs).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.dir_add_vis"
ROUNDS="${DAV_ROUNDS:-24}"

if [ "$R" = 1 ]; then
    rm -rf "$D"
    mkdir -p "$D"
    sync
fi
ck "dav barrier ready" coord_barrier "dav_ready"

for round in $(seq 1 "$ROUNDS"); do
    echo "mxfs-DAVph r=${round} rank=${R} PHASE=add" > /dev/kmsg 2>/dev/null || true
    ck "dav r${round} add own" sh -c "echo 'dav ${R} ${round}' > '$D/r${round}_n${R}'"
    sync
    ck "dav barrier add r${round}" coord_barrier "dav_add_${round}"

    # Full-cluster visibility of the CURRENT round's adds, from every node.
    for n in $(seq 1 "$T"); do
        ck "dav r${round} sees n${n}" test -f "$D/r${round}_n${n}"
    done
    # Aggregate count never regresses (catches silent loss of OLD rounds'
    # dirents by a stale-base publish, not just missing fresh adds).
    ckeq "dav r${round} total count" "$(( round * T ))" \
         "$(ls "$D" 2>/dev/null | wc -l | tr -d ' ')"
    ck "dav barrier verify r${round}" coord_barrier "dav_ver_${round}"
done

coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
