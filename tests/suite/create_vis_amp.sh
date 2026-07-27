#!/bin/bash
# create_vis_amp — AMPLIFIED create-visibility race repro (dead-shell class).
#
# dir_reuse_coherency hits the P-IGET-ENOENT dead-shell race only RARELY and
# it is a Heisenbug (observation perturbs the timing).  This isolates and
# amplifies the exact sequence so it fires deterministically at volume, so a
# fix can be verified.  NOT in the manifest (diagnostic only) — run via
# scripts/run_adhoc_suite_test.sh.
#
# The race (dead-shell): a reader igets a peer's inode (caches it), the inode
# is then FREED and REUSED by the creator (with a content-write that fires the
# multinode mtime/ctime ->update_time EX+iflush), and the reader must re-resolve
# the reused inode.  If the reader cache-HITS its stale reclaimable mode-0 shell
# it returns -ENOENT for a name readdir just showed it.
#
# Roles (needs >=2 nodes): rank1 = READER, rank2 = CREATOR.
# Each round, barrier-serialized (no TOCTOU):
#   1. creator: create NF files WITH content (fires the ts update), sync.
#   2. reader: readdir; every VISIBLE name must be iget-able (cat) — a visible
#      dirent whose iget fails is THE BUG (igetfail++).  cat also caches the
#      inode so the next free turns it into a dead shell.
#   3. creator: rm all NF files (reader's cached inodes -> reclaimable shells).
#   4. next round reuses the same inodes/daddrs.
#
# Env: CVA_ROUNDS (default 300), CVA_NF files/round (default 8).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

R="$RANK"; T="$NODES"
D="$MNT/.create_vis_amp"
ROUNDS="${CVA_ROUNDS:-300}"
NF="${CVA_NF:-8}"

if [ "$T" -lt 2 ]; then
    echo "RESULT: SKIP | test=create_vis_amp | nodes=$T | measured=need>=2 | reason=2-node race"
    exit 0
fi

if [ "$R" = 1 ]; then rm -rf "$D"; mkdir -p "$D"; sync; fi
ck "cva ready" coord_barrier "cva_ready"

igetfail=0      # dirent visible but iget/read failed  == THE BUG
notvisible=0    # dirent not visible at all (weaker coherency gap)
for round in $(seq 1 "$ROUNDS"); do
    echo "mxfs-CVAph r=${round} rank=${R} PHASE=start" > /dev/kmsg 2>/dev/null || true

    # 1. creator: create + content-write (fires the ts update path).
    if [ "$R" = 2 ]; then
        for i in $(seq 1 "$NF"); do echo "cva $round $i" > "$D/f$i"; done
        sync
    fi
    coord_barrier "cva_add_${round}" >/dev/null

    # 2. reader: every visible name must be iget-able.
    if [ "$R" = 1 ]; then
        for i in $(seq 1 "$NF"); do
            if [ -e "$D/f$i" ]; then
                if ! cat "$D/f$i" >/dev/null 2>&1; then
                    igetfail=$((igetfail + 1))
                    echo "mxfs-CVA r=${round} IGETFAIL f$i (dirent visible, iget/read -ENOENT)" > /dev/kmsg 2>/dev/null || true
                fi
            else
                notvisible=$((notvisible + 1))
            fi
        done
    fi
    coord_barrier "cva_verify_${round}" >/dev/null

    # 3. creator: free the inodes -> reader's cached copies become dead shells.
    if [ "$R" = 2 ]; then for i in $(seq 1 "$NF"); do rm -f "$D/f$i"; done; sync; fi
    coord_barrier "cva_rm_${round}" >/dev/null
done

# rank1 owns the correctness verdict (it is the reader).
if [ "$R" = 1 ]; then
    ckeq "cva no dirent-visible iget failures" 0 "$igetfail"
    echo "CVA-STATS rank=1 igetfail=$igetfail notvisible=$notvisible rounds=$ROUNDS nf=$NF" >&2
fi
coord_barrier "cva_done" >/dev/null
coord_done "$([ "$FAIL_N" -eq 0 ] && echo PASS || echo FAIL)"
finish
