#!/bin/bash
# lone_dir_block_authority.sh — D-LONE-MOUNT-DIRECTORY-BLOCK-IMAGE-SHIPS-AUTH-NOT-HELD:
# what authority does a directory's block-format image CAPTURE on a node that
# is mounted alone, versus the same node with a peer mounted?
#
# HYPOTHESIS (falsifiable): on a mount that has never had a peer, the inode
# DLM entry (mxfs_dlm_ilock_begin) returns at the never-multi bypass before the
# unpublished-directory divert, so the directory is never published, its
# authority state never reaches DURABLE_EX, and the capture point stamps every
# image of its blocks non-durable (P239-OWNAUTH-NONDUR blft=10 outcome=UNPUB or
# NONE, unpub=1).  With a peer mounted the divert runs, the dir takes a real
# grant, and no P239-OWNAUTH-NONDUR line names the directory.
#   PROVEN    if the lone arm prints P239-OWNAUTH-NONDUR blft=10 for the
#             witness dir's ino and the peer arm prints none for it.
#   DISPROVEN if the lone arm prints none (then the AUTH_NOT_HELD image in
#             s53f came from elsewhere), or the peer arm prints them too.
#
# No crash: this is the capture-time measurement the s53f evidence lacks
# (the victim's own kernel log died with it).
#
# budget (derived): per arm mkfs 32 slices ~20 s + module reload + mount ~10 s
# (+ peer mount ~10 s) + 40 creates <1 s + captures ~5 s + unmount(s) ~3 s
# each, bound 90 s -> lone ~130 s worst, peer ~230 s worst; ~60 s typical each.
#
# Usage: tests/lone_dir_block_authority.sh <label> [lone|peer|both]
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default /dev/sda)
# Exit 0 = measured (rows printed), 2 = INFRA/ABORT.
set -u
LABEL=${1:?label}
ARMS=${2:-both}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
TR=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lonedirauth_$LABEL
mkdir -p "$OUT"
aborts=0
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
cnt()  { grep -ac "$2" "$1"; }
s0=$(date +%s); el() { echo $(( $(date +%s) - s0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== lone_dir_block_authority label=$LABEL arms=$ARMS A=$A B=$B sv=$SV $(date -u +%FT%TZ) ==="

umount_node() { # <node> -> rc
    rs 110 "$1" "timeout 90 umount $MNT; echo UMOUNT_RC=\$?" | sed -n 's/^UMOUNT_RC=//p' | head -1
}

run_arm() { # <lone|peer>
    local arm=$1 WINO mark
    echo "=== ARM $arm at +$(el)s ==="
    # Never reformat under a live peer: a node still mounted on the old
    # filesystem is fenced by the fresh mount, withdraws, and its module can
    # no longer be unloaded (s54a: test2 stuck in the fenced-self inspection
    # loop, rmmod refused, VM reboot needed).
    echo "  pre-arm unmounts: $B rc=$(umount_node "$B") $A rc=$(umount_node "$A")"
    rs 200 "$A" "MXFS_DEV=$MXFS_DEV MXFS_LOG_SLICES=32 bash /src/mxfs/tests/setup/prep_fs.sh 2>&1 | tail -2; MXFS_DEV=$MXFS_DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh $TR 2>&1 | grep -a 'NODE_PREP_OK\|FAIL' | head -2" > "$OUT/${arm}_prep_$A.txt" 2>&1
    if [ "$(cnt "$OUT/${arm}_prep_$A.txt" 'NODE_PREP_OK')" != 1 ]; then
        echo "  ABORT $arm: $A did not prep: $(tail -2 "$OUT/${arm}_prep_$A.txt" | tr '\n' ' ')"; aborts=$((aborts+1)); return
    fi
    if [ "$arm" = peer ]; then
        rs 200 "$B" "MXFS_DEV=$MXFS_DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh $TR 2>&1 | grep -a 'NODE_PREP_OK\|FAIL' | head -2" > "$OUT/${arm}_prep_$B.txt" 2>&1
        if [ "$(cnt "$OUT/${arm}_prep_$B.txt" 'NODE_PREP_OK')" != 1 ]; then
            echo "  ABORT $arm: $B did not prep: $(tail -2 "$OUT/${arm}_prep_$B.txt" | tr '\n' ' ')"; aborts=$((aborts+1)); return
        fi
        # the membership must be two before the workload
        rs 30 "$A" "sleep 3; dmesg | grep -a 'peer\|member' | tail -3" > "$OUT/${arm}_membership.txt" 2>&1
    fi
    mark=$(rs 10 "$A" 'date +%s' | tail -1)
    WINO=$(rs 40 "$A" "mkdir -p $MNT/w_$arm && cd $MNT/w_$arm && for i in \$(seq 1 40); do echo w\$i > f\$i; done; sync -f $MNT/w_$arm; stat -c %i $MNT/w_$arm" | tail -1)
    echo "STAGE $arm: witness dir ino=${WINO:-?} written+synced at +$(el)s"
    [ -n "$WINO" ] || { echo "  ABORT $arm: no witness inode"; aborts=$((aborts+1)); return; }
    rs 60 "$A" "journalctl -k --since @$mark --no-pager 2>/dev/null | grep -a 'P239-OWNAUTH\|H39-SINGLE\|P3L-DIRLOG-BIRTH\|P241-AUTHTRY\|P-LONE-DIR\|UNPUB-DIR' | cut -c1-400" > "$OUT/${arm}_capture.txt"
    rs 60 "$A" "journalctl -k --since @$mark --no-pager 2>/dev/null | cut -c1-400" > "$OUT/${arm}_journal.txt"
    local nondur_dir nondur_w unpub_w outcome births
    nondur_dir=$(grep -a 'P239-OWNAUTH-NONDUR' "$OUT/${arm}_capture.txt" | grep -ac 'blft=10 ')
    nondur_w=$(grep -a 'P239-OWNAUTH-NONDUR' "$OUT/${arm}_capture.txt" | grep -a 'blft=10 ' | grep -ac "ino=$WINO ")
    outcome=$(grep -a 'P239-OWNAUTH-NONDUR' "$OUT/${arm}_capture.txt" | grep -a 'blft=10 ' | grep -a "ino=$WINO " | grep -oE 'outcome=[0-9]+ ino=[0-9]+ mode=[0-9]+ unpub=[0-9]+' | sort | uniq -c | tr -s ' ' | tr '\n' ';')
    births=$(cnt "$OUT/${arm}_capture.txt" 'P3L-DIRLOG-BIRTH')
    echo "--- $arm capture lines ($(wc -l < "$OUT/${arm}_capture.txt")):"
    sed 's/.*kernel: /    /' "$OUT/${arm}_capture.txt" | cut -c1-200 | head -12
    echo "ROW $arm | wino=$WINO | dir_births=$births | nondur_dirblock_images=$nondur_dir | nondur_dirblock_images_of_w=$nondur_w | outcomes_of_w=${outcome:-none} |" | tee -a "$OUT/rows.txt"
    [ "$arm" = peer ] && echo "  $B unmount rc=$(umount_node "$B")"
    echo "  $A unmount rc=$(umount_node "$A")"
}
case $ARMS in
    lone) run_arm lone ;;
    peer) run_arm peer ;;
    both) run_arm lone; run_arm peer ;;
    *) echo "bad arm $ARMS"; exit 2 ;;
esac
echo "ROWS:"; sed 's/^/  /' "$OUT/rows.txt" 2>/dev/null
if [ $aborts -gt 0 ]; then echo "RESULT: ABORT label=$LABEL aborts=$aborts wall=$(el)s evidence=$OUT"; exit 2; fi
echo "RESULT: MEASURED label=$LABEL wall=$(el)s evidence=$OUT"
