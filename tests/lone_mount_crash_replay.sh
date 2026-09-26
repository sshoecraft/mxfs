#!/bin/bash
# lone_mount_crash_replay.sh — D-LONE-MOUNT-DIRECTORY-BLOCK-IMAGE-SHIPS-AUTH-NOT-HELD:
# a node mounted ALONE (never had a peer) logs a directory's block-format
# image and a file's bmap-btree image, fsyncs, and dies before either is
# checkpointed.  Its next incarnation returns alone, fences the dead one and
# replays the slice.  Every fsynced witness must be back, nothing refused,
# nothing quarantined, and the other node must read the same bytes cold.
#
# Two witnesses, both inode-owned images that only the owner's grant can
# authorize:
#   w/        mkdir + 40 creates -> shortform-to-block conversion -> a
#             XFS_BLFT_DIR_BLOCK_BUF image (the s53f refusal)
#   bt        a file fallocated as 48 disjoint 64 KiB extents -> extent map in
#             a bmap btree block (XFS_BLFT_BMBT_BUF)
#   xa        a file with a 3000-byte xattr -> an attribute leaf block
#             (XFS_BLFT_ATTR_LEAF_BUF)
#
# budget (derived): pre-unmounts 2 x <=90 (typ 3) + mkfs 32 slices + lone
# mount ~25 + witnesses ~5 + platter probe ~10 + boot ~120-150 + mount with
# own-slice recovery <=180 (typ 5-90) + checks ~10 + B mount ~10 + unmounts
# ~6 + chk_mxfs ~15 -> ~520 s worst, ~250 s typical.
#
# Usage: tests/lone_mount_crash_replay.sh <label> [same|peer]
#   same (default): the victim's own next incarnation returns alone and
#                   replays the slice; the other node then joins and reads cold
#   peer:           the OTHER node mounts (alone, never had a peer itself),
#                   fences the victim and replays its slice; the victim then
#                   reboots, joins and reads cold
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default /dev/sda),
#        MXFS_TRANSPORT (tcp|caw, default tcp)
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT, 3 VACUOUS (a witness was already
# checkpointed before the kill, so the replay was not exercised).
set -u
LABEL=${1:?label}
RECOVERER=${2:-same}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
TR=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the victim
B=${MXFS_NODE_LIST##*,}          # platter probe, then the recoverer (peer) or the cold reader (same)
case $RECOVERER in same) R=$A; C=$B ;; peer) R=$B; C=$A ;; *) echo "bad recoverer $RECOVERER"; exit 2 ;; esac
SI=/src/mxfs/tools/slice_image.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lonecrash_$LABEL
mkdir -p "$OUT"
IMG=/src/mxfs/$OUT               # the same directory as the nodes see it (NFS)
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# rs/rsx/cnt/capture_require/ensure_src_or_abort: every capture a verdict is
# taken from is proven to hold its tool's shape first (tests/lib/rig.sh).
. "$(dirname "$0")/lib/rig.sh"
# MXFS_FAULT_UMOUNT_SRC=<node>:<stage> (verification of the capture contract
# only): lazily unmounts /src on <node> immediately before the named
# acquisition (home_probe | recover | cold), a real fault at the real
# acquisition point; the lap must then ABORT, never reach a verdict.
fault_before() { # <stage>
    case ${MXFS_FAULT_UMOUNT_SRC:-} in
        *:"$1") echo "STAGE FAULT: unmounting /src on ${MXFS_FAULT_UMOUNT_SRC%%:*} before $1"; rs 30 "${MXFS_FAULT_UMOUNT_SRC%%:*}" "umount -l /src; mountpoint -q /src && echo STILL || echo GONE" | tail -1 ;;
    esac
}
VIRSH="timeout 30 virsh -c qemu:///system"
s0=$(date +%s); el() { echo $(( $(date +%s) - s0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== lone_mount_crash_replay label=$LABEL victim=$A recoverer=$R($RECOVERER) cold_reader=$C transport=$TR sv=$SV $(date -u +%FT%TZ) ==="

umount_node() { # <node> -> rc
    rs 110 "$1" "timeout 90 umount $MNT; echo UMOUNT_RC=\$?" | sed -n 's/^UMOUNT_RC=//p' | head -1
}
# boot_wait_into <var> <node>: wait for the node's login to open (polling,
# never a verdict), then the tree mount, across the boundary: SRC_OK or
# SRC_NOT_MOUNTED from a node that answered; a node that never answered is
# an ABORT, never an empty value that fails to equal SRC_OK
boot_wait_into() {
    local w=0
    until [ "$(rs 15 "$2" 'test -e /run/nologin && echo booting || echo ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do w=$((w+1)); sleep 5; done
    value_now_into "$1" "$2" 150 "$OUT/boot_$2.txt" '^SRC_(OK|NOT_MOUNTED)$' "the tree mount on $2 after boot" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.120.1:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src && echo SRC_OK || echo SRC_NOT_MOUNTED"
}

# Both nodes need the tree (the probes, prep scripts and dump tool live on
# the NFS share): a node rebooted by a previous lap may not have it mounted,
# and a probe that cannot open its script reports nothing (s54j/s54k).
ensure_src_or_abort $A $B
# Never reformat under a live peer: it is fenced, withdraws, and its module
# can no longer be unloaded (s54a).
echo "STAGE pre-unmounts: $B rc=$(umount_node "$B") $A rc=$(umount_node "$A")"
rsx 200 "$A" "MXFS_DEV=$MXFS_DEV MXFS_LOG_SLICES=32 bash /src/mxfs/tests/setup/prep_fs.sh 2>&1 | tail -2; MXFS_DEV=$MXFS_DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh $TR 2>&1 | grep -a 'NODE_PREP_OK\|FAIL' | head -2; true" > "$OUT/prep.txt"
capture_require "$OUT/prep.txt" '^(NODE_PREP_OK|NODE_PREP_FAIL)' "the format and lone mount of $A (the prep script must have run)"
ck "fresh format and lone mount of $A" "$(cnt "$OUT/prep.txt" 'NODE_PREP_OK')" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
slot=$(rs 20 "$A" "dmesg | grep -a 'claimed heartbeat slot' | tail -1" | grep -oE 'claimed heartbeat slot [0-9]+' | grep -oE '[0-9]+$')
echo "STAGE $A alone in slot ${slot:-?} at +$(el)s"

# the witnesses: log-forced, then killed before they can be checkpointed
MARK=$(rs 10 "$A" 'date +%s' | tail -1)
rsx 60 "$A" "cd $MNT && mkdir w && for i in \$(seq 1 40); do echo w\$i > w/f\$i; done && : > bt && for i in \$(seq 0 47); do fallocate -o \$((i*131072)) -l 65536 bt || echo FALLOC_FAIL; done && : > xa && setfattr -n user.big -v \$(head -c 3000 /dev/zero | tr '\\0' 'x') xa || echo XATTR_FAIL; sync -f $MNT && echo XAINO=\$(stat -c %i xa) XALEN=\$(getfattr --only-values -n user.big xa 2>/dev/null | wc -c) && echo WINO=\$(stat -c %i w) BTINO=\$(stat -c %i bt) BTEXT=\$(filefrag -v bt 2>/dev/null | grep -cE '^ +[0-9]+:') && md5sum w/f* | md5sum | cut -c1-32; journalctl -k --since @$MARK --no-pager 2>/dev/null | grep -a 'P239-OWNAUTH-NONDUR\|P3L-DIRLOG-BIRTH' | cut -c1-300 > $IMG/victim_capture.txt; true" > "$OUT/witness.txt"
# the witness workload's own account must be complete before the node dies:
# its inode numbers and md5 are what every later assertion is measured against
capture_require "$OUT/witness.txt" '^WINO=[0-9]+ BTINO=[0-9]+ BTEXT=[0-9]+$' "the witness workload on $A"
$VIRSH destroy "$A" > /dev/null 2>&1
echo "STAGE witnesses written+synced, $A destroyed at +$(el)s: $(grep -a 'WINO=' "$OUT/witness.txt")"
WINO=$(grep -a 'WINO=' "$OUT/witness.txt" | grep -oE 'WINO=[0-9]+' | cut -d= -f2)
BTINO=$(grep -a 'BTINO=' "$OUT/witness.txt" | grep -oE 'BTINO=[0-9]+' | cut -d= -f2)
BTEXT=$(grep -a 'BTEXT=' "$OUT/witness.txt" | grep -oE 'BTEXT=[0-9]+' | cut -d= -f2)
WMD5=$(tail -1 "$OUT/witness.txt")
[ -n "$WINO" ] && [ -n "$BTINO" ] || { echo "RESULT: ABORT label=$LABEL stage=witness evidence=$OUT"; exit 2; }
ck "the bt file's extent map has more extents than an inode fork holds (btree)" "$([ "${BTEXT:-0}" -ge 40 ] && echo btree || echo "inline:$BTEXT")" "btree"
ck "no fallocate failure" "$(cnt "$OUT/witness.txt" FALLOC_FAIL)" 0
ck "no xattr failure" "$(cnt "$OUT/witness.txt" XATTR_FAIL)" 0
XAINO=$(grep -a 'XAINO=' "$OUT/witness.txt" | grep -oE 'XAINO=[0-9]+' | cut -d= -f2)
ck "the xa file's 3000-byte xattr was stored (an attribute leaf block, outside the inode core)" "$(grep -a 'XALEN=' "$OUT/witness.txt" | grep -oE 'XALEN=[0-9]+' | cut -d= -f2)" 3000
echo "STAGE victim capture-time lines: $(wc -l < "$OUT/victim_capture.txt" 2>/dev/null || echo 0), non-durable inode-owned captures: $(cnt "$OUT/victim_capture.txt" 'P239-OWNAUTH-NONDUR' 2>/dev/null || echo 0)"
fault_before home_probe
rsx 30 "$B" "python3 $SI dinode $MXFS_DEV $WINO; python3 $SI dinode $MXFS_DEV $BTINO" > "$OUT/home_before.txt"
capture_require "$OUT/home_before.txt" 'state=[A-Z]+' "the platter dinode probe on $B"
home_w=$(grep -oE 'state=[A-Z]+' "$OUT/home_before.txt" | sed -n 1p | cut -d= -f2)
home_bt=$(grep -oE 'state=[A-Z]+' "$OUT/home_before.txt" | sed -n 2p | cut -d= -f2)
echo "STAGE home dinodes before recovery: w=${home_w:-?} bt=${home_bt:-?} (FREE/NOMAGIC = lives only in the log)"

# the recoverer mounts alone and replays the dead incarnation's slice: the
# victim's own next incarnation (same), or the other node (peer)
if [ "$RECOVERER" = same ]; then
    $VIRSH start "$A" > /dev/null 2>&1
    boot_wait_into bw "$A"; ck "$A booted with /src" "$bw" "SRC_OK"
fi
RMARK=$(date +%s)
fault_before recover
rsx 200 "$R" "MXFS_DEV=$MXFS_DEV timeout 180 bash /src/mxfs/tests/setup/prep_node.sh $TR 2>&1 | grep -a 'NODE_PREP_OK\|FAIL\|refused\|rc=' | head -3; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED; echo WCOUNT=\$(ls $MNT/w 2>/dev/null | wc -l); echo WMD5=\$(cd $MNT && md5sum w/f* 2>/dev/null | md5sum | cut -c1-32); echo BTEXT=\$(filefrag -v $MNT/bt 2>/dev/null | grep -cE '^ +[0-9]+:'); echo XALEN=\$(getfattr --only-values -n user.big $MNT/xa 2>/dev/null | wc -c); echo ROOTLS=\$(ls $MNT 2>&1 | tr '\n' ' ')" > "$OUT/recover.txt" 2>&1
# A node returning ALONE to a volume whose only other record is its own dead
# incarnation is a whole-cluster bootstrap: it adopts that slot
# (P-BOOT-ADOPTED slot N) instead of claiming a free one, so either line
# proves the mount reached its slot.  Requiring only the claim line aborted
# every run after recovery had already succeeded.
rsx 60 "$R" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | grep -a 'XFS\|MXFS\|mxfs' | grep -ai 'recover\|mismatch\|corrupt\|torn\|refus\|quarantin\|ATOMIC-SKIP\|P227-TOKEN \|P241\|P240\|claimed heartbeat\|P-BOOT-ADOPTED slot' | cut -c1-300" > "$OUT/recovery_lines.txt"
capture_require "$OUT/recovery_lines.txt" 'claimed heartbeat slot|P-BOOT-ADOPTED slot' "the recovery kernel log on $R"
rsx 60 "$R" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/recovery_journal.txt"
capture_require "$OUT/recovery_journal.txt" 'kernel: ' "the kernel journal on $R after recovery"
echo "--- recovery lines ($(wc -l < "$OUT/recovery_lines.txt")):"
sed 's/.*kernel: /    /' "$OUT/recovery_lines.txt" | cut -c1-190 | head -16
capture_require "$OUT/recover.txt" '^(NODE_PREP_OK|NODE_PREP_FAIL)' "the node preparation on $R (a remote command list masks an early failure behind a later successful command: the prep script must have run)"
capture_require "$OUT/recover.txt" '^(MOUNTED|NOT_MOUNTED)$' "the recovery mount on $R"
ck "$R mounted after the crash (replay of $A's dead incarnation)" "$(cnt "$OUT/recover.txt" '^MOUNTED')" 1
ck "all 40 witness files are back" "$(sed -n 's/^WCOUNT=//p' "$OUT/recover.txt" | head -1)" "40"
ck "the witness files' bytes match what was fsynced" "$(sed -n 's/^WMD5=//p' "$OUT/recover.txt" | head -1)" "$WMD5"
ck "the bt file's btree extent map is back" "$(sed -n 's/^BTEXT=//p' "$OUT/recover.txt" | head -1)" "$BTEXT"
ck "the xa file's 3000-byte xattr is back" "$(sed -n 's/^XALEN=//p' "$OUT/recover.txt" | head -1)" 3000
ck "no image refused, no transaction skipped, nothing quarantined" "$(grep -aic 'P227-FR-ATOMIC-SKIP\|P227-FR-TORN\|P241-RECOV-TERMINAL\|P240-QUAR\|quarantined by\|NOT_HELD' "$OUT/recovery_lines.txt")" 0
ck "no mismatched-uuid / corruption in recovery" "$(grep -aic 'mismatched\|corrupt' "$OUT/recovery_lines.txt")" 0
ck "zero shutdown / BUG / Oops on $R" "$(( $(cnt "$OUT/recovery_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/recovery_journal.txt" 'BUG:\|Oops') ))" 0
tok=$(grep -a 'P227-TOKEN ' "$OUT/recovery_lines.txt" | grep -oE 'blft=[0-9]+ v=[0-9]+ class=[0-9]+ st=[0-9]+' | sort | uniq -c | tr -s ' ' | tr '\n' ';')
echo "STAGE replayed token classes: ${tok:-none printed}"
ck "a directory-block image replayed inode-class VALID (blft=10 class=3 st=1)" "$([ "$(grep -a 'P227-TOKEN ' "$OUT/recovery_lines.txt" | grep -ac 'blft=10 v=3 class=3 st=1')" -ge 1 ] && echo yes || echo no)" yes
ck "an attribute-leaf image replayed inode-class VALID (blft=16 class=3 st=1)" "$([ "$(grep -a 'P227-TOKEN ' "$OUT/recovery_lines.txt" | grep -ac 'blft=16 v=3 class=3 st=1')" -ge 1 ] && echo yes || echo no)" yes
ck "a bmap-btree image replayed inode-class VALID (blft=4 class=3 st=1)" "$([ "$(grep -a 'P227-TOKEN ' "$OUT/recovery_lines.txt" | grep -ac 'blft=4 v=3 class=3 st=1')" -ge 1 ] && echo yes || echo no)" yes
ck "no replayed transaction skipped an image (P227-TOKENSUM wskip=0 everywhere)" "$(grep -a 'P227-TOKENSUM' "$OUT/recovery_journal.txt" | grep -avc 'wskip=0 ')" 0
# the recovered namespace must accept ordinary mutation
rsx 40 "$R" "cd $MNT && echo after > w/f41 && mkdir w/sub && echo MUT_OK; ls w | wc -l" > "$OUT/mutate.txt" 2>&1
capture_require "$OUT/mutate.txt" '^[0-9]+$' "the post-recovery mutation on $R"
ck "the recovered directory accepts a create and a mkdir" "$(cnt "$OUT/mutate.txt" MUT_OK)" 1

# the other node reads the witnesses cold, then the offline check
if [ "$RECOVERER" = peer ]; then
    $VIRSH start "$A" > /dev/null 2>&1
    boot_wait_into bw "$A"; ck "$A booted with /src" "$bw" "SRC_OK"
fi
fault_before cold
rsx 200 "$C" "MXFS_DEV=$MXFS_DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh $TR 2>&1 | grep -a 'NODE_PREP_OK\|FAIL' | head -2; echo WCOUNT=\$(ls $MNT/w 2>/dev/null | grep -c '^f[0-9]*\$'); echo WMD5=\$(cd $MNT && md5sum w/f[0-9]* 2>/dev/null | grep -v f41 | md5sum | cut -c1-32); echo BTEXT=\$(filefrag -v $MNT/bt 2>/dev/null | grep -cE '^ +[0-9]+:'); echo XALEN=\$(getfattr --only-values -n user.big $MNT/xa 2>/dev/null | wc -c)" > "$OUT/cold_$C.txt" 2>&1
capture_require "$OUT/cold_$C.txt" '^(NODE_PREP_OK|NODE_PREP_FAIL)' "the node preparation on $C"
capture_require "$OUT/cold_$C.txt" '^WCOUNT=[0-9]+' "the cold read on $C"
ck "$C joined the recovered filesystem" "$(cnt "$OUT/cold_$C.txt" 'NODE_PREP_OK')" 1
ck "$C reads all 41 witness files cold (40 + the post-recovery create)" "$(sed -n 's/^WCOUNT=//p' "$OUT/cold_$C.txt" | head -1)" "41"
ck "$C reads the fsynced bytes" "$(sed -n 's/^WMD5=//p' "$OUT/cold_$C.txt" | head -1)" "$WMD5"
ck "$C reads the bt extent map" "$(sed -n 's/^BTEXT=//p' "$OUT/cold_$C.txt" | head -1)" "$BTEXT"
ck "$C reads the 3000-byte xattr" "$(sed -n 's/^XALEN=//p' "$OUT/cold_$C.txt" | head -1)" 3000
echo "STAGE unmounts: $C rc=$(umount_node "$C") $R rc=$(umount_node "$R")"
rsx 120 "$B" "timeout 90 /src/mxfs/tools/chk_mxfs -v $MXFS_DEV 2>&1 | tail -4" > "$OUT/chk.txt" 2>&1
capture_require "$OUT/chk.txt" 'chk_mxfs: ' "the offline check on $B"
ck "offline check clean" "$(grep -aic 'error\|corrupt\|bad' "$OUT/chk.txt")" 0
echo "ROW $LABEL/$RECOVERER/$TR | home_w=${home_w:-?} home_bt=${home_bt:-?} | mounted=$(cnt "$OUT/recover.txt" '^MOUNTED') | wfiles=$(sed -n 's/^WCOUNT=//p' "$OUT/recover.txt" | head -1) | md5_ok=$([ "$(sed -n 's/^WMD5=//p' "$OUT/recover.txt" | head -1)" = "$WMD5" ] && echo 1 || echo 0) | bt_ext=$(sed -n 's/^BTEXT=//p' "$OUT/recover.txt" | head -1)/$BTEXT | refusals=$(grep -aic 'P227-FR-ATOMIC-SKIP\|P227-FR-TORN\|P241-RECOV-TERMINAL\|P240-QUAR\|quarantined by\|NOT_HELD' "$OUT/recovery_lines.txt") | cold_files=$(sed -n 's/^WCOUNT=//p' "$OUT/cold_$C.txt" | head -1) | fails=$fails |" | tee "$OUT/rows.txt"
if [ $fails = 0 ] && { [ "${home_w:-}" = ALLOCATED ] || [ "${home_bt:-}" = ALLOCATED ]; }; then
    echo "RESULT: VACUOUS label=$LABEL fails=0 (a witness was checkpointed before the kill) wall=$(el)s evidence=$OUT"; exit 3
fi
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
