#!/bin/bash
# d0531_stale_slice_recovery.sh — D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531:
# what does recovery do with a slice whose never-written blocks hold a
# PREVIOUS incarnation's genuine log records?
#
# THE QUESTION (design consult, 2026-09-18).  A record from another
# incarnation cannot be assembled (its h_fs_uuid is refused at the found head
# and per record), so the decisive failure is not foreign replay.  It is
# recovery that SUCCEEDS with a committed current-incarnation transaction
# missing, because head discovery consumed foreign cycle/header data before
# per-record validation and picked an earlier head, truncated the replay
# interval or cleared the wrong stale blocks.  Refusal ("mismatched uuid") is
# the availability outcome; correct recovery for this layout is the disproof.
#
# SHAPE (two arms, each a genuine crash; nothing forged — the planted bytes
# are real records the previous incarnation wrote at the same offsets):
#   U1: prep both nodes, fill both slices with real records, unmount both,
#       save slot 0's slice image (the OLD records).
#   arm control:  mkfs U2 (zeroed) -> mount test1 alone -> mkdir w + 40 files
#       + fsync (log-forced) -> virsh destroy within a second -> read the home
#       dinode of w (must be FREE/absent: the transaction lives only in the
#       log) -> save the crash image C -> boot -> mount alone (own-slice
#       recovery) -> w and its 40 files must be back, no refusal.
#   arm variant:  same, but between the fresh format and the lone mount every
#       all-zero 512 B block of slot 0's freshly formatted slice is replaced
#       by the U1 image's block at the same offset, so the blocks U2 never
#       writes carry old records including the head-search / wrap region —
#       exactly the platter a non-durable mkfs zero leaves.  The first mount,
#       the witness, the crash and the recovery all run on that slice.
#       Recovery must reach the same result as the control.
#       Since 0.88.0 the slot claimant zeroes the slice through the kernel
#       FUA path before its first journal write (the slice lifecycle record,
#       INIT_REQUIRED -> ZEROING -> READY), so the plant must be PROVEN on
#       the platter before the claim (old_blocks_planted, verify=OK) and
#       GONE at the crash (foreign_at_crash=0), with the first-mount window
#       carrying the lifecycle line before=INIT_REQUIRED after=READY on both
#       arms.  Measured before the fix (s60j): plant still present at the
#       crash, recovery refused at a stale head, 0 of 40 files back.
#       The plant is written by test1 itself, right after its own mkfs and
#       before it registers: an unregistered initiator cannot write the LUN
#       while a dead incarnation's Write Exclusive all-registrants reservation
#       stands (measured s54z: a post-crash plant from test2 was refused
#       EBADE), and this rig's LUN is a QNAP target with no host-side backing
#       store to write around it.
#
# budget (derived): prep 50 s (300) + fill 60 s + unmounts 2x90 + per arm
# (mkfs+lone mount 60 + witness 5 + dumps 40 + boot 150 + mount 60 (bound
# 180) + umount 90) x2 + final prep 300 -> ~1400 s worst, ~800 s typical.
# Measured 0.88.0: 766 s (s61a) and 759 s (s61b, PASS); bound 1000 s.
#
# Usage: tests/d0531_stale_slice_recovery.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV (default /dev/sda),
#        MXFS_TRANSPORT (tcp|caw, default tcp)
#        MXFS_FAULT_UMOUNT_SRC=<node>:<stage> (verification of the capture
#        contract only): lazily unmounts /src on <node> immediately before
#        the named acquisition (home_probe | dump | recover), a real fault
#        at the real acquisition point; the lap must then ABORT, never
#        reach a verdict.
# Exit 0 PASS, 1 FAIL, 2 INFRA/ABORT, 3 VACUOUS.
#
# Every capture a verdict is taken from is acquired with rsx and proven to
# hold its tool's shape (capture_require, tests/lib/rig.sh) before any count
# is read from it: a probe that ran on a node without the tree, a device
# from another rig, or a timeout is an ABORT about the instrument, not a
# number about MXFS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
A=${MXFS_NODE_LIST%%,*}          # crashes and recovers its own slice
B=${MXFS_NODE_LIST##*,}          # fill partner, then the probe that images the LUN
TR=${MXFS_TRANSPORT:-tcp}
SI=/src/mxfs/tools/slice_image.py
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0531ssr_$LABEL
mkdir -p "$OUT"
IMG=/src/mxfs/$OUT               # the same directory as the nodes see it (NFS)
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# ckge: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
. "$(dirname "$0")/lib/rig.sh"
# the verification-only fault barrier (see the header)
fault_before() { # <stage>
    case ${MXFS_FAULT_UMOUNT_SRC:-} in
        *:"$1") echo "STAGE FAULT: unmounting /src on ${MXFS_FAULT_UMOUNT_SRC%%:*} before $1"; rs 30 "${MXFS_FAULT_UMOUNT_SRC%%:*}" "umount -l /src; mountpoint -q /src && echo STILL || echo GONE" | tail -1 ;;
    esac
}
VIRSH="timeout 30 virsh -c qemu:///system"
s0=$(date +%s); el() { echo $(( $(date +%s) - s0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0531_stale_slice_recovery label=$LABEL A=$A B(probe)=$B sv=$SV $(date -u +%FT%TZ) ==="

# umount_node_into <var> <node>: the unmount's rc, across the boundary (the
# ssh's status observed, the UMOUNT_RC line present): a node that could not
# be reached is an ABORT, never an empty rc that fails to equal 0
umount_node_into() {
    value_now_into "$1" "$2" 110 "$OUT/umount_$2.txt" '^UMOUNT_RC=[0-9]+$' "the unmount of $MNT on $2" "timeout 90 umount $MNT; echo UMOUNT_RC=\$?"
    printf -v "$1" '%s' "${!1#UMOUNT_RC=}"
}
# boot_wait_into <var> <node>: wait for the node's login to open (polling,
# never a verdict), then the tree mount, across the boundary: SRC_OK or
# SRC_NOT_MOUNTED from a node that answered; a node that never answered is
# an ABORT, never an empty value that fails to equal SRC_OK
boot_wait_into() {
    local w=0
    until [ "$(rs 15 "$2" 'test -e /run/nologin && echo booting || echo ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do w=$((w+1)); sleep 5; done
    value_now_into "$1" "$2" 150 "$OUT/boot_$2.txt" '^SRC_(OK|NOT_MOUNTED)$' "the tree mount on $2 after boot" "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src && echo SRC_OK || echo SRC_NOT_MOUNTED"
}

# ── U1: fill both slices with real records, then save slot 0's image ──────
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep_u1.log" 2>&1
prc=$?
echo "STAGE prep U1 rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep_u1.log" | cut -c1-120)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
U1=$(rs 30 "$A" "python3 $SI geom $MXFS_DEV" | sed -n 's/^sb_uuid=//p')
echo "STAGE U1 uuid=$U1"
for h in $A $B; do
    rsx 120 "$h" "mkdir -p $MNT/fill_$h && cd $MNT/fill_$h && for i in \$(seq 1 3000); do : > f\$i; done; sync -f $MNT; for i in \$(seq 1 2 3000); do rm -f f\$i; done; sync -f $MNT; ls | wc -l" > "$OUT/fill_$h.txt" 2>&1 &
done; wait
capture_require "$OUT/fill_$A.txt" '^[0-9]+$' "the slice fill on $A"
capture_require "$OUT/fill_$B.txt" '^[0-9]+$' "the slice fill on $B"
ck "$A filled its slice (files left)" "$(tail -1 "$OUT/fill_$A.txt")" "1500"
ck "$B filled its slice (files left)" "$(tail -1 "$OUT/fill_$B.txt")" "1500"
umount_node_into urc "$B"; ck "$B unmounted" "$urc" "0"
umount_node_into urc "$A"; ck "$A unmounted" "$urc" "0"
ensure_src_or_abort "$B"
rsx 60 "$B" "python3 $SI scan $MXFS_DEV $U1 --dev" > "$OUT/scan_u1.txt" 2>&1
capture_require "$OUT/scan_u1.txt" '^slot=[0-9]+ headers=' "the U1 slice scan on $B"
sed 's/^/    /' "$OUT/scan_u1.txt" | cut -c1-200
u1_slot0=$(grep -a '^slot=0 ' "$OUT/scan_u1.txt" | grep -oE 'current=[0-9]+' | cut -d= -f2)
ckge "slot 0 carries U1 records to plant" "${u1_slot0:-0}" 50
rsx 120 "$B" "python3 $SI dump $MXFS_DEV 0 $IMG/u1_slot0.img" > "$OUT/dump_u1.txt" 2>&1
capture_require "$OUT/dump_u1.txt" '^dumped slot=0 ' "the U1 slice dump on $B"
cat "$OUT/dump_u1.txt" | sed 's/^/    /'
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=U1 evidence=$OUT"; exit 2; }

run_arm() { # <control|variant>
    local arm=$1 mk mrc slot WINO home_before ims recov mrc2 wcount home_after
    echo "=== ARM $arm at +$(el)s ==="
    # fresh incarnation, zeroed by mkfs; test1 mounts ALONE
    # 32 slices, as run.sh formats: the U1 image's slice geometry must match
    rsx 120 "$A" "MXFS_DEV=$MXFS_DEV MXFS_LOG_SLICES=32 bash /src/mxfs/tests/setup/prep_fs.sh 2>&1 | tail -2" > "$OUT/${arm}_prep.txt" 2>&1
    capture_require "$OUT/${arm}_prep.txt" '^(FS_PREP_OK|FS_PREP_FAIL)' "the fresh format on $A"
    ck "$arm: fresh format by $A" "$(cnt "$OUT/${arm}_prep.txt" 'FS_PREP_OK')" 1
    rs 30 "$A" "python3 $SI geom $MXFS_DEV" > "$OUT/${arm}_geom.txt" 2>&1
    U2=$(sed -n 's/^sb_uuid=//p' "$OUT/${arm}_geom.txt")
    [ -n "$U2" ] || { echo "  ABORT: no sb_uuid from the fresh format on $A"; echo "RESULT: ABORT label=$LABEL stage=${arm}_geom evidence=$OUT"; exit 2; }
    # slot 0's slice starts at the log itself: the independent number the
    # claim's payload_off is held to below
    LOGPHYS=$(sed -n 's/^log_phys=//p' "$OUT/${arm}_geom.txt")
    if [ "$arm" = variant ]; then
        # the plant: slot 0's slice as mkfs left it, every all-zero block
        # replaced by U1's block at the same offset, written back by the
        # node that just formatted (nothing is registered yet, so nothing
        # refuses the write), and read back from the platter
        # block 0 stays zero: head discovery reads it first and a zero cycle
        # there is "completely zeroed log", so the first mount proceeds and
        # writes its records from block 0 with the old records BEYOND its
        # genuine head — the layout under test.  With block 0 planted too
        # the first mount is refused at head discovery (mismatched uuid,
        # -117; measured s60i) and the incarnation never writes anything.
        rsx 200 "$A" "python3 $SI dump $MXFS_DEV 0 $IMG/${arm}_fresh.img && python3 $SI compose $IMG/${arm}_fresh.img $IMG/u1_slot0.img $IMG/${arm}_planted.img --keep-first 1 && python3 $SI scan $IMG/${arm}_planted.img $U2 && python3 $SI load $MXFS_DEV 0 $IMG/${arm}_planted.img" > "$OUT/${arm}_plant.txt" 2>&1
        capture_require "$OUT/${arm}_plant.txt" '^loaded slot=0 .*verify=' "the planted-image load on $A"
        ckge "$arm: old records planted into the blocks mkfs left zero" "$(grep -a 'composed' "$OUT/${arm}_plant.txt" | grep -oE 'old_blocks_planted=[0-9]+' | cut -d= -f2)" 100
        ck "$arm: the planted image is on the platter" "$(cnt "$OUT/${arm}_plant.txt" 'verify=OK')" 1
        sed 's/^/    /' "$OUT/${arm}_plant.txt" | cut -c1-200
    fi
    local FM="D0531-FM-$arm-$LABEL-$$"
    rsx 200 "$A" "echo '$FM' > /dev/kmsg; MXFS_DEV=$MXFS_DEV timeout 120 bash /src/mxfs/tests/setup/prep_node.sh $TR 2>&1 | grep -a 'NODE_PREP_OK\|FAIL' | head -2" >> "$OUT/${arm}_prep.txt" 2>&1
    capture_require "$OUT/${arm}_prep.txt" '^(NODE_PREP_OK|NODE_PREP_FAIL)' "the lone mount on $A"
    ck "$arm: lone mount of $A on the fresh filesystem" "$(cnt "$OUT/${arm}_prep.txt" 'NODE_PREP_OK')" 1
    # the first mount's own recovery lines on a slice full of old records:
    # THIS mount's window, from its marker, never the whole ring
    window_into "$OUT/${arm}_firstmount_win.txt" "$A" 40 "$FM"
    grep -a 'XFS\|MXFS\|mxfs' "$OUT/${arm}_firstmount_win.txt" | grep -ai 'recover\|mismatch\|corrupt\|log has\|head\|tail\|P-FR\|P163\|P-LREC\|torn\|refus\|claimed heartbeat\|stale\|P-SLIFE' | cut -c1-300 > "$OUT/${arm}_firstmount_lines.txt"
    # the filtered window is what the counts below read: a lone mount that
    # got as far as its log — admitted or refused at head discovery — has
    # logged its heartbeat slot claim first, so that line is the shape
    capture_require "$OUT/${arm}_firstmount_lines.txt" 'claimed heartbeat slot|P-SLIFE' "the first-mount kernel lines on $A"
    echo "--- $arm first-mount lines ($(wc -l < "$OUT/${arm}_firstmount_lines.txt")):"; sed 's/.*kernel: /    /' "$OUT/${arm}_firstmount_lines.txt" | cut -c1-190 | head -8
    ck "$arm: no mismatched-uuid / corruption / image refusal at the first mount" "$(grep -aic 'mismatched\|corrupt\|P227-FR-ATOMIC-SKIP\|P227-FR-TORN\|P241-RECOV-TERMINAL\|P240-QUAR\|quarantined by' "$OUT/${arm}_firstmount_lines.txt")" 0
    # the slice lifecycle at the claim (0.88.0): a fresh format's slice is
    # INIT_REQUIRED and the claimant must bring it to READY through the FUA
    # zero before this mount journals anything — on both arms, since the
    # control's mkfs zero is exactly as untrusted as the variant's plant
    ck "$arm: the claim brought slice 0 INIT_REQUIRED -> READY (P-SLIFE) before the first journal write" "$(cnt "$OUT/${arm}_firstmount_lines.txt" 'P-SLIFE slot=0 slice=0 before=INIT_REQUIRED after=READY')" 1
    ck "$arm: the claim-time zero was not refused or skipped as legacy" "$(cnt "$OUT/${arm}_firstmount_lines.txt" 'P-SLIFE-REFUSED\|P-SLIFE-LEGACY\|P-SLIFE-ZERO-READBACK\|P-SLIFE-ZERO-IO')" 0
    # WHERE the zero landed: the claim's own payload_off against the slice
    # offset slice_image.py derives from the envelope and the XFS sb.  The
    # first lap of 0.88.0 (s61a) reported READY after zeroing 64 MiB of the
    # data area 23 GiB below the slice; the state machine cannot see that,
    # only this comparison can
    ck "$arm: the zero landed on slot 0's slice (P-SLIFE-ZEROING payload_off == slice_image log_phys=${LOGPHYS:-?})" "$(grep -a 'P-SLIFE-ZEROING slice=0 ' "$OUT/${arm}_firstmount_win.txt" | grep -oE 'payload_off=[0-9]+' | head -1 | cut -d= -f2)" "${LOGPHYS:-?}"
    ck "$arm: the zero covered the whole slice (P-SLIFE-ZEROING len == slice_bytes)" "$(grep -a 'P-SLIFE-ZEROING slice=0 ' "$OUT/${arm}_firstmount_win.txt" | grep -oE ' len=[0-9]+' | head -1 | cut -d= -f2)" "$(sed -n 's/^slice_bytes=//p' "$OUT/${arm}_geom.txt")"
    if [ "$(cnt "$OUT/${arm}_prep.txt" 'NODE_PREP_OK')" != 1 ]; then
        # a refused first mount is the availability outcome for this layout,
        # measured; the witness cannot be written and the crash arm would
        # only measure the root filesystem under an unmounted mountpoint
        echo "ROW $arm | first_mount=REFUSED | planted=$(grep -a 'composed' "$OUT/${arm}_plant.txt" | grep -oE 'old_blocks_planted=[0-9]+' | cut -d= -f2) | refusals=$(grep -aic 'mismatched\|corrupt\|P227-FR-ATOMIC-SKIP\|P227-FR-TORN\|P241-RECOV-TERMINAL\|P240-QUAR\|quarantined by' "$OUT/${arm}_firstmount_lines.txt") |" | tee -a "$OUT/rows.txt"
        return
    fi
    window_into "$OUT/rv_slot_1.txt" "$A" 20; slot=$(cat "$OUT/rv_slot_1.txt" | grep -a 'claimed heartbeat slot' | tail -1 | grep -oE 'claimed heartbeat slot [0-9]+' | grep -oE '[0-9]+$')
    echo "STAGE $arm: U2 uuid=$U2 slot=${slot:-?}"
    ck "$arm: $A claimed slot 0 (the slice the U1 image belongs to)" "${slot:-?}" "0"
    [ "$U2" != "$U1" ] || { echo "  FAIL U2 == U1"; fails=$((fails+1)); }
    # the witness: log-forced, then killed before it can be checkpointed
    rsx 40 "$A" "mkdir -p $MNT/w_$arm && cd $MNT/w_$arm && for i in \$(seq 1 40); do echo w\$i > f\$i; done; sync -f $MNT/w_$arm; stat -c %i $MNT/w_$arm" > "$OUT/${arm}_witness.txt" 2>&1
    $VIRSH destroy "$A" > /dev/null 2>&1
    capture_require "$OUT/${arm}_witness.txt" '^[0-9]+$' "the witness creation on $A"
    WINO=$(grep -aE '^[0-9]+$' "$OUT/${arm}_witness.txt" | tail -1)
    echo "STAGE $arm: witness dir ino=${WINO:-?} written+synced, $A destroyed at +$(el)s"
    [ -n "$WINO" ] || { echo "  FAIL no witness inode"; fails=$((fails+1)); return; }
    fault_before home_probe
    rsx 30 "$B" "python3 $SI dinode $MXFS_DEV $WINO" > "$OUT/${arm}_home_before.txt" 2>&1
    capture_require "$OUT/${arm}_home_before.txt" '^ino=[0-9]+ .*state=[A-Z]+' "the home dinode probe on $B before recovery"
    home_before=$(grep -oE 'state=[A-Z]+' "$OUT/${arm}_home_before.txt" | head -1 | cut -d= -f2)
    echo "STAGE $arm: home dinode of w before recovery: ${home_before:-?} (FREE/NOMAGIC = the mkdir lives only in the log)"
    fault_before dump
    rsx 120 "$B" "python3 $SI dump $MXFS_DEV 0 $IMG/${arm}_crash.img" > "$OUT/${arm}_dump.txt" 2>&1
    capture_require "$OUT/${arm}_dump.txt" '^dumped slot=0 ' "the crash-image dump on $B"
    rsx 60 "$B" "python3 $SI scan $IMG/${arm}_crash.img $U2" >> "$OUT/${arm}_dump.txt" 2>&1
    capture_require "$OUT/${arm}_dump.txt" '^img=.* headers=' "the crash-image scan on $B"
    if [ "$arm" = variant ]; then
        # the old records planted before the mount (proven on the platter
        # above: old_blocks_planted, verify=OK) must be GONE at the crash:
        # the claimant zeroed the whole payload through the FUA path before
        # its first journal write, so the recovery about to run faces only
        # this incarnation's records.  Before 0.88.0 this count was the
        # plant itself (2866 foreign headers at the crash, s60j) and the
        # recovery landed on one of them.
        ck "$arm: the crash image carries none of the planted old records (foreign headers) — the claim-time zero removed them" "$(grep -a '^img=' "$OUT/${arm}_dump.txt" | tail -1 | grep -oE 'foreign=[0-9]+' | cut -d= -f2)" 0
    fi
    sed 's/^/    /' "$OUT/${arm}_dump.txt" | cut -c1-200
    rsx 60 "$B" "python3 $SI scan $MXFS_DEV $U2 --dev" > "$OUT/${arm}_scan_before_recovery.txt" 2>&1
    capture_require "$OUT/${arm}_scan_before_recovery.txt" '^slot=[0-9]+ headers=' "the platter scan on $B before recovery"
    sed 's/^/    /' "$OUT/${arm}_scan_before_recovery.txt" | cut -c1-200 | head -2
    # boot and recover the slice at the lone mount
    $VIRSH start "$A" > /dev/null 2>&1
    boot_wait_into bw "$A"; ck "$arm: $A booted with /src" "$bw" "SRC_OK"
    RMARK=$(date +%s)
    fault_before recover
    rsx 200 "$A" "MXFS_DEV=$MXFS_DEV timeout 180 bash /src/mxfs/tests/setup/prep_node.sh $TR 2>&1 | grep -a 'NODE_PREP_OK\|FAIL\|refused\|rc=' | head -3; mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED; ls $MNT/w_$arm 2>/dev/null | wc -l; cat $MNT/w_$arm/f40 2>/dev/null" > "$OUT/${arm}_recover.txt" 2>&1
    capture_require "$OUT/${arm}_recover.txt" '^(NODE_PREP_OK|NODE_PREP_FAIL)' "the recovery mount on $A"
    capture_require "$OUT/${arm}_recover.txt" '^(MOUNTED|NOT_MOUNTED)$' "the mount state on $A after recovery"
    rsx 60 "$A" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | grep -a 'XFS\|MXFS\|mxfs' | grep -ai 'recover\|mismatch\|corrupt\|log has\|head\|tail\|P-FR\|P163\|P-LREC\|torn\|refus\|claimed heartbeat\|P-SLIFE' | cut -c1-300" > "$OUT/${arm}_recovery_lines.txt"
    capture_require "$OUT/${arm}_recovery_lines.txt" 'claimed heartbeat slot' "the recovery kernel log on $A"
    rsx 60 "$A" "journalctl -k --since @$RMARK --no-pager 2>/dev/null | cut -c1-600" > "$OUT/${arm}_journal.txt"
    capture_require "$OUT/${arm}_journal.txt" 'kernel: ' "the kernel journal on $A after recovery"
    echo "--- $arm recovery lines ($(wc -l < "$OUT/${arm}_recovery_lines.txt")):"
    sed 's/.*kernel: /    /' "$OUT/${arm}_recovery_lines.txt" | cut -c1-190 | head -14
    ck "$arm: $A mounted after the crash (own-slice recovery)" "$(cnt "$OUT/${arm}_recover.txt" '^MOUNTED')" 1
    wcount=$(sed -n '/^MOUNTED/{n;p}' "$OUT/${arm}_recover.txt" | head -1)
    ck "$arm: all 40 witness files are back" "${wcount:-0}" "40"
    ck "$arm: the last witness file has its content" "$(cnt "$OUT/${arm}_recover.txt" '^w40$')" 1
    ck "$arm: no mismatched-uuid / corruption / image refusal in recovery" "$(grep -aic 'mismatched\|corrupt\|P227-FR-ATOMIC-SKIP\|P227-FR-TORN\|P241-RECOV-TERMINAL\|P240-QUAR\|quarantined by' "$OUT/${arm}_recovery_lines.txt")" 0
    ck "$arm: zero shutdown / BUG / Oops" "$(( $(cnt "$OUT/${arm}_journal.txt" 'shutting down filesystem') + $(cnt "$OUT/${arm}_journal.txt" 'BUG:\|Oops') ))" 0
    rsx 30 "$B" "python3 $SI dinode $MXFS_DEV $WINO" > "$OUT/${arm}_home_after.txt" 2>&1
    capture_require "$OUT/${arm}_home_after.txt" '^ino=[0-9]+ .*state=[A-Z]+' "the home dinode probe on $B after recovery"
    home_after=$(grep -oE 'state=[A-Z]+' "$OUT/${arm}_home_after.txt" | head -1 | cut -d= -f2)
    echo "STAGE $arm: home dinode of w after recovery: ${home_after:-?}; before: ${home_before:-?}"
    echo "ROW $arm | home_before=${home_before:-?} | planted=$( [ "$arm" = variant ] && grep -a 'composed' "$OUT/${arm}_plant.txt" | grep -oE 'old_blocks_planted=[0-9]+' | cut -d= -f2 || echo 0 ) | foreign_at_crash=$(grep -a '^img=' "$OUT/${arm}_dump.txt" | tail -1 | grep -oE 'foreign=[0-9]+' | cut -d= -f2) | mounted=$(cnt "$OUT/${arm}_recover.txt" '^MOUNTED') | witness_files=${wcount:-0} | refusals=$(grep -aic 'mismatched\|corrupt\|P227-FR-ATOMIC-SKIP\|P227-FR-TORN\|P241-RECOV-TERMINAL\|P240-QUAR\|quarantined by' "$OUT/${arm}_recovery_lines.txt") | home_after=${home_after:-?} |" | tee -a "$OUT/rows.txt"
    umount_node_into urc "$A"; ck "$arm: $A unmounted" "$urc" "0"
    if [ "${home_before:-}" = ALLOCATED ]; then
        echo "  NOTE $arm: the witness was already checkpointed before the kill, so this arm did not exercise a necessary replay"
        vacuous=$((vacuous+1))
    fi
}
vacuous=0
run_arm control
run_arm variant

# ── leave the fleet formed on a fresh, zeroed filesystem ─────────────────
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep_final.log" 2>&1
echo "STAGE final prep rc=$? wall=$(el)s"
echo "ROWS:"; sed 's/^/  /' "$OUT/rows.txt"
if [ $fails = 0 ] && [ $vacuous -gt 0 ]; then
    echo "RESULT: VACUOUS label=$LABEL fails=0 arms_with_checkpointed_witness=$vacuous wall=$(el)s evidence=$OUT"; exit 3
fi
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
