#!/bin/bash
# tests/admitted_write_parked_across_unmount.sh — an operation that PASSED the
# authority gate and had not yet reached the layer below it when its own node
# published every AG grant it held and a peer took one.
# (ledger D-AN-UNEXPIRED-LEASE-DOES-NOT-RESTORE-SURRENDERED-RESOURCE-OWNERSHIP)
#
# WHY THIS IS NOT THE FENCE LAP.  tests/admitted_write_parked_across_fence.sh
# drives the schedule where the node is FENCED underneath an admitted write: the
# lease dies, a successor certifies and replays.  This one drives the schedule
# the record is actually about, in which nothing dies at all.  The lease stays
# UNEXPIRED for the whole lap.  What changes underneath the admitted write is
# not the node's right to write — it is the node's ownership of the RESOURCE,
# surrendered voluntarily by its own put_super when it publishes its AG grants
# as free.  An unexpired lease answers "yes" to both, because the gate is a
# node-wide admission condition and asks nothing about the resource.
#
# THE ORDERING QUESTION IS THE LAP.  put_super publishes the grants at
# mxfs_dlm_ag_force_release_all (pal/linux/xfs_super.c:2492), whose own last act
# is P482-UMOUNT-AGREL; from that line on a peer may legitimately take any AG
# this node held.  Everything before it — the prepare half of xfs_unmountfs, the
# explicit log force, the whole-AIL push, xfs_buftarg_wait, the final SB summary
# sync — is a series of WAITS.  So there are exactly three outcomes, and the lap
# reports which one it got rather than assuming one:
#
#   order=barrier    P292-ADMIT-PARK-END precedes P482-UMOUNT-AGREL.  The
#                    unmount could not reach the publication while the
#                    submission was in flight, because one of those waits was
#                    waiting for it.  That is the proof the record's step 3
#                    asks for — "prove that after grant publication the only
#                    remaining producers are permitted" — for this class, and
#                    it is a result, not a non-result.
#   order=overlap    P482-UMOUNT-AGREL precedes P292-ADMIT-PARK-END.  The
#                    submission outlived the publication.  The platter
#                    verdicts below are then load-bearing and decide the case.
#   order=vfs-busy   the unmount was refused outright while the submission was
#                    parked (a held descriptor, not the gate).  A barrier, but
#                    one made of a VFS reference count rather than of anything
#                    MXFS decided, and the RESULT says so in those words.
#
# A LAP THAT PASSES IN MORE THAN ONE OF THOSE HAS TO SAY WHICH, or the reader
# takes a barrier for an exonerated overlap.  So `order=` is on the RESULT line
# every time, and when it is not `overlap` the summary states in full that the
# platter assertions were satisfied because the two never met.
#
# THE INJECTION CHANGES NO DECISION.  mxfs.dbg_admit_park_site names one of the
# gate's call sites and mxfs.dbg_admit_park_ms holds the FIRST submission of
# that class between the gate's "yes" (pal/linux/xfs_super.c:2183) and the
# caller's submission.  `ok` is computed before the park and returned after it,
# unaltered.  Nothing is weakened and no refusal the build has is removed.
#
# SITE.  "dio" (default) parks a direct write to the probe file, so the probe
# block IS the oracle and the descriptor is held by a live writer — the arm
# that can produce order=vfs-busy.  "data" parks buffered writeback's ioend for
# the same file, with no descriptor held, which is the arm that can produce
# order=overlap if any can.  "log" parks the iclog submission a create+fsync
# forces; it holds a descriptor too, so it runs the dio-shaped schedule, and it
# has an oracle of its own.  "meta" is still REFUSED: its submission lands in
# shared metadata, which neither oracle covers, and the record's own vacuity
# clause excludes a "meta"-only measurement outright.
#
# THE TWO ORACLES.  ORACLE=block ("dio", "data") reads the probe file's own
# physical block off the raw device.  ORACLE=slice ("log") reads B's log slice
# instead — a journal write lands there and never in the probe block — and it
# reads it for a NONCE rather than for a digest: the parked transaction creates
# a file whose name is unique to this lap, so that name appears verbatim in the
# logged directory and inode images and nowhere else on the volume.  A digest
# could not be used, because B legitimately rewrites its own slice throughout
# its unmount and A rewrites it again on its remount.
#
# AND FOR "log" THE SLICE READ IS NOT THE VERDICT — THE ORDER AND THE COLD
# CHECK ARE.  B's journal slice is a resource B has NOT surrendered at the AG
# grant publication; the tail's log cover and unmount record are exactly the
# permitted journal-retirement producers the record's step 3 allows.  So a log
# write crossing the publication is not by itself the defect.  What the arm is
# for is the ORDER: if put_super cannot reach the publication with an iclog in
# flight, that is the barrier proof step 3 asks for, and it is the finding.
# The slice read's graded part is the VACUITY guard — the nonce must still be
# absent at R1, or the write was never held across the publication at all —
# and what decides integrity is the cold check, which is where an allocation
# recorded against an AG the peer now owns would show up.
#
# THE VERDICT IS THE PLATTER, NEVER THE RETURN CODE.  The probe file's physical
# extent is taken with FIEMAP while B's mount is healthy, and the block is read
# off the raw device from A with O_DIRECT at three instants:
#
#   R1  after B published its grants AND A has taken one by allocating;
#   R2  after B's unmount has returned and the parked submission has resumed;
#   R3  after A has been unmounted and mounted again.
#
# R2 != R1 is a surrendered-ownership write landing in a region the peer now
# owns.  R3 != R1 is the same thing arriving through the journal, which an
# immediate byte comparison cannot see.
#
# THE CONTROL IS NOT OPTIONAL.  Both verdicts are that a block did NOT change,
# and a harness whose probe has quietly broken satisfies both.  So the same
# O_DIRECT write runs on a healthy B first and MUST change the block.
#
# THE PEER MUST ACTUALLY TAKE A PUBLISHED GRANT, or there is no second owner
# and "the block did not change" is about nothing.  A's workload is an
# allocating one and the lap asserts it both completed and logged AG acquires
# after B's publication; a peer that never took one is VACUOUS, by the record's
# own clause.
#
# THE BUDGET (derived, a timeout is a failure and never a safety net):
#   boot-wait 200 (infra) + prep 300 (measured 43-233) + probe, extent, control
#   and baseline 90 + arm and trigger 40 + the park appearing 90 + the pair
#   [wait for B's publication, then the remainder of the hold] which is bounded
#   by the hold itself plus slack, never by two independent terms: PARK_MS/1000
#   + 30 = 150 + A's allocating workload 120 + R1 20 + B's unmount returning
#   and R2 120 + A's unmount, remount and R3 200 + the cold check 300 +
#   captures 80.
#   200+300+90+40+90+150+120+20+120+200+300+80 = 1710.  Caller bound 1750 s.
#
# THE SLICE ARM COSTS MORE AND ITS BOUND SAYS SO.  It replaces four 4 KiB dd
# reads with FIVE whole-slice scans (control, the parked nonce's baseline, R1,
# R2, R3).  The rate is not guessed: slice_image.py's own `scan --dev` note
# measures 4 slices over iSCSI at ~40 s, i.e. ~10 s for one slice, and `find`
# does strictly less per byte than that census does.  FIND_T is 90 s — margin
# over a measured rate, not a round number standing in for a derivation — so
# the arm adds 5 x 90 = 450 s worst case: 1710 + 450 = 2160.  Caller bound
# 2200 s for SITE=log.  THE FIRST LOG LAP MUST REPORT EACH SCAN'S WALL (it
# prints them) AND THE BOUND MUST THEN BE TIGHTENED TOWARD WHAT WAS MEASURED.
#
# PARK_MS follows from that and not the other way round: the hold has only to
# outlast B's publication plus A taking a grant (an allocating workload bounded
# at 120 s), so 120 s is that with margin.  A longer hold buys nothing and
# spends the lap's budget.
#
# IT LEAVES B UNMOUNTED AND A UNMOUNTED after the cold check.  Nothing is
# destroyed and nothing is forged; the next lap's prep restores both.
#
# Usage: tests/admitted_write_parked_across_unmount.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2) — FIRST is A, the peer that survives and
#        takes a published grant; SECOND is B, whose write is admitted, parked,
#        and left in flight across B's own unmount.
#        SITE (dio), PARK_MS (120000), AFILES (2000), UMOUNT_BOUND (derived),
#        LOG_FSYNC (1; 0 with SITE=log runs the DESCRIPTOR-FREE log arm: the
#        create is committed and closed without an fsync, and the log write
#        the gate parks is the unmount's own log force — the only log arm
#        that can reach put_super, because s138l/s140e showed the fsync arm
#        is refused at the VFS, order=vfs-busy, and never measures the log's
#        own wait on its in-flight iclog).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the peer: survives, takes a published grant
B=${MXFS_NODE_LIST##*,}          # the node whose write is admitted and parked
[ "$A" = "$B" ] && { echo "ABORT: this lap needs two distinct nodes (MXFS_NODE_LIST=$MXFS_NODE_LIST)"; exit 2; }
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
SITE=${SITE:-dio}
LOG_FSYNC=${LOG_FSYNC:-1}
# the writer's mode: the gate site, except that the descriptor-free log arm
# runs the writer in "logclose" while the gate site it parks is still "log"
WMODE=$SITE; [ "$SITE" = log ] && [ "$LOG_FSYNC" = 0 ] && WMODE=logclose
PARK_MS=${PARK_MS:-120000}
AFILES=${AFILES:-2000}
SLICETOOL=/src/mxfs/tools/slice_image.py
FIND_T=${FIND_T:-90}
UMOUNT_BOUND=${UMOUNT_BOUND:-$(( PARK_MS / 1000 + 180 ))}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_admumnt_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="ADMUMNT-MARK-$LABEL"
PDIR=$MNT/admumnt_$LABEL
ADIR=$MNT/admumnt_${LABEL}_peer
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# A withdrawal through the cluster-fence entry is what the authority machinery
# is for.  Every other shutdown is bad news, on either node.
bad_lines() { echo $(( $(grep -a 'hutting down filesystem' "$1" 2>/dev/null | grep -avc 'mxfs_dlm_fence_notify') + $(cnt "$1" 'BUG:\|Oops') )); }
# The monotonic stamp dmesg puts on a line, in milliseconds, for the FIRST
# occurrence of a pattern in a window.  Both stamps compared below are taken
# from the SAME node's ring, so no clock reconciliation is owed; comparing two
# nodes' stamps this way would be meaningless and this helper is never used
# across nodes.
stamp_ms() {   # <file> <pattern>  -> integer ms, or "" when absent
    grep -a -- "$2" "$1" 2>/dev/null | head -1 |
        sed -n 's/^[^0-9[]*\[ *\([0-9][0-9]*\)\.\([0-9][0-9][0-9]\)[0-9]*\].*/\1\2/p'
}

echo "=== admitted_write_parked_across_unmount label=$LABEL A(peer)=$A B(parked+unmounts)=$B site=$SITE writer=$WMODE park=${PARK_MS}ms $(date -u +%FT%TZ) ==="

case $SITE in
    dio|data) ORACLE=block ;;
    log)      ORACLE=slice ;;
    meta)
        echo "ABORT: site 'meta' submits into shared metadata, which is neither"
        echo "       the probe file's own block nor B's log slice, so neither of"
        echo "       this lap's two oracles covers it — and the record's own"
        echo "       vacuity clause excludes a 'meta'-only measurement outright."
        echo "RESULT: ABORT label=$LABEL stage=site evidence=$OUT"; exit 2 ;;
    *)  echo "ABORT: '$SITE' is not one of the authority gate's call sites (log, data, dio, dio-zoned, meta)"
        echo "RESULT: ABORT label=$LABEL stage=site evidence=$OUT"; exit 2 ;;
esac

# ---- 0. the build must carry the injection and every probe this lap reads
for sym in P292-ADMIT-PARK P482-UMOUNT-AGREL P304-RETIRE-DRAIN; do
    [ "$(strings -a mxfs.ko | grep -c "$sym")" != 0 ] || {
        echo "ABORT: mxfs.ko carries no $sym, so there is nothing here to measure"
        echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
done
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')

waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 "$SSH" "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build-check evidence=$OUT"; exit 2; }

# The slice arm needs B's own slice index, and a heartbeat slot IS its slice
# index (identity, never modulo — a slot with no slice may not journal at all).
# It is read from B's own DLM-initialised line rather than assumed.  The two
# nonces are unique to THIS lap so a re-run of the same label cannot find its
# predecessor's leftovers in a slice nothing has zeroed since.
BSLOT=
NONCE="MXUMNTN-$LABEL-$(date -u +%Y%m%dT%H%M%SZ)-$$"
CTRLNONCE="MXUMNTC-$LABEL-$(date -u +%Y%m%dT%H%M%SZ)-$$"
if [ "$ORACLE" = slice ]; then
    value_now_into BSLOT "$B" 30 "$OUT/B_slot.txt" '^[0-9]+$' "B's heartbeat slot, which is the index of the log slice its journal writes land in" \
        "dmesg | grep -a 'DLM initialized' | tail -1 | grep -oE 'slot=[0-9]+' | cut -d= -f2"
    echo "STAGE B's log slice is slice $BSLOT on $MXFS_DEV"
    TAG_CTRL=$CTRLNONCE
    TAG_PARK=$NONCE
else
    TAG_CTRL=control-write
    TAG_PARK=parked-surrendered-write
fi

# ---- 1. B's probe target, durable before anything is armed, and its physical
#         extent on the LUN.  A successful write is not evidence that bytes
#         reached the platter; the block read off the raw device is.
EXTENT_B64=$(base64 -w0 <<'PY'
import os, sys, struct, fcntl
p = sys.argv[1]
fd = os.open(p, os.O_RDONLY)
# struct fiemap { u64 start; u64 length; u32 flags; u32 mapped; u32 count; u32 res; }
buf = bytearray(32 + 56)
struct.pack_into("<QQIIII", buf, 0, 0, 1 << 20, 0, 0, 1, 0)
fcntl.ioctl(fd, 0xC020660B, buf)          # FS_IOC_FIEMAP
mapped = struct.unpack_from("<I", buf, 20)[0]
os.close(fd)
if mapped < 1:
    print("EXTENT none")
else:
    lo, po, ln, _, fl = struct.unpack_from("<QQQQI", buf, 32)
    print("EXTENT logical=%d physical=%d length=%d flags=0x%x" % (lo, po, ln, fl))
print("EXTENT_END")
PY
)
# The writer.  One 4096-byte block with a caller-given tag.  mode=dio goes
# through O_DIRECT, so the submission the gate sees is the 'dio' class and the
# descriptor stays open for the whole park.  mode=data writes buffered and
# CLOSES the descriptor before returning, so nothing holds the mount and the
# submission the gate sees is writeback's ioend — the arm in which the unmount
# is free to run ahead of the parked work if anything can.
WRITER_B64=$(base64 -w0 <<'PY'
import os, sys, errno, time, mmap
d, tag, mode = sys.argv[1], sys.argv[2], sys.argv[3]
blk = 4096
print("WRITER_START tag=%s mode=%s" % (tag, mode)); sys.stdout.flush()
t = time.monotonic()
rc, err = 0, "-"
try:
    if mode == "dio":
        buf = mmap.mmap(-1, blk)
        buf.write(tag.encode().ljust(blk, b"\0"))
        fd = os.open(d + "/probe", os.O_WRONLY | os.O_DIRECT)
        try:
            os.pwrite(fd, buf, 0)
        finally:
            os.close(fd)
    elif mode in ("log", "logclose"):
        # the tag IS the file name: XFS logs the directory entry and the inode
        # image verbatim, so the name is what makes this transaction findable
        # in the log slice and nowhere else on the volume.  In mode "log" the
        # fsync is the log force whose iclog submission the "log" site sits
        # on, and the descriptor stays open across it.  In mode "logclose"
        # there is NO fsync: the transaction is committed into an iclog that
        # nothing has written yet, the descriptor is closed, and the log
        # write the gate then sees is produced by the unmount's own log force
        # (or the log worker's), with no descriptor held anywhere — the shape
        # the VFS cannot refuse an unmount for.
        fd = os.open(os.path.join(d, tag), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, (tag + "\n").encode())
            if mode == "log":
                os.fsync(fd)
        finally:
            os.close(fd)
        if mode == "log":
            dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    else:
        fd = os.open(d + "/probe", os.O_WRONLY)
        try:
            os.pwrite(fd, tag.encode().ljust(blk, b"\0"), 0)
        finally:
            os.close(fd)
except OSError as e:
    rc, err = 1, errno.errorcode.get(e.errno, "E%d" % e.errno)
except Exception as e:
    rc, err = 1, "OTHER:" + type(e).__name__
print("WRITER_DONE rc=%d err=%s ms=%d" % (rc, err, (time.monotonic() - t) * 1000))
print("WRITER_END"); sys.stdout.flush()
PY
)
measure "$B" 60 "$OUT/B_target.txt" '^EXTENT_END$' "B's probe target, made durable before anything is armed, and its physical extent" \
    "d=$PDIR; mkdir -p \$d && python3 -c \"
import os
b=bytearray(4096); b[0:9]=b'baseline\n'
fd=os.open('\$d/probe', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644); os.write(fd,b); os.fsync(fd); os.close(fd)
\" && sync -f $MNT && echo $EXTENT_B64 | base64 -d > /run/admumnt_extent.py && python3 /run/admumnt_extent.py \$d/probe"
PHYS=$(grep -ao 'physical=[0-9]*' "$OUT/B_target.txt" | head -1 | cut -d= -f2)
echo "STAGE probe block physical offset on the LUN: ${PHYS:-none}"
[ -n "${PHYS:-}" ] || { echo "ABORT: the probe block's physical extent could not be read, so a landed write could not be distinguished from an acknowledged one"; echo "RESULT: ABORT label=$LABEL stage=extent evidence=$OUT"; exit 2; }
platter_into() {   # <file> <what>
    measure "$A" 60 "$1" '^PLATTER_END$' "$2" \
        "dd if=$MXFS_DEV bs=4096 skip=$((PHYS / 4096)) count=1 iflag=direct 2>/dev/null | md5sum | sed 's/^/PLATTER md5=/'; dd if=$MXFS_DEV bs=4096 skip=$((PHYS / 4096)) count=1 iflag=direct 2>/dev/null | head -c 48 | od -c | head -3; echo PLATTER_END"
}
platter_md5() { grep -ao 'md5=[0-9a-f]*' "$1" | head -1 | cut -d= -f2; }
# The slice read, from A, O_DIRECT, over B's whole slice.  Each scan prints its
# own wall so the FIND_T this lap derived can be tightened toward what the rig
# actually costs rather than left at its safe first value.
slice_find_into() {   # <file> <what> <pattern>
    measure "$A" "$FIND_T" "$1" '^FIND_END$' "$2" \
        "s=\$(date +%s); python3 $SLICETOOL find $MXFS_DEV $BSLOT $3; echo SCAN_WALL s=\$(( \$(date +%s) - s ))"
}
slice_hits() { grep -aoE '^FIND slot=.*hits=[0-9]+' "$1" | grep -oE 'hits=[0-9]+' | head -1 | cut -d= -f2; }
oracle_into() {   # <file> <what> -> ORACLE_VAL
    case $ORACLE in
        block) platter_into "$1" "$2"; ORACLE_VAL=$(platter_md5 "$1") ;;
        slice) slice_find_into "$1" "$2" "$NONCE"; ORACLE_VAL=$(slice_hits "$1")
               echo "    scan wall: $(grep -ao 'SCAN_WALL s=[0-9]*' "$1" | head -1)" ;;
    esac
}

# ---- 1b. THE CONTROL.  Every verdict below is that something did NOT appear,
#          and a broken probe satisfies all of them.  A healthy B's identical
#          operation must be visible in the oracle's own region.
MD_BASE=; MD_CONTROL=; CH=
if [ "$ORACLE" = block ]; then
    platter_into "$OUT/P_base.txt" "the probe block on the platter before the control"
    MD_BASE=$(platter_md5 "$OUT/P_base.txt")
fi
measure "$B" 60 "$OUT/B_control.txt" '^WRITER_END$' "the control write on a healthy B" \
    "echo $WRITER_B64 | base64 -d > /run/admumnt_writer.py; python3 /run/admumnt_writer.py $PDIR $TAG_CTRL $SITE; sync -f $MNT"
ck "control: a healthy node's write returns 0" "$(field "$OUT/B_control.txt" rc)" 0
if [ "$ORACLE" = block ]; then
    platter_into "$OUT/P_control.txt" "the probe block after the control write"
    MD_CONTROL=$(platter_md5 "$OUT/P_control.txt")
    [ -n "$MD_BASE" ] && [ -n "$MD_CONTROL" ] || { echo "ABORT: the probe block could not be read off the raw device, so the platter oracle does not work and no verdict below would mean anything"; echo "RESULT: ABORT label=$LABEL stage=platter evidence=$OUT"; exit 2; }
    if [ "$MD_BASE" = "$MD_CONTROL" ]; then
        echo "  FAIL control: a healthy node's write did not reach the platter (md5 $MD_BASE unchanged)"
        echo "ABORT: the platter oracle cannot see a write that DID land, so 'the block did not change' would be true of everything"
        echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2
    fi
    echo "  PASS control: a healthy node's write changed the block on the platter ($MD_BASE -> $MD_CONTROL)"
else
    slice_find_into "$OUT/S_control.txt" "the control nonce inside B's log slice on the platter" "$CTRLNONCE"
    CH=$(slice_hits "$OUT/S_control.txt")
    [ -n "$CH" ] || { echo "ABORT: B's log slice could not be scanned off the raw device, so the slice oracle does not work and no verdict below would mean anything"; echo "RESULT: ABORT label=$LABEL stage=slice evidence=$OUT"; exit 2; }
    if [ "$CH" -lt 1 ] 2>/dev/null; then
        echo "  FAIL control: a healthy node's journal write is not visible in its own log slice (hits=$CH)"
        echo "ABORT: the slice oracle cannot see a journal write that DID land, so 'the nonce is absent' would be true of everything"
        echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2
    fi
    echo "  PASS control: a healthy node's journal write is visible in its own log slice (hits=$CH, scan $(grep -ao 'SCAN_WALL s=[0-9]*' "$OUT/S_control.txt" | head -1))"
    slice_find_into "$OUT/S_base.txt" "this lap's parked nonce before anything is armed" "$NONCE"
    BH=$(slice_hits "$OUT/S_base.txt")
    ck "baseline: this lap's nonce is not already on the platter" "$BH" 0
fi
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }

# ---- 2. the marks, in both rings, before anything is armed
for n in "$A" "$B"; do
    rsx 30 "$n" "echo $MARK > /dev/kmsg; echo MARKED" > "$OUT/${n}_mark.txt"
    capture_require "$OUT/${n}_mark.txt" '^MARKED$' "the ring mark on $n"
done

# ---- 3. arm the park, put ONE admitted submission under it, and unmount B.
#         The two orders differ by class and the difference is not cosmetic:
#         a direct write parks in the WRITER's own syscall and holds a
#         descriptor, so it must be started and seen parked BEFORE the unmount
#         is attempted; a buffered write has already returned and its ioend is
#         produced BY the unmount's own flush, so the park can only fire after
#         the unmount has started.
# AN ARM THAT NEVER FIRED IS STILL ARMED WHEN THIS LAP ENDS, SO IT IS UNDONE ON
# EVERY EXIT.  The park is one-shot — the module zeroes dbg_admit_park_ms itself
# the moment it fires — so a lap that parked something leaves nothing behind.
# The exits that matter are the ones where it never fired: the arm ABORT below
# and both park VACUOUS exits.  Those leave a 120 s hold armed for the first
# submission of this class on B, and the next thing to submit on B is the NEXT
# lap's prep, whose own unmount would then pay it.  Writing ms=0 disarms
# whatever the site knob still says, so the charp is left alone rather than
# cleared with an echo that would only put a newline in it.
PARKED=0
admumnt_cleanup() {
    [ "$PARKED" = 1 ] || return 0
    timeout 20 "$SSH" "$B" "echo 0 > $PARM/dbg_admit_park_ms" > /dev/null 2>&1
    echo "CLEANUP: dbg_admit_park_ms was set to 0 on $B so an arm that never fired cannot park the next lap's first submission"
    return 0
}
trap admumnt_cleanup EXIT
# Set before the knob write: if the arm dies part-way the knob may already have
# landed, and disarming something already disarmed costs nothing.
PARKED=1
measure "$B" 40 "$OUT/B_arm_park.txt" '^ARMED' "the post-admission park armed on B" \
    "echo $SITE > $PARM/dbg_admit_park_site; echo $PARK_MS > $PARM/dbg_admit_park_ms; echo ARMED site=\$(cat $PARM/dbg_admit_park_site) ms=\$(cat $PARM/dbg_admit_park_ms)"
ck "the park is armed for this site" "$(field "$OUT/B_arm_park.txt" site)" "$SITE"
ck "the park hold is the one this lap derived" "$(field "$OUT/B_arm_park.txt" ms)" "$PARK_MS"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

WPID=
start_writer() {
    ( timeout $(( PARK_MS / 1000 + 180 )) "$SSH" "$B" "python3 /run/admumnt_writer.py $PDIR $TAG_PARK $SITE" \
          2> "$OUT/B_writer_stderr.txt" | filt > "$OUT/B_writer.txt" ) &
    WPID=$!
}
start_umount() {
    ( timeout "$UMOUNT_BOUND" "$SSH" "$B" "umount $MNT; echo UMOUNT rc=\$?" \
          2> "$OUT/B_umount_stderr.txt" | filt > "$OUT/B_umount.txt" ) &
    UPID=$!
}

if [ "$WMODE" != data ] && [ "$WMODE" != logclose ]; then
    # dio and log both block inside the writer's own syscall holding a
    # descriptor, so the submission must be seen parked BEFORE the unmount is
    # attempted.  Only the buffered arm and the closed-log arm have already
    # returned by then.
    start_writer
    echo "STAGE the ${SITE} writer was started on $B at +$(el)s"
    wait_for_into parked "$B" 90 "$MARK" 'P292-ADMIT-PARK site='
    if [ "$parked" = timeout ]; then
        echo "VACUOUS: no submission of class '$SITE' was admitted and parked within 90 s, so nothing was ever in flight across the publication"
        echo "RESULT: VACUOUS label=$LABEL site=$SITE stage=park evidence=$OUT"
        kill "$WPID" 2>/dev/null; exit 3
    fi
    echo "STAGE the write is ADMITTED and parked below the gate at +$(el)s (waited ${parked}s)"
    start_umount
    echo "STAGE B's unmount was started at +$(el)s under a ${UMOUNT_BOUND}s bound"
else
    # buffered: the write returns and closes its descriptor, leaving a dirty
    # page.  The unmount's own flush produces the ioend the gate then parks.
    # logclose: the create returns and closes its descriptor, leaving a
    # committed transaction in an unwritten iclog.  The unmount's own log
    # force (or the 30 s log worker's, whichever comes first — both are
    # descriptor-free) produces the log write the gate then parks.
    measure "$B" 60 "$OUT/B_writer.txt" '^WRITER_END$' "the $WMODE write whose deferred submission the unmount will produce" \
        "python3 /run/admumnt_writer.py $PDIR $TAG_PARK $WMODE"
    echo "STAGE the $WMODE write returned and its descriptor is closed at +$(el)s"
    start_umount
    echo "STAGE B's unmount was started at +$(el)s under a ${UMOUNT_BOUND}s bound"
    wait_for_into parked "$B" 90 "$MARK" 'P292-ADMIT-PARK site='
    if [ "$parked" = timeout ]; then
        echo "VACUOUS: no submission of class '$SITE' was admitted and parked within 90 s of the unmount starting, so nothing was ever in flight across the publication"
        echo "RESULT: VACUOUS label=$LABEL site=$SITE stage=park evidence=$OUT"
        kill "$UPID" 2>/dev/null; exit 3
    fi
    echo "STAGE the deferred $SITE submission is ADMITTED and parked below the gate at +$(el)s (waited ${parked}s): $(grep -a 'P292-ADMIT-PARK site=' "$OUT/B_win.txt" 2>/dev/null | head -1 | grep -ao 'comm=[^ ]*')"
fi

# ---- 4. did B's unmount reach the publication while the submission was held?
#         P482-UMOUNT-AGREL is the last act of mxfs_dlm_ag_force_release_all:
#         from that line on a peer may legitimately take any AG B held.
AGREL_BOUND=$(( PARK_MS / 1000 + 30 ))
wait_for_into agrel "$B" "$AGREL_BOUND" "$MARK" 'P482-UMOUNT-AGREL'
window_into "$OUT/B_order.txt" "$B" 60 "$MARK"
TS_PARK=$(stamp_ms "$OUT/B_order.txt" 'P292-ADMIT-PARK site=')
TS_END=$(stamp_ms "$OUT/B_order.txt" 'P292-ADMIT-PARK-END')
TS_AGREL=$(stamp_ms "$OUT/B_order.txt" 'P482-UMOUNT-AGREL')
UMRC=$(field "$OUT/B_umount.txt" rc)
if [ -n "$TS_AGREL" ] && [ -n "$TS_END" ]; then
    if [ "$TS_AGREL" -lt "$TS_END" ]; then ORDER=overlap; else ORDER=barrier; fi
elif [ -n "$TS_AGREL" ]; then
    ORDER=overlap            # published, and the park has not ended yet
elif [ -n "${UMRC:-}" ] && [ "${UMRC:-0}" != 0 ]; then
    ORDER=vfs-busy           # the unmount was refused outright
else
    ORDER=barrier            # no publication while the hold was on
fi
echo "STAGE ordering on $B: ADMIT-PARK=${TS_PARK:-none}ms ADMIT-PARK-END=${TS_END:-none}ms UMOUNT-AGREL=${TS_AGREL:-none}ms umount_rc=${UMRC:-pending} -> order=$ORDER (agrel wait ${agrel}s) at +$(el)s"

# ---- 5. the peer takes a published grant.  Without this there is no second
#         owner and "the block did not change" is a statement about nothing.
AWORK_START=$(date +%s)
rsx 120 "$A" "set -e; mkdir -p $ADIR; \
     for i in \$(seq 1 $AFILES); do printf 'PEER %05d\n' \$i > $ADIR/p\$i; done; \
     sync; echo AWORK_N=\$(ls $ADIR | wc -l); echo AWORK_END" > "$OUT/A_work.txt"
arc=$?
echo "STAGE the peer's allocating workload: rc=$arc wall=$(( $(date +%s) - AWORK_START ))s at +$(el)s"
if [ "$arc" = 124 ]; then
    echo "  FAIL the peer's allocating workload did not complete inside its 120 s bound — a request for a resource B had published parked"
    fails=$((fails+1))
else
    capture_require "$OUT/A_work.txt" '^AWORK_END$' "the peer's allocating workload"
    ck "the peer allocated every file it was asked for" "$(field "$OUT/A_work.txt" AWORK_N)" "$AFILES"
fi
window_into "$OUT/A_work_win.txt" "$A" 60 "$MARK"
count_file_into A_aglock "$OUT/A_work_win.txt" 'P130\|AG-ACQ\|ag grant\|aglock'
echo "STAGE the peer's AG activity lines since the mark: $A_aglock at +$(el)s"

oracle_into "$OUT/P_r1.txt" "the oracle region after B published and the peer allocated"
MD_R1=$ORACLE_VAL
echo "STAGE R1 $ORACLE=$MD_R1 at +$(el)s"
# An empty R1 would make "R2 equals R1" true of two things nobody read: the
# assertion compares two values and both being absent satisfies it.  The
# control above proved the oracle works, so an empty read here is the raw
# device having become unreadable mid-lap, which is an abort and not a verdict.
[ -n "$MD_R1" ] || { echo "ABORT: the oracle region could not be read off the raw device after B published, so every comparison below would be between two absent values"; echo "RESULT: ABORT label=$LABEL site=$SITE order=$ORDER stage=r1 evidence=$OUT"; exit 2; }
# THE SLICE ARM'S VACUITY GUARD, FOR THE OVERLAP ORDER ONLY.  When B published
# while the submission was parked, the nonce must still be absent here, or the
# transaction carrying it was submitted before the peer took a grant and
# nothing was held across the publication at all — a non-measurement, not a
# verdict.  In the other two orders the nonce being on the platter at R1 is
# what the order MEANS: under `barrier` the hold ended and the write landed
# BEFORE the publication (that is the barrier), and under `vfs-busy` there
# was no publication for R1 to be "after".  s138l (site=log, order=vfs-busy)
# was graded VACUOUS by this guard when it had already found its order.
if [ "$ORACLE" = slice ] && [ "$ORDER" = overlap ] && [ "${MD_R1:-0}" -gt 0 ] 2>/dev/null; then
    echo "VACUOUS: this lap's nonce was already inside B's log slice when the peer took a published grant (hits=$MD_R1), so the journal write it names was never held across the publication"
    echo "RESULT: VACUOUS label=$LABEL site=$SITE order=$ORDER stage=r1 evidence=$OUT"
    exit 3
fi

# ---- 6. the hold ends, the submission is handed below the gate, and B's
#         unmount returns.  Both are waited for; neither is assumed.
if [ -n "$WPID" ]; then
    wait "$WPID" 2>/dev/null
    if ! grep -qa '^WRITER_DONE' "$OUT/B_writer.txt" 2>/dev/null; then
        capture_require_bg "$OUT/B_writer.txt" "$OUT/B_writer_stderr.txt" '^WRITER_DONE' "the parked writer on $B" || {
            echo "ABORT: the parked writer never returned and its stderr is silent — it is still in the kernel, which is a result this lap cannot grade as either outcome"
            echo "RESULT: ABORT label=$LABEL stage=writer evidence=$OUT"; exit 2; }
    fi
    echo "STAGE the parked writer returned at +$(el)s: $(grep -a '^WRITER_DONE' "$OUT/B_writer.txt" | head -1)"
fi
wait "$UPID" 2>/dev/null
UMRC=$(field "$OUT/B_umount.txt" rc)
echo "STAGE B's unmount returned at +$(el)s: $(grep -a '^UMOUNT rc=' "$OUT/B_umount.txt" | head -1)"
if [ -z "${UMRC:-}" ]; then
    capture_require_bg "$OUT/B_umount.txt" "$OUT/B_umount_stderr.txt" '^UMOUNT rc=' "B's unmount" || {
        echo "ABORT: B's unmount neither returned nor failed inside ${UMOUNT_BOUND}s — a timeout is a failure, and it is one this lap cannot grade as either ordering"
        echo "RESULT: FAIL label=$LABEL site=$SITE order=$ORDER stage=umount-timeout fails=$((fails+1)) wall=$(el)s evidence=$OUT"; exit 1; }
fi
# The schedule is over here.  If B's unmount was REFUSED while the submission
# was parked, B is still mounted, and the cold check below would read a
# filesystem another node holds — O_EXCL is local to a node and says nothing
# about a peer's mount, so the checker would report a live filesystem's
# in-flight state as damage.  So the unmount is re-attempted now that the hold
# has ended and the descriptor is released.  This is cleanup, not a retry of
# the measurement: `order` was decided above and is not revisited.
B_UNMOUNTED=1
if [ "${UMRC:-1}" != 0 ]; then
    measure "$B" 180 "$OUT/B_umount2.txt" '^UMOUNT rc=' "B's unmount, re-attempted after the hold ended" \
        "umount $MNT; echo UMOUNT rc=\$?"
    UMRC2=$(field "$OUT/B_umount2.txt" rc)
    echo "STAGE B's unmount was refused during the hold (rc=${UMRC:-?}); re-attempted after it: rc=${UMRC2:-?} at +$(el)s"
    [ "${UMRC2:-1}" = 0 ] || B_UNMOUNTED=0
fi
# give the resumed submission every chance to reach the platter before it is read
sleep 5
oracle_into "$OUT/P_r2.txt" "the oracle region after the parked submission resumed and B's unmount returned"
MD_R2=$ORACLE_VAL
echo "STAGE R2 $ORACLE=$MD_R2 at +$(el)s"
window_into "$OUT/B_win.txt" "$B" 60 "$MARK"

# ---- 7. a LATER mount must decide the same way.  A write that reached the
#         journal is invisible to R2 and still changes what the next mount
#         replays.
measure "$A" 120 "$OUT/A_umount.txt" '^UMOUNT rc=' "A's clean unmount" \
    "umount $MNT; echo UMOUNT rc=\$?"
ck "A unmounted cleanly" "$(field "$OUT/A_umount.txt" rc)" 0
measure "$A" 180 "$OUT/A_remount.txt" '^MOUNT rc=' "A's remount" \
    "mount -t mxfs $MXFS_DEV $MNT; echo MOUNT rc=\$?"
ck "A mounted again" "$(field "$OUT/A_remount.txt" rc)" 0
oracle_into "$OUT/P_r3.txt" "the oracle region after A was unmounted and mounted again"
MD_R3=$ORACLE_VAL
echo "STAGE R3 $ORACLE=$MD_R3 at +$(el)s"

# ---- 8. the cold check.  B is already unmounted; A is unmounted here so the
#         checker can take the device exclusively.
if [ "$B_UNMOUNTED" = 0 ]; then
    echo "  FAIL B could not be unmounted even after the hold ended, so the cold check"
    echo "       cannot run: the checker takes the device O_EXCL on A only, which says"
    echo "       nothing about a peer that still holds it, and a live mount's in-flight"
    echo "       state would be reported as damage.  A node that cannot depart is itself"
    echo "       a stability failure, so this is counted rather than skipped."
    fails=$((fails+1))
    CHKRC=skipped
else
    measure "$A" 120 "$OUT/A_umount2.txt" '^UMOUNT rc=' "A's unmount before the cold check" \
        "umount $MNT; echo UMOUNT rc=\$?"
    ck "A unmounted before the cold check" "$(field "$OUT/A_umount2.txt" rc)" 0
    mxfs_chk_on_node "$A" "$OUT/A_chk.txt" "the cold filesystem check after the lap" -v
    CHKRC=$(mxfs_chk_rc "$OUT/A_chk.txt")
    ck "the filesystem is clean after an admitted write outlived its node's grant publication" "$CHKRC" 0
fi

# ---- 9. the verdicts
count_file_into B_parkend "$OUT/B_win.txt" 'P292-ADMIT-PARK-END'
count_file_into B_agrel   "$OUT/B_win.txt" 'P482-UMOUNT-AGREL'
count_file_into B_drain   "$OUT/B_win.txt" 'P304-RETIRE-DRAIN'
count_file_into B_bad     "$OUT/B_win.txt" 'BUG:\|Oops'
window_into "$OUT/A_win.txt" "$A" 60 "$MARK"
count_file_into A_bad     "$OUT/A_win.txt" 'BUG:\|Oops'
echo "--- verdicts (site=$SITE, order=$ORDER, writer rc=$(field "$OUT/B_writer.txt" rc), umount rc=${UMRC:-?}) ---"
ckge "the parked submission was released below the gate" "$B_parkend" 1
if [ "$ORACLE" = block ]; then
    ck "THE PLATTER: the admitted write did not change the block after the peer took a published grant" "$MD_R2" "$MD_R1"
    ck "THE LATER MOUNT: a fresh mount of the same filesystem decides the same way" "$MD_R3" "$MD_R1"
else
    # For the journal class the slice read is evidence, not the verdict: B never
    # surrendered its own slice, and the tail's log cover and unmount record are
    # permitted producers.  What decides this arm is the ORDER printed above and
    # the cold check asserted below; the nonce counts say only whether the held
    # transaction ever reached the platter, and they are reported for that.
    if [ "$ORDER" = overlap ]; then
        echo "  NOTE the held journal write's nonce in B's slice: R1=$MD_R1 R2=$MD_R2 R3=$MD_R3 (R1=0 was required and held; R2/R3 are evidence, not verdicts — see ORDER and the cold check)"
    else
        echo "  NOTE the held journal write's nonce in B's slice: R1=$MD_R1 R2=$MD_R2 R3=$MD_R3 (order=$ORDER: the write landed before any publication, so R1>0 is expected; the nonce counts are evidence, not verdicts — see ORDER and the cold check)"
    fi
fi
ck "no host or guest kernel BUG/Oops on A" "$A_bad" 0
ck "no host or guest kernel BUG/Oops on B" "$B_bad" 0
ck "no shutdown of A's filesystem outside the cluster-fence entry" "$(bad_lines "$OUT/A_win.txt")" 0

echo "--- evidence ---"
if [ "$ORACLE" = block ]; then
    echo "  control:                      $MD_BASE -> $MD_CONTROL (a healthy write does move this block)"
else
    echo "  control:                      the control nonce $CTRLNONCE was found $CH time(s) in slice $BSLOT (a healthy journal write IS visible there)"
    echo "  nonce:                        $NONCE"
fi
echo "  R1 after B published + peer allocated: $MD_R1"
echo "  R2 after the parked write resumed:     $MD_R2"
echo "  R3 after A remounted:                  $MD_R3"
echo "  B's publication lines:        $B_agrel  ($(grep -a 'P482-UMOUNT-AGREL' "$OUT/B_win.txt" | head -1 | cut -c1-200))"
echo "  B's departure drain lines:    $B_drain  ($(grep -a 'P304-RETIRE-DRAIN' "$OUT/B_win.txt" | head -1 | cut -c1-200))"
echo "  the park:                     $(grep -a 'P292-ADMIT-PARK ' "$OUT/B_win.txt" | head -1 | cut -c1-200)"
echo "  the cold check:               ${CHKRC}  $(grep -a '^CHK_RC=' "$OUT/A_chk.txt" 2>/dev/null | head -1)"
case $ORDER in
  overlap)
    echo "  ORDER=overlap: B published its AG grants at ${TS_AGREL}ms while the admitted"
    echo "                 submission was still parked (released at ${TS_END:-never}ms), so the"
    echo "                 platter verdicts above are load-bearing and decide this case." ;;
  barrier)
    echo "  ORDER=barrier: the admitted submission was released at ${TS_END:-?}ms and B's grant"
    echo "                 publication happened at ${TS_AGREL:-never}ms — after it, or not while"
    echo "                 the hold was on.  The unmount could not reach the publication with"
    echo "                 this class of submission in flight, because one of put_super's own"
    echo "                 waits was waiting for it.  THE PLATTER ASSERTIONS ABOVE ARE"
    echo "                 THEREFORE SATISFIED BECAUSE THE TWO NEVER MET, and they exonerate"
    echo "                 nothing on their own; the barrier is this lap's whole finding." ;;
  vfs-busy)
    echo "  ORDER=vfs-busy: B's unmount was REFUSED (rc=${UMRC:-?}) while the submission was"
    echo "                 parked, so the publication was never reached.  The barrier here is"
    echo "                 a VFS reference count on an open descriptor, not anything MXFS"
    echo "                 decided, and it does not generalise to a class whose submission"
    echo "                 holds no descriptor.  THE PLATTER ASSERTIONS ABOVE ARE SATISFIED"
    echo "                 BECAUSE THE TWO NEVER MET." ;;
esac
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL site=$SITE writer=$WMODE order=$ORDER fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL site=$SITE writer=$WMODE order=$ORDER fails=$fails wall=$(el)s evidence=$OUT"; exit 1
