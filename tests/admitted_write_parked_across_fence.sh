#!/bin/bash
# tests/admitted_write_parked_across_fence.sh — an operation that PASSED the
# authority gate and had not yet reached the layer below it when a successor
# fenced this node and replayed its journal slice.
#
# THE SCHEDULE UNDER TEST, and why no existing lap reaches it.  Every authority
# lap in this tree parks a caller BEFORE the gate: the lease then expires, the
# gate refuses, and the refusal is the result.  That proves the gate refuses.
# It says nothing about the one schedule the gate cannot see — an operation
# the gate ADMITTED, still in flight, when the node stopped being the node that
# owned the resource.  If such an operation can still change what the successor
# recovered, then no second check anywhere near the gate closes it: another
# check only moves the pause point, and the disposition has to be an ordering
# mechanism or storage-side exclusion instead.
#
# THE INJECTION IS AT THE GATE'S OWN EXIT AND CHANGES NO DECISION.
# mxfs.dbg_admit_park_site names one of the gate's five call sites and
# mxfs.dbg_admit_park_ms holds the FIRST submission of that class between the
# gate's "yes" and the caller's submission.  The gate's answer is computed
# before the park and returned after it, unaltered; nothing is weakened, no
# certificate is forged, and no refusal the build has is removed.
#
# THE ORDER MATTERS AND IS NOT NEGOTIABLE.  The write is admitted and parked
# FIRST, and only then does B stop heartbeating.  Reversing the two would let
# the gate see a dead lease and refuse, which is the schedule that is already
# measured.
#
# B IS MADE BLIND ON PURPOSE.  dbg_resv_health_pause_ms holds off the periodic
# PR IN and dbg_auth_pump_pause_ms holds off the periodic lease evaluation, so
# nothing withdraws B's mount while the write is parked.  That is the most
# adversarial form of the question: when the hold ends, the submission is
# handed to the block layer by a node that believes nothing has happened, and
# the only thing left that can stop it reaching the platter is the target's own
# exclusion.  A lap that PASSES therefore says storage-side exclusion held
# without any help from B having noticed.
#
# THE VERDICT IS THE PLATTER, NEVER THE RETURN CODE.  Whatever the class, the
# lap reads the LUN from A with O_DIRECT at three instants:
#
#   R1  immediately after A's recovery of B's slice completes;
#   R2  after the park ends and the parked writer has returned;
#   R3  after A is unmounted cleanly and mounted again.
#
# A difference between R2 and R1 is an old-epoch write landing in a region a
# successor has already recovered.  A difference between R3 and R1 is the same
# thing arriving by a later replay, which an immediate comparison cannot see —
# a late journal write is invisible at R2 and still changes what the NEXT
# recovery decides.
#
# THERE ARE TWO ORACLES, BECAUSE THE FIVE SUBMISSION CLASSES DO NOT ALL LAND IN
# THE SAME PLACE, AND GRADING ONE AGAINST THE OTHER'S REGION REPORTS "NOTHING
# CHANGED" FOR A WRITE THAT DID LAND.
#
#   ORACLE=block — sites "dio" and "data".  Both submit a data write to the
#   probe file, so the probe file's own physical block IS the region.  Its
#   extent is taken with FIEMAP while B's mount is healthy and the block is
#   read back off the raw device; the three reads are md5s of that block.
#
#   ORACLE=slice — site "log".  A journal write lands in the WRITING node's log
#   slice, which the probe block never covers.  The region is therefore B's own
#   slice (slice index == heartbeat slot, identity), read with
#   tools/slice_image.py.  The three reads are NOT digests of that slice, and
#   deliberately so: A legitimately rewrites B's slice while recovering it and
#   again on its own remount, so a digest that moved would not distinguish the
#   successor's own work from an old-epoch arrival.  The read is CONTENT-
#   ADDRESSED instead — the parked transaction creates a file whose NAME is a
#   nonce unique to this lap, so that nonce appears verbatim in the logged
#   directory/inode image and nowhere else on the volume.  The question at each
#   instant is simply: is this lap's nonce on the platter inside B's slice?
#   The recovered filesystem is asked the same question a second way after A
#   remounts — does a file by that name exist — because a journal write that
#   landed AND was replayed produces one.
#
# THE CONTROL IS NOT OPTIONAL.  Every verdict below is that something did NOT
# appear, and a harness whose probe has quietly broken satisfies all of them.
# So the identical operation runs on a healthy, unfenced B first and MUST be
# visible in the oracle's own region: a block whose md5 moves (block), or the
# control nonce found inside B's slice (slice).  A lap whose control fails has
# measured its own plumbing and says so.  The slice arm additionally reads the
# PARKED nonce before anything is armed and requires zero, so "absent at R1"
# is a measurement rather than a property of the pattern.
#
# VACUOUS IF the park never fires (nothing was parked, so nothing was in
# flight); if A's recovery does not complete while the hold is still on (the
# fence did not happen inside it, so the two never overlapped); if the control's
# operation does not land; or — slice arm only — if the lap's nonce is already
# on the platter at R1, which means the submission carrying it went out before
# the fence and was never held across the replay.
#
# THE BUDGET (derived, a timeout is a failure): boot-wait 200 (infra) + prep
# 300 (measured 43-233) + identities, probe, extent, control and reset 90 +
# arm and trigger 30 + the blind arm and the heartbeat park 10 + R1 20 +
# R2 40 + A's unmount, remount and R3 200 + captures 70, and then the one
# term that has to be counted as a PAIR rather than as two: the wait for A's
# recovery and the rest of the hold after it.  They are not additive.  Either
# the recovery lands inside the hold — and the two together cannot exceed the
# hold itself — or it does not, and the overlap check exits VACUOUS without
# ever waiting out the remainder.  So the pair is bounded by PARK_MS + 20,
# never by the recovery bound plus a guess at what is left: 220.
# 200+300+90+30+10+20+40+200+70+220 = 1180.  Caller bound 1200 s.
#
# THE SLICE ARM COSTS MORE AND ITS BOUND SAYS SO.  It replaces four cheap
# 4 KiB dd reads with FIVE whole-slice scans (control, the parked nonce's
# baseline, R1, R2, R3).  The rate is not guessed: slice_image.py's own
# `scan --dev` note measures 4 slices over iSCSI at ~40 s, i.e. ~10 s for one
# slice, and `find` does strictly less per byte than that census does.  FIND_T
# is 90 s — an order of margin over the measured rate, not a round number
# standing in for a derivation — so the arm adds 5 x 90 = 450 s worst case:
# 1180 + 450 = 1630.  Caller bound 1650 s for SITE=log.  THE FIRST LOG LAP
# MUST REPORT EACH SCAN'S WALL (it prints them) AND THE BOUND MUST THEN BE
# TIGHTENED TOWARD WHAT WAS MEASURED.
#
# PARK_MS follows from that, not the other way round: the hold has to outlast
# the 62 s dead window plus the fence, certification, seal and slice replay
# (measured 77 s end to end after a kill), so ~140 s is the floor and 200 s
# is that with margin.  A longer hold buys nothing — the write is already
# across the replay — and spends the lap's whole budget.
#
# IT LEAVES B FENCED AND A MOUNTED.  Nothing is destroyed and nothing is
# forged; the next lap's prep restores both.
#
# Usage: tests/admitted_write_parked_across_fence.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2) — FIRST is A, the prover that fences and
#        recovers; SECOND is B, whose write is admitted and parked.
#        SITE (dio), PARK_MS (200000), PAUSE_MS (1260000),
#        HEALTH_PAUSE_MS (1260000), AUTHPUMP (1260000), RECOV_BOUND (180),
#        FIND_T (90, the slice arm's per-scan bound).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover: fences B, replays B's slice
B=${MXFS_NODE_LIST##*,}          # the victim: its admitted write is parked
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
CHK=/src/mxfs/tools/chk_mxfs
SLICETOOL=/src/mxfs/tools/slice_image.py
SITE=${SITE:-dio}
PARK_MS=${PARK_MS:-200000}
FIND_T=${FIND_T:-90}
# THE BLINDING MUST OUTLAST THE LAP, NOT MERELY THE HOLD.  These three knobs
# are one-shot durations, and when one lapses B starts beating, probing its
# registration and evaluating its lease again — as the OLD incarnation, into a
# slot the successor has already fenced and replayed.  That may well be worth
# measuring, but it is a different question, and arriving in the middle of R3
# it would decide this lap's verdict for a reason that is not this lap's
# subject.  So each is set past the caller bound (1650 s, the larger of the two
# arms) rather than past the park: they cannot expire inside a run that has not
# already failed its budget.
PAUSE_MS=${PAUSE_MS:-1710000}
HEALTH_PAUSE_MS=${HEALTH_PAUSE_MS:-1710000}
AUTHPUMP=${AUTHPUMP:-1710000}
RECOV_BOUND=${RECOV_BOUND:-180}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_admpark_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="ADMPARK-MARK-$LABEL"
# The nonce is the slice arm's whole oracle, so it has to be unique to THIS
# lap and unable to occur by accident anywhere on the volume.  Label, wall
# clock and pid: a re-run of the same label cannot collide with its own
# predecessor's leftovers in a slice nothing has zeroed since.
NONCE="MXPARKN-$LABEL-$(date -u +%Y%m%dT%H%M%SZ)-$$"
CTRLNONCE="MXPARKC-$LABEL-$(date -u +%Y%m%dT%H%M%SZ)-$$"
echo "=== admitted_write_parked_across_fence label=$LABEL A(prover)=$A B(parked)=$B site=$SITE park=${PARK_MS}ms $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# A withdrawal through the cluster-fence entry is not automatically bad news —
# it is what the authority machinery is for.  Every other shutdown is.
bad_lines() { echo $(( $(grep -a 'hutting down filesystem' "$1" 2>/dev/null | grep -avc 'mxfs_dlm_fence_notify') + $(cnt "$1" 'BUG:\|Oops') )); }
waitboot() {
    local n w=0
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}

# ORACLE says WHERE the write is read back from; SITE says WHICH class submits
# it.  They are not the same choice: "dio" and "data" share the platter oracle
# and land on the same probe block, but they enter the gate at two different
# call sites and only one of them is reachable with a given writer.  CLASSDESC
# names the operation the control actually performed, so a control line cannot
# claim an O_DIRECT write on a lap that issued a buffered one.
case $SITE in
    dio)      ORACLE=block; CLASSDESC="O_DIRECT write" ;;
    data)     ORACLE=block; CLASSDESC="buffered write + fsync" ;;
    log)      ORACLE=slice; CLASSDESC="create+fsync" ;;
    meta)
        echo "ABORT: site 'meta' submits into shared metadata, which is neither"
        echo "       the probe file's own block nor B's log slice, so neither of"
        echo "       this lap's two oracles covers it.  It is also the one class"
        echo "       the departure drain and the quiescence assertion already"
        echo "       account for, so it is not where the unmeasured risk is."
        echo "RESULT: ABORT label=$LABEL stage=site evidence=$OUT"; exit 2 ;;
    *)  echo "ABORT: '$SITE' is not one of the authority gate's call sites (log, data, dio, dio-zoned, meta)"
        echo "RESULT: ABORT label=$LABEL stage=site evidence=$OUT"; exit 2 ;;
esac

# ---- 0. the build must carry the injection and every probe this lap reads
for sym in P292-ADMIT-PARK P163-RECOVERY-COMPLETE P-HB-INJECT-PAUSE \
           P-DBG-RESV-HEALTH-PAUSE P-DBG-AUTH-PUMP-PAUSE; do
    [ "$(strings -a mxfs.ko | grep -c "$sym")" != 0 ] || {
        echo "ABORT: mxfs.ko carries no $sym, so there is nothing here to measure"
        echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
done
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')

for n in "$A" "$B"; do
    st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
    [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
done
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
# index (identity, never modulo — a slot with no slice may not journal at
# all).  It is read from B's own DLM-initialised line rather than assumed.
BSLOT=
if [ "$ORACLE" = slice ]; then
    value_now_into BSLOT "$B" 30 "$OUT/B_slot.txt" '^[0-9]+$' "B's heartbeat slot, which is the index of the log slice its journal writes land in" \
        "dmesg | grep -a 'DLM initialized' | tail -1 | grep -oE 'slot=[0-9]+' | cut -d= -f2"
    echo "STAGE B's log slice is slice $BSLOT on $MXFS_DEV"
fi

# ---- 1. B's probe target, durable before anything is armed.  A successful
#         write is not evidence that bytes reached the platter; the region read
#         off the raw device is.  The block arm additionally needs the probe
#         file's physical extent, taken while B's mount is still healthy.
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
# The block arm's writer.  One 4096-byte block with a caller-given tag, landing
# on the SAME probe block either way, but submitted through the class the
# caller names — because the platter oracle and the submission class are two
# different choices and collapsing them makes one of the two sites unreachable.
#
#   dio    O_DIRECT, no page cache in the way: this reaches the LUN or it does
#          not, and the gate sees it as the "dio" class.
#   data   BUFFERED, then fsync.  The submission the gate sees is the ioend
#          writeback builds, which is the "data" class, and the fsync is what
#          keeps THIS process inside that submission — so the write is still in
#          flight while the park holds it, which is the whole subject.  An
#          O_DIRECT write never reaches buffered writeback's ioend at all, so
#          driving site=data with it parks nothing and the lap is vacuous by
#          construction however the module behaves (measured s132e: "no
#          submission of class 'data' was admitted and parked within 60 s").
WRITER_B64=$(base64 -w0 <<'PY'
import os, sys, errno, time, mmap
d, tag = sys.argv[1], sys.argv[2]
site = sys.argv[3] if len(sys.argv) > 3 else "dio"
blk = 4096
print("WRITER_START tag=%s site=%s" % (tag, site)); sys.stdout.flush()
t = time.monotonic()
rc, err = 0, "-"
try:
    if site == "data":
        fd = os.open(d + "/probe", os.O_WRONLY)
        try:
            os.pwrite(fd, tag.encode().ljust(blk, b"\0"), 0)
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        buf = mmap.mmap(-1, blk)
        buf.write(tag.encode().ljust(blk, b"\0"))
        fd = os.open(d + "/probe", os.O_WRONLY | os.O_DIRECT)
        try:
            os.pwrite(fd, buf, 0)
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
# The slice arm's writer.  It creates a file NAMED for the tag and fsyncs it,
# which is a transaction commit followed by a log force — the submission the
# "log" site sits on.  The name is what makes the write findable: XFS logs the
# directory entry and the inode image verbatim, so the tag is in the journal
# payload and in nothing else on the volume.  The directory fsync that follows
# is not decoration: it is what makes the create durable rather than merely
# committed, so a lap that PASSES cannot be a lap whose write was never issued.
LOGWRITER_B64=$(base64 -w0 <<'PY'
import os, sys, errno, time
d, tag = sys.argv[1], sys.argv[2]
print("WRITER_START tag=%s" % tag); sys.stdout.flush()
t = time.monotonic()
rc, err = 0, "-"
try:
    fd = os.open(os.path.join(d, tag), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, (tag + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except OSError as e:
    rc, err = 1, errno.errorcode.get(e.errno, "E%d" % e.errno)
except Exception as e:
    rc, err = 1, "OTHER:" + type(e).__name__
print("WRITER_DONE rc=%d err=%s ms=%d" % (rc, err, (time.monotonic() - t) * 1000))
print("WRITER_END"); sys.stdout.flush()
PY
)
measure "$B" 60 "$OUT/B_target.txt" '^EXTENT_END$' "B's probe target, made durable before anything is armed, and its physical extent" \
    "d=$MNT/admpark_$LABEL; mkdir -p \$d && python3 -c \"
import os
b=bytearray(4096); b[0:9]=b'baseline\n'
fd=os.open('\$d/probe', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644); os.write(fd,b); os.fsync(fd); os.close(fd)
\" && sync -f $MNT && echo $EXTENT_B64 | base64 -d > /run/admpark_extent.py && python3 /run/admpark_extent.py \$d/probe"
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
#          and a broken probe satisfies all of them.  A healthy, unfenced B's
#          identical operation must be visible in the oracle's own region.
if [ "$ORACLE" = block ]; then
    platter_into "$OUT/P_base.txt" "the probe block on the platter before the control"
    MD_BASE=$(platter_md5 "$OUT/P_base.txt")
    measure "$B" 60 "$OUT/B_control.txt" '^WRITER_END$' "the control write on a healthy B" \
        "echo $WRITER_B64 | base64 -d > /run/admpark_writer.py; python3 /run/admpark_writer.py $MNT/admpark_$LABEL control-write $SITE; sync -f $MNT"
    CRC=$(field "$OUT/B_control.txt" rc)
    ck "control: a healthy node's $CLASSDESC returns 0" "$CRC" 0
    platter_into "$OUT/P_control.txt" "the probe block after the control write"
    MD_CONTROL=$(platter_md5 "$OUT/P_control.txt")
    [ -n "$MD_BASE" ] && [ -n "$MD_CONTROL" ] || { echo "ABORT: the probe block could not be read off the raw device, so the platter oracle does not work and no verdict below would mean anything"; echo "RESULT: ABORT label=$LABEL stage=platter evidence=$OUT"; exit 2; }
    if [ "$MD_BASE" = "$MD_CONTROL" ]; then
        echo "  FAIL control: a healthy node's $CLASSDESC reached the platter (md5 $MD_BASE unchanged)"
        echo "ABORT: the platter oracle cannot see a write that DID land, so 'the block did not change' would be true of everything"
        echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2
    fi
    echo "  PASS control: a healthy node's $CLASSDESC changed the block on the platter ($MD_BASE -> $MD_CONTROL)"
else
    measure "$B" 60 "$OUT/B_control.txt" '^WRITER_END$' "the control journal write on a healthy B" \
        "echo $LOGWRITER_B64 | base64 -d > /run/admpark_logwriter.py; python3 /run/admpark_logwriter.py $MNT/admpark_$LABEL $CTRLNONCE; sync -f $MNT"
    CRC=$(field "$OUT/B_control.txt" rc)
    ck "control: a healthy node's create+fsync returns 0" "$CRC" 0
    slice_find_into "$OUT/S_control.txt" "the control nonce inside B's log slice on the platter" "$CTRLNONCE"
    CH=$(slice_hits "$OUT/S_control.txt")
    [ -n "$CH" ] || { echo "ABORT: B's log slice could not be scanned off the raw device, so the slice oracle does not work and no verdict below would mean anything"; echo "RESULT: ABORT label=$LABEL stage=slice evidence=$OUT"; exit 2; }
    if [ "$CH" -lt 1 ] 2>/dev/null; then
        echo "  FAIL control: a healthy node's journal write is not visible in its own log slice (hits=$CH)"
        echo "ABORT: the slice oracle cannot see a journal write that DID land, so 'the nonce is absent' would be true of everything"
        echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2
    fi
    echo "  PASS control: a healthy node's journal write is visible in its own log slice (hits=$CH, scan $(grep -ao 'SCAN_WALL s=[0-9]*' "$OUT/S_control.txt" | head -1))"
    # And the PARKED nonce must be absent before anything is armed, so that
    # "absent at R1" below is a measurement and not a property of the pattern.
    slice_find_into "$OUT/S_base.txt" "this lap's parked nonce before anything is armed" "$NONCE"
    BH=$(slice_hits "$OUT/S_base.txt")
    ck "baseline: this lap's nonce is not already on the platter" "$BH" 0
fi
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }

# ---- 2. arm the park and put ONE admitted write under it.  The trigger runs
#         in the background because it is going to sleep inside the kernel for
#         the whole hold; its stdout is kept so its rc can be read when it
#         returns.
rsx 30 "$B" "echo $MARK > /dev/kmsg; echo MARKED" > "$OUT/B_mark.txt"
capture_require "$OUT/B_mark.txt" '^MARKED$' "the ring mark on $B"
rsx 30 "$A" "echo $MARK > /dev/kmsg; echo MARKED" > "$OUT/A_mark.txt"
capture_require "$OUT/A_mark.txt" '^MARKED$' "the ring mark on $A"
measure "$B" 40 "$OUT/B_arm_park.txt" '^ARMED' "the post-admission park armed on B" \
    "echo $SITE > $PARM/dbg_admit_park_site; echo $PARK_MS > $PARM/dbg_admit_park_ms; echo ARMED site=\$(cat $PARM/dbg_admit_park_site) ms=\$(cat $PARM/dbg_admit_park_ms)"
ck "the park is armed for this site" "$(field "$OUT/B_arm_park.txt" site)" "$SITE"
ck "the park hold is the one this lap derived" "$(field "$OUT/B_arm_park.txt" ms)" "$PARK_MS"
if [ "$ORACLE" = block ]; then
    ( timeout $(( PARK_MS / 1000 + 180 )) $SSH "$B" "python3 /run/admpark_writer.py $MNT/admpark_$LABEL parked-old-epoch-write $SITE" \
          2> "$OUT/B_writer_stderr.txt" | filt > "$OUT/B_writer.txt" ) &
else
    ( timeout $(( PARK_MS / 1000 + 180 )) $SSH "$B" "python3 /run/admpark_logwriter.py $MNT/admpark_$LABEL $NONCE" \
          2> "$OUT/B_writer_stderr.txt" | filt > "$OUT/B_writer.txt" ) &
fi
WPID=$!
echo "STAGE the parked writer was started on $B at +$(el)s (pid $WPID)"
wait_for_into parked "$B" 60 "$MARK" 'P292-ADMIT-PARK site='
if [ "$parked" = timeout ]; then
    echo "VACUOUS: no submission of class '$SITE' was admitted and parked within 60 s, so nothing was ever in flight across the fence"
    echo "RESULT: VACUOUS label=$LABEL stage=park evidence=$OUT"
    kill "$WPID" 2>/dev/null; exit 3
fi
echo "STAGE the write is ADMITTED and parked below the gate at +$(el)s (waited ${parked}s)"

# ---- 3. B stops heartbeating, and stops being able to notice anything.  The
#         one-shot knob is not in effect when the write returns — a beat
#         already in flight would otherwise satisfy the test — so the arm waits
#         for the module's own line.
# THE PARK OUTLIVES THIS LAP ON EVERY EXIT, INCLUDING A CLEAN ONE, SO IT IS
# CLEANED UP UNCONDITIONALLY.  PAUSE_MS is 28 minutes against a lap bounded at
# 27, and the heartbeat thread it parks is exactly what an unmount waits for —
# so a lap that ends with that thread still sleeping stalls the NEXT lap on
# this fleet behind its own prep.  Measured previously with a 480 s park left
# armed by an early exit: the following prep was still running at 150 s against
# a 45-58 s norm and had to be abandoned.  There are four exits between the arm
# below and the tail (the arm ABORT, the recovery and overlap VACUOUS exits and
# the writer ABORT) and none of them can be the one place this is undone.
# Destroying and restarting the victim is what releases the sleeping thread;
# the knob itself is reset by the module reload the next prep performs.  This
# cannot change a verdict: every graded read is a raw-device read taken from A
# (R1, R2, R3), and B is fenced and blind from the arm onwards.
PARKED=0
admpark_cleanup() {
    [ "$PARKED" = 1 ] || return 0
    echo "CLEANUP: the heartbeat park was armed on $B — destroying and restarting it so the next prep's unmount does not wait on a sleeping heartbeat thread"
    $VIRSH destroy "$B" > /dev/null 2>&1
    $VIRSH start "$B" > /dev/null 2>&1
    return 0
}
trap admpark_cleanup EXIT
# Set BEFORE the knob write, not after: if the arm dies part-way the knob may
# already have landed, and a needless domain restart costs one boot while a
# missed one costs the next lap's measurement.
PARKED=1
measure "$B" 40 "$OUT/B_arm_blind.txt" '^ARMED' "B's detectors held off and its heartbeat parked" \
    "echo $AUTHPUMP > $PARM/dbg_auth_pump_pause_ms; echo $HEALTH_PAUSE_MS > $PARM/dbg_resv_health_pause_ms; sleep 1; echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms; echo ARMED health=\$(cat $PARM/dbg_resv_health_pause_ms) pause=\$(cat $PARM/dl_inject_hb_pause_ms) pump=\$(cat $PARM/dbg_auth_pump_pause_ms)"
wait_for_into paused "$B" 40 "$MARK" 'P-HB-INJECT-PAUSE'
ck "B's heartbeat thread reported that it is parked" "$([ "$paused" = timeout ] && echo no || echo yes)" yes
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }
echo "STAGE B is quiet and blind at +$(el)s — waiting for A's fence and recovery (dead window 62 s, bound ${RECOV_BOUND}s)"

# ---- 4. A declares B dead, fences it, certifies and replays its slice
wait_for_into recovered "$A" "$RECOV_BOUND" "$MARK" 'P163-RECOVERY-COMPLETE'
if [ "$recovered" = timeout ]; then
    window_into "$OUT/A_norecov.txt" "$A" 60 "$MARK"
    echo "VACUOUS: A did not complete a recovery of B's slice inside ${RECOV_BOUND}s, so the admitted write and the successor's replay never overlapped and nothing about their ordering was measured"
    echo "  A's fence evidence: $(grep -ac 'P-FENCE\|PREEMPT' "$OUT/A_norecov.txt") fence lines, $(cnt "$OUT/A_norecov.txt" 'foreign replay') foreign-replay lines"
    echo "RESULT: VACUOUS label=$LABEL stage=recovery evidence=$OUT"
    kill "$WPID" 2>/dev/null; exit 3
fi
echo "STAGE A completed the recovery of B's slice at +$(el)s (waited ${recovered}s)"
# R1 — the region the successor recovered, read before the hold ends
oracle_into "$OUT/P_after_replay.txt" "the oracle region immediately after A's recovery completed"
R1=$ORACLE_VAL
echo "STAGE R1 $ORACLE=$R1 at +$(el)s"
# The overlap is the whole point: the hold must still have been on.  If the
# writer has already returned, the fence did not happen inside it.
if grep -qa '^WRITER_DONE' "$OUT/B_writer.txt" 2>/dev/null; then
    echo "VACUOUS: the parked writer had already returned before A's recovery completed, so the admitted write was never in flight across the replay"
    echo "RESULT: VACUOUS label=$LABEL stage=overlap evidence=$OUT"
    exit 3
fi
# And for the slice arm: if this lap's nonce is ALREADY on the platter, the
# submission carrying it went out before the fence — whatever the park held, it
# was not this transaction, and nothing was held across the replay.
if [ "$ORACLE" = slice ] && [ "${R1:-0}" -gt 0 ] 2>/dev/null; then
    echo "VACUOUS: this lap's nonce was already inside B's log slice when A's recovery completed (hits=$R1), so the transaction carrying it was submitted before the fence and never crossed the replay"
    echo "RESULT: VACUOUS label=$LABEL stage=overlap evidence=$OUT"
    exit 3
fi

# ---- 5. the hold ends and the admitted write is handed below the gate
wait "$WPID" 2>/dev/null
WRC=$(field "$OUT/B_writer.txt" rc)
WERR=$(field "$OUT/B_writer.txt" err)
echo "STAGE the parked writer returned at +$(el)s: $(grep -a '^WRITER_DONE' "$OUT/B_writer.txt" | head -1)"
if ! grep -qa '^WRITER_DONE' "$OUT/B_writer.txt" 2>/dev/null; then
    capture_require_bg "$OUT/B_writer.txt" "$OUT/B_writer_stderr.txt" '^WRITER_DONE' "the parked writer on $B" || {
        echo "ABORT: the parked writer never returned and its stderr is silent — it is still in the kernel, which is a result this lap cannot grade as either outcome"
        echo "RESULT: ABORT label=$LABEL stage=writer evidence=$OUT"; exit 2; }
fi
# give the submission every chance to reach the platter before it is read
sleep 5
oracle_into "$OUT/P_after_resume.txt" "the oracle region after the admitted write was submitted"
R2=$ORACLE_VAL
echo "STAGE R2 $ORACLE=$R2 at +$(el)s"

# B's window is taken HERE, while B is known to be answering.  Taking it after
# A's unmount and remount would let a late ssh failure on a fenced node abort
# the lap AFTER everything it came to measure had already been measured.
window_into "$OUT/B_win.txt" "$B" 60 "$MARK"

# ---- 6. and a LATER recovery must decide the same way.  A write that reached
#         the journal is invisible to R2 and still changes what the next mount
#         replays, so A is unmounted and mounted again.
measure "$A" 120 "$OUT/A_umount.txt" '^UMOUNT rc=' "A's clean unmount" \
    "umount $MNT; echo UMOUNT rc=\$?"
ck "A unmounted cleanly" "$(field "$OUT/A_umount.txt" rc)" 0
# No cold chk_mxfs here, and the reason is structural rather than an omission:
# B is still MOUNTED — fenced, blind, but holding the device — so no node can
# take the LUN exclusively and the checker would refuse every caller.  Making
# room for it would mean unmounting a node under a terminal quarantine, which
# is a separate open defect and would decide this lap's result for reasons that
# have nothing to do with its subject.  R3 below is the durable verdict.
measure "$A" 180 "$OUT/A_remount.txt" '^MOUNT rc=' "A's remount" \
    "mount -t mxfs $MXFS_DEV $MNT; echo MOUNT rc=\$?"
ck "A mounted again" "$(field "$OUT/A_remount.txt" rc)" 0
oracle_into "$OUT/P_after_remount.txt" "the oracle region after A was unmounted and mounted again"
R3=$ORACLE_VAL
echo "STAGE R3 $ORACLE=$R3 at +$(el)s"
# The slice arm asks the recovered FILESYSTEM the same question a second way.
# A journal write that landed and was replayed produces a file by that name;
# a scan that missed it and a namespace that carries it disagree, and the
# namespace is the one that decides what a user sees.
NF=
if [ "$ORACLE" = slice ]; then
    value_now_into NF "$A" 60 "$OUT/A_nonce_file.txt" '^NONCEFILE count=[0-9]+$' \
        "whether the old-epoch transaction's file exists in the filesystem A recovered and remounted" \
        "n=\$(ls -1 $MNT/admpark_$LABEL 2>/dev/null | grep -c -- $NONCE); echo NONCEFILE count=\$n"
    NF=${NF#NONCEFILE count=}
fi

# ---- 7. the verdicts
window_into "$OUT/A_win.txt" "$A" 60 "$MARK"
count_file_into A_recov "$OUT/A_win.txt" 'P163-RECOVERY-COMPLETE'
count_file_into A_bad "$OUT/A_win.txt" 'BUG:\|Oops'
count_file_into B_bad "$OUT/B_win.txt" 'BUG:\|Oops'
count_file_into B_parkend "$OUT/B_win.txt" 'P292-ADMIT-PARK-END'
echo "--- verdicts (site=$SITE, oracle=$ORACLE, writer rc=${WRC:-?} err=${WERR:-?}) ---"
ckge "A recovered B's slice while the admitted write was still in flight" "$A_recov" 1
ckge "the parked submission was released below the gate" "$B_parkend" 1
if [ "$ORACLE" = block ]; then
    ck "THE PLATTER: the admitted old-epoch write did not change the block the successor recovered" "$R2" "$R1"
    ck "THE LATER RECOVERY: a fresh mount of the same filesystem decides the same way" "$R3" "$R1"
else
    ck "THE SLICE: the admitted old-epoch journal write did not reach the log slice the successor had already recovered" "$R2" 0
    ck "THE LATER RECOVERY: it is still absent from that slice after A unmounted and mounted again" "$R3" 0
    ck "THE RECOVERED FILESYSTEM: the old-epoch transaction left no file behind in the namespace A recovered" "$NF" 0
fi
ck "no host or guest kernel BUG/Oops on A" "$A_bad" 0
ck "no host or guest kernel BUG/Oops on B" "$B_bad" 0
ck "no shutdown of A's filesystem outside the cluster-fence entry" "$(bad_lines "$OUT/A_win.txt")" 0

echo "--- evidence ---"
if [ "$ORACLE" = block ]; then
    echo "  control:   $MD_BASE -> $MD_CONTROL (a healthy write does move this block)"
else
    echo "  control:   the control nonce $CTRLNONCE was found $CH time(s) in slice $BSLOT (a healthy journal write IS visible there)"
    echo "  nonce:     $NONCE"
fi
echo "  R1 after A's recovery:        $R1"
echo "  R2 after the admitted write:  $R2"
echo "  R3 after A remounted:         $R3"
[ "$ORACLE" = slice ] && echo "  the nonce-named file after A remounted: ${NF:-?}"
echo "  the parked writer:            $(grep -a '^WRITER_DONE' "$OUT/B_writer.txt" | head -1)"
echo "  the park:                     $(grep -a 'P292-ADMIT-PARK ' "$OUT/B_win.txt" | head -1 | cut -c1-200)"
if [ "$fails" = 0 ]; then
    echo "RESULT: PASS label=$LABEL site=$SITE writer_rc=${WRC:-?} writer_err=${WERR:-?} fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL site=$SITE writer_rc=${WRC:-?} writer_err=${WERR:-?} fails=$fails wall=$(el)s evidence=$OUT"; exit 1
