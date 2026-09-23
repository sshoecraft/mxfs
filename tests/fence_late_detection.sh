#!/bin/bash
# fence_late_detection.sh — a fenced node that has NOT yet noticed, meeting a
# LUN that has stopped refusing anyone.
#
# THE ORDERING UNDER TEST (design-consult ruling, session 86,
# docs/rulings/early-revocation-ownership-epoch-split.md §1).  Containment of a
# fenced-but-alive node is established by that node NOTICING, two ways:
#
#   reactive   a data-path write bounces with SCSI RESERVATION CONFLICT; three
#              of them launch the inspection thread, which confirms with PR IN
#              and withdraws the mount.  It needs the node to be issuing I/O.
#   proactive  v5_resv_health_tick's periodic PR IN ranks SELF_GONE ahead of
#              ABSENT, so a node whose own key is missing withdraws.  Its
#              cadence is 5 s for the elected maintainer and 60 s for an
#              auditor — which in a two-node cluster the victim often is.
#
# A node doing no I/O, whose tick has not come round, is fenced and knows
# nothing.  If the prover then dies, the target purges the prover's
# registration AND the reservation with it, and an unreserved LUN refuses
# nobody.  The question this lap answers is what happens when that node then
# writes: it has not detected anything, it still believes its old storage
# incarnation owns the mount, and nothing is left to bounce it.
#
# WHAT WAS ALREADY MEASURED, AND WHY IT IS NOT THIS.  The silent-victim arm of
# tests/fence_crash_cuts.sh keeps a WRITER running, so the reactive path fires
# within a few seconds and the node withdraws long before the reservation
# disappears.  Its "zero fsync succeeded after the prover's death" result is
# preservation of a containment latch ALREADY ESTABLISHED.  This lap removes
# both detectors — no workload, and dbg_resv_health_pause_ms holds the tick off
# — so the latch is never established in the first place.
#
# THE INJECTION IS AT THE DETECTOR, NOT AT THE REFUSAL.  Nothing here weakens
# a gate, forges a certificate or touches the write path.  The victim's
# proactive check is delayed, exactly as a stalled node's would be, and every
# refusal the build has stays in place.  A lap that PASSES therefore says the
# refusal does not depend on having noticed; a lap that FAILS says containment
# is detection-dependent and there is a window in which a fenced incarnation
# can write.
#
# SHAPE:
#   1. prep 2 nodes; B creates its probe target and syncs, then goes QUIET.
#   2. B: arm dbg_resv_health_pause_ms, then park its heartbeat.
#   3. A declares B dead and PREEMPT AND ABORTs a key that is still PRESENT,
#      so the fence is a real completed target operation.
#   4. assert B has noticed NOTHING (no conflict, no PR IN, no withdrawal).
#   5. destroy A.  Poll from B until the target holds no key and no
#      reservation — B may still issue PR IN unregistered.
#   6. assert B STILL has noticed nothing.
#   7. B writes: one data write + fsync, one metadata create.  BOTH MUST FAIL.
#   8. capture what refused them, or what let them through.
#
# the budget rule (derived): boot-wait, 152 s measured when this lap's own
# previous run left the prover powered off + prep <= 300 (measured 43-58, 210
# including a cold boot) + payload, extent and arm 60 + the 62 s dead window and
# the fence, bound 120 + captures 20 + destroy 10 + the registration purge,
# measured 30 s after the cut, bound 120 + captures 20 + the probe, whose slow
# arm waits out the DLM membership-change retry budget, bound 280 + the platter
# reads 80 + captures 30 + A restart 10 = 1200.  Caller bound 1200 s.
#
# IT LEAVES A DESTROYED AND B FENCED.  The next lap's prep restores both.
#
# Usage: tests/fence_late_detection.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, PAUSE_MS (600000),
#        HEALTH_PAUSE_MS (600000), FENCE_BOUND (120), PURGE_BOUND (120)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the prover; fences B, then is destroyed
B=${MXFS_NODE_LIST##*,}          # the victim; fenced, quiet, and unaware
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
CHK=/src/mxfs/tools/chk_mxfs
DUMP=/src/mxfs/tools/disklock_hb_dump.py
PAUSE_MS=${PAUSE_MS:-600000}
# AUTHPUMP>0 parks the PERIODIC evaluation of the authority lease as well, so
# the only thing left that can discover the expiry is a mutating submission.
# A lap that still refuses the writes with this armed has proved containment is
# a property of the write path and not of a worker thread being scheduled.
AUTHPUMP=${AUTHPUMP:-600000}
HEALTH_PAUSE_MS=${HEALTH_PAUSE_MS:-600000}
FENCE_BOUND=${FENCE_BOUND:-120}
PURGE_BOUND=${PURGE_BOUND:-120}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lated_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
MARK="LATED-MARK-$LABEL"
echo "=== fence_late_detection label=$LABEL A(prover)=$A B(victim)=$B $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: the arm
# prints "SEEN=1 PAUSED=1" on one line, and an anchored match read SEEN and
# handed PAUSED an empty string — which the verdict helper correctly refused to
# grade, aborting a healthy lap at the arm.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# A shutdown is no longer automatically bad news here: withdrawing the mount is
# what the authority lease is FOR, and a lap in which the filesystem went down
# because the lease expired is a lap in which containment worked.
#
# The withdrawal announces itself as "Metadata I/O Error ... at
# mxfs_dlm_fence_notify", because that is the call XFS is given to force a
# shutdown through and it names its own reason rather than the caller's.  So
# the exemption is keyed on that CALL SITE — the cluster-withdrawal entry —
# and on nothing broader: a shutdown from anywhere else still counts, and
# WHICH withdrawal this was is settled separately by the assertion that no
# LUN-dependent detector fired anywhere in the lap.
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
keys_into() {   # <node> <file> <what>
    # sg_persist prints the decisive line as "there is NO reservation held" —
    # capitals.  A case-sensitive filter dropped it, so the purge poll could
    # never see the LUN go permissive and spent its whole bound waiting for a
    # string that had already been thrown away: lap s87b sat 120 s on a target
    # that had in fact purged every key 40 s in, then declared itself vacuous.
    measure "$1" 40 "$2" '^KEYS_END$' "$3" "$CHK --pr-keys $MXFS_DEV 2>&1; sg_persist -i -k $MXFS_DEV 2>&1 | grep -ao 'PR generation=0x[0-9a-f]*'; sg_persist -i -r $MXFS_DEV 2>&1 | grep -ai 'Key=\|type:\|reservation held\|no reservation' | sed 's/^/RESV /'; echo KEYS_END"
}
key_present() { grep -aoE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | grep -ac "^$2$"; }
normkey() { printf '0x%016x' "$(( $1 ))"; }
resv_none() { grep -aiq 'RESV.*no reservation held' "$1" && echo yes || echo no; }
# EVERY LINE THE VICTIM WOULD PRINT IF SOMETHING HAD TOLD IT.  All of these
# need the LUN to answer or a peer to act: a write that bounced with
# RESERVATION CONFLICT, a PR IN that found its key gone, a heartbeat CAS that
# miscompared against a survivor's recovery guard.  They are what this lap must
# see ZERO of, because a lap in which any of them fired has measured the
# ordinary detection path that was already known to work.
#
# The local authority lease is deliberately NOT in this list.  It is the fix,
# it needs nothing from the outside world, and a lap that PASSES is one where
# it was the only thing that fired — so the P131-SELF-FENCE line it emits is
# excluded by its reason rather than by its name.
DETECT='P277-RESV-CONFLICT\|P277-PR-FULLSTATUS\|P277-FENCED-SELF-WITHDRAW\|P277-RESV-INSPECT\|P305-RESV-SELF-GONE\|P131-SELF-FENCE\|P236-SELF-FENCE'
detected_in() { grep -a "$DETECT" "$1" 2>/dev/null | grep -avc 'AUTHORITY_LEASE_EXPIRED'; }
closed_in()   { cnt "$1" 'P290-AUTH-CLOSED'; }

# THE PROBE SCRIPT, defined up here because both the control (step 1b) and the
# fenced probe (step 7) run it; they differ only in which arms they select.
#         Each arm is timed, because a refusal and a 40 s stall that ends in a
#         refusal are different results and only one of them is containment
#         working: lap s87b's manual probe blocked in fsync until an unrelated
#         detector woke up and shut the filesystem down, which is the write
#         being caught by detection rather than by a gate.
PROBE_B64=$(base64 -w0 <<'PY'
import os, sys, errno, time
d = sys.argv[1]
blk = 4096


def name(e):
    try:
        return errno.errorcode[e]
    except Exception:
        return "E%d" % e


def arm(tag, fn):
    t = time.monotonic()
    rc, err = 0, "-"
    try:
        fn()
    except OSError as e:
        rc, err = 1, name(e.errno)
    except Exception as e:
        rc, err = 1, "OTHER:" + type(e).__name__
    print("PROBE_%s rc=%d err=%s ms=%d" % (tag, rc, err, (time.monotonic() - t) * 1000))
    sys.stdout.flush()


def buffered():
    fd = os.open(d + "/probe", os.O_WRONLY)
    try:
        os.write(fd, b"fenced-incarnation-write\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def direct():
    # no page cache in the way: this reaches the LUN or it does not.  O_DIRECT
    # wants a page-aligned buffer, which mmap gives and bytearray does not.
    import mmap
    buf = mmap.mmap(-1, blk)
    buf.write(b"fenced-direct-write\n".ljust(blk, b"\0"))
    fd = os.open(d + "/probe", os.O_WRONLY | os.O_DIRECT)
    try:
        os.pwrite(fd, buf, 0)
    finally:
        os.close(fd)
        buf.close()


def meta():
    os.mkdir(d + "/late_dir")


# The arms are selected by the caller, because the metadata create is the slow
# one — with the peer gone it sits on the DLM's membership-change retry budget,
# and with the victim's detector held off nothing ever arrives to end that wait.
# Running it in the same acquisition as the write arms let one arm's timeout
# abort the lap BEFORE the platter read that says whether the writes landed,
# which is the only thing the lap exists to find out.
for a in sys.argv[2:]:
    arm(a, {"DATA": buffered, "DIRECT": direct, "META": meta}[a])
print("PROBE_END")
PY
)

# ---- 0. the fleet on the tree build, with the injection in it
if [ "$AUTHPUMP" != 0 ] && [ "$(strings -a mxfs.ko | grep -c 'P-DBG-AUTH-PUMP-PAUSE')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no dbg_auth_pump_pause_ms injection, so the"
    echo "       periodic half of the authority lease cannot be held off and a"
    echo "       refusal could not be attributed to the submission path.  Run"
    echo "       with AUTHPUMP=0 to grade the periodic half instead."
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
if [ "$(strings -a mxfs.ko | grep -c 'P-DBG-RESV-HEALTH-PAUSE')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no dbg_resv_health_pause_ms injection, so the"
    echo "       victim's proactive detector cannot be held off and this lap"
    echo "       would measure the cadence race rather than the ordering."
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
# this lap DESTROYS the prover and only restarts it on the paths that reach the
# end; a VACUOUS exit leaves it off, and the next lap's boot-wait then polls a
# powered-off VM for its whole bound before prep fails on a node that was never
# going to answer.  Start anything that is not running before waiting for it.
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

# ---- 1. identities, and B's probe target created and made durable BEFORE it
#         goes quiet (the probe must not need an allocation to reach the LUN)
dump_into() { measure "$1" 60 "$2" '^slot +[0-9]+ magic=' "$3" "python3 $DUMP $MXFS_DEV"; }
dump_into "$A" "$OUT/hb_0.txt" "the disklock table before the arm"
value_now_into BNODE "$B" 30 "$OUT/B_node.txt" '^NODE=[0-9]+$' "B's node id" "echo NODE=\$(dmesg | grep -ao 'DLM init: node_id=[0-9]*' | tail -1 | cut -d= -f2)"
value_now_into BKEY "$B" 30 "$OUT/B_key.txt" '^KEY=0x[0-9a-f]+$' "B's PR key" "echo KEY=\$(dmesg | grep -ao 'P-PRKEY-REGISTERED .*key=0x[0-9a-f]*' | tail -1 | grep -ao '0x[0-9a-f]*')"
echo "STAGE identities: victim B=$BNODE key=$BKEY"
[ -n "${BKEY:-}" ] || { echo "ABORT: B's PR key could not be read"; echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2; }
# The probe file is created, filled to a whole block and made durable here, and
# its PHYSICAL extent is recorded.  A successful fsync is not evidence that
# anything reached the LUN; the only thing that settles it is reading the block
# back off the device, and that has to be done without the mount — which by then
# is either shut down or the thing under suspicion.  FIEMAP gives the device
# offset while the filesystem is still healthy enough to answer.
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
measure "$B" 60 "$OUT/B_target.txt" '^EXTENT_END$' "B's probe target, made durable before it goes quiet, and its physical extent" \
    "d=$MNT/lated_$LABEL; mkdir -p \$d && python3 -c \"
import os
b=bytearray(4096); b[0:9]=b'baseline\n'
fd=os.open('\$d/probe', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644); os.write(fd,b); os.fsync(fd); os.close(fd)
\" && sync -f $MNT && echo $EXTENT_B64 | base64 -d > /run/lated_extent.py && python3 /run/lated_extent.py \$d/probe"
PHYS=$(grep -ao 'physical=[0-9]*' "$OUT/B_target.txt" | head -1 | cut -d= -f2)
echo "STAGE probe file physical offset on the LUN: ${PHYS:-none}"
[ -n "${PHYS:-}" ] || { echo "ABORT: the probe file's physical extent could not be read, so a landed write could not be distinguished from an acknowledged one"; echo "RESULT: ABORT label=$LABEL stage=extent evidence=$OUT"; exit 2; }
# mark A's ring as well: a window taken with an empty mark dumps the WHOLE
# ring and will happily count an event from a previous lap
rsx 30 "$A" "echo $MARK > /dev/kmsg; echo MARKED" > "$OUT/A_mark.txt"
capture_require "$OUT/A_mark.txt" '^MARKED$' "the ring mark on $A"
keys_into "$A" "$OUT/K0.txt" "READ KEYS before the arm"
ck "before the arm: B's key is registered" "$(key_present "$OUT/K0.txt" "$(normkey "$BKEY")")" 1

# ---- 1b. THE CONTROL.  Every assertion below is that a write FAILS, and a
#          harness that has quietly broken its own probe satisfies all of them.
#          So run the identical probe on B while it is healthy, mounted and
#          unfenced, and require it to SUCCEED.  A lap whose control fails has
#          measured its own plumbing and says so instead of grading MXFS.
measure "$B" 60 "$OUT/B_control.txt" '^PROBE_END$' "the control probe on a healthy B" \
    "echo $PROBE_B64 | base64 -d > /run/lated_probe.py; python3 /run/lated_probe.py $MNT/lated_$LABEL DATA DIRECT META"
CD=$(grep -a '^PROBE_DATA' "$OUT/B_control.txt" | head -1)
CX=$(grep -a '^PROBE_DIRECT' "$OUT/B_control.txt" | head -1)
CM=$(grep -a '^PROBE_META' "$OUT/B_control.txt" | head -1)
echo "STAGE control (healthy B): $CD | $CX | $CM"
ck "control: a healthy node's buffered write SUCCEEDS" "$(echo "$CD" | grep -ao 'rc=[0-9]*' | cut -d= -f2)" 0
ck "control: a healthy node's O_DIRECT write SUCCEEDS" "$(echo "$CX" | grep -ao 'rc=[0-9]*' | cut -d= -f2)" 0
ck "control: a healthy node's metadata create SUCCEEDS" "$(echo "$CM" | grep -ao 'rc=[0-9]*' | cut -d= -f2)" 0
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=control evidence=$OUT"; exit 2; }
# put the block back the way the fenced probe expects to find it, and clear the
# control's directory so the fenced metadata arm creates rather than collides
measure "$B" 60 "$OUT/B_control_reset.txt" '^RESET_END$' "the probe block restored after the control" \
    "d=$MNT/lated_$LABEL; rmdir \$d/late_dir 2>/dev/null; python3 -c \"
import os
b=bytearray(4096); b[0:9]=b'baseline\n'
fd=os.open('\$d/probe', os.O_WRONLY); os.write(fd,b); os.fsync(fd); os.close(fd)
\" && sync -f $MNT && echo RESET_END"
measure "$B" 40 "$OUT/B_platter0.txt" '^PLATTER_END$' "the probe block on the LUN before the fence" \
    "dd if=$MXFS_DEV bs=4096 skip=$((PHYS / 4096)) count=1 iflag=direct 2>/dev/null | head -c 64 | od -c | head -3; echo PLATTER_END"
ck "the baseline block on the LUN carries no fenced-incarnation bytes" "$(grep -ac 'f   e   n   c   e   d' "$OUT/B_platter0.txt")" 0

# ---- 2. hold off B's proactive detector, then park its heartbeat.  B issues
#         nothing from here on: no workload, and the parked heartbeat is the
#         only periodic write it had.
measure "$B" 30 "$OUT/B_arm.txt" '^ARMED=[0-9]+ pause=[0-9]+ pump=[0-9]+$' "the detector hold-off and heartbeat park on $B" \
    "echo $MARK > /dev/kmsg; echo $AUTHPUMP > $PARM/dbg_auth_pump_pause_ms; echo $HEALTH_PAUSE_MS > $PARM/dbg_resv_health_pause_ms; sleep 1; echo $PAUSE_MS > $PARM/dl_inject_hb_pause_ms; sleep 4; echo ARMED=\$(cat $PARM/dbg_resv_health_pause_ms) pause=\$(cat $PARM/dl_inject_hb_pause_ms) pump=\$(cat $PARM/dbg_auth_pump_pause_ms)"
# the injection is ONE-SHOT and consumed by the first tick, so reading back 0
# is the armed state, not a failure to arm; the kernel line is the witness
measure "$B" 30 "$OUT/B_arm_seen.txt" '^SEEN=[0-9]+ PAUSED=[0-9]+ PUMP=[0-9]+$' "the arm's own kernel lines on $B" \
    "echo SEEN=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*pausing') PAUSED=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-DBG-RESV-HEALTH-PAUSE node') PUMP=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-DBG-AUTH-PUMP-PAUSE node')"
ck "B's heartbeat thread parked" "$(field "$OUT/B_arm_seen.txt" SEEN)" 1
# B's proactive PR detector must be unable to run, and there are two ways to
# say so.  With AUTHPUMP armed the whole PR worker arm is parked, which also
# parks the health tick — strictly stronger, and it leaves the one-shot health
# pause armed but unconsumed, so its own witness line never prints.  Grade
# whichever one applies rather than demanding the line that cannot appear.
if [ "$AUTHPUMP" = 0 ]; then
    ck "B's proactive reservation-health check is held off" "$(field "$OUT/B_arm_seen.txt" PAUSED)" 1
else
    ck "B's periodic authority-lease evaluation is held off — which parks the proactive PR check with it, leaving only a submission to find the expiry" "$(field "$OUT/B_arm_seen.txt" PUMP)" 1
fi
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }
T0=$(date +%s)
echo "STAGE $B is fenceable, quiet and blind at +$(el)s — waiting for A's PREEMPT AND ABORT (dead window 62 s, bound ${FENCE_BOUND}s)"

# ---- 3. A fences B.  The proof that it was a REAL target operation is that
#         B's key was PRESENT when it started and is gone afterwards, with the
#         PR generation moved (a purge does not move it; a PROUT does).
w=0
while [ $w -lt "$FENCE_BOUND" ]; do
    keys_into "$A" "$OUT/K1.txt" "READ KEYS while waiting for the fence"
    [ "$(key_present "$OUT/K1.txt" "$(normkey "$BKEY")")" = 0 ] && break
    sleep 5; w=$((w+5))
done
G0=$(grep -ao 'PR generation=0x[0-9a-f]*' "$OUT/K0.txt" | head -1 | cut -d= -f2)
G1=$(grep -ao 'PR generation=0x[0-9a-f]*' "$OUT/K1.txt" | head -1 | cut -d= -f2)
echo "STAGE fence: B's key present=$(key_present "$OUT/K1.txt" "$(normkey "$BKEY")") after ${w}s; PR generation $G0 -> $G1"
if [ "$(key_present "$OUT/K1.txt" "$(normkey "$BKEY")")" != 0 ]; then
    window_into "$OUT/A_nofence.txt" "$A" 30 "$MARK"
    echo "  A never removed B's key inside ${FENCE_BOUND}s; its fence lines:"
    grep -a 'P236-FENCE\|P238-FENCE\|MXFS-MEMBERSHIP' "$OUT/A_nofence.txt" | sed 's/.*mxfs: /    /' | cut -c1-170 | tail -6
    echo "RESULT: VACUOUS label=$LABEL stage=no-fence wall=$(el)s evidence=$OUT"; exit 3
fi
ck "the fence was a real target operation (the PR generation moved)" "$([ "$G0" != "$G1" ] && echo moved || echo same)" moved
window_into "$OUT/A_at_fence.txt" "$A" 20 "$MARK"
echo "    $(grep -a 'P236-FENCEKIND' "$OUT/A_at_fence.txt" | tail -1 | sed 's/.*mxfs: //' | cut -c1-160)"

# ---- 4. B must have noticed NOTHING.  If it has, the lap has measured the
#         path that was already measured and says so rather than grading it.
measure "$B" 60 "$OUT/B_after_fence.txt" '^JOURNAL_END$' "B's journal after the fence" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-600; echo JOURNAL_END"
d1=$(detected_in "$OUT/B_after_fence.txt")
echo "STAGE B's awareness right after the fence: $d1 detection line(s)"
if [ "$d1" != 0 ]; then
    grep -a "$DETECT" "$OUT/B_after_fence.txt" | sed 's/.*: /    /' | cut -c1-170 | head -4
    echo "  B noticed the fence before the reservation disappeared, which is the"
    echo "  ordering tests/fence_crash_cuts.sh already measures.  This lap needs the"
    echo "  victim to stay unaware: check that no workload is running on it."
    echo "RESULT: VACUOUS label=$LABEL stage=early-detect wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 5. destroy the prover; wait for the target to drop the last registration
#         and the reservation with it.  B can still issue PR IN unregistered.
$VIRSH destroy "$A" > /dev/null 2>&1
echo "STAGE destroyed $A at +$(el)s — waiting for the purge (measured 30-46 s, bound ${PURGE_BOUND}s)"
w=0
while [ $w -lt "$PURGE_BOUND" ]; do
    keys_into "$B" "$OUT/K2.txt" "READ KEYS from the victim while waiting for the purge"
    [ "$(resv_none "$OUT/K2.txt")" = yes ] && break
    sleep 5; w=$((w+5))
done
NK=$(grep -acE '^  0x[0-9a-f]+' "$OUT/K2.txt")
echo "STAGE purge: reservation=$(resv_none "$OUT/K2.txt") keys=$NK after ${w}s"
if [ "$(resv_none "$OUT/K2.txt")" != yes ]; then
    echo "  the reservation did not disappear inside ${PURGE_BOUND}s, so the LUN never"
    echo "  became permissive and the ordering was not reached"
    grep -a 'RESV' "$OUT/K2.txt" | sed 's/^/    /' | head -3
    echo "RESULT: VACUOUS label=$LABEL stage=no-purge wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 6. still unaware?
measure "$B" 60 "$OUT/B_after_purge.txt" '^JOURNAL_END$' "B's journal after the purge" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-600; echo JOURNAL_END"
d2=$(detected_in "$OUT/B_after_purge.txt")
echo "STAGE B's awareness after the purge: $d2 detection line(s)"
ck "B has still noticed nothing when the LUN stops refusing (the ordering under test)" "$d2" 0
[ "$d2" = 0 ] || echo "  (the assertions below still run, but they now measure a node that HAS noticed)"

# ---- 7. THE PROBE.  A fenced incarnation writes into an unreserved LUN.
#         Both must fail, and the errno class is kept — rc=1 in 0 s is ENOENT
#         as readily as EIO, and only one of those means the write was refused.
# derived bound: both write arms are a page each to a LUN one hop away, and a
# healthy one answers in single-digit milliseconds; 30 s is two orders of
# magnitude of slack and anything past it is a stall, not a slow disk.
measure "$B" 30 "$OUT/B_probe.txt" '^PROBE_END$' "the fenced incarnation's writes" \
    "echo $PROBE_B64 | base64 -d > /run/lated_probe.py; python3 /run/lated_probe.py $MNT/lated_$LABEL DATA DIRECT"
# THE DECISIVE READ.  Whatever the return codes said, this is the block itself,
# read off the LUN with O_DIRECT and no filesystem in the path.
measure "$B" 40 "$OUT/B_platter1.txt" '^PLATTER_END$' "the probe block on the LUN after the fenced incarnation wrote" \
    "dd if=$MXFS_DEV bs=4096 skip=$((PHYS / 4096)) count=1 iflag=direct 2>/dev/null | head -c 64 | od -c | head -3; echo PLATTER_END"
LANDED=$(grep -ac 'f   e   n   c   e   d' "$OUT/B_platter1.txt")
echo "STAGE the platter after the probe: $(grep -a '0000000' "$OUT/B_platter1.txt" | head -1 | cut -c1-120)"
ck "the fenced incarnation's bytes did NOT reach the LUN" "$LANDED" 0

# The metadata arm runs separately and SOFT.  A create that never returns is a
# finding in its own right — with the peer gone and the detector held off there
# is nothing left to end its wait — but it must not take the lap down with it,
# so the timeout is recorded and the lap continues to the read that matters.
# Bound: the DLM gives a lock 60 membership-change retries, observed to end in
# -117 about 130 s after the peer went away; 2x that is 260.
rsx 260 "$B" "python3 /run/lated_probe.py $MNT/lated_$LABEL META" > "$OUT/B_probe_meta.txt" 2>&1
mrc=$?
grep -a '^PROBE_META' "$OUT/B_probe_meta.txt" >> "$OUT/B_probe.txt" 2>/dev/null
[ $mrc = 0 ] || echo "PROBE_META rc=STALLED err=no-answer-in-260s ms=260000" >> "$OUT/B_probe.txt"

PD=$(grep -a '^PROBE_DATA' "$OUT/B_probe.txt" | head -1)
PM=$(grep -a '^PROBE_META' "$OUT/B_probe.txt" | head -1)
PX=$(grep -a '^PROBE_DIRECT' "$OUT/B_probe.txt" | head -1)
echo "STAGE probe: $PD | $PM | $PX"
ck "a buffered data write from the fenced incarnation is REFUSED" "$(echo "$PD" | grep -ao 'rc=[0-9]*' | cut -d= -f2)" 1
# STALLED is not REFUSED and must not be scored as either a pass or an empty
# verdict: a create still waiting after its whole bound was neither let through
# nor turned away, and the lap says so in those words.
PMRC=$(echo "$PM" | grep -aoE 'rc=[A-Za-z0-9]+' | head -1 | cut -d= -f2)
ck "a metadata create from the fenced incarnation is REFUSED" "$PMRC" 1
ck "an O_DIRECT write from the fenced incarnation is REFUSED" "$(echo "$PX" | grep -ao 'rc=[0-9]*' | cut -d= -f2)" 1
# WHAT refused them has to be the local lease and nothing else, or the lap has
# re-measured the detection path it was built to bypass.
measure "$B" 60 "$OUT/B_final_probe.txt" '^JOURNAL_END$' "what refused the fenced incarnation's writes" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-600; echo JOURNAL_END"
ckge "the local authority lease CLOSED this node's authority" "$(closed_in "$OUT/B_final_probe.txt")" 1
ck "it closed because the lease expired, not because something told it" \
    "$(grep -a 'P290-AUTH-CLOSED' "$OUT/B_final_probe.txt" | head -1 | grep -ao 'reason=[A-Z_]*' | cut -d= -f2)" AUTHORITY_LEASE_EXPIRED
ck "no LUN-dependent detector fired at any point in this lap" "$(detected_in "$OUT/B_final_probe.txt")" 0
echo "    $(grep -a 'P290-AUTH-CLOSED' "$OUT/B_final_probe.txt" | head -1 | sed 's/.*mxfs: //' | cut -c1-200)"
grep -a 'P290-AUTH-REFUSED' "$OUT/B_final_probe.txt" | sed 's/.*mxfs: /    /' | cut -c1-170 | head -4
# whether the proactive detector was still held off WHILE the probe ran is the
# difference between "the gate refused it" and "a detector woke up and shut the
# filesystem down underneath it"; record it either way
measure "$B" 30 "$OUT/B_pause_state.txt" '^PAUSEEND=[0-9]+ WITHDRAW=[0-9]+$' "whether B's detector resumed during the probe" \
    "echo PAUSEEND=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P-DBG-RESV-HEALTH-PAUSE-END') WITHDRAW=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ac 'P277-FENCED-SELF-WITHDRAW')"
echo "STAGE during the probe: detector resumed=$(field "$OUT/B_pause_state.txt" PAUSEEND) withdrawals=$(field "$OUT/B_pause_state.txt" WITHDRAW)"

# ---- 8. what refused them (or what did not)
measure "$B" 60 "$OUT/B_final.txt" '^JOURNAL_END$' "B's journal after the probe" \
    "dmesg | sed -n '/$MARK/,\$p' | cut -c1-600; echo JOURNAL_END"
echo "STAGE B's journal after the probe: $(detected_in "$OUT/B_final.txt") detection line(s)"
grep -a "$DETECT" "$OUT/B_final.txt" | sed 's/.*: /    /' | cut -c1-170 | head -5
ck "B: zero shutdown / BUG / Oops" "$(bad_lines "$OUT/B_final.txt")" 0
dump_into "$B" "$OUT/hb_final.txt" "the disklock table at the end"
echo "STAGE table at the end: $(cnt "$OUT/hb_final.txt" '^slot') record(s)"

# POWER-CYCLE THE VICTIM TOO, once every capture is banked.  Its heartbeat
# thread is parked inside an injected sleep that no knob can shorten, and a
# park that outlives the lap stalls the NEXT lap's prep on an unmount waiting
# for a sleeping thread — measured: lap s87i spent its whole 300 s prep budget
# on "test2 did not release mxfs" and ended up power-cycling the node anyway,
# 300 s later.  B is fenced, withdrawn and about to be re-mkfs'd; there is
# nothing here to preserve and nothing to learn from letting the injection
# time out on its own.
$VIRSH destroy "$B" > /dev/null 2>&1
$VIRSH start "$A" > /dev/null 2>&1
$VIRSH start "$B" > /dev/null 2>&1
echo "STAGE restarted $A and $B; the fleet needs prep_cluster before the next lap"
echo "RESULT: $( [ $fails = 0 ] && echo PASS || echo FAIL ) label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"
[ $fails = 0 ]
