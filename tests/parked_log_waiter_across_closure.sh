#!/bin/bash
# tests/parked_log_waiter_across_closure.sh — does closing a mount's authority
# free a task that was ALREADY PARKED in a log wait when the closure happened,
# and does that freeing depend on the withdrawal pump?
#
# WHAT IS BEING MEASURED, AND WHY IT IS NOT COVERED BY ANYTHING ELSE.
# The record this lap belongs to established, by reading, that nothing in the
# journal consults the authority.  xlog_grant_head_wait (xfs/xfs_log.c:233-290)
# sets TASK_UNINTERRUPTIBLE and schedule()s, and its only two exits are
# xlog_is_shutdown(log) and enough grant space becoming available — no timeout,
# no signal, no authority test.  So a closure reaches a task parked there by
# exactly one route:
#
#     the lease expires
#       -> SOME caller asks mxfs_authority_ok (dlm/disklock.c:2460), which
#          CASes ADMITTED->CLOSED itself and raises withdraw_pending
#       -> v5_authority_withdraw_pump (dlm/v5_mount.c:11542) takes that
#          withdrawal on the PR worker's 250 ms tick
#       -> fence_notify -> mxfs_dlm_fence_notify (xfs/xfs_mxfs_dlm.c:59131)
#       -> xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR)
#       -> xlog_is_shutdown() is finally true and the parked task is woken.
#
# The pump is the SOLE consumer of that closure, and its own comment argues it
# is not load-bearing: "If this worker is stalled too, every mutating
# submission still refuses on its own; all that is lost is the promptness of
# the withdrawal."  That argument does not cover a task already parked.  It is
# not being refused.  It is asleep, and only the shutdown wakes it.  This lap
# exists to turn that sentence from an assertion into a measurement.
#
# THE TWO ARMS, ON ONE BUILD.  PUMP_HOLD_MS selects them and nothing else
# differs, so the comparison carries no other explanation:
#   PUMP_HOLD_MS=0        CONTROL.  The pump runs.  The closure must reach the
#                         shutdown and the parked task must be freed, and the
#                         interval from the close to its return is the number
#                         the record asked for.
#   PUMP_HOLD_MS=<ms>     THE SUBJECT.  mxfs.dbg_auth_withdraw_pause_ms holds off
#                         the withdrawal pump ALONE (dlm/v5_mount.c, the PR
#                         worker's periodic half): the gate is still asked on
#                         every tick exactly as in production, so the closure
#                         lands at the deadline, and what is withheld is the
#                         one thing that converts it into the shutdown.
#                         Prediction: P290-AUTH-CLOSED on time, no withdrawal,
#                         and the parked task still parked when the window
#                         ends.  That is the defect, and a FAIL here is the
#                         finding.
#                         (Until 0.89.66 this lap used dbg_auth_pump_pause_ms,
#                         which skips the gate call as well, and with every
#                         writer parked in the very log wait this lap creates
#                         nothing else asked the gate: s132c, s133b and s140d
#                         all read no-closure.  That knob measures the wrong
#                         absence here and still serves the laps that need a
#                         fenced node kept blind; this one is its complement.)
#
# HOW A TASK IS PUT IN A LOG WAIT ON PURPOSE.  mxfs.dbg_ail_pin_ino names one
# inode item xfsaild must never flush, so the log tail sticks at that item's
# LSN while the head keeps moving.  Once the head laps the pinned tail there is
# no grant space left and the next reservation parks in xlog_grant_head_wait.
# The same knob is how tests/tcp_death_replay.sh reaches a 53-checkpoint replay,
# so the mechanism is already measured on this rig.
#
# WHO ASKS THE GATE WHILE THE WRITER IS PARKED.  Since 0.89.66 the PR worker's
# periodic evaluation does, in both arms — the hold no longer covers it.  The
# paragraphs below record how the earlier knob shape made the subject arm
# unmeasurable, because the poker they describe is still run and still dates
# the closure when it can.
#
# The mount is not idle: the tail is pinned precisely BECAUSE the AIL is full,
# so xfsaild is pushing it, and every metadata buffer it submits goes through
# the 'meta' arm of mxfs_mount_write_admitted (pal/linux/xfs_buf.c:9794).  That
# is what discovers the expiry, and the module's own P290-AUTH-CLOSED is the
# evidence the verdict rests on.
#
# THAT PARAGRAPH IS AN ARGUMENT, AND s132c MEASURED IT FALSE.  With the pump
# held, the victim logged ZERO P290-AUTH-CLOSED across a 120 s window that
# began well after the lease had to expire, while xfsaild logged only two holds
# on the pinned item.  So on this arm nothing asked the gate at all: the AIL
# push has nothing left to submit once every item behind the pinned tail is
# already written, and the one caller that was supposed to keep asking - the
# poker - may have parked in the very log wait the lap creates, because an
# O_DIRECT overwrite still takes a timestamp-update reservation.  The lap
# cannot tell those apart by counting refusals, because BOTH produce an empty
# errno list, so the window now carries the poker's completed-write count
# either side of the lease deadline AND the poker's own kernel stack.  If the
# next run shows the poker parked, this lap needs a gate caller that takes no
# log reservation at all before its subject arm can mean anything; if it shows
# the poker still completing writes past the deadline, the answer is already in
# hand and it is a FAIL of this record, not a vacuous lap.
#
# A second process on the victim issues O_DIRECT writes into a file that was
# fully allocated and synced BEFORE the tail was pinned, through the 'dio' arm
# (pal/linux/xfs_file.c:1275), and its first EIO DATES the closure to the
# second.  It is corroboration, never the requirement: an O_DIRECT overwrite
# still takes a timestamp-update transaction, so the poker can itself end up in
# the same log wait as the filler, and a lap must not be scored vacuous for
# that.  Its health IS asserted while the mount is still healthy, so that a
# poker which never worked at all can never be read as a poker the gate
# refused.
#
# THE VICTIM IS ALWAYS RECYCLED.  A task in xlog_grant_head_wait is
# uninterruptible: on the arm where it is still parked, SIGKILL cannot end it
# and the node would carry an unkillable task into the next lap's prep.  Every
# capture is taken before the recycle, so the domain carries no evidence.
#
# BOUND.  boot-wait 200 + prep 150 (measured 72-137) + identity 30 + setup 60 +
#   fill-until-parked 240 + park and lease expiry 45 + observation 120 +
#   captures 40 + cleanup 60 = 945.  Caller bound 950 s.
#
# Usage: tests/parked_log_waiter_across_closure.sh <label>
# Env:   MXFS_NODE_LIST (default test1,test2), PUMP_HOLD_MS (0),
#        PARK_MS (240000), OBSERVE (120), FILL_MAX (240)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
V=${MXFS_NODE_LIST%%,*}          # the victim: its writer parks, its lease dies
P=${MXFS_NODE_LIST##*,}          # the peer: it only keeps the cluster real
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
PARM=/sys/module/mxfs/parameters
# The park must outlast the whole observation: if the heartbeat resumes, the
# renew path closes authority on its own schedule and the arms stop differing.
PARK_MS=${PARK_MS:-240000}
OBSERVE=${OBSERVE:-120}
FILL_MAX=${FILL_MAX:-240}
PUMP_HOLD_MS=${PUMP_HOLD_MS:-0}
POKE_MB=${POKE_MB:-16}
# THE INSTANT AFTER WHICH A COMPLETED POKE IS A WRITE ADMITTED UNDER AN EXPIRED
# LEASE.  The authority lease is 30 s from the last LANDED beat
# (MXFS_DISKLOCK_AUTH_LEASE_MS; a lap's own P290-AUTH-CLOSED line shows it as
# deadline_ms - last_ok_ms = 30000 exactly).  The observation window opens
# AFTER the park has been confirmed, and that confirmation costs at most one
# heartbeat cadence (2 s) plus the 12 s the park poll is allowed, so the last
# landed beat is at most 14 s before the window opens and the lease cannot
# expire before window + 16 s — but it MUST have expired by window + 30 s.
# 35 s is that upper bound with a cadence of margin, so a poke completing after
# it was admitted under a lease that had certainly expired.  It is not a
# tolerance to widen: raising it only discards evidence, and lowering it below
# 30 would count legitimately-admitted writes as violations.
LEASE_SAFE_S=${LEASE_SAFE_S:-35}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_plwait_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="PLW-MARK-$LABEL"
# THE SECOND MARK MUST NOT CONTAIN THE FIRST.  window_into scopes the capture
# with `sed -n "/$MARK/,$p"` and then guards it with `grep -F "$MARK"` — a guard
# whose entire purpose is to catch a mark that was never written or whose ring
# has wrapped.  While the park mark was spelled as the window mark with a
# "-PARK" suffix glued on, it CONTAINED the
# window mark, so the guard matched the park line and passed even when the real
# mark was gone, and the window silently opened at the park instead of at the
# arm.  Measured s133b (2026-09-21): the window's first line was
# `PLW-MARK-s133b-PARK` at ring 250.9, fifty-five seconds after the arm, so the
# pump-hold injector's own confirmation line fell outside it, read zero, and the
# lap graded a window it had already lost as a measurement of MXFS.
PMARK="PLWPARK-$LABEL"
D=$MNT/plw_$LABEL
ARM=$([ "$PUMP_HOLD_MS" = 0 ] && echo control-pump-runs || echo subject-pump-held)
echo "=== parked_log_waiter_across_closure label=$LABEL arm=$ARM victim=$V peer=$P park=${PARK_MS}ms observe=${OBSERVE}s $(date -u +%FT%TZ) ==="
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
vac() { echo "  VACUOUS $1"; echo "RESULT: VACUOUS label=$LABEL arm=$ARM reason=$2 evidence=$OUT wall=$(el)s"; exit 3; }
# a field is read wherever it sits on the line, not only at its start: an arm
# printing "SEEN=1 PAUSED=1" had its second field read as an empty string under
# an anchored match, which aborted healthy laps elsewhere in this directory.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# Every knob this lap arms and both helpers it starts are undone on every path
# out, including an abort.  The victim is recycled unconditionally: its mount
# has been force-shut-down by the time this runs on the healthy path, and on
# the arm the lap is for it holds a task nothing can kill.
CLEANED=0
cleanup() {
    local rc=$?
    [ "$CLEANED" = 1 ] && return $rc
    CLEANED=1
    rs 20 "$P" "for k in dbg_ail_pin_ino dl_inject_hb_pause_ms dbg_auth_withdraw_pause_ms; do [ -w $PARM/\$k ] && echo 0 > $PARM/\$k; done; true" >/dev/null 2>&1 || true
    $VIRSH destroy "$V" >/dev/null 2>&1
    sleep 3
    $VIRSH start "$V" >/dev/null 2>&1
    echo "STAGE cleanup: $V recycled (its knobs and its parked task go with the boot); the caller must prep_cluster before the next lap at +$(el)s"
    return $rc
}
trap cleanup EXIT

# ---- 0. the fleet on the tree build
[ -f mxfs.ko ] || { echo "ABORT: no mxfs.ko in the tree (build it first)"; echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 40 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
waitboot "$V" "$P"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$V" "$P"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }

# Every knob this lap needs has to be writable BEFORE anything is staged: a
# missing one would otherwise be discovered as a silent no-op half way through
# and read as "the module did not do it".
value_now_into kn "$V" 20 "$OUT/V_knobs.txt" '^KNOBS=[01]{3}$' "the three knobs on $V" \
    "echo KNOBS=\$(for k in dbg_ail_pin_ino dl_inject_hb_pause_ms dbg_auth_withdraw_pause_ms; do test -w $PARM/\$k && printf 1 || printf 0; done)"
[ "$kn" = "KNOBS=111" ] || { echo "ABORT: $V does not carry all three knobs writable ($kn)"; echo "RESULT: ABORT label=$LABEL stage=knobs evidence=$OUT"; exit 2; }

# ---- 1. identity
value_now_into cl "$V" 30 "$OUT/V_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $V" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
VSLOT=${cl##* }
[ -n "$VSLOT" ] || { echo "ABORT: could not read $V's slot"; echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2; }
echo "STAGE identities: victim $V slot $VSLOT at +$(el)s"

# ---- 2. the two files the measurement needs, BOTH fully allocated and synced
#         BEFORE the tail is pinned.  'pin' is the inode xfsaild will be told
#         never to flush; 'poke' is the O_DIRECT target whose writes must need
#         no transaction, which is only true once its extents exist.
measure "$V" 120 "$OUT/V_setup.txt" '^SETUP_OK ' "the pin and poke files on $V" \
    "mkdir -p $D && dd if=/dev/zero of=$D/poke bs=1M count=$POKE_MB status=none oflag=direct && : > $D/pin && sync -f $D && echo SETUP_OK pin_ino=\$(stat -c %i $D/pin) poke_blocks=\$(stat -c %b $D/poke)"
PINO=$(field "$OUT/V_setup.txt" pin_ino)
PBLK=$(field "$OUT/V_setup.txt" poke_blocks)
case "${PINO:-}" in ''|*[!0-9]*) echo "ABORT: no pin inode number (setup='$(tr '\n' ' ' < "$OUT/V_setup.txt" | cut -c1-160)')"; echo "RESULT: ABORT label=$LABEL stage=setup evidence=$OUT"; exit 2;; esac
[ "${PBLK:-0}" -gt 0 ] || { echo "ABORT: the poke file has no allocated blocks, so its O_DIRECT writes would take a transaction and could park in the log themselves"; echo "RESULT: ABORT label=$LABEL stage=setup evidence=$OUT"; exit 2; }
echo "STAGE setup: pin inode $PINO, poke file $POKE_MB MiB in $PBLK 512-byte blocks at +$(el)s"

# ---- 3. mark the ring, arm the withdrawal hold FIRST (so the pump is
#         already off before anything can expire), then pin the tail.
# THE VICTIM'S RING IS FOLLOWED INTO A FILE FROM THE MARK ON.  The filler's
# transactions log enough between here and the end-of-lap window that the
# 1 MiB ring no longer reached back to the mark on s138e and s138f, and both
# laps ABORTed at the window read with the observation already made.  The
# follower dumps the ring (mark included) and then appends every later line,
# so the window at step 8 is read from the file and cannot lose its mark to a
# wrap.  The peer's mark stays in its ring: nothing windows the peer.
KMSGF=/run/plw_kmsg_$LABEL.txt
kmsg_follow_start "$V" "$MARK" "$KMSGF"
rs 15 "$P" "echo $MARK > /dev/kmsg" >/dev/null 2>&1
if [ "$PUMP_HOLD_MS" != 0 ]; then
    value_now_into ph "$V" 20 "$OUT/V_pumphold.txt" "^$PUMP_HOLD_MS\$" "dbg_auth_withdraw_pause_ms after arming on $V" "echo $PUMP_HOLD_MS > $PARM/dbg_auth_withdraw_pause_ms; cat $PARM/dbg_auth_withdraw_pause_ms"
    echo "STAGE dbg_auth_withdraw_pause_ms=$ph armed on $V at +$(el)s"
    # THE INJECTOR'S OWN LINE IS READ NOW, NOT THREE MINUTES LATER.  The knob
    # reading back is the value being stored, not the pump having taken it, and
    # the pump's tick is 250 ms, so its P-DBG-AUTH-WITHDRAW-PAUSE lands within a
    # couple of seconds of this write or not at all.  It used to be counted only
    # from the end-of-lap window, which meant the confirmation had to survive
    # the filler's entire log volume in the victim's ring; on s133b it did not,
    # the count read 0, and the subject arm failed its own arming assertion for
    # a reason that had nothing to do with the pump.  A bound of 20 s is the
    # 250 ms tick with two orders of margin, and its failure is an ABORT and not
    # a verdict: an arm that cannot show it armed has measured nothing.
    wait_for_into pumparm "$V" 20 "$MARK" 'P-DBG-AUTH-WITHDRAW-PAUSE'
    if [ "$pumparm" = timeout ]; then
        echo "ABORT: dbg_auth_withdraw_pause_ms reads back $ph on $V but the module never logged P-DBG-AUTH-WITHDRAW-PAUSE within 20 s, so the pump's periodic evaluation is NOT known to be held off and the subject arm has no arming"
        echo "RESULT: ABORT label=$LABEL arm=$ARM stage=pump-arm evidence=$OUT"; exit 2
    fi
    echo "STAGE the withdrawal pump is confirmed held off, with the lease still evaluated every tick (P-DBG-AUTH-WITHDRAW-PAUSE after ${pumparm}s) at +$(el)s"
fi
value_now_into pn "$V" 20 "$OUT/V_pin.txt" "^$PINO\$" "dbg_ail_pin_ino after arming on $V" "echo $PINO > $PARM/dbg_ail_pin_ino; cat $PARM/dbg_ail_pin_ino"
echo "STAGE dbg_ail_pin_ino=$pn armed on $V at +$(el)s"

# ---- 4. dirty the pinned inode so it is IN the AIL (the knob keeps an item
#         there; it cannot put one there), then start the filler.  The filler
#         prints one line per completed transaction to tmpfs — never to the
#         mount under test, whose writes are the thing being stopped.
FILLER=$(base64 -w0 <<'PY'
import os, sys, time
d, log, pin = sys.argv[1], sys.argv[2], sys.argv[3]
with open(log, "w") as f:
    f.write("FILLER_PID %d\n" % os.getpid()); f.flush()
    # touch the pinned inode inside a transaction so it enters the AIL
    fd = os.open(pin, os.O_WRONLY)
    os.write(fd, b"x"); os.fsync(fd); os.close(fd)
    f.write("PINNED_DIRTY\n"); f.flush()
    i = 0
    while True:
        p = os.path.join(d, "fill%d" % i)
        try:
            fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o600)
            os.write(fd, b"\0" * 65536)
            os.fsync(fd)
            os.close(fd)
            if i >= 16:
                try: os.unlink(os.path.join(d, "fill%d" % (i - 16)))
                except OSError: pass
        except OSError as e:
            f.write("FILL_ERR %d errno=%d\n" % (i, e.errno)); f.flush()
            time.sleep(0.5)
        f.write("F %d %.3f\n" % (i, time.time())); f.flush()
        i += 1
PY
)
# O_DIRECT requires a memory-aligned buffer.  A plain bytes object is not
# guaranteed to be, and an unaligned one fails EINVAL — which would look
# exactly like the gate refusing and would date the closure at zero seconds on
# every lap.  mmap(-1, ...) is page-aligned by construction, and the errno is
# read rather than the failure counted, so EIO (the gate) can never be confused
# with EINVAL (this harness's own bug).
POKER=$(base64 -w0 <<'PY'
import os, sys, time, mmap
poke, log = sys.argv[1], sys.argv[2]
mm = mmap.mmap(-1, 4096)
mm.write(b"\0" * 4096)
with open(log, "w") as f:
    f.write("POKER_PID %d\n" % os.getpid()); f.flush()
    n = 0
    while True:
        try:
            fd = os.open(poke, os.O_WRONLY | os.O_DIRECT)
            try:
                os.pwrite(fd, mm, 0)
            finally:
                os.close(fd)
            f.write("P ok %d %.3f\n" % (n, time.time()))
        except OSError as e:
            f.write("P err %d errno=%d %.3f\n" % (n, e.errno, time.time()))
        f.flush()
        n += 1
        time.sleep(0.5)
PY
)
rs 40 "$V" "echo $FILLER | base64 -d > /run/plw_fill.py; echo $POKER | base64 -d > /run/plw_poke.py; nohup python3 /run/plw_fill.py $D /run/plw_fill.txt $D/pin > /dev/null 2>&1 & echo \$! > /run/plw_fill.pid; nohup python3 /run/plw_poke.py $D/poke /run/plw_poke.txt > /dev/null 2>&1 & echo \$! > /run/plw_poke.pid; sleep 3; echo STARTED fill=\$(cat /run/plw_fill.pid) poke=\$(cat /run/plw_poke.pid)" > "$OUT/V_start.txt" 2>/dev/null
capture_require "$OUT/V_start.txt" '^STARTED ' "the filler and poker starting on $V"
FPID=$(grep -ao 'fill=[0-9]*' "$OUT/V_start.txt" | head -1 | cut -d= -f2)
case "${FPID:-}" in ''|*[!0-9]*) echo "ABORT: the filler did not report a pid"; echo "RESULT: ABORT label=$LABEL stage=start evidence=$OUT"; exit 2;; esac
# THE POKER MUST WORK BEFORE IT IS TRUSTED TO FAIL.  Its later EIO is what
# dates the closure, so a poker that cannot write at all — a misaligned
# O_DIRECT buffer, a file with no extents — would date every closure at zero
# and the arms would stop differing for a reason that is this harness's.
measure "$V" 30 "$OUT/V_poke_ok.txt" '^POKE_BASE ' "the poker's own health on $V" \
    "echo POKE_BASE ok=\$(grep -ac '^P ok ' /run/plw_poke.txt) err=\$(grep -ac '^P err ' /run/plw_poke.txt) first_err=\"\$(grep -a '^P err ' /run/plw_poke.txt | head -1)\""
POK=$(grep -ao 'ok=[0-9]*' "$OUT/V_poke_ok.txt" | head -1 | cut -d= -f2)
PERR=$(grep -ao ' err=[0-9]*' "$OUT/V_poke_ok.txt" | head -1 | cut -d= -f2)
[ "${POK:-0}" -ge 1 ] || { echo "ABORT: the poker never completed an O_DIRECT write while the mount was healthy ($(tr '\n' ' ' < "$OUT/V_poke_ok.txt" | cut -c1-200)) — its later refusals would say nothing about the authority gate"; echo "RESULT: ABORT label=$LABEL stage=poker evidence=$OUT"; exit 2; }
[ "${PERR:-0}" = 0 ] || { echo "ABORT: the poker is already failing before anything was injected: $(grep -a 'first_err' "$OUT/V_poke_ok.txt" | cut -c1-200)"; echo "RESULT: ABORT label=$LABEL stage=poker evidence=$OUT"; exit 2; }
echo "STAGE filler pid=$FPID parked-subject, poker healthy ($POK O_DIRECT writes, 0 errors) at +$(el)s"

# ---- 5. wait for the filler to STOP making progress and confirm, from its own
#         kernel stack, that it stopped in the log wait and nowhere else.  A
#         filler that merely slowed down, or that parked in some other wait,
#         measures nothing this record is about.
rs $((FILL_MAX + 60)) "$V" "
last=''; still=0
for i in \$(seq 1 $FILL_MAX); do
    now=\$( (grep -ac '^F ' /run/plw_fill.txt 2>/dev/null || echo 0) | tail -1 )
    if [ \"\$now\" = \"\$last\" ]; then still=\$((still+1)); else still=0; fi
    last=\$now
    [ \$still -ge 12 ] && break
    sleep 1
done
echo FILL_COUNT=\$last STILL_S=\$still
echo STACK_BEGIN
cat /proc/$FPID/stack 2>/dev/null
echo STACK_END
echo PARKED_END" > "$OUT/V_parked.txt" 2>/dev/null
capture_require "$OUT/V_parked.txt" '^PARKED_END$' "the filler's park probe on $V"
FCOUNT=$(grep -ao 'FILL_COUNT=[0-9]*' "$OUT/V_parked.txt" | head -1 | cut -d= -f2)
STILL=$(grep -ao 'STILL_S=[0-9]*' "$OUT/V_parked.txt" | head -1 | cut -d= -f2)
echo "STAGE filler stopped after $FCOUNT transactions, unchanged for ${STILL}s at +$(el)s; its stack:"
sed -n '/^STACK_BEGIN/,/^STACK_END/p' "$OUT/V_parked.txt" | grep -a '\[' | head -12 | sed 's/^/    /'
[ "${STILL:-0}" -ge 12 ] || vac "the filler never stopped making progress within ${FILL_MAX}s, so nothing was ever parked in a log wait (count=$FCOUNT)" never-parked
grep -qa 'xlog_grant_head_wait' "$OUT/V_parked.txt" || vac "the filler stopped, but not in xlog_grant_head_wait — this lap only speaks about the log grant wait, and a park anywhere else is a different question" wrong-wait
echo "STAGE the filler is parked in xlog_grant_head_wait at +$(el)s — the subject exists"

# ---- 6. park the victim's heartbeat so its own authority lease expires.  The
#         park is confirmed from the module's own line, not from the write
#         returning: a beat already in flight can otherwise satisfy the test.
#         THE CONFIRMATION IS POLLED, IT CARRIES ITS OWN ANCHOR, AND IT SAYS
#         WHICH WAY IT FAILED.  The first version slept 4 s and then counted
#         the line in a window anchored on the mark this lap emits at its
#         start; it read 0 on BOTH arms of the s131 queue while the subject
#         itself was produced correctly (the filler parked in
#         xlog_grant_head_wait, stack captured), so two laps were thrown away
#         with nothing to tell them apart.  Three things can make that read 0:
#
#           * the knob is taken at the TOP of the heartbeat loop, so the line
#             lands up to one cadence (MXFS_DISKLOCK_HB_INTERVAL_MS, 2000 ms)
#             plus one 64-slot monitor pass after the write returns — and this
#             lap has deliberately saturated the very LUN that pass reads;
#           * the start-of-lap anchor is by now 100+ s and ~8000 transactions
#             old and can have left the kernel ring entirely, which empties
#             the window and counts 0 for a line that is present;
#           * the heartbeat thread is genuinely not running.
#
#         So the probe writes a FRESH anchor immediately before arming, polls
#         until the line lands instead of sleeping, and reports the anchor's
#         own presence, the unanchored tail count, and the knob's value.  The
#         knob is one-shot and cleared by the thread that takes it, so
#         KNOB_NOW discriminates the cases outright: 0 means the thread took
#         it and any zero count is the window's fault, non-zero means the
#         thread never reached the top of its loop.
#
#         THE POLL'S BOUND.  Six cadences, 12 s: the arming is consumed one
#         cadence after the write in the healthy case, and the module's own
#         standard for a heartbeat that has stopped is 31 missed beats
#         (MXFS_DISKLOCK_DEAD_THRESHOLD, 62 s), so 12 s is a fifth of the
#         interval the cluster itself treats as alive.  A beat that has not
#         come round inside it is a stalled heartbeat thread — a finding of
#         its own, which the probe now names — not an arming to wait longer
#         for.
T_PARK=$(date +%s)
rs 15 "$V" "echo $PMARK > /dev/kmsg" >/dev/null 2>&1
measure "$V" 45 "$OUT/V_park.txt" '^PARK_PROBE_END$' "the heartbeat park on $V" \
    "echo $PARK_MS > $PARM/dl_inject_hb_pause_ms
n=0
for i in \$(seq 1 12); do
    n=\$(dmesg | sed -n '/$PMARK/,\$p' | grep -ac 'P-HB-INJECT-PAUSE.*pausing')
    [ \"\$n\" != 0 ] && break
    sleep 1
done
echo PAUSE_SEEN=\$n
echo ANCHOR_SEEN=\$(dmesg | grep -ac '$PMARK')
echo PAUSE_TAIL=\$(dmesg | tail -400 | grep -ac 'P-HB-INJECT-PAUSE.*pausing')
echo KNOB_NOW=\$(cat $PARM/dl_inject_hb_pause_ms)
echo PARK_PROBE_END"
PSEEN=$(field "$OUT/V_park.txt" PAUSE_SEEN)
echo "STAGE the heartbeat park on $V: $(grep -a '^PAUSE_SEEN=\|^ANCHOR_SEEN=\|^PAUSE_TAIL=\|^KNOB_NOW=' "$OUT/V_park.txt" | tr '\n' ' ')at +$(el)s"
ck "$V's heartbeat thread parked (P-HB-INJECT-PAUSE)" "${PSEEN:-0}" 1
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=park evidence=$OUT"; exit 2; }
echo "STAGE $V's heartbeat parked ${PARK_MS}ms at +$(el)s; its 30 s authority lease expires from its last landed beat"

# ---- 7. the observation.  Two questions, read from two independent places:
#         did the AUTHORITY close (the poker's first EIO and the module's own
#         line), and did the PARKED filler come back (its own progress count
#         moving again, or the pid going away)?
#
#         AND IT READS THE POKER'S PROGRESS, NOT ONLY ITS FAILURES.  The s132c
#         arm read POKE_ERRNOS empty and called that "no closure" — but an
#         empty errno list is produced by two opposite states: a poker that was
#         itself parked and issued nothing, and a poker whose O_DIRECT writes
#         were STILL BEING ADMITTED 120 s after the lease it holds had expired.
#         The second is the direct refutation of the argument the withdrawal
#         pump is documented as resting on (that every mutating submission
#         refuses on its own), so it may not be left indistinguishable from the
#         first.  The window therefore carries the poker's ok/err DELTAS and
#         its kernel stack, and the filler's own transaction errors, which is
#         what says why the filler came back.
rs $((OBSERVE + 90)) "$V" "
t0=\$(date +%s)
base=\$( (grep -ac '^F ' /run/plw_fill.txt 2>/dev/null || echo 0) | tail -1 )
pok0=\$( (grep -ac '^P ok ' /run/plw_poke.txt 2>/dev/null || echo 0) | tail -1 )
perr0=\$( (grep -ac '^P err ' /run/plw_poke.txt 2>/dev/null || echo 0) | tail -1 )
ferr0=\$( (grep -ac '^FILL_ERR ' /run/plw_fill.txt 2>/dev/null || echo 0) | tail -1 )
closed=0; freed=0
for i in \$(seq 1 $OBSERVE); do
    if [ \$closed = 0 ] && grep -qa '^P err .*errno=5 ' /run/plw_poke.txt 2>/dev/null; then
        closed=\$(( \$(date +%s) - t0 ))
        [ \$closed = 0 ] && closed=-1
    fi
    now=\$( (grep -ac '^F ' /run/plw_fill.txt 2>/dev/null || echo 0) | tail -1 )
    if [ \$freed = 0 ] && { [ \"\$now\" != \"\$base\" ] || [ ! -d /proc/$FPID ]; }; then
        freed=\$(( \$(date +%s) - t0 ))
        [ \$freed = 0 ] && freed=-1
        break
    fi
    sleep 1
done
echo OBS closed_s=\$closed freed_s=\$freed base=\$base now=\$( (grep -ac '^F ' /run/plw_fill.txt 2>/dev/null || echo 0) | tail -1 ) alive=\$([ -d /proc/$FPID ] && echo 1 || echo 0)
echo POKE_FIRST_ERR=\"\$(grep -a '^P err ' /run/plw_poke.txt 2>/dev/null | head -1)\" POKE_ERRNOS=\"\$(grep -ao 'errno=[0-9]*' /run/plw_poke.txt 2>/dev/null | sort -u | tr '\n' ',')\"
echo POKE_WINDOW ok_delta=\$(( \$( (grep -ac '^P ok ' /run/plw_poke.txt 2>/dev/null || echo 0) | tail -1 ) - pok0 )) err_delta=\$(( \$( (grep -ac '^P err ' /run/plw_poke.txt 2>/dev/null || echo 0) | tail -1 ) - perr0 ))
tl=\$(( t0 + $LEASE_SAFE_S ))
echo POKE_POST after=\$tl ok=\$(awk -v t=\$tl '\$1==\"P\" && \$2==\"ok\" && \$4+0 > t' /run/plw_poke.txt 2>/dev/null | wc -l) err=\$(awk -v t=\$tl '\$1==\"P\" && \$2==\"err\" && \$5+0 > t' /run/plw_poke.txt 2>/dev/null | wc -l)
echo FILL_WINDOW err_delta=\$(( \$( (grep -ac '^FILL_ERR ' /run/plw_fill.txt 2>/dev/null || echo 0) | tail -1 ) - ferr0 )) first=\"\$(grep -a '^FILL_ERR ' /run/plw_fill.txt 2>/dev/null | tail -n +\$(( ferr0 + 1 )) | head -1)\"
echo STACK_BEGIN
cat /proc/$FPID/stack 2>/dev/null
echo STACK_END
echo PSTACK_BEGIN
cat /proc/\$(cat /run/plw_poke.pid 2>/dev/null)/stack 2>/dev/null
echo PSTACK_END
echo OBS_END" > "$OUT/V_observe.txt" 2>/dev/null
capture_require "$OUT/V_observe.txt" '^OBS_END$' "the observation on $V"
CLOSED=$(grep -ao 'closed_s=-\?[0-9]*' "$OUT/V_observe.txt" | head -1 | cut -d= -f2)
FREED=$(grep -ao 'freed_s=-\?[0-9]*' "$OUT/V_observe.txt" | head -1 | cut -d= -f2)
ALIVE=$(grep -ao 'alive=[01]' "$OUT/V_observe.txt" | head -1 | cut -d= -f2)
POKOK=$(grep -a '^POKE_WINDOW ' "$OUT/V_observe.txt" | grep -ao 'ok_delta=-\?[0-9]*' | head -1 | cut -d= -f2)
POKERR=$(grep -a '^POKE_WINDOW ' "$OUT/V_observe.txt" | grep -ao 'err_delta=-\?[0-9]*' | head -1 | cut -d= -f2)
FERRD=$(grep -a '^FILL_WINDOW ' "$OUT/V_observe.txt" | grep -ao 'err_delta=-\?[0-9]*' | head -1 | cut -d= -f2)
# A MISSING DELTA IS NOT A DELTA OF ZERO, AND READING IT AS ONE DISCARDED A
# CONTROL ARM THAT HAD WORKED.  On s133a the observer's POKE_WINDOW and
# FILL_WINDOW lines were never printed at all — their counts were built with
# `$(grep -ac PAT FILE || echo 0)`, and `grep -c` prints "0" AND exits 1 when it
# matches nothing, so the `||` fired too and the substitution produced two
# zeros, which is an arithmetic syntax error.  POKE_POST, which counts with
# `wc -l`, printed normally, and that contrast is what identified it.  The
# verdict below then read `${FERRD:-0}` as "the filler completed further
# transactions without a single error" and threw the lap away as a drain
# confound, while the window showed the authority closing at 26 s, the
# withdrawal, the self-fence and the shutdown, and both tasks released.  The
# counts are fixed at the source; this refuses the lap if they are ever absent
# again, because every branch below treats these as measurements.
for fld in POKOK POKERR FERRD; do
    eval "v=\${$fld:-}"
    case ${v:-} in
        ''|*[!0-9-]*)
            echo "ABORT: the observer's window deltas are missing or non-numeric ($fld='${v:-}') — POKE_WINDOW/FILL_WINDOW did not reach the capture, so the filler's and poker's behaviour across the window was never measured and no verdict below would be one"
            echo "RESULT: ABORT label=$LABEL arm=$ARM stage=observe evidence=$OUT"; exit 2 ;;
    esac
done
POKPOST=$(grep -a '^POKE_POST ' "$OUT/V_observe.txt" | grep -ao ' ok=[0-9]*' | head -1 | cut -d= -f2)
POKPOSTE=$(grep -a '^POKE_POST ' "$OUT/V_observe.txt" | grep -ao ' err=[0-9]*' | head -1 | cut -d= -f2)
echo "STAGE observation over ${OBSERVE}s: authority-closed at ${CLOSED}s, parked-filler freed at ${FREED}s, filler alive=$ALIVE at +$(el)s"
echo "    $(grep -a '^POKE_FIRST_ERR=' "$OUT/V_observe.txt" | cut -c1-180)"
echo "    the poker across the window: $(grep -a '^POKE_WINDOW ' "$OUT/V_observe.txt" | cut -c1-120)"
echo "    the poker past the lease:    $(grep -a '^POKE_POST ' "$OUT/V_observe.txt" | cut -c1-120)"
echo "    the filler across the window: $(grep -a '^FILL_WINDOW ' "$OUT/V_observe.txt" | cut -c1-160)"
echo "    the filler's stack at the end of the window:"
sed -n '/^STACK_BEGIN/,/^STACK_END/p' "$OUT/V_observe.txt" | grep -a '\[' | head -10 | sed 's/^/      /'
echo "    the poker's stack at the end of the window:"
sed -n '/^PSTACK_BEGIN/,/^PSTACK_END/p' "$OUT/V_observe.txt" | grep -a '\[' | head -6 | sed 's/^/      /'

# ---- 8. the victim's own window, captured BEFORE the recycle — from the
#         follower's file, not the ring (see step 3).
window_into "$OUT/V_window.txt" "$V" 60 "$MARK" "$KMSGF"
count_file_into aclose  "$OUT/V_window.txt" 'P290-AUTH-CLOSED'
count_file_into awith   "$OUT/V_window.txt" 'P290-AUTH-WITHDRAW'
count_file_into sfence  "$OUT/V_window.txt" 'P131-SELF-FENCE'
count_file_into shut    "$OUT/V_window.txt" 'hutting down filesystem\|Log I/O Error\|forced shutdown'
count_file_into pumphold "$OUT/V_window.txt" 'P-DBG-AUTH-WITHDRAW-PAUSE'
count_file_into ailpin  "$OUT/V_window.txt" "P-AILPIN-HOLD ino=$PINO "
count_file_into oops    "$OUT/V_window.txt" 'BUG:\|Oops\|kernel NULL pointer'
echo "STAGE window on $V: auth-closed=$aclose auth-withdraw=$awith self-fence=$sfence shutdown=$shut pump-hold=$pumphold ail-pin-holds=$ailpin oops=$oops"
grep -a 'P290-AUTH-\|P131-SELF-FENCE\|P-DBG-AUTH-WITHDRAW-PAUSE' "$OUT/V_window.txt" | tail -6 | sed 's/.*mxfs: /    /; s/.*XFS (sd[a-z]): /    /' | cut -c1-200

# ---- 9. the verdict
ck "no BUG/Oops on $V" "$oops" 0

# THE PIN IS A PRODUCTION MECHANISM, NOT THE SUBJECT, AND IT WAS BEING GRADED
# AS ONE.  What this lap is about is a task parked in xlog_grant_head_wait when
# its authority closes, and that is established at step 5 from the task's OWN
# kernel stack.  s132b produced exactly that subject — the filler stopped dead
# for 12 s with xlog_grant_head_wait on its stack — and the lap was then thrown
# away because xfsaild had logged no hold on the pinned inode.  It had not
# needed to: the filler's own 8047 transactions filled the log before the
# pinned item ever reached the tail, so the knob was never the thing holding it
# down.  What the pin genuinely protects against is a filler released by the
# AIL draining rather than by the closure, and that confound is now asserted
# directly from the filler's own transaction errors below, where it belongs.
[ "${ailpin:-0}" -ge 1 ] || echo "  NOTE: xfsaild logged no hold on inode $PINO — the tail was held down by the filler's own log consumption instead.  The park is proven by the filler's stack; its release is attributed below."

# The closure is established by the MODULE's own line.  The poker only dates
# it, and it is allowed to have parked in the same log wait as the filler.
if [ "$aclose" -lt 1 ]; then
    # An authority that never closed is normally nothing to ask about.  It is
    # NOT nothing when the poker went on being ADMITTED past the point the
    # lease had certainly expired: this node's mutating submissions were then
    # being accepted under a dead lease with nothing having noticed, which is
    # the refutation — on its own terms — of the argument the withdrawal pump
    # is documented as resting on, that every mutating submission refuses on
    # its own.  That is this record's subject, not a separate finding.
    if [ "${POKPOST:-0}" -ge 1 ]; then
        echo "  FAIL: the authority never closed inside the window (0 x P290-AUTH-CLOSED) and the poker completed ${POKPOST} O_DIRECT write(s) more than ${LEASE_SAFE_S}s into it, by which point the 30 s lease had certainly expired (${POKPOSTE:-0} refusal(s) in the same span) — mutating submissions are still ADMITTED under a dead lease, so nothing in the submission path refuses on its own and the withdrawal pump is the only thing that would ever have noticed"
        fails=$((fails+1))
        echo "RESULT: FAIL label=$LABEL arm=$ARM closed_s=${CLOSED} freed_s=${FREED} poke_post_ok=${POKPOST} fails=$fails wall=$(el)s evidence=$OUT"; exit 1
    fi
    vac "the authority never closed inside the window ($aclose x P290-AUTH-CLOSED) and the poker completed no write past the lease either (post-lease ok=${POKPOST:-?} err=${POKPOSTE:-?}; window ok=${POKOK:-?} err=${POKERR:-?}) — nothing exercised the gate, so there is no closure to ask about and both arms would read the same" no-closure
fi

# A FILLER THAT CAME BACK MUST HAVE COME BACK FOR THE RIGHT REASON.  The log
# wait's other exit is ordinary log progress, and a filler released that way
# resumes with no error at all, while one released by the shutdown the closure
# drives fails its next transaction.  Without this, an AIL that happened to
# drain at the right moment reads as "the closure reached the parked task".
if [ "${FREED:-0}" != 0 ] && [ "${FERRD:-0}" = 0 ]; then
    vac "the parked filler resumed and completed further transactions without a single error (FILL_ERR delta 0), so the log grant wait was satisfied by ordinary log progress and not by the closure — the release is the AIL draining, which this lap says nothing about" drain-confound
fi
CLOSED_BY=$([ "${CLOSED:-0}" = 0 ] && echo "the module's own P290-AUTH-CLOSED (the poker did not date it — it parked too)" || echo "the poker's first EIO at ${CLOSED}s, corroborating P290-AUTH-CLOSED")
echo "STAGE the authority closed; established by $CLOSED_BY"
if [ "$PUMP_HOLD_MS" = 0 ]; then
    ckge "CONTROL: the pump converted the closure into a withdrawal" "$awith" 1
    ckge "CONTROL: the withdrawal forced the shutdown that is the parked task's only exit" "$shut" 1
    if [ "${FREED:-0}" = 0 ]; then
        echo "  FAIL CONTROL: the parked filler was STILL in xlog_grant_head_wait ${OBSERVE}s after its authority closed, with the pump running — the shutdown route does not reach a task already parked in the log at all"
        fails=$((fails+1))
    else
        echo "  PASS CONTROL: the parked filler was freed ${FREED}s into the window (authority closed at ${CLOSED}s), so with the pump running the closure does reach a task already parked in the log"
    fi
else
    # The arming was established at the arm, from the module's own line, and a
    # failure to establish it aborted there.  What this reports is the same
    # probe counted again in the end-of-lap window: it CORROBORATES, and a zero
    # here means the victim's ring no longer reaches back to the arm, not that
    # the pump was running.  Grading the arm on this count is what made s133b
    # unreadable.
    echo "  PASS SUBJECT: the withdrawal pump was held off with the lease still evaluated (P-DBG-AUTH-WITHDRAW-PAUSE ${pumparm}s after the arm; the end-of-lap window still carries $pumphold of them)"
    # BEFORE 0.89.66's withdraw thread this arm FAILed as predicted (s146e:
    # P290-AUTH-CLOSED on time, 0 withdrawals, the filler still parked 120 s
    # later — the PR worker's pump was the only consumer of the closure).
    # The fix gives the withdrawal its own thread, so the prediction is now
    # the opposite: the closure is converted WITHOUT the PR worker, by name.
    count_file_into wthread "$OUT/V_window.txt" 'P290-AUTH-WITHDRAW.*via=withdraw-thread'
    count_file_into wpump   "$OUT/V_window.txt" 'P290-AUTH-WITHDRAW.*via=pr-worker'
    # 0.89.68: the thread announces itself at mount.  s148b on 0.89.67
    # measured a closure nothing converted because the TCP init path returned
    # before the thread was started; a build that carries the thread must
    # show it on the victim, or the subject arm is measuring its absence.
    # 0.89.69: read from the module's own counter, not the ring.  s149c read
    # the whole ring 150 s after the mount and counted 0 while the thread
    # converted the closure by name: a mount's first minutes log thousands of
    # capped probe lines and the INFO announcement had rotated out.  A module
    # that carries the announcement but not the counter is read from the
    # ring as before, so that reading is a lower bound.
    if [ "$(strings -a mxfs.ko | grep -c 'auth_withdraw_threads')" != 0 ]; then
        value_now_into wt_up "$V" 20 "$OUT/V_wthread.txt" '^WTHREAD=[0-9]+$' "the module's count of running withdraw threads on $V" \
            "echo WTHREAD=\$(cat $PARM/auth_withdraw_threads)"
        ckge "SUBJECT: the withdraw thread is running on $V (auth_withdraw_threads)" "${wt_up#WTHREAD=}" 1
    elif [ "$(strings -a mxfs.ko | grep -c 'P290-AUTH-WITHDRAW-THREAD')" != 0 ]; then
        value_now_into wt_up "$V" 20 "$OUT/V_wthread.txt" '^WTHREAD=[0-9]+$' "whether the withdraw thread announced itself on $V at mount" \
            "echo WTHREAD=\$(dmesg | grep -ac 'P290-AUTH-WITHDRAW-THREAD')"
        ckge "SUBJECT: the withdraw thread was started on $V at mount (P290-AUTH-WITHDRAW-THREAD, ring only: a rotated ring reads 0)" "${wt_up#WTHREAD=}" 1
    fi
    ck "SUBJECT: the held PR-worker pump took no withdrawal" "$wpump" 0
    ckge "SUBJECT: the withdraw thread converted the closure (P290-AUTH-WITHDRAW via=withdraw-thread)" "$wthread" 1
    if [ "${FREED:-0}" = 0 ]; then
        echo "  FAIL SUBJECT: the authority closed at ${CLOSED}s and the parked filler was STILL in xlog_grant_head_wait ${OBSERVE}s later (alive=$ALIVE, withdrawals=$awith, shutdowns=$shut) — the closure freed nothing, so a task already parked in a log wait still depends on the PR worker's tick"
        fails=$((fails+1))
    else
        echo "  PASS SUBJECT: the parked filler came back ${FREED}s into the window with the PR worker's pump held — the withdraw thread converted the closure ($awith withdrawal(s), $shut shutdown(s), $sfence self-fence(s))"
    fi
fi

if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM closed_s=${CLOSED} freed_s=${FREED} fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL arm=$ARM closed_s=${CLOSED} freed_s=${FREED} fails=$fails wall=$(el)s evidence=$OUT"; exit 1
