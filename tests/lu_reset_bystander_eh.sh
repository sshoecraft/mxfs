#!/bin/bash
# lu_reset_bystander_eh.sh — WHY is a bystander initiator never rescued from a
# LOGICAL UNIT RESET it was not told about?
#
# WHAT IS ALREADY MEASURED, and what is not.  tests/lu_reset_probe.sh live arm
# established the behaviour: a LU reset issued from one node leaves the OTHER
# node's writer in D state in blk_io_schedule inside __iomap_dio_rw, for 3m39s
# and counting, with no error, no retry and nothing in that node's kernel log.
# A task in uninterruptible sleep cannot be killed, and the node had to be
# power cycled.  What is NOT established is the mechanism, and the mechanism
# decides the fix — including whether "hang" is even the right word, because
# the record's own reasoning rests on a command timeout of 30 s and the
# timeout on this device is 180 (see H-EH below).  Something either never
# armed a timer, kept resetting it, or had simply not run out yet, and those
# are three different findings with three different answers.
#
# THE HYPOTHESIS, written before the instrument, so it can be wrong.
#
#   H-EH  The stranded command never reaches the SCSI error handler at all,
#         because iscsi_eh_cmd_timed_out() answers every expiry with
#         SCSI_EH_RESET_TIMER rather than letting the command out to EH.
#
#         Read out of drivers/scsi/libiscsi.c, the ladder that function walks
#         on each expiry is: (1) the task transferred something since the last
#         timeout -> "Command making progress", reset the timer; (2) some OLDER
#         running task on the session has transferred since our last timeout ->
#         reset the timer; (3) we have not yet pinged the transport -> send a
#         nop-out, set have_checked_conn, reset the timer; (4) we HAVE pinged
#         -> fall through returning SCSI_EH_NOT_HANDLED, which is what starts
#         the error handler.  So the earliest EH can run is about three
#         expiries — unless arm (2) keeps firing, which on a node under
#         continuous write load is exactly what one would expect.
#
#         AND AN EXPIRY HERE IS 180 SECONDS, NOT 30.  /sys/block/<dev>/device/
#         timeout on this rig reads 180, and it reads that because MXFS'S OWN
#         INFRASTRUCTURE SETS IT — scripts/verify_infra.sh and
#         tools/prep_tcm_node_scst.sh both write 180 during prep.  That single
#         fact reframes the original observation: 3m39s is 219 s, which is 1.2
#         expiries, so the initiator had made exactly ONE decision (rung 1,
#         which always resets the timer) before the watching stopped.  Nothing
#         had failed to rescue the command at that point; the measurement
#         simply ended before the stack's first real opportunity.  Three
#         expiries is 540 s, and the error handler's own budget on top of that
#         is abort_timeout 15 + lu_reset_timeout 30 + tgt_reset_timeout 30
#         (/etc/iscsi/iscsid.conf).  Any window shorter than ~10 minutes cannot
#         tell "never rescued" from "not yet".
#
#         PREDICTION IF TRUE: with debug_libiscsi_eh armed, the bystander
#         prints a decision line every ~30 s, the last of them says "timer
#         reset", and no abort or device reset is ever attempted.
#         PREDICTION IF FALSE: a decision line says "shutdown or nh", the error
#         handler runs, and the question becomes why ITS recovery does not
#         resolve the task — a different defect in the same place.
#
# WHY dmesg silence was not evidence.  The earlier probe recorded that the
# bystander's kernel "logged NO reset, NO unit attention and NO I/O error", and
# concluded nothing on that node could observe the condition.  But the SCSI
# error handler narrates itself through SCSI_LOG_ERROR_RECOVERY and libiscsi
# through iscsi_dbg_lib_eh, and BOTH ARE OFF BY DEFAULT.  A quiet log is what a
# silent subsystem looks like as well as an idle one.  This harness arms both
# on the bystander before the reset lands, and disarms them on every exit — a
# trace flag left on is its own hazard.
#
# THE STRAND IS A RACE, AND ONE SHOT MISSES IT.  Measured s84g: a single reset,
# 85 ms of target time, left the bystander completely undisturbed — 109,054
# O_DIRECT writes across the reset at ~1,600/s, zero errors, zero error-handler
# activity of any kind.  That is not "rescued late"; nothing was ever stranded.
# For a task to be stranded the target has to be holding a command it has
# accepted and not yet completed AT THE INSTANT the task-management function
# executes, and then drop it without status.  So this harness issues a SERIES
# of resets rather than one, and samples the writer's own progress counter
# finely enough that a stall which later recovers is still visible.  A lap that
# does not reproduce the strand says so in those words — it is not a pass for
# the behaviour, and "cannot reproduce" disposes of nothing.
#
# WHAT IS GRADED
#   1. the bystander's writer is not left stranded: after the last reset its
#      progress counter advances again within the window.  A strand that is
#      never resolved is the defect.
#   2. the ISSUING node's writer terminated and made progress across the series
#      (its own error handler fails its commands and the midlayer re-submits
#      them).  If this ever fails the reset did something else entirely.
#   3. nothing crashed, hung the kernel, or shut a filesystem down, and both
#      nodes still answer.
#
# WHAT IS RECORDED AND NOT GRADED: the LONGEST STALL in the bystander's
# progress across the series.  A stall that recovers is a pace finding; a stall
# that does not is the hang.  Only the second is graded, but the first is the
# number that says how close this stimulus came.
# Also recorded: every libiscsi EH decision line, the block layer's in-flight
# count, the writer's kernel stack sampled through the window, and whether the
# error handler ran at all.  That is the evidence a fix would be designed from.
#
# IF THE BYSTANDER STRANDS it is left that way: a task in D state cannot be
# killed and the node cannot be unmounted; RUN prep_cluster AFTER THIS HARNESS,
# which power cycles it.  Nothing here fences anything and nothing here certifies anything.
#
# Budget (derived from the ladder and the timers, not chosen).  prep <=120
# (measured 45-64) + writer start and its liveness 25 + the reset series
# RESETS * (RESET_GAP + one sample) ~= 130 + the watch + the issuer's tally
# wait <=200 + captures and disarm 60.
#
# THE WATCH HAS TWO LENGTHS because the two outcomes need different evidence.
# If the writer keeps advancing, CLEAN_AFTER (90 s) of continuous progress is
# enough to say the stimulus never reached it, and the lap ends at ~625 s.
# If it FREEZES, the window has to cover the stack's own rescue path before
# "never rescued" can be claimed: an expiry is 180 s (the device timeout, set
# by MXFS's prep), the earliest the error handler can be let in is three of
# them = 540 s, and EH's own budget is 15 + 30 + 30 s from iscsid.conf, so one
# full opportunity is ~615 s and OBSERVE is 900.  That path ends at ~1435 s.
# Caller bound 1500 s.  A 240 s window cannot distinguish "never" from "not
# yet" and must not be used for this question.
#
# THE PREMISE IS ASSERTED, not assumed: the lap ABORTs if the device timeout is
# not the 180 s this budget is derived from.  A harness whose budget rests on a
# tunable has to check the tunable.
#
# Usage: tests/lu_reset_bystander_eh.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2), OBSERVE (900), EXPECT_CMD_TIMEOUT (180)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?usage: lu_reset_bystander_eh.sh <label>}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # issues the reset; its own EH covers it
B=${MXFS_NODE_LIST##*,}          # the BYSTANDER, never told the reset happened
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OBSERVE=${OBSERVE:-900}          # the long watch, only entered if it stalls
EXPECT_CMD_TIMEOUT=${EXPECT_CMD_TIMEOUT:-180}
RESETS=${RESETS:-10}             # one shot missed the race; try a series
RESET_GAP=${RESET_GAP:-6}        # seconds between resets
SAMPLE_EVERY=${SAMPLE_EVERY:-10} # fine enough to see a stall that recovers
CLEAN_AFTER=${CLEAN_AFTER:-90}   # continuous progress that says "not stranded"
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lrbe_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
MARK="LRBE-MARK-$LABEL"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# A trace flag left on is a hazard in its own right.  Disarm on every exit.
ARMED=0
disarm() {
    [ "$ARMED" = 1 ] || return 0
    timeout 30 $SSH "$B" \
        "echo 0 > /sys/module/libiscsi/parameters/debug_libiscsi_eh 2>/dev/null; \
         echo 0 > /proc/sys/dev/scsi/logging_level 2>/dev/null; \
         echo EH=\$(cat /sys/module/libiscsi/parameters/debug_libiscsi_eh 2>/dev/null) \
              LOG=\$(cat /proc/sys/dev/scsi/logging_level 2>/dev/null)" \
        > "$OUT/B_disarm.txt" 2>&1
    echo "STAGE disarmed the traces on $B at +$(el)s: $(tr '\n' ' ' < "$OUT/B_disarm.txt" | cut -c1-80)"
}
trap disarm EXIT

echo "=== lu_reset_bystander_eh label=$LABEL A(issuer)=$A B(bystander)=$B observe=${OBSERVE}s $(date -u +%FT%TZ) ==="

# ---- 1. both nodes mounted on the tree build
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' \
        "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; DEV_A=$MXFS_DEV_RESOLVED
mxfs_dev_resolve "$B"; DEV_B=$MXFS_DEV_RESOLVED

# ---- 2. the timers that are supposed to rescue the bystander, read BEFORE the
# stimulus so the observation can be compared against what the stack promised.
measure "$B" 40 "$OUT/B_timers.txt" '^TIMERS_END$' "the bystander's timeout configuration" \
    "echo CMD_TIMEOUT=\$(cat /sys/block/$(basename "$DEV_B")/device/timeout 2>/dev/null); \
     echo EH_DEADLINE=\$(cat /sys/block/$(basename "$DEV_B")/device/eh_deadline 2>/dev/null); \
     for s in /sys/class/iscsi_session/session*; do \
       echo RECOVERY_TMO=\$(cat \$s/recovery_tmo 2>/dev/null); \
       echo NOOP_INT=\$(cat \$s/../iscsi_connection/connection*/ping_tmo 2>/dev/null | head -1); \
       echo NOOP_TMO=\$(cat \$s/../iscsi_connection/connection*/recv_tmo 2>/dev/null | head -1); \
     done; echo TIMERS_END"
echo "STAGE the bystander's stack promises: $(grep -a '=' "$OUT/B_timers.txt" | grep -av TIMERS_END | tr '\n' ' ' | cut -c1-160)"
# The whole observation budget is derived from this number.  If it is not what
# the header derived from, every conclusion below would be about a different
# ladder — so say so and stop, rather than measuring the wrong thing quietly.
ck "the device command timeout is the one this lap's budget is derived from" \
   "$(field "$OUT/B_timers.txt" CMD_TIMEOUT)" "$EXPECT_CMD_TIMEOUT"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=timers evidence=$OUT"; exit 2; }

# ---- 3. arm the two subsystems that narrate error recovery.  Neither is on by
# default, which is why the earlier probe's silent log proved nothing.
#
# THE LOGGING LEVEL IS A PACKED FIELD AND THE WRONG VALUE IS A HAZARD, not just
# a wrong answer.  drivers/scsi/scsi_logging.h gives each class three bits:
# ERROR at shift 0, TIMEOUT at 3, SCAN 6, MLQUEUE 9, MLCOMPLETE 12, and up.
# 63 is (7 << 0) | (7 << 3) — error recovery and timeouts at full verbosity and
# NOTHING ELSE.  A value that reaches shift 12 logs every command completion on
# a node under continuous write load, which is how a trace flag left on once
# produced over a million kernel lines and deadlocked the journal of the
# filesystem holding the log.  Derive the number from the shifts; do not pick a
# hex constant that looks about right.
measure "$B" 40 "$OUT/B_arm.txt" '^EH=1 LOG=63$' "the libiscsi EH trace on the bystander" \
    "echo $MARK > /dev/kmsg; \
     echo 1 > /sys/module/libiscsi/parameters/debug_libiscsi_eh; \
     echo 63 > /proc/sys/dev/scsi/logging_level 2>/dev/null; \
     echo EH=\$(cat /sys/module/libiscsi/parameters/debug_libiscsi_eh) \
          LOG=\$(cat /proc/sys/dev/scsi/logging_level 2>/dev/null)"
ARMED=1
ck "the bystander is narrating its error recovery" "$(field "$OUT/B_arm.txt" EH)" 1
measure "$A" 30 "$OUT/A_mark.txt" '^MARKED$' "the issuer's lap mark" \
    "echo $MARK > /dev/kmsg; echo MARKED"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }

# ---- 4. in-flight MXFS I/O on BOTH nodes: the bystander is the subject, the
# issuer is the control that says the reset did what it always does.
for n in "$A" "$B"; do
    measure "$n" 60 "$OUT/${n}_writer_start.txt" '^WPID=[0-9]+$' "the writer on $n" \
        "rm -f /tmp/lrbe_writer.err; mkdir -p $MNT/lrbe_$LABEL && \
         dd if=/dev/zero of=$MNT/lrbe_$LABEL/w_$n bs=4096 count=64 oflag=direct 2>/dev/null; \
         setsid python3 /src/mxfs/tests/lu_reset_writer.py $MNT/lrbe_$LABEL/w_$n 0 $([ "$n" = "$B" ] && echo $((OBSERVE + 180)) || echo $((RESETS * RESET_GAP + 60))) \
             > /tmp/lrbe_writer.err 2>&1 < /dev/null & \
         echo WPID=\$!"
done
WPID_B=$(field "$OUT/${B}_writer_start.txt" WPID)
WPID_A=$(field "$OUT/${A}_writer_start.txt" WPID)
sleep 6
# NON-VACUITY: a writer that never started reports no errors, which reads
# exactly like a writer the reset did not disturb.
measure "$B" 40 "$OUT/B_writer_live.txt" '^WLIVE_END$' "that the bystander's writer is running" \
    "echo COMM=\$(cat /proc/$WPID_B/comm 2>/dev/null); \
     echo STATE=\$(cut -d' ' -f3 /proc/$WPID_B/stat 2>/dev/null); \
     echo STARTED=\$(grep -ac '^WRITER_START' /tmp/lrbe_writer.err 2>/dev/null); \
     echo ENDED=\$(grep -ac '^WRITER_DONE' /tmp/lrbe_writer.err 2>/dev/null); echo WLIVE_END"
echo "STAGE writers: $B pid=$WPID_B comm=$(field "$OUT/B_writer_live.txt" COMM) state=$(field "$OUT/B_writer_live.txt" STATE) started=$(field "$OUT/B_writer_live.txt" STARTED); $A pid=$WPID_A"
if [ "$(field "$OUT/B_writer_live.txt" STARTED)" != 1 ] ||
   [ "$(field "$OUT/B_writer_live.txt" ENDED)" != 0 ]; then
    echo "  FAIL <the bystander's writer was not running with work in flight when the reset was issued; nothing would have been stranded>"
    echo "RESULT: VACUOUS label=$LABEL stage=writer wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 5. THE STIMULUS, as a series.  One reset is 85 ms of target time and
# misses the race; ten spaced six seconds apart give the target ten chances to
# be holding one of the bystander's commands when the task-management function
# executes.  Escalation stays forbidden, so what lands is exactly one LU reset
# each time and never a local teardown wearing its clothes.
BD=$(basename "$DEV_B")
reset_once() {
    rs 60 "$A" "python3 - <<'PY'
import fcntl, os, struct, time
SG_SCSI_RESET = 0x2284
SG_SCSI_RESET_DEVICE = 1
SG_SCSI_RESET_NO_ESCALATE = 0x100
buf = bytearray(struct.pack('i', SG_SCSI_RESET_DEVICE | SG_SCSI_RESET_NO_ESCALATE))
fd = os.open('$DEV_A', os.O_RDWR | os.O_NONBLOCK)
t0 = time.time()
try:
    fcntl.ioctl(fd, SG_SCSI_RESET, buf, True)
    rc = 0
except OSError as e:
    rc = e.errno
print('RESET_WALL_MS=%d' % int((time.time() - t0) * 1000))
print('RESET_RC=%d' % rc)
PY"
}

# One sample of the bystander, appended to the evidence and echoed as a line.
# OKN is the writer's own progress counter: `ok` climbing is healthy, `err`
# climbing is hurt but alive, both frozen is stranded.  The task state is NOT
# the discriminator — a healthy O_DIRECT writer sits in D most of the time.
SAMPLE_OK=; SAMPLE_ERR=; SAMPLE_STATE=; SAMPLE_EH=
sample_b() {
    rs 30 "$B" \
      "P=\$(grep -a '^WRITER_PROGRESS' /tmp/lrbe_writer.err 2>/dev/null | tail -1); \
       echo === t=\$(( \$(date +%s) - $T0 ))s; \
       echo STATE=\$(cut -d' ' -f3 /proc/$WPID_B/stat 2>/dev/null); \
       echo OKN=\$(printf '%s' \"\$P\" | sed -n 's/.*ok=\\([0-9]*\\).*/\\1/p'); \
       echo ERRN=\$(printf '%s' \"\$P\" | sed -n 's/.*err=\\([0-9]*\\).*/\\1/p'); \
       echo DONE=\$(grep -ac '^WRITER_DONE' /tmp/lrbe_writer.err 2>/dev/null); \
       echo INFLIGHT=\$(cat /sys/block/$BD/inflight 2>/dev/null); \
       echo EHLINES=\$(dmesg | sed -n \"/$MARK/,\\\$p\" | grep -ac 'iscsi_eh_cmd_timed_out\|iscsi_eh_abort\|iscsi_eh_device_reset\|scsi_eh'); \
       sed -n '1,6p' /proc/$WPID_B/stack 2>/dev/null | sed 's/^/STACK /'" \
      >> "$OUT/B_samples.txt" 2>&1
    SAMPLE_OK=$(grep -a '^OKN=' "$OUT/B_samples.txt" | tail -1 | cut -d= -f2)
    SAMPLE_ERR=$(grep -a '^ERRN=' "$OUT/B_samples.txt" | tail -1 | cut -d= -f2)
    SAMPLE_STATE=$(grep -a '^STATE=' "$OUT/B_samples.txt" | tail -1 | cut -d= -f2)
    SAMPLE_EH=$(grep -a '^EHLINES=' "$OUT/B_samples.txt" | tail -1 | cut -d= -f2)
}

T0=$(date +%s)
: > "$OUT/B_samples.txt"
: > "$OUT/A_resets.txt"
LAST_OK=
LAST_ADVANCE=$T0
MAX_STALL=0
RESET_OK=0
echo "STAGE issuing $RESETS resets ${RESET_GAP}s apart, sampling the bystander between each"
r=1
while [ "$r" -le "$RESETS" ]; do
    reset_once >> "$OUT/A_resets.txt" 2>&1
    rc=$(grep -a '^RESET_RC=' "$OUT/A_resets.txt" | tail -1 | cut -d= -f2)
    ms=$(grep -a '^RESET_WALL_MS=' "$OUT/A_resets.txt" | tail -1 | cut -d= -f2)
    [ "${rc:-1}" = 0 ] && RESET_OK=$(( RESET_OK + 1 ))
    sample_b
    now=$(date +%s)
    if [ -n "${SAMPLE_OK:-}" ] && [ -n "$LAST_OK" ] && [ "${SAMPLE_OK:-0}" -gt "$LAST_OK" ]; then
        LAST_ADVANCE=$now
    fi
    [ -n "${SAMPLE_OK:-}" ] && LAST_OK=$SAMPLE_OK
    stall=$(( now - LAST_ADVANCE ))
    [ "$stall" -gt "$MAX_STALL" ] && MAX_STALL=$stall
    echo "  reset $r/$RESETS rc=${rc:-?} ${ms:-?}ms  t=$(( now - T0 ))s state=${SAMPLE_STATE:-?} ok=${SAMPLE_OK:-?} err=${SAMPLE_ERR:-?} stall=${stall}s eh=${SAMPLE_EH:-?}"
    r=$(( r + 1 ))
    [ "$r" -le "$RESETS" ] && sleep "$RESET_GAP"
done
ck "every reset in the series returned success with escalation forbidden" "$RESET_OK" "$RESETS"

# ---- 6. THE WATCH.  If the writer is advancing, watch CLEAN_AFTER seconds of
# continuous progress and call the hazard not reproduced.  If it has frozen,
# switch to the long watch: the ladder needs three 180 s expiries before the
# error handler is even allowed in, so a stall is only "never rescued" after
# OBSERVE seconds.
STRANDED=0
RESOLVED_AT=
i=0
while [ "$i" -lt "$OBSERVE" ]; do
    sleep "$SAMPLE_EVERY"
    i=$(( i + SAMPLE_EVERY ))
    sample_b
    now=$(date +%s)
    if [ -n "${SAMPLE_OK:-}" ] && [ -n "$LAST_OK" ] && [ "${SAMPLE_OK:-0}" -gt "$LAST_OK" ]; then
        LAST_ADVANCE=$now
        [ "$STRANDED" = 1 ] && { RESOLVED_AT=$(( now - T0 )); STRANDED=0; }
    fi
    [ -n "${SAMPLE_OK:-}" ] && LAST_OK=$SAMPLE_OK
    stall=$(( now - LAST_ADVANCE ))
    [ "$stall" -gt "$MAX_STALL" ] && MAX_STALL=$stall
    [ "$stall" -ge $(( SAMPLE_EVERY * 2 )) ] && STRANDED=1
    echo "  t=$(( now - T0 ))s state=${SAMPLE_STATE:-?} ok=${SAMPLE_OK:-?} err=${SAMPLE_ERR:-?} stall=${stall}s max_stall=${MAX_STALL}s eh=${SAMPLE_EH:-?}"
    # Advancing and never having stalled past a sample pair: the stimulus did
    # not reach the bystander at all.  Stop watching once that is established.
    if [ "$STRANDED" = 0 ] && [ "$MAX_STALL" -lt $(( SAMPLE_EVERY * 2 )) ] &&
       [ "$i" -ge "$CLEAN_AFTER" ]; then
        break
    fi
done
echo "STAGE the bystander over the whole series: longest stall ${MAX_STALL}s, stranded_now=$STRANDED$([ -n "$RESOLVED_AT" ] && echo ", recovered at t=${RESOLVED_AT}s")"

# The issuer is the control: its own error handler fails its outstanding
# commands and the midlayer re-submits them, so its writer must TERMINATE and
# must have made progress.  Wait for it rather than reading a tally it has not
# printed yet — the writer tallies only at the end of its run.
measure "$A" 200 "$OUT/A_writer_tally.txt" '^TALLY_END$' "the issuer's writer tally" \
    "for i in \$(seq 1 180); do grep -aq '^WRITER_DONE' /tmp/lrbe_writer.err 2>/dev/null && break; sleep 1; done; \
     echo DONE=\$(grep -ac '^WRITER_DONE' /tmp/lrbe_writer.err 2>/dev/null); \
     echo OK=\$(sed -n 's/^WRITER_OK=//p' /tmp/lrbe_writer.err | head -1); \
     echo ERRTOTAL=\$(sed -n 's/^WRITER_ERRTOTAL=//p' /tmp/lrbe_writer.err | head -1); \
     grep -a '^WRITER_ERR_' /tmp/lrbe_writer.err 2>/dev/null; echo TALLY_END"
ADONE=$(field "$OUT/A_writer_tally.txt" DONE)
AOK=$(field "$OUT/A_writer_tally.txt" OK)
AERR=$(field "$OUT/A_writer_tally.txt" ERRTOTAL)
grep -a '^WRITER_ERR_' "$OUT/A_writer_tally.txt" | sed 's/^/    /'
echo "STAGE the issuer's writer: done=$ADONE writes_ok=$AOK errors=$AERR"

# ---- 7. what the error handler actually did, which is the point of the lap
window_into "$OUT/B_window.txt" "$B" 120 "$MARK"
window_into "$OUT/A_window.txt" "$A" 120 "$MARK"
TIMEDOUT=$(cnt "$OUT/B_window.txt" 'iscsi_eh_cmd_timed_out')
RESETTIMER=$(cnt "$OUT/B_window.txt" 'return timer reset')
NOTHANDLED=$(cnt "$OUT/B_window.txt" 'return shutdown or nh')
ABORTS=$(cnt "$OUT/B_window.txt" 'iscsi_eh_abort\|aborting sc')
DEVRESET=$(cnt "$OUT/B_window.txt" 'iscsi_eh_device_reset\|dev reset')
grep -a 'iscsi_eh_\|scsi_eh\|abort' "$OUT/B_window.txt" | sed 's/.*kernel: //' | cut -c1-200 | tail -8
echo "STAGE the bystander's error recovery: timeouts=$TIMEDOUT timer_reset=$RESETTIMER not_handled=$NOTHANDLED aborts=$ABORTS device_resets=$DEVRESET"
echo "FINDING H-EH predicted every expiry answered 'timer reset' and no abort: timer_reset=$RESETTIMER not_handled=$NOTHANDLED aborts=$ABORTS — $([ "${NOTHANDLED:-0}" = 0 ] && [ "${ABORTS:-0}" = 0 ] && echo 'CONSISTENT with H-EH' || echo 'H-EH DISPROVED: the error handler was let in')"

# ---- 8. the grades
#
# The defect is a strand that is NEVER resolved.  A strand that recovers is a
# pace finding and is reported, not graded — grading it here would make this
# harness fail for something it did not set out to measure and would bury the
# one outcome that matters.
ck "the bystander's writer is not left stranded" \
   "$([ "$STRANDED" = 1 ] && echo stranded || echo advancing)" advancing
ck "the issuing node's writer terminated rather than hanging" "${ADONE:-0}" 1
ck "the issuing node's writer made progress across the series" \
   "$([ -n "${AOK:-}" ] && [ "${AOK:-0}" -gt 0 ] && echo yes || echo no)" yes
if [ "$MAX_STALL" -lt $(( SAMPLE_EVERY * 2 )) ]; then
    echo "FINDING THE HAZARD DID NOT REPRODUCE on this lap: $RESETS resets never stalled the bystander's writes for as much as $(( SAMPLE_EVERY * 2 ))s (longest ${MAX_STALL}s).  That disposes of nothing — the strand needs the target to be holding one of this initiator's commands at the instant the task-management function runs, and this series did not catch it."
else
    echo "FINDING THE HAZARD REPRODUCED: the bystander's writes stalled for ${MAX_STALL}s$([ -n "$RESOLVED_AT" ] && echo " and recovered at t=${RESOLVED_AT}s" || echo " and had not recovered when the watch ended at ${OBSERVE}s")"
fi
for n in "$A" "$B"; do
    f="$OUT/A_window.txt"; [ "$n" = "$B" ] && f="$OUT/B_window.txt"
    ck "no BUG or Oops on $n" "$(cnt "$f" 'BUG:\|Oops')" 0
    ck "no filesystem shutdown on $n" "$(cnt "$f" 'Filesystem has been shut down')" 0
    value_now_into alive "$n" 30 "$OUT/${n}_alive.txt" '^ALIVE=1$' "liveness of $n" "echo ALIVE=1"
    ck "$n still answers" "$alive" "ALIVE=1"
done

echo "--- resets=$RESET_OK/$RESETS max_stall=${MAX_STALL}s stranded=$STRANDED issuer_writes=${AOK:-?} issuer_errors=${AERR:-?} bystander_eh: timeouts=$TIMEDOUT timer_reset=$RESETTIMER not_handled=$NOTHANDLED aborts=$ABORTS"
echo "NOTE if the bystander stranded it has unkillable I/O and cannot be unmounted; run prep_cluster before any lap that mounts."
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails wall=$(el)s evidence=$OUT"; exit 1
