#!/bin/bash
# lu_reset_probe.sh — can this target give us a RETIREMENT WITNESS, and does
# the operation that would give it destroy the exclusion we need to keep?
#
# WHY THIS PROBE EXISTS.
# A fence certificate authorises replaying a dead node's journal slice, and it
# may only do that if the target is finished with the writes it already
# accepted from that node.  Registration absence does not establish it, an
# elapsed interval does not establish it, and no PERSISTENT RESERVE IN reports
# it.  The one broadly specified operation whose defined completion retires
# tasks for a logical unit ACROSS its I_T nexuses — so its scope does not
# depend on the victim's registration still existing — is LOGICAL UNIT RESET.
#
# Before designing anything around it, four questions have to be measured on
# the actual appliance.  Each is written here as a falsifiable statement and
# each can kill the route on its own:
#
#   H1  the target COMPLETES a LOGICAL UNIT RESET task-management function.
#       Measured as: the ioctl returns 0 with escalation forbidden.  On this
#       transport that is a target acknowledgement and not a local teardown,
#       and that is not an assumption — it is read out of the kernel this
#       fleet runs.  scsi_ioctl_reset() maps SG_SCSI_RESET_DEVICE with
#       SG_SCSI_RESET_NO_ESCALATE to exactly scsi_try_bus_device_reset() with
#       no fallthrough to target/bus/host reset, and returns 0 only for
#       SUCCESS; iscsi_eh_device_reset() returns SUCCESS only when
#       session->tmf_state == TMF_SUCCESS, and iscsi_tmf_rsp() sets that only
#       on ISCSI_TMF_RSP_COMPLETE in the target's own TMF response PDU.  A
#       timeout returns FAILED through iscsi_conn_failure(); a session that is
#       not LOGGED_IN returns FAILED without sending anything.
#
#   H2  the reset PRESERVES persistent reservations and registrations.  This
#       is the one that decides whether the route is usable at all: the reset
#       would be issued while an admission barrier is held, and an operation
#       that clears the PR state destroys the exclusion it was issued under.
#       A conforming LU reset preserves them.  This target has never been
#       asked.
#
#   H3  the iSCSI session is not torn down by it — the sid and the session
#       state are unchanged across the call, so the SUCCESS above cannot be a
#       reconnect wearing a witness's clothes.
#
#   H4  what happens to a node that owns in-flight I/O when the reset lands,
#       and it is TWO different questions.  The node that ISSUES the reset runs
#       its own error handler, which fails its outstanding commands so the
#       midlayer re-submits them: it must come back, and a hang there is a
#       defect.  A BYSTANDER initiator is never told the reset happened — its
#       command is aborted at the target and no completion is ever sent — so it
#       can wait for a BIO that never completes.  Measured: it does, in
#       blk_io_schedule inside __iomap_dio_rw, in D state, with no error, no
#       timeout and no retry.  That is why this operation may only be issued by
#       a SOLE LIVE INITIATOR, and it is recorded rather than graded.
#
# THE ARMS
#   bare  no MXFS anywhere: the module is unloaded on both nodes and this
#         script owns the PR state through sg_persist.  Pure target behaviour,
#         nothing of ours to misread — H1, H2, H3, and H4 against a writer
#         this script starts itself.
#   live  the peer is mounted and writing MXFS traffic when the reset lands.
#         Characterises the collateral: what the reset does to a live
#         filesystem on the OTHER initiator.  Asserts what must hold whatever
#         the collateral is — both nodes answering, no BUG or Oops, no
#         filesystem shutdown, and the PR state intact — and records the
#         writer's fate as the finding it is.  A peer left with stranded I/O
#         cannot unmount; the next prep_cluster power-cycles it.
#
# NOTHING HERE FENCES ANYTHING and nothing here certifies anything.  It is a
# measurement of the target, and its result feeds a design decision that is
# recorded in the queue, not a code path.
#
# THE BARE ARM WRITES RAW SECTORS INTO THE LUN TAIL to have in-flight I/O of
# its own, the way tests/pr_retirement_probe.sh does, and it installs and then
# removes its own PR registration.  Both leave the volume unfit for a mount
# without a fresh prep: RUN prep_cluster AFTER THIS ARM before any lap that
# mounts.  The arm says so again on its last line.
#
# Usage: tests/lu_reset_probe.sh <label> [bare|live]
# Env:   MXFS_NODE_LIST (test1,test2)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# Budget (derived, then measured): teardown 10 or prep <=120 (measured 45-64)
# + the PR setup and its read-back 15 + starting the writer 8 + the reset
# itself <=30 (libiscsi's own LU-reset timeout bounds it, and a longer wall IS
# the finding: measured 42 ms with work in flight, sub-millisecond without)
# + the read-backs and the transport window 15 + waiting out the writer's 90 s
# run for its tally 95 + captures 25.  bare ~= 190 s, caller bound 240 s;
# measured 102 s.  live adds the prep: ~= 250 s, caller bound 300 s.
set -u
LABEL=${1:?label}
ARM=${2:-bare}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # where the reset is issued
B=${MXFS_NODE_LIST##*,}          # the peer; mounted and writing on the live arm
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lurst_${LABEL}_$ARM
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
# a field is read wherever it sits on the line, not only at its start: an
# arm that prints "SEEN=1 PAUSED=1" on one line had its second field read as
# an empty string under an anchored match, which aborts a healthy lap.
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
MARK="LURST-MARK-$LABEL-$ARM"
# A key this script owns.  Top bit clear on purpose: a key with it set is
# negative in shell arithmetic and half of all derived keys have silently
# failed to arm a knob that way before.
KW=0x1213141516171819

echo "=== lu_reset_probe label=$LABEL arm=$ARM A(issuer)=$A B(peer)=$B $(date -u +%FT%TZ) ==="
case "$ARM" in bare|live) ;; *)
    echo "ABORT: unknown arm '$ARM' (bare|live)"
    echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2 ;;
esac

# ---- 1. the fleet in the state this arm needs
if [ "$ARM" = bare ]; then
    # Nothing of MXFS may hold the LUN: its registration would be read as ours
    # and its I/O would confound H4.
    for n in "$A" "$B"; do
        measure "$n" 90 "$OUT/${n}_teardown.txt" '^TEARDOWN_RC=' "the MXFS teardown on $n" \
            "umount $MNT > /dev/null 2>&1; rmmod mxfs > /dev/null 2>&1; sleep 1; echo LOADED=\$(lsmod | grep -c '^mxfs '); echo TEARDOWN_RC=0"
        ck "no mxfs module is loaded on $n" "$(field "$OUT/${n}_teardown.txt" LOADED)" 0
    done
else
    MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
    [ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
fi
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=fleet evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED
echo "STAGE device on $A: $DEV at +$(el)s"

# ---- 2. the PR state the reset must not destroy
# On the bare arm this script installs it; on the live arm MXFS's own mount
# already holds one and we only read it.  Either way H2 compares the same two
# captures.
if [ "$ARM" = bare ]; then
    measure "$A" 60 "$OUT/A_prsetup.txt" '^SETUP_RC=' "the PR state this probe installs on $A" \
        "R=\$(readlink -f $DEV); \
         sg_persist --out --register-ignore --param-sark=$KW \$R > /dev/null 2>&1; \
         sg_persist --out --reserve --param-rk=$KW --prout-type=7 \$R 2>&1 | tail -2; \
         echo SETUP_RC=\$?"
fi
# THE FIRST COMMAND AFTER A RESET EATS THE UNIT ATTENTION.
# A logical unit reset makes the target report POWER ON / RESET OCCURRED to the
# next command on each nexus, so a single READ KEYS issued straight afterwards
# fails and prints nothing — which this probe read as "the registrations are
# gone" and called the route dead.  The UA is an EXPECTED EVENT of the
# operation: absorb it deliberately, record that it happened, and read the
# state with the command after it.  Absorbing it before the BEFORE capture too
# keeps the two captures symmetric.
prstate_into() {   # $1 outfile, $2 what
    measure "$A" 60 "$1" '^PR_END$' "$2" \
        "R=\$(readlink -f $DEV); \
         ua=\$(sg_persist -i -k \$R 2>&1); \
         echo UA_ABSORBER_RC=\$?; \
         printf '%s\\n' \"\$ua\" | grep -aiE 'unit attention|reset occurred|check condition' | head -2 | sed 's/^/UA: /'; \
         echo '--- keys'; sg_persist -i -k \$R 2>&1 | grep -a '0x' | sort; \
         echo '--- resv'; sg_persist -i -r \$R 2>&1 | grep -aiv 'generation' | sed -n '2,6p'; echo PR_END"
    sed -n '/^--- keys/,/^PR_END/p' "$1" | grep -av '^PR_END$' > "$1.state"
}
prstate_into "$OUT/A_pr_before.txt" "the PR state before the reset"
NKEYS0=$(grep -ac '0x' "$OUT/A_pr_before.txt.state")
ck "the LUN carries at least one registration before the reset" \
   "$([ "$NKEYS0" -ge 1 ] && echo yes || echo no)" yes
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prstate evidence=$OUT"; exit 2; }

# ---- 3. the session identity, so a teardown cannot pass as a witness, and the
# TMF RESPONSE COUNTER, which is the only thing here that says the TARGET
# answered rather than the initiator deciding by itself.
#
# THE RETURN CODE ALONE IS NOT THE WITNESS.  The kernel path that maps a 0 to
# "the target sent Function Complete" was read out of /src/linux, and the nodes
# do not run /src/linux — so the mapping is an argument about a kernel, not a
# measurement of this one.  tmfrsp_pdus counts task-management RESPONSE PDUs
# received on the connection; an increment across the call is the target's own
# answer, and no increment means whatever returned 0 never reached it.  The
# node's kernel release is captured beside it because the argument is
# version-specific.
sessid_into() {    # $1 outfile, $2 what
    measure "$A" 40 "$1" '^SESS_END$' "$2" \
        "uname -r | sed 's/^/KREL=/'; \
         for s in /sys/class/iscsi_session/session*; do \
            [ -e \$s ] || continue; \
            echo SID=\$(basename \$s) STATE=\$(cat \$s/state 2>/dev/null) \
                 RECOV=\$(cat \$s/recovery_tmo 2>/dev/null); \
         done; \
         echo TMFRSP=\$(iscsiadm -m session -s 2>/dev/null | awk '/tmfrsp_pdus/{s+=\$2} END{print s+0}'); \
         echo SESS_END"
    grep -a '^SID=' "$1" | sort > "$1.ids"
}
sessid_into "$OUT/A_sess_before.txt" "the iSCSI session identity before the reset"
TMF0=$(field "$OUT/A_sess_before.txt" TMFRSP)
echo "STAGE $A kernel $(field "$OUT/A_sess_before.txt" KREL), tmfrsp_pdus=$TMF0 at +$(el)s"

# The transport's own account of the exchange, as a second and independent
# witness to the counter: with this on, libiscsi prints the LU Reset it sends
# and the result it reached.
measure "$A" 40 "$OUT/A_ehdbg.txt" '^EHDBG=' "the libiscsi EH debug switch on $A" \
    "echo 1 > /sys/module/libiscsi/parameters/debug_libiscsi_eh 2>/dev/null; \
     echo $MARK > /dev/kmsg; \
     echo EHDBG=\$(cat /sys/module/libiscsi/parameters/debug_libiscsi_eh 2>/dev/null)"

# ---- 4. in-flight I/O, so the reset has something of ours to abort
# O_DIRECT into the LUN tail on the bare arm (nothing else owns the device);
# ordinary filesystem traffic from the PEER on the live arm.
# setsid, because a job backgrounded from an ssh command dies with the session
# that launched it — the first run of this probe graded an empty workload that
# way.  The writer is a file in the tree, reached through the NFS mount the
# nodes already carry, never a script smuggled through a quoted ssh line.
if [ "$ARM" = bare ]; then
    WRITER_HOST=$A
    $SSH "$A" "echo $MARK > /dev/kmsg; rm -f /tmp/lurst_writer.err; \
        R=\$(readlink -f $DEV); OFF=\$(( ( \$(blockdev --getsz \$R) - 4096 ) * 512 )); \
        setsid python3 /src/mxfs/tests/lu_reset_writer.py \$R \$OFF 90 \
            > /tmp/lurst_writer.err 2>&1 < /dev/null &" \
        > "$OUT/A_writer_start.txt" 2>&1
else
    WRITER_HOST=$B
    $SSH "$B" "echo $MARK > /dev/kmsg; rm -f /tmp/lurst_writer.err; \
        mkdir -p $MNT/lurst_$LABEL && dd if=/dev/zero of=$MNT/lurst_$LABEL/w bs=4096 count=64 oflag=direct 2>/dev/null; \
        setsid python3 /src/mxfs/tests/lu_reset_writer.py $MNT/lurst_$LABEL/w 0 90 \
            > /tmp/lurst_writer.err 2>&1 < /dev/null &" \
        > "$OUT/B_writer_start.txt" 2>&1
fi
sleep 6
# NON-VACUITY FOR H4.  A writer that never started reports no errors, which
# reads exactly like a writer the reset did not disturb.  Require evidence it
# is running — its error file exists and a dd is on the process table — before
# any statement about what the reset did to in-flight I/O.
# The writer announces itself on its first line and flushes; that line is the
# liveness signal, not a process name — this check looked for `dd` while the
# writer was python3 and refused two good laps before the name was the bug.
measure "$WRITER_HOST" 40 "$OUT/${WRITER_HOST}_writer_live.txt" '^WLIVE_END$' "that the writer is actually running on $WRITER_HOST" \
    "echo STARTED=\$(grep -ac '^WRITER_START' /tmp/lurst_writer.err 2>/dev/null); \
     echo ENDED=\$(grep -ac '^WRITER_DONE' /tmp/lurst_writer.err 2>/dev/null); \
     echo PROCS=\$(ps -o pid= -C python3 2>/dev/null | grep -ac .); \
     head -2 /tmp/lurst_writer.err 2>/dev/null; echo WLIVE_END"
WLIVE=$(field "$OUT/${WRITER_HOST}_writer_live.txt" STARTED)
WENDED=$(field "$OUT/${WRITER_HOST}_writer_live.txt" ENDED)
echo "STAGE writer on $WRITER_HOST: started=$WLIVE ended=$WENDED python3procs=$(field "$OUT/${WRITER_HOST}_writer_live.txt" PROCS) at +$(el)s"
[ "${WENDED:-0}" = 0 ] || { echo "  FAIL <the writer had already finished before the reset was issued: nothing was in flight>"
    echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=writerdone wall=$(el)s evidence=$OUT"; exit 3; }
if [ "${WLIVE:-0}" = 0 ]; then
    echo "  FAIL <no writer is running, so nothing was in flight when the reset landed: H4 would grade an empty workload>"
    echo "RESULT: VACUOUS label=$LABEL arm=$ARM stage=nowriter wall=$(el)s evidence=$OUT"; exit 3
fi

# ---- 5. THE RESET.  DEVICE, and escalation forbidden.
# Without NO_ESCALATE the kernel falls through to target, bus and host reset
# and a SUCCESS could come from any of them — which would be a different
# operation with a different scope, and no witness for the one we asked for.
measure "$A" 60 "$OUT/A_reset.txt" '^RESET_RC=' "the LOGICAL UNIT RESET on $A" \
    "R=\$(readlink -f $DEV); python3 - \"\$R\" <<'PYEOF'
import fcntl, os, struct, sys, time
SG_SCSI_RESET = 0x2284
SG_SCSI_RESET_DEVICE = 1
SG_SCSI_RESET_NO_ESCALATE = 0x100
dev = sys.argv[1]
fd = os.open(dev, os.O_RDWR)
buf = bytearray(struct.pack('i', SG_SCSI_RESET_DEVICE | SG_SCSI_RESET_NO_ESCALATE))
t0 = time.time()
rc = 0
try:
    fcntl.ioctl(fd, SG_SCSI_RESET, buf, True)
except OSError as e:
    rc = e.errno
ms = int((time.time() - t0) * 1000)
os.close(fd)
print('RESET_WALL_MS=%d' % ms)
print('RESET_RC=%d' % rc)
PYEOF"
RESET_RC=$(field "$OUT/A_reset.txt" RESET_RC)
RESET_MS=$(field "$OUT/A_reset.txt" RESET_WALL_MS)
echo "STAGE the reset returned rc=$RESET_RC in ${RESET_MS}ms at +$(el)s"

# H1.  rc=0 is the initiator's verdict.  The TARGET's answer is the counter,
# and both are required: a 0 with no new TMF response PDU is the initiator
# deciding by itself, which is exactly the substitute this route may not accept.
ck "the reset call returned success with escalation forbidden" "$RESET_RC" 0

# ---- 6. H2 and H3: what the reset cost us
prstate_into "$OUT/A_pr_after.txt" "the PR state after the reset"
sessid_into "$OUT/A_sess_after.txt" "the iSCSI session identity after the reset"
TMF1=$(field "$OUT/A_sess_after.txt" TMFRSP)
window_into "$OUT/A_ehwindow.txt" "$A" 90 "$MARK"
EHLU=$(cnt "$OUT/A_ehwindow.txt" 'LU Reset')
EHRES=$(grep -ac 'dev reset result = SUCCESS' "$OUT/A_ehwindow.txt")
echo "STAGE tmfrsp_pdus $TMF0 -> $TMF1, libiscsi EH lines: lu_reset=$EHLU result_success=$EHRES at +$(el)s"
ck "the TARGET answered a task-management function (its response PDU was counted)" \
   "$([ -n "$TMF1" ] && [ -n "$TMF0" ] && [ "$TMF1" -gt "$TMF0" ] && echo yes || echo no)" yes
ck "the transport logged the LOGICAL UNIT RESET it sent" \
   "$([ "$EHLU" -ge 1 ] && echo yes || echo no)" yes
ck "the registrations and the reservation survived the reset" \
   "$(diff -q "$OUT/A_pr_before.txt.state" "$OUT/A_pr_after.txt.state" > /dev/null && echo same || echo differs)" same
ck "the iSCSI session was not torn down by the reset" \
   "$(diff -q "$OUT/A_sess_before.txt.ids" "$OUT/A_sess_after.txt.ids" > /dev/null && echo same || echo differs)" same

# ---- 7. H4: the initiator that had work in flight
# The writer tallies at the END of its run, so reading its file while it is
# still writing reports zero errors whatever the reset did — the same false
# negative as a writer that never started, one stage later.  Wait for it, and
# treat a writer that never finishes as the finding it is: that is a hang.
measure "$WRITER_HOST" 150 "$OUT/${WRITER_HOST}_writer.txt" '^WRITER_END$' "what the in-flight writer saw on $WRITER_HOST" \
    "for i in \$(seq 1 130); do grep -aq '^WRITER_DONE' /tmp/lurst_writer.err 2>/dev/null && break; sleep 1; done; \
     echo DONE=\$(grep -ac '^WRITER_DONE' /tmp/lurst_writer.err 2>/dev/null); \
     echo OK=\$(sed -n 's/^WRITER_OK=//p' /tmp/lurst_writer.err | head -1); \
     echo ERRTOTAL=\$(sed -n 's/^WRITER_ERRTOTAL=//p' /tmp/lurst_writer.err | head -1); \
     grep -a '^WRITER_ERR_' /tmp/lurst_writer.err 2>/dev/null; echo WRITER_END"
WDONE=$(field "$OUT/${WRITER_HOST}_writer.txt" DONE)
WOK=$(field "$OUT/${WRITER_HOST}_writer.txt" OK)
WERR=$(field "$OUT/${WRITER_HOST}_writer.txt" ERRTOTAL)
echo "STAGE writer verdict on $WRITER_HOST: done=$WDONE writes_ok=$WOK errors=$WERR at +$(el)s"
grep -a '^WRITER_ERR_' "$OUT/${WRITER_HOST}_writer.txt" | sed 's/^/    /'
# THE ISSUER and A BYSTANDER are different questions, and only one of them is
# a pass/fail here.
#
# bare: the writer is on the node that ISSUES the reset.  Its own error handler
# runs, fails its outstanding commands and the midlayer re-submits them, so it
# must come back — measured 169662 writes and zero errors across the reset.  A
# hang there is a defect.
#
# live: the writer is on the PEER, which is never told the reset happened.  Its
# command was aborted at the target and no completion is ever sent, so it waits
# in blk_io_schedule inside __iomap_dio_rw for good — measured, D state, no
# error, no timeout, no retry.  That is a characterised HAZARD of this
# operation and the reason it may only be issued by a sole live initiator; it
# is recorded here rather than graded, because a probe that FAILs on the
# behaviour it was written to characterise teaches nobody anything.
if [ "$ARM" = bare ]; then
    ck "the issuing node's in-flight writer terminated rather than hanging" "$WDONE" 1
    ck "the issuing node's in-flight writer made progress across the reset" \
       "$([ -n "$WOK" ] && [ "$WOK" -gt 0 ] && echo yes || echo no)" yes
elif [ "$WDONE" = 1 ]; then
    echo "STAGE HAZARD-NOT-SEEN: the peer's writer completed ($WOK writes, $WERR errors) — this lap did NOT reproduce the stranded-I/O hazard"
else
    echo "STAGE HAZARD: the peer's in-flight write never completed and never failed — the reset stranded it. The peer needs a power cycle before it can unmount; the next prep_cluster does that."
fi

for n in "$A" "$B"; do
    value_now_into alive "$n" 30 "$OUT/${n}_alive.txt" '^ALIVE=1$' "liveness of $n after the reset" \
        "echo ALIVE=1"
    ck "$n is still answering after the reset" "$alive" "ALIVE=1"
    window_into "$OUT/${n}_dmesg.txt" "$n" 120 ""
    ck "no BUG or Oops on $n" "$(cnt "$OUT/${n}_dmesg.txt" 'BUG:\|Oops')" 0
    if [ "$ARM" = live ]; then
        ck "no filesystem shutdown on $n" \
           "$(cnt "$OUT/${n}_dmesg.txt" 'hutting down filesystem')" 0
    else
        echo "STAGE $n shutdown lines (recorded, not asserted on this arm): $(cnt "$OUT/${n}_dmesg.txt" 'hutting down filesystem')"
    fi
done

# ---- 8. give the LUN back the way we found it
if [ "$ARM" = bare ]; then
    measure "$A" 60 "$OUT/A_cleanup.txt" '^CLEAN_RC=' "releasing this probe's PR state on $A" \
        "R=\$(readlink -f $DEV); \
         sg_persist --out --release --param-rk=$KW --prout-type=7 \$R > /dev/null 2>&1; \
         sg_persist --out --register --param-rk=$KW \$R > /dev/null 2>&1; echo CLEAN_RC=\$?"
fi

echo "--- arm=$ARM reset_rc=$RESET_RC reset_ms=$RESET_MS keys_before=$NKEYS0"
[ "$ARM" = bare ] && echo "--- this arm wrote raw sectors into the LUN tail and held its own PR registration: run prep_cluster before any lap that mounts"
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"; exit 1
