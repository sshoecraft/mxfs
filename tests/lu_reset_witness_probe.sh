#!/bin/bash
# lu_reset_witness_probe.sh — does the MODULE get a trustworthy LOGICAL UNIT
# RESET witness, and does it refuse when it should?
#
# WHAT THIS IS FOR.  tests/lu_reset_probe.sh measured the TARGET: it answers a
# LOGICAL UNIT RESET, it preserves the persistent reservation and the
# registrations across it, and it does not tear the session down.  That said
# nothing about the module, because the reset was issued from a shell.  This
# probe exercises the path the fence will actually take: the module generates a
# nonce, executes the node-local helper, and judges the report the helper
# writes back into /proc/fs/mxfs/lu_reset_report.  What is under test is the
# JUDGEMENT, not the target.
#
# THE ARMS, and every one of them runs in the SAME lap on purpose.  A probe
# built only from refusals measures nothing: a module that refused everything —
# a broken channel, a helper that never runs, a parse bug — would pass every
# refusal arm and fail nobody.  So there is a control arm that MUST be
# witnessed, and the refusals only mean something beside it.
#
#   control        the designator the LUN actually carries.  The module must
#                  reach verdict=WITNESSED with issued=1 and reset_rc=0, and
#                  the report it logs must carry the nonce it generated.
#   wrong-wwid     a designator no device on the node carries.  The helper must
#                  refuse BEFORE opening anything, so the module must reach
#                  verdict=REFUSED with issued=0.  A REFUSED here is the only
#                  outcome that says the wrong logical unit was not reset.
#   no-helper      lu_reset_helper set to a path that does not exist.  The exec
#                  fails, so the module must reach verdict=NOT_RUN — the one
#                  verdict that states nothing was issued and the attempt is
#                  retryable.
#   replay         a write into the report channel while NO invocation is
#                  outstanding.  It must be refused (EPERM).  This is what
#                  makes the channel invocation-bound rather than a file: a
#                  report nobody asked for can never be read as an answer.
#
# WHAT IS ASSERTED AND WHAT IS ONLY RECORDED.  The verdicts are asserted.  The
# wall times are recorded — a reset that takes much longer than the 39-42 ms
# this fleet measured is a finding about the target and not a failure of this
# code — and so is the helper's own report, verbatim, because the module logs
# it and a reader should be able to see what the module judged.
#
# NOTHING HERE MOUNTS ANYTHING.  The module is loaded and not mounted, so it
# holds no registration and the probe cannot be confounded by MXFS's own PR
# state; the persistent reservation is captured before and after all the same,
# because a reset that destroyed it would invalidate every use this path has.
#
# Usage: tests/lu_reset_witness_probe.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
#
# Budget (derived): teardown on both nodes 2x15 + copying the helper and the
# module load 25 + the PR capture 15 + control arm, bounded by the module's own
# 45 s upcall bound but measured near 1 s, 45 + two refusal arms that return
# without issuing anything 20 + the replay check 10 + captures 20 = 165 s.
# Caller bound 200 s.
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # where the module runs and the reset is issued
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_lurw_${LABEL}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
# THE KERNEL-LOG WINDOW MUST BE UNIQUE TO THIS LAP.  The ring survives module
# reloads and the nodes are not rebooted between laps, so a marker built from
# the arm name alone matches the PREVIOUS lap's marker first and every verdict
# read out of that window belongs to a run that has already finished.  Measured:
# a second lap reported the first lap's nonce and wall time to the millisecond.
MARKID="LURW-$LABEL-$(date +%s%N)"
HELPER=/root/mxfs_lu_reset_witness.py
PROBE=/proc/fs/mxfs/lu_reset_probe
CHAN=/proc/fs/mxfs/lu_reset_report

echo "=== lu_reset_witness_probe label=$LABEL A(issuer)=$A $(date -u +%FT%TZ) ==="

# ---- 1. no MXFS may hold the LUN: a mounted peer's registration and its I/O
#         would both be collateral this probe has no reason to take.
for n in "$A" "$B"; do
    measure "$n" 60 "$OUT/${n}_teardown.txt" '^TEARDOWN_RC=' "the MXFS teardown on $n" \
        "umount $MNT > /dev/null 2>&1; rmmod mxfs > /dev/null 2>&1; sleep 1; echo LOADED=\$(lsmod | grep -c '^mxfs '); echo TEARDOWN_RC=0"
    ck "no mxfs module is loaded on $n" "$(field "$OUT/${n}_teardown.txt" LOADED)" 0
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=teardown evidence=$OUT"; exit 2; }

mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED
echo "STAGE device on $A: $DEV at +$(el)s"

# ---- 2. the designator, read from the node itself.  The module will be handed
#         this exact string and the helper must resolve the same device from it;
#         reading it here rather than from data/rigs.json means the two ends are
#         compared against what the node reports, not against a file.
measure "$A" 40 "$OUT/A_wwid.txt" '^WWID_END$' "the LUN designator on $A" \
    "R=\$(readlink -f $DEV); D=\$(basename \$R); \
     echo WWID=\$(cat /sys/block/\$D/device/wwid 2>/dev/null); \
     echo KREL=\$(uname -r); echo WWID_END"
WWID=$(field "$OUT/A_wwid.txt" WWID)
KREL=$(field "$OUT/A_wwid.txt" KREL)
if [ -z "$WWID" ]; then
    echo "ABORT: $A reports no wwid for $DEV — the module would have nothing to name"
    echo "RESULT: ABORT label=$LABEL stage=wwid evidence=$OUT"; exit 2
fi
echo "STAGE wwid=$WWID krel=$KREL at +$(el)s"

# ---- 3. the helper, node-local.  A fence that upcalls into the NFS export
#         would make one node's storage recovery depend on the build host.
KOMD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
measure "$A" 90 "$OUT/A_deploy.txt" '^DEPLOY_RC=' "deploying the helper and the module on $A" \
    "cp -f /src/mxfs/tools/mxfs_lu_reset_witness.py $HELPER && chmod 755 $HELPER; \
     echo HELPER_MD5=\$(md5sum $HELPER | awk '{print \$1}'); \
     cp -f /src/mxfs/mxfs.ko /root/mxfs.ko.lurw; \
     echo KO_MD5=\$(md5sum /root/mxfs.ko.lurw | awk '{print \$1}'); \
     insmod /root/mxfs.ko.lurw dyndbg=+p force_transport=1 target_cache_protected=1 \
        lu_reset_probe_enable=1 lu_reset_helper=$HELPER > /dev/null 2>&1; \
     echo INSMOD_RC=\$?; \
     echo LOADED=\$(lsmod | grep -c '^mxfs '); \
     echo CHAN=\$([ -e $CHAN ] && echo yes || echo no); \
     echo PROBEF=\$([ -e $PROBE ] && echo yes || echo no); \
     echo DEPLOY_RC=0"
ck "$A carries the module this tree built" "$(field "$OUT/A_deploy.txt" KO_MD5)" "$KOMD5"
ck "$A loaded the module" "$(field "$OUT/A_deploy.txt" LOADED)" 1
ck "the report channel exists" "$(field "$OUT/A_deploy.txt" CHAN)" yes
ck "the probe trigger exists" "$(field "$OUT/A_deploy.txt" PROBEF)" yes
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=deploy evidence=$OUT"; exit 2; }

# ---- 4. the replay check, BEFORE anything is armed.  An unsolicited report
#         must be refused; if it were accepted it could be read as the answer to
#         a later question.
measure "$A" 30 "$OUT/A_replay.txt" '^REPLAY_END$' "an unsolicited report write on $A" \
    "printf 'MXFS-LURW-BEGIN\\nNONCE=0000000000000000\\nWITNESSED=1\\nMXFS-LURW-END\\n' > $CHAN 2>/dev/null; \
     echo REPLAY_RC=\$?; echo REPLAY_END"
ck "an unsolicited report is refused by the channel" \
   "$([ "$(field "$OUT/A_replay.txt" REPLAY_RC)" != 0 ] && echo refused || echo accepted)" refused

# ---- 5. the PR state, so a reset that destroyed the exclusion it is issued
#         under cannot pass unnoticed.  Absorb the unit attention first: the
#         command after a reset reports POWER ON / RESET OCCURRED, and a reader
#         that does not consume it reports absent state that is present.
prstate_into() {   # $1 outfile, $2 what
    measure "$A" 60 "$1" '^PR_END$' "$2" \
        "R=\$(readlink -f $DEV); \
         sg_persist -i -k \$R > /dev/null 2>&1; \
         echo '--- keys'; sg_persist -i -k \$R 2>&1 | grep -a '0x' | sort; \
         echo '--- resv'; sg_persist -i -r \$R 2>&1 | grep -aiv 'generation' | sed -n '2,6p'; \
         echo PR_END"
    sed -n '/^--- keys/,/^PR_END/p' "$1" | grep -av '^PR_END$' > "$1.state"
}
prstate_into "$OUT/A_pr_before.txt" "the PR state before any reset"

# ---- 6. the arms.  Each writes one line into the module's probe trigger and
#         the verdict is read out of the module's own log, not out of the
#         helper's exit status: what is under test is what the MODULE concluded.
arm() {   # $1 name, $2 designator to hand the module, $3 extra pre-command
    local name=$1 wwid=$2 pre=${3:-true}
    measure "$A" 120 "$OUT/A_arm_${name}.txt" '^ARM_END$' "arm $name on $A" \
        "$pre; \
         echo '$MARKID-$name' > /dev/kmsg 2>/dev/null; \
         s=\$(date +%s%N); \
         echo '$wwid 7 lurw-$name' > $PROBE 2>/dev/null; \
         echo WRITE_RC=\$?; \
         e=\$(date +%s%N); echo WALL_MS=\$(( (e-s)/1000000 )); \
         dmesg | sed -n '/$MARKID-$name/,\$p' | grep -a 'P305-LURESET' | sed 's/^/DMESG: /'; \
         echo ARM_END"
    grep -a '^DMESG: ' "$OUT/A_arm_${name}.txt" > "$OUT/A_arm_${name}.dmesg"
}

# control — this must be witnessed or every refusal below proves nothing.
arm control "$WWID"
VERD=$(grep -ao 'verdict=[A-Z_]*' "$OUT/A_arm_control.dmesg" | head -1 | cut -d= -f2)
ISSUED=$(grep -ao 'issued=[0-9]*' "$OUT/A_arm_control.dmesg" | head -1 | cut -d= -f2)
RRC=$(grep -ao 'reset_rc=-\?[0-9]*' "$OUT/A_arm_control.dmesg" | head -1 | cut -d= -f2)
NONCE_ISS=$(grep -ao 'P305-LURESET-ISSUE.*nonce=[0-9a-f]*' "$OUT/A_arm_control.dmesg" | grep -ao 'nonce=[0-9a-f]*' | head -1 | cut -d= -f2)
NONCE_REP=$(grep -a 'P305-LURESET-REPORT' "$OUT/A_arm_control.dmesg" | grep -ao 'nonce=[0-9a-f]*' | head -1 | cut -d= -f2)
RESET_MS=$(grep -ao 'reset_ms=[0-9]*' "$OUT/A_arm_control.dmesg" | head -1 | cut -d= -f2)
UP_MS=$(grep -ao 'upcall_ms=[0-9]*' "$OUT/A_arm_control.dmesg" | head -1 | cut -d= -f2)
ck "control: the module reached a witness" "${VERD:-none}" WITNESSED
ck "control: the command boundary was crossed" "${ISSUED:-none}" 1
ck "control: the reset returned success" "${RRC:-none}" 0
ck "control: the report carries the nonce the module generated" \
   "$([ -n "$NONCE_ISS" ] && [ "$NONCE_ISS" = "$NONCE_REP" ] && echo bound || echo unbound)" bound
echo "FINDING control reset_ms=${RESET_MS:-?} upcall_ms=${UP_MS:-?} nonce=${NONCE_ISS:-?} at +$(el)s"

# wrong-wwid — nothing on this node carries it, so the helper must refuse before
# opening any device.  issued=0 is the assertion that matters.
arm wrongwwid "naa.0000000000000000000000000000dead"
VERD2=$(grep -ao 'verdict=[A-Z_]*' "$OUT/A_arm_wrongwwid.dmesg" | head -1 | cut -d= -f2)
ISSUED2=$(grep -ao 'issued=[0-9]*' "$OUT/A_arm_wrongwwid.dmesg" | head -1 | cut -d= -f2)
ck "wrong-wwid: the module refused" "${VERD2:-none}" REFUSED
ck "wrong-wwid: nothing was issued" "${ISSUED2:-none}" 0

# no-helper — the exec fails, so NOT_RUN.  Restore the path afterwards so a
# later arm in the same lap is not silently testing the broken one.
arm nohelper "$WWID" "echo /root/does-not-exist-mxfs-lurw > /sys/module/mxfs/parameters/lu_reset_helper"
VERD3=$(grep -ao 'verdict=[A-Z_]*' "$OUT/A_arm_nohelper.dmesg" | head -1 | cut -d= -f2)
ISSUED3=$(grep -ao 'issued=[0-9]*' "$OUT/A_arm_nohelper.dmesg" | head -1 | cut -d= -f2)
ck "no-helper: the module reports that nothing ran" "${VERD3:-none}" NOT_RUN
ck "no-helper: nothing was issued" "${ISSUED3:-none}" 0
$SSH "$A" "echo $HELPER > /sys/module/mxfs/parameters/lu_reset_helper" > /dev/null 2>&1

# ---- 7. the PR state again.  A reset that cleared the registrations or the
#         reservation would have destroyed the exclusion every use of this path
#         is issued under, and that is a failure of the route, not a finding.
prstate_into "$OUT/A_pr_after.txt" "the PR state after the reset"
if diff -q "$OUT/A_pr_before.txt.state" "$OUT/A_pr_after.txt.state" > /dev/null 2>&1; then
    ck "the reset preserved the registrations and the reservation" same same
else
    ck "the reset preserved the registrations and the reservation" changed same
    diff -u "$OUT/A_pr_before.txt.state" "$OUT/A_pr_after.txt.state" > "$OUT/pr_diff.txt" 2>&1
fi

# ---- 8. the node is still healthy.  An LU reset whose aborted commands crash,
#         hang or shut down the issuing node fails the bar even when the
#         target-side retirement was valid.
measure "$A" 40 "$OUT/A_health.txt" '^HEALTH_END$' "the node's health after the resets" \
    "echo BUGS=\$(dmesg | grep -ac 'BUG:\|Oops\|kernel panic'); \
     echo SHUT=\$(dmesg | grep -ac 'Shutting down filesystem'); \
     echo LOADED=\$(lsmod | grep -c '^mxfs '); \
     echo ALIVE=yes; echo HEALTH_END"
ck "no BUG or Oops on the issuing node" "$(field "$OUT/A_health.txt" BUGS)" 0
ck "no filesystem shutdown on the issuing node" "$(field "$OUT/A_health.txt" SHUT)" 0
ck "the issuing node still answers" "$(field "$OUT/A_health.txt" ALIVE)" yes

$SSH "$A" "rmmod mxfs > /dev/null 2>&1; true" > /dev/null 2>&1

echo "=== lu_reset_witness_probe $LABEL: fails=$fails wall=$(el)s ==="
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; exit 1
