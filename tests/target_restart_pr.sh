#!/bin/bash
# target_restart_pr.sh — the fence-matrix ruling's TARGET-RESTART tranche
# (docs/rulings/fence-crash-matrix-cuts.md, "Target restart";
# D-FENCE-CRASH-MATRIX-UNTESTED): does the target's persistent-reservation
# database survive a restart of its iSCSI service (MODE=service) or of the
# target host (MODE=host) with the LATEST COMPLETE state — the survivor's
# registration present, the fenced victim's key STILL ABSENT after its
# acknowledged PREEMPT AND ABORT, the fencing reservation held — while a
# recovery is ACTIVE (certified, claimed, unreplayed)?  And does MXFS fail
# closed if it does not?
#
# ACCESS.  The target is restarted over ssh to its host.  The lap takes that
# access from the lab secrets store (~/.config/mxfslab/secrets, resolved by
# tools/mxfs_secrets.sh, never in the tree) as one entry keyed by the RIG TAG
# tools/mxfs_rig_tag.sh prints, so the same lap runs against any declared rig:
#
#     <tag> host=<addr> username=<user> password=<pw> restart_cmd=<cmd> reboot_cmd=<cmd>
#
# restart_cmd is the target host's own command that restarts its iSCSI target
# service; reboot_cmd reboots that host.  Fields with spaces are not
# representable in that store's one-token-per-field format, so a command with
# arguments is given as a path to a script ON THE TARGET HOST.  Without the
# entry the lap ABORTs at stage=access and measures nothing.  The password goes
# to sshpass through its environment (sshpass -e); it is never written to a
# file.
#
# A rig whose data/rigs.json entry declares restart_forbidden is never acted on:
# the lap ABORTs at stage=forbidden before it resolves any credential.  This
# tranche is measured on a rig whose target may be restarted freely, such as an
# LIO or SCST target stood up on a bench host for the purpose
# (tools/lio_bench_target.sh).
#
# A TARGET HOST THAT IS A VM ON THIS HOST (data/rigs.json target_vm) is crashed
# in MODE=host with virsh destroy and started again, not asked to reboot itself:
# a crash loses whatever the target had not written durably, which is the
# question the host arm asks, and a clean reboot would flush it first.  That
# arm needs no ssh entry; the service arm still does.
#
# THE DEVICE IS BOUND BY IDENTIFIER BEFORE THE PREP.  The rig tag selects the
# LUN (data/rigs.json lun_wwid) and the prep is told that device by its
# /dev/disk/by-id name when the caller has not set MXFS_DEV, because a prep
# that is not told formats the transport's default disk, and on a node that
# reaches two targets that is the OTHER rig's LUN.
#
# THE SHAPE, in the order the ruling requires ("restart laps run around P&A
# completion, certification and active recovery, not only on an idle cluster"):
#   1. prep; tests/pr_aptpl_probe.sh must PASS (APTPL capable AND active) —
#      the tranche opens with that and a capable-but-off target is that
#      probe's FAIL, not this lap's subject.
#   2. the victim B fsyncs files; the survivor A arms dbg_replay_hold_ms so
#      the recovery parks CLAIMED and SEALED before any image; B is destroyed;
#      A fences it (the P&A is acknowledged, B's key is gone), certifies, claims
#      and holds.
#   3. PR state BEFORE, read from A: A's key present, B's key absent, the
#      fencing reservation held, generation G0.
#   4. a poller on A reads the reservation once a second across the restart
#      into a file, so the FIRST answer the target gives after it returns is on
#      record — an unreserved answer there is the "unreserved access window"
#      the ruling names.  The poll in flight when the sessions drop does not
#      fail: the initiator queues it through session recovery and it is the
#      first command to reach the LUN once the sessions return, so its answer
#      is what the reopened LUN said to the first command in, and the gap
#      between its timestamp and the previous poll's is the outage as this
#      initiator saw it (2 s for a service restart, 16-17 s for a crash and
#      reboot of the target VM, s162a-d).
#   5. the restart, over ssh to the target host; the nodes' iSCSI sessions drop
#      and iscsid re-logs them in (replacement_timeout 120 s).
#   6. PR state AFTER, read from A once its session is back: persistence is
#      A's key present AND B's key absent AND the reservation held; generation
#      G1 is recorded (it may reset or wrap — MXFS never compares it).
#   7. what MXFS did: with persistence, A's health tick stays OK, the hold
#      ends by its timer, the slice is replayed (P163-RECOVERY-COMPLETE), B
#      returns and every file it fsynced is byte-identical.  Without it, A
#      reads SELF_GONE and withdraws (P277-FENCED-SELF-WITHDRAW), the hold ends
#      on the shutdown and nothing is replayed — graded FAIL on persistence
#      (the target did not keep what its APTPL bit promised) and PASS on
#      failing closed, both stated.
#
# BUDGET (derived): B's boot after the previous lap destroyed it <=150 + prep
# <=400 (64 s on a warm fleet, 354-364 s when B has just booted) + APTPL probe
# 30 + files 30 + fence to hold ~90 + PR reads 30 + the restart and the
# sessions' return: RECONNECT_BOUND 120 s for BOTH modes, iscsid's
# replacement_timeout, past which the session is torn down and this lap's
# reconnect wait cannot succeed at all (measured returns: 2 s service, 16-17 s
# for the target VM's crash and reboot — its kernel is up in <3 s and
# target.service has restored the configuration ~5 s after boot; s162a-d) +
# the hold's remainder (HOLD_MS 300 s covers both with margin) + the replay
# ~20 + B's boot ~150 + B's mount ~90 + verify 40 = ~1100 s.  Caller bound
# 1200 for either mode (measured walls 606-1021 s, s162a-d).  The hold is
# armed long enough that the restart lands INSIDE it; a hold that ends before
# the target is back is graded VACUOUS, not PASS.
#
# Cleanup: B started; A is left as the lap left it; the next prep re-formats.
#
# Usage: MODE=service|host tests/target_restart_pr.sh <label>
# Env:   MXFS_NODE_LIST (test1,test2), NFILES (32), HOLD_MS (300000),
#        RECONNECT_BOUND (120), FENCE_BOUND (200)
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
MODE=${MODE:-service}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the survivor / prover
B=${MXFS_NODE_LIST##*,}          # the victim
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
NFILES=${NFILES:-32}
HOLD_MS=${HOLD_MS:-300000}
FENCE_BOUND=${FENCE_BOUND:-200}
case $MODE in
    service) RECONNECT_BOUND=${RECONNECT_BOUND:-120}; CMD_FIELD=restart_cmd ;;
    host)    RECONNECT_BOUND=${RECONNECT_BOUND:-120}; CMD_FIELD=reboot_cmd ;;
    *) echo "ABORT: MODE must be service or host (got '$MODE')"; exit 2 ;;
esac
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_trpr_${MODE}_${LABEL}
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
. "$(dirname "$0")/../tools/mxfs_secrets.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MARK="TRPR-MARK-$LABEL"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
waitboot() {
    local n w=0 st
    for n in "$@"; do
        st=$($VIRSH domstate "$n" 2>/dev/null | head -1)
        [ "$st" = running ] || { echo "STAGE $n was '$st' — starting it"; $VIRSH start "$n" >/dev/null 2>&1; }
    done
    for n in "$@"; do
        until [ "$(timeout 15 $SSH "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 48 ]; do
            w=$((w+1)); sleep 5
        done
    done
    echo "STAGE boot-wait $* polls=$w at +$(el)s"
}
CLEANED=0
cleanup() {
    [ "$CLEANED" = 1 ] && return 0
    CLEANED=1
    $VIRSH start "$B" >/dev/null 2>&1
    echo "STAGE cleanup: $B started; the caller must prep_cluster before the next lap at +$(el)s"
}
trap cleanup EXIT

echo "=== target_restart_pr label=$LABEL mode=$MODE A(survivor)=$A B(victim)=$B hold_ms=$HOLD_MS reconnect_bound=${RECONNECT_BOUND}s $(date -u +%FT%TZ) ==="

# ---- 0. the rig's own word first: a target the lab may never restart.
# data/rigs.json[<tag>].restart_forbidden is the owner's directive that this
# rig's target is not restartable for tests.  It is read before any credential
# is resolved, so no entry in the secrets store can make this lap act on such a
# target; the guard is the directive in code and is not bypassed.
RIG_TAG=$(tools/mxfs_rig_tag.sh 2>/dev/null || true)
if [ -z "$RIG_TAG" ]; then
    echo "ABORT: the rig cannot be established (tools/mxfs_rig_tag.sh), so its restart policy is unknown; a target of unknown policy is never restarted"
    echo "RESULT: ABORT label=$LABEL stage=forbidden mode=$MODE evidence=$OUT"; exit 2
fi
if [ "$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print("yes" if (d.get(sys.argv[2]) or {}).get("restart_forbidden") else "no")' data/rigs.json "$RIG_TAG" 2>/dev/null)" != no ]; then
    echo "ABORT: rig '$RIG_TAG' declares restart_forbidden in data/rigs.json — its target is never restarted, so this tranche cannot be measured on it; it needs a target the lab owns and may restart"
    echo "RESULT: ABORT label=$LABEL stage=forbidden mode=$MODE evidence=$OUT"; exit 2
fi

# ---- 0a. the device, by the rig's declared identifier, before the prep is told one
if [ -z "${MXFS_DEV:-}" ]; then
    decl=$(mxfs_dev_declared) || { echo "$decl"; exit 2; }
    export MXFS_DEV=/dev/disk/by-id/wwn-0x$decl
fi
echo "STAGE device for rig '$RIG_TAG': $MXFS_DEV"

# ---- 0b. the access this tranche needs, checked before anything is spent
TARGET_VM=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1])); print((d.get(sys.argv[2]) or {}).get("target_vm") or "")' data/rigs.json "$RIG_TAG" 2>/dev/null)
if [ "$MODE" = host ] && [ -n "$TARGET_VM" ]; then
    st=$($VIRSH domstate "$TARGET_VM" 2>/dev/null | head -1)
    if [ "$st" != running ]; then
        echo "ABORT: rig '$RIG_TAG' declares its target host is the VM '$TARGET_VM' on this host, but it is '${st:-absent}' rather than running"
        echo "RESULT: ABORT label=$LABEL stage=access mode=$MODE evidence=$OUT"; exit 2
    fi
    echo "STAGE target host for rig '$RIG_TAG' is the VM '$TARGET_VM' on this host (running): the host arm crashes it with virsh destroy at +$(el)s"
else
    QHOST=$(secrets_get "$RIG_TAG" host 2>/dev/null || true)
    QUSER=$(secrets_get "$RIG_TAG" username 2>/dev/null || true)
    QCMD=$(secrets_get "$RIG_TAG" "$CMD_FIELD" 2>/dev/null || true)
    if [ -z "$QHOST" ] || [ -z "$QUSER" ] || [ -z "$QCMD" ] || ! secrets_get "$RIG_TAG" password >/dev/null 2>&1; then
        echo "ABORT: no target-host access in the secrets store for rig '$RIG_TAG' (need an entry '$RIG_TAG host= username= password= $CMD_FIELD='); the target cannot be restarted from this host"
        echo "RESULT: ABORT label=$LABEL stage=access mode=$MODE evidence=$OUT"; exit 2
    fi
    echo "STAGE target-host access resolved for rig '$RIG_TAG': $QUSER@$QHOST, $CMD_FIELD present at +$(el)s"
fi
targethost() {   # <bound> <command...> — one ssh to the target host, password via the environment only
    local bound=$1; shift
    SSHPASS=$(secrets_get "$RIG_TAG" password) timeout "$bound" sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 "$QUSER@$QHOST" "$@" < /dev/null
}

# ---- 1. the fleet, and APTPL capable AND active
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
if [ "$(strings -a mxfs.ko | grep -c 'P-FREPLAY-HOLD')" = 0 ]; then
    echo "ABORT: mxfs.ko carries no P-FREPLAY-HOLD replay hold (build the tree first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV
timeout 90 tests/pr_aptpl_probe.sh "${LABEL}-aptpl" "$A" > "$OUT/aptpl.log" 2>&1
arc=$?
echo "STAGE APTPL probe rc=$arc: $(grep -a 'PTPL_C\|RESULT' "$OUT/aptpl.log" | tr '\n' ' ' | cut -c1-200)"
if [ "$arc" != 0 ]; then
    echo "ABORT: APTPL is not both capable and active on this LUN (tests/pr_aptpl_probe.sh rc=$arc); the restart tranche opens with that and this lap does not measure past it"
    echo "RESULT: ABORT label=$LABEL stage=aptpl evidence=$OUT"; exit 2
fi
for n in "$A" "$B"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "ASLOT=\$slot_$A; BSLOT=\$slot_$B"
echo "STAGE identities: $A slot $ASLOT (survivor), $B slot $BSLOT (victim) at +$(el)s"

# ---- 2. the victim's dirty slice, the hold, the cut, the fence, the claim
measure "$B" 90 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/trpr_$LABEL; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'trpr %s file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before the cut" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=files evidence=$OUT"; exit 2; }
measure "$A" 30 "$OUT/A_arm.txt" '^ARMED hold_ms=[0-9]+$' "the replay hold on $A" \
    "echo $MARK > /dev/kmsg; echo $HOLD_MS > $PARM/dbg_replay_hold_ms; echo ARMED hold_ms=\$(cat $PARM/dbg_replay_hold_ms)"
ck "A armed the replay hold for this lap" "$(grep -a '^ARMED' "$OUT/A_arm.txt")" "ARMED hold_ms=$HOLD_MS"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=arm evidence=$OUT"; exit 2; }
$VIRSH destroy "$B" > "$OUT/destroy.txt" 2>&1
echo "STAGE $B destroyed at +$(el)s — the survivor must fence it (P&A), seal, claim, and then hold"
wait_for_into held "$A" "$FENCE_BOUND" "$MARK" "P-FREPLAY-HOLD slot"
window_into "$OUT/A_fence.txt" "$A" 60 "$MARK"
SEALED=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-SEALED')
HELD=$(cnt "$OUT/A_fence.txt" 'P-FREPLAY-HOLD slot')
CLAIMED=$(cnt "$OUT/A_fence.txt" 'P236-RECOV-CLAIMED')
echo "STAGE the survivor reached the hold at +$(el)s: waited=${held}s sealed=$SEALED claimed=$CLAIMED held=$HELD"
if [ "$HELD" = 0 ]; then
    echo "  VACUOUS the replay hold never fired: no certified, claimed, unreplayed recovery stands for the restart to land on"
    echo "RESULT: VACUOUS label=$LABEL reason=nohold wall=$(el)s evidence=$OUT"; exit 3
fi
ck "the certificate was sealed before the hold" "$([ "$SEALED" -ge 1 ] && echo yes || echo no)" yes
ck "the survivor holds the recovery execution lease" "$([ "$CLAIMED" -ge 1 ] && echo yes || echo no)" yes
HOLD_T0=$(date +%s)

# ---- 3. PR state BEFORE, from the survivor
pr_read() {   # <node> <file> <what>
    measure "$1" 40 "$2" '^PR_END$' "$3" \
        "sg_persist --in --read-keys \$(readlink -f $MXFS_DEV) 2>&1; sg_persist --in --read-reservation \$(readlink -f $MXFS_DEV) 2>&1; echo PR_END"
}
pr_read "$A" "$OUT/A_pr_before.txt" "the PR state on $A before the restart"
mapfile -t KEYS0 < <(grep -aoE '^ +0x[0-9a-f]+$' "$OUT/A_pr_before.txt" | tr -d ' ')
G0=$(grep -ao 'PR generation=0x[0-9a-f]*' "$OUT/A_pr_before.txt" | head -1 | cut -d= -f2)
RESV0=$(grep -a 'scope:' "$OUT/A_pr_before.txt" | head -1 | tr -s ' ' | sed 's/^ //')
# The victim's key as the fence recorded it: P-PRKEY-FENCED names the slot
# index and the key in hex when the P&A removed it; the certified line carries
# the same key in decimal and is the fallback for a fence kind that logs no
# P-PRKEY-FENCED.  (The arm line names victim and prover only, never the key;
# reading it here produced an empty capture, s161a/s161b.)
value_now_into bkey "$A" 30 "$OUT/B_key.txt" '^0x[0-9a-f]+$' "the victim's PR key as the fence recorded it" \
    "k=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ao 'P-PRKEY-FENCED idx=$BSLOT key=0x[0-9a-f]*' | head -1 | grep -ao '0x[0-9a-f]*'); [ -n \"\$k\" ] || k=\$(dmesg | sed -n '/$MARK/,\$p' | grep -ao 'P236-FENCE-CERTIFIED slot=$BSLOT .*key=[0-9]*' | head -1 | grep -ao 'key=[0-9]*' | cut -d= -f2 | xargs -r printf '0x%x'); echo \$k"
echo "STAGE PR state before: keys=${#KEYS0[@]} [${KEYS0[*]:-none}] reservation='${RESV0:-none}' generation=$G0; the victim's fenced key was $bkey at +$(el)s"
ck "the fenced victim's key is absent before the restart (the P&A was acknowledged)" "$(printf '%s\n' "${KEYS0[@]}" | grep -ac "^$bkey$")" 0
ck "exactly one registration (the survivor's) stands before the restart" "${#KEYS0[@]}" 1
ck "the fencing reservation is held before the restart" "$([ -n "$RESV0" ] && echo yes || echo no)" yes
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=pr-before evidence=$OUT"; exit 2; }
AKEY=${KEYS0[0]}

# ---- 4. the poller on the survivor, across the restart
POLL_S=$(( RECONNECT_BOUND + 60 ))
rs 20 "$A" "rm -f /run/trpr_poll.txt; nohup sh -c 'for i in \$(seq 1 $POLL_S); do printf \"%s \" \$(date +%s); sg_persist --in --read-reservation \$(readlink -f $MXFS_DEV) 2>&1 | grep -a \"scope:\|NO reservation\|rror\|fail\|Unit\|not ready\" | head -1 | tr -s \" \"; echo; sleep 1; done; echo POLL_END' > /run/trpr_poll.txt 2>&1 & echo POLLER_STARTED" > "$OUT/A_poll_start.txt" 2>/dev/null
capture_require "$OUT/A_poll_start.txt" '^POLLER_STARTED$' "the reservation poller on $A"
rs 15 "$A" "echo $MARK-RESTART > /dev/kmsg" >/dev/null 2>&1
T_RESTART=$(date +%s)

# ---- 5. THE RESTART
if [ "$MODE" = host ] && [ -n "$TARGET_VM" ]; then
    { $VIRSH destroy "$TARGET_VM"; echo "destroy rc=$?"; $VIRSH start "$TARGET_VM"; echo "start rc=$?"; } > "$OUT/target_restart.txt" 2>&1
    QRC=$(grep -ao 'start rc=[0-9]*' "$OUT/target_restart.txt" | cut -d= -f2)
    echo "STAGE target VM '$TARGET_VM' crashed and started again at +$(el)s: $(tr '\n' ' ' < "$OUT/target_restart.txt" | cut -c1-160)"
    if [ "${QRC:-1}" != 0 ]; then
        echo "ABORT: the target VM did not start again (rc=${QRC:-none}); read $OUT/target_restart.txt"
        echo "RESULT: ABORT label=$LABEL stage=restart mode=$MODE evidence=$OUT"; exit 2
    fi
else
    targethost 60 "$QCMD" > "$OUT/target_restart.txt" 2>&1
    QRC=$?
    echo "STAGE target-host $MODE restart command returned rc=$QRC at +$(el)s: $(tr '\n' ' ' < "$OUT/target_restart.txt" | cut -c1-160)"
    if [ "$MODE" = service ] && [ "$QRC" != 0 ]; then
        echo "ABORT: the target host's restart command failed (rc=$QRC); read $OUT/target_restart.txt"
        echo "RESULT: ABORT label=$LABEL stage=restart evidence=$OUT"; exit 2
    fi
    # (a host reboot drops the ssh session and may return non-zero by itself)
fi

# ---- 6. the sessions come back, then PR state AFTER
rs $(( RECONNECT_BOUND + 30 )) "$A" "for i in \$(seq 1 $RECONNECT_BOUND); do if sg_persist --in --read-keys \$(readlink -f $MXFS_DEV) >/dev/null 2>&1; then echo BACK_AFTER=\$i; break; fi; sleep 1; done; echo SESSIONS=\$(iscsiadm -m session 2>/dev/null | grep -c .); echo RECONNECT_END" > "$OUT/A_reconnect.txt" 2>/dev/null
capture_require "$OUT/A_reconnect.txt" '^RECONNECT_END$' "the survivor's reconnect wait"
BACK=$(field "$OUT/A_reconnect.txt" BACK_AFTER)
echo "STAGE the survivor's LUN answered PR IN again after '${BACK:-never within ${RECONNECT_BOUND}s}' (sessions=$(field "$OUT/A_reconnect.txt" SESSIONS)) at +$(el)s"
if [ -z "${BACK:-}" ]; then
    echo "  FAIL the LUN did not answer PR IN within ${RECONNECT_BOUND}s of the restart — read $OUT/A_reconnect.txt and the target host"
    fails=$((fails+1))
    echo "RESULT: FAIL label=$LABEL fails=$fails stage=reconnect evidence=$OUT"; exit 1
fi
pr_read "$A" "$OUT/A_pr_after.txt" "the PR state on $A after the restart"
mapfile -t KEYS1 < <(grep -aoE '^ +0x[0-9a-f]+$' "$OUT/A_pr_after.txt" | tr -d ' ')
G1=$(grep -ao 'PR generation=0x[0-9a-f]*' "$OUT/A_pr_after.txt" | head -1 | cut -d= -f2)
RESV1=$(grep -a 'scope:' "$OUT/A_pr_after.txt" | head -1 | tr -s ' ' | sed 's/^ //')
echo "STAGE PR state after: keys=${#KEYS1[@]} [${KEYS1[*]:-none}] reservation='${RESV1:-none}' generation=$G1 (was $G0) at +$(el)s"
A_PRESENT=$(printf '%s\n' "${KEYS1[@]}" | grep -ac "^$AKEY$")
B_PRESENT=$(printf '%s\n' "${KEYS1[@]}" | grep -ac "^$bkey$")
ck "PERSISTENCE: the survivor's registration survived the $MODE restart" "$A_PRESENT" 1
ck "PERSISTENCE: the fenced victim's key STAYED ABSENT across the $MODE restart (an acknowledged P&A is not undone by a restored database)" "$B_PRESENT" 0
ck "PERSISTENCE: the fencing reservation survived the $MODE restart" "$([ -n "$RESV1" ] && echo yes || echo no)" yes
ck "PERSISTENCE: the reservation is the same type as before" "$RESV1" "$RESV0"
[ "$G1" = "$G0" ] && echo "  INFO the PR generation is unchanged across the restart ($G0): a matching number proves nothing about what happened between, and MXFS never compares it" \
                  || echo "  INFO the PR generation moved across the restart ($G0 -> $G1)"

# the poller: the first answer after the outage
sleep 3
measure "$A" 40 "$OUT/A_poll.txt" '^POLL_END$|^[0-9]+ ' "the reservation poller's record on $A" "cat /run/trpr_poll.txt; grep -q POLL_END /run/trpr_poll.txt || echo POLL_END"
FIRST_BACK=$(awk -v t="$T_RESTART" '$1>=t && ($0 ~ /scope:/ || $0 ~ /NO reservation/) {print; exit}' "$OUT/A_poll.txt")
# The poll in flight when the sessions dropped blocks in session recovery and
# completes as the first command into the reopened LUN, so the outage as this
# initiator saw it is the largest gap between consecutive poll timestamps from
# the restart on, not a count of failed polls (which are few or none).
GAP=$(awk -v t="$T_RESTART" '$1 ~ /^[0-9]+$/ { if (prev && $1 >= t && $1 - prev > gap) gap = $1 - prev; prev = $1 } END { print gap + 0 }' "$OUT/A_poll.txt")
UNANSWERED=$(awk -v t="$T_RESTART" '$1>=t && ($0 ~ /rror/ || $0 ~ /fail/ || $0 ~ /not ready/ || NF==1) {c++} END {print c+0}' "$OUT/A_poll.txt")
echo "STAGE the poller's outage gap was ${GAP}s (largest gap between consecutive polls from the restart on; $UNANSWERED poll(s) answered with an error); the first answer after the outage: [$(echo "$FIRST_BACK" | cut -c1-140)]"
case $FIRST_BACK in
    *scope:*)          echo "  PASS the first PR IN to reach the reopened LUN found the reservation HELD — the poll queued through the ${GAP}s outage was the first command in after the sessions returned; no unreserved window observed" ;;
    *"NO reservation"*) echo "  FAIL the first PR IN to reach the reopened LUN found it UNRESERVED — an unreserved access window exists while the target reopens"; fails=$((fails+1)) ;;
    *)                 echo "  INFO the poller produced no readable answer after the restart; the window is unmeasured by it (read $OUT/A_poll.txt)" ;;
esac

# ---- 7. what MXFS did with it
HOLD_LEFT=$(( HOLD_MS / 1000 - ( $(date +%s) - HOLD_T0 ) ))
if [ "$HOLD_LEFT" -le 0 ]; then
    echo "  VACUOUS the replay hold (${HOLD_MS} ms) ended before the target was back; the recovery was not active across the restart — raise HOLD_MS"
    echo "RESULT: VACUOUS label=$LABEL reason=hold-ended wall=$(el)s evidence=$OUT"; exit 3
fi
wait_for_into hend "$A" $(( HOLD_LEFT + 30 )) "$MARK-RESTART" "P-FREPLAY-HOLD-END"
sleep 5
window_into "$OUT/A_window.txt" "$A" 60 "$MARK-RESTART"
count_file_into selfgone "$OUT/A_window.txt" 'P305-RESV-SELF-GONE-INSPECT'
count_file_into withdrew "$OUT/A_window.txt" 'P277-FENCED-SELF-WITHDRAW'
count_file_into repaired "$OUT/A_window.txt" 'P305-RESV-REPAIRED'
count_file_into health   "$OUT/A_window.txt" 'P305-RESV-HEALTH'
count_file_into complete "$OUT/A_window.txt" 'P163-RECOVERY-COMPLETE'
count_file_into oops     "$OUT/A_window.txt" 'BUG:\|Oops\|kernel NULL pointer'
count_file_into scsi     "$OUT/A_window.txt" 'session recovery\|connection[0-9]*:[0-9]* is operational\|reset\|abort'
HSHUT=$(grep -ao 'P-FREPLAY-HOLD-END slot=[0-9]* held_ms=[0-9]* shutdown=[01]' "$OUT/A_window.txt" | tail -1 | sed -n 's/.*shutdown=//p')
echo "STAGE window on $A from the restart: health-events=$health self-gone=$selfgone withdraw=$withdrew repaired=$repaired hold-end shutdown='${HSHUT:-none}' (after ${hend}s) recovery-complete=$complete scsi-recovery-lines=$scsi oops=$oops"
grep -a 'P305-RESV\|P277-\|P-FREPLAY-HOLD-END\|P163-RECOVERY-COMPLETE\|session recovery\|is operational' "$OUT/A_window.txt" | head -n 12 | cut -c1-230 | sed 's/^/    /'
ck "no BUG/Oops on the survivor" "$oops" 0
if [ "$A_PRESENT" = 1 ] && [ "$B_PRESENT" = 0 ] && [ -n "$RESV1" ]; then
    ck "with the state persisted, the survivor never read its own key as gone" "$selfgone" 0
    ck "with the state persisted, the hold ended by its timer, not on a shutdown" "${HSHUT:-none}" 0
    ckge "with the state persisted, the recovery completed after the restart (P163-RECOVERY-COMPLETE)" "$complete" 1
    $VIRSH start "$B" > "$OUT/start.txt" 2>&1
    waitboot "$B"
    KO_MD5=$(md5sum mxfs.ko 2>/dev/null | awk '{print $1}')
    measure "$B" 240 "$OUT/B_rejoin.txt" '^PREP_RC=' "the re-prep of $B" \
        "for try in 1 2 3 4 5 6; do mountpoint -q /src && break; mkdir -p /src; timeout 12 mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null; sleep 4; done; mountpoint -q /src || echo SRC_NOT_MOUNTED; MXFS_DEV='$MXFS_DEV' MXFS_KO_MD5='$KO_MD5' timeout 200 bash /src/mxfs/tests/setup/prep_node.sh tcp > /tmp/trpr_prep.log 2>&1; echo PREP_RC=\$?"
    measure "$B" 210 "$OUT/B_mount.txt" '^MOUNT_RC=' "the mount on $B after the recovery" \
        "if mountpoint -q $MNT; then echo MOUNT_RC=0; else timeout 150 mount -t mxfs $MXFS_DEV $MNT; echo MOUNT_RC=\$?; fi"
    MRC=$(field "$OUT/B_mount.txt" MOUNT_RC)
    ck "the victim got its filesystem back after the restart and the replay" "${MRC:-none}" 0
    if [ "${MRC:-none}" = 0 ]; then
        measure "$B" 90 "$OUT/B_verify.txt" '^VERIFY_END$' "B's files after the recovery" "cd $MNT/trpr_$LABEL && sha256sum f* | sort; echo VERIFY_END"
        grep -av '^VERIFY_END' "$OUT/B_verify.txt" > "$OUT/B_verify_sha.txt"
        ck "every file B fsynced before the cut survived byte-identical" "$(diff -q "$OUT/B_files_sha.txt" "$OUT/B_verify_sha.txt" > /dev/null && echo same || echo differs)" same
    fi
else
    echo "  the PR database did NOT persist as the APTPL bit promised (survivor key present=$A_PRESENT, victim key present=$B_PRESENT, reservation='${RESV1:-none}'): grading MXFS on failing closed"
    ckge "FAIL-CLOSED: the survivor read its own registration as gone (P305-RESV-SELF-GONE-INSPECT)" "$selfgone" 1
    ckge "FAIL-CLOSED: the survivor withdrew rather than continue as a registrant-less member (P277-FENCED-SELF-WITHDRAW)" "$withdrew" 1
    ck   "FAIL-CLOSED: the replay hold ended on the shutdown (P-FREPLAY-HOLD-END shutdown=1)" "${HSHUT:-none}" 1
    ck   "FAIL-CLOSED: the recovery did NOT complete under the lost exclusion" "$complete" 0
fi
echo "--- mode=$MODE gen=$G0->$G1 keys_before=${#KEYS0[@]} keys_after=${#KEYS1[@]} victim_key_after=$B_PRESENT survivor_key_after=$A_PRESENT resv_after='${RESV1:-none}' back_after=${BACK}s"
echo "=== target_restart_pr $LABEL: fails=$fails wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL mode=$MODE fails=0 persisted=$([ "$A_PRESENT" = 1 ] && [ "$B_PRESENT" = 0 ] && [ -n "$RESV1" ] && echo 1 || echo 0) back_after=$BACK evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL mode=$MODE fails=$fails back_after=${BACK:-none} evidence=$OUT"; exit 1
