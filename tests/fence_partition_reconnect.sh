#!/bin/bash
# tests/fence_partition_reconnect.sh — the PARTITION AND RECONNECT laps of the
# fence crash matrix (ledger D-FENCE-CRASH-MATRIX-UNTESTED; the design-consult
# ruling that fixed what a lap here must check is banked in
# docs/rulings/fence-crash-matrix-cuts.md).
#
# WHY IT EXISTS.  The ruling is explicit that killing both VMs exercises
# neither a partition nor a reconnect, and that the thing a reconnect lap must
# check is the PR TRANSITION, never "no re-registration":
#
#     "Under an all-registrants reservation a stale re-registration restores
#      write access; under plain WE a registration alone does not, but
#      preempting the holder, changing the reservation or relaxing it back
#      does.  The harness checks those transitions."
#
# and, from the target-restart section, the same measurement discipline that
# applies to any path that comes back:
#
#     "persistence is measured before automatic re-registration masks a loss
#      (observe the REGISTER traffic, or hold the initiators off until the
#      restored state is inspected)".
#
# So this harness samples the target's PR state CONTINUOUSLY across the
# reconnect rather than reading it once at each end, and it keeps a write
# oracle on the partitioned node whose successes are timed by COMPLETION, not
# by when the attempt started.
#
# NOBODY IS CRASHED HERE.  Both nodes stay up for the whole lap; the prover
# runs the fence, the certification, the seal and the victim's slice replay to
# completion.  That is the difference from tests/fence_crash_cuts.sh, whose
# every lap is a total outage graded through the whole-cluster bootstrap owner.
#
# TWO ARMS, credited separately.
#
#   ARM=storage (default) — B loses the PATH TO THE LUN and keeps the network.
#     B's iSCSI portal traffic is dropped on B itself (iptables, node-local:
#     nothing on the host or the target is touched).  On this rig the target
#     purges a dead session's registration (data/rigs.json
#     pr_registration_on_session_loss=purged), so B1's key leaves the target
#     with the PR generation UNCHANGED — a target-internal purge, no PROUT —
#     and B's disklock heartbeat stops because it cannot write it.  A then sees
#     B dead, fences it, certifies, seals and replays B1's slice.  The lap's
#     subject is what happens when the path comes BACK: whether B1's key
#     returns, whether anything about the RESERVATION changes with it, and —
#     the only question that matters for integrity — whether any write from the
#     fenced incarnation COMPLETES after the path is restored.
#
#   ARM=network — B loses the DLM/discovery NETWORK to A and keeps the LUN.
#     This is the classic split brain: both nodes are alive and both keep
#     heartbeating to the shared LUN.  WHICH OUTCOME IS CORRECT DEPENDS ON HOW
#     LONG THE LINK IS GONE, and the module says so itself: a TCP peer that
#     goes silent is SUSPECT, and it is declared dead only if it fails to
#     reconnect inside tcp_death_grace_ms — a live, writable parameter.  So
#     this arm reads that number off the running module and grades the
#     partition it actually held against it:
#       - held INSIDE the grace: nobody may be fenced.  Both mounts survive,
#         both keys stay registered, and B is writing again after the heal.
#         That is the transient-flap tolerance, and it is the only shape in
#         which "zero certificates" is a property rather than a hope.
#       - held PAST the grace: exactly one side must fence the other and owe
#         the whole chain — a durable certificate, a sealed manifest, the
#         victim's slice replayed to completion, the victim containing itself
#         and never completing another write.
#     Neither shape may ever produce TWO certificates: two nodes each
#     certifying the other is the split brain this arm exists to detect.
#     WHICH SIDE WINS IS NOT A ROLE.  The fault is symmetric — both nodes keep
#     the LUN, both keep heartbeating, and either may reach the PREEMPT first.
#     Measured s125: the PARTITIONED node fenced the other one, and every
#     assertion that named the unpartitioned node "the survivor" then graded a
#     textbook-correct resolution against the wrong side — six FAILs, none of
#     them a defect.  So this arm binds WIN/LOSE from the certificates it
#     observes and every verdict after that point is written in those terms.
#     This is NOT tests/suite/fault_netpartition.sh, which holds its partition
#     for 3 s deliberately — "<< 62s lease => no fence" — and so never crosses
#     the dead window.  This arm holds it for PART_S (120 s default), past both
#     the grace and the window, which is the only version of the lap that can
#     show whether the resolution a lost DLM link forces is carried through to
#     the end.
#
# WHAT IS ASSERTED (storage arm)
#   - before the partition: both keys registered, the reservation recorded;
#   - at the fence: B1's key is gone from the target and A minted a
#     certificate, and the PR generation moved or did not move consistently
#     with the mechanism that removed the key (a purge moves nothing, a
#     PREEMPT AND ABORT moves it);
#   - A's recovery of B1 reached P163-RECOVERY-COMPLETE;
#   - across the reconnect the RESERVATION (holder key and type) is unchanged:
#     no preempt, no release, no type change, no relaxation back;
#   - NO write from the fenced incarnation completes successfully after the
#     certificate, and in particular none after the path is restored;
#   - B contains itself once it can see the LUN again (self-withdraw, own key
#     gone, self-fence or shutdown);
#   - the dirty-death oracle: every file B fsynced before the partition is
#     present and byte-identical afterwards, read from A;
#   - no shutdown, BUG or Oops on A.
#
# THE BUDGET (derived, a timeout is a failure and never a safety net):
#   prep ~60 s (bound 300) + identities and baseline ~25 s + B's 64 oracle
#   files ~10 s + the partition + the 62 s dead window + the fence, certify,
#   seal and replay ~60 s + captures ~30 s + the reconnect and its 60 s
#   sampler + B's containment ~30 s + the oracle read ~20 s + cleanup ~20 s
#   ≈ 380-460 s, plus up to 150 s of boot when the domains start powered off.
#   Caller bound 700 s.
#   The NETWORK arm is a different sum, because it holds the partition through
#   the whole resolution and grades it to the end: prep 300 (measured 233) +
#   identities and baseline 25 + B's 64 oracle files 10 + the sampler 5 + the
#   partition 120 + the fence settle 100 (measured 67.5 from the first fence
#   marker, most of it inside the partition) + the victim's slice replayed to
#   completion 180 + the heal, its 45 s settle, containment, the oracle read
#   and cleanup 140 = 880, plus the two captures the direction-agnostic
#   grading added — the loser's containment window (60) and the loser's final
#   window (40), each a dmesg read measured at a few seconds — = 980.
#   Caller bound 1000 s.
#
# Usage: tests/fence_partition_reconnect.sh <label>
# Env:   ARM (storage|network), MXFS_NODE_LIST (default test1,test2),
#        PART_S (how long the partition stands before it is healed; default
#        180 for storage — it must outlast the 62 s dead window, the fence and
#        the replay — and 120 for network), NFILES (64), JOIN_BOUND (300).
# Exit 0 PASS, 1 FAIL, 2 ABORT/INFRA, 3 VACUOUS.
set -u
LABEL=${1:?label}
ARM=${ARM:-storage}
case $ARM in storage|network) ;; *) echo "ARM must be storage or network"; exit 2;; esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}          # the node that is NOT partitioned by this lap
B=${MXFS_NODE_LIST##*,}          # the node the partition is installed on
# WHO WINS IS A RESULT, NOT A ROLE.  In the storage arm the direction is forced
# by construction — B loses the LUN, so only A can fence — and A is the winner
# by definition.  In the NETWORK arm the fault is symmetric: both nodes keep the
# LUN and both keep heartbeating, so either side may reach the PREEMPT first.
# Measured s125: B (the partitioned node) fenced A, and every assertion below
# that named A the survivor graded the correct outcome against the wrong node —
# six FAILs, none of them an MXFS defect.  So WIN/LOSE start at the storage
# arm's forced direction and the network arm REBINDS them from the certificates
# it actually observed.
WIN=$A; LOSE=$B
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
NFILES=${NFILES:-64}
JOIN_BOUND=${JOIN_BOUND:-300}
if [ "$ARM" = storage ]; then PART_S=${PART_S:-180}; else PART_S=${PART_S:-120}; fi
# The DLM transport's TCP port and the discovery multicast port, for the
# network arm.  Both are the module's compiled-in defaults (dlm/mxfs.h:115,
# dlm/mount.c:1712); a rig that overrides them on the mount line must override
# these too or the arm blocks nothing and the lap is VACUOUS, which it says.
DLM_PORT=${DLM_PORT:-7600}
DISC_PORT=${DISC_PORT:-7601}
CHK=/src/mxfs/tools/chk_mxfs
DUMP=/src/mxfs/tools/disklock_hb_dump.py
PARM=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_fpart_${ARM}_$LABEL
mkdir -p "$OUT"
fails=0
. "$(dirname "$0")/lib/rig.sh"
VIRSH="timeout 30 virsh -c qemu:///system"
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}
MARK="FPART-MARK-$LABEL-$ARM"
echo "=== fence_partition_reconnect arm=$ARM label=$LABEL A(unpartitioned)=$A B(partitioned)=$B part=${PART_S}s nfiles=$NFILES $(date -u +%FT%TZ) ==="
[ "$ARM" = network ] && echo "    the network arm's fault is symmetric: which side wins is read off the certificates, not assumed from this naming"
s0=$(date +%s)
el() { echo $(( $(date +%s) - s0 )); }
field(){ grep -aoE "(^| )$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }

# ---- the partition primitives.  Node-local iptables on B only: nothing on
#      this host and nothing on the target is touched, so a lap that dies
#      half way leaves the host and the SAN exactly as it found them.
# The rules carry no comment match: tests/suite/fault_netpartition.sh has
# proved plain -p tcp --dport rules work on these nodes, and xt_comment is one
# more module that can be absent on a stripped guest.  Identity is the port
# instead, which is what iptables -S prints back.
PORTPAT=$( [ "$ARM" = storage ] && echo 3260 || echo "$DLM_PORT" )
part_rules() {          # one iptables argument list per line
    if [ "$ARM" = storage ]; then
        echo "OUTPUT -p tcp --dport 3260 -j DROP"
        echo "INPUT -p tcp --sport 3260 -j DROP"
    else
        echo "OUTPUT -p tcp --dport $DLM_PORT -j DROP"
        echo "INPUT -p tcp --sport $DLM_PORT -j DROP"
        echo "OUTPUT -p tcp --sport $DLM_PORT -j DROP"
        echo "INPUT -p tcp --dport $DLM_PORT -j DROP"
        echo "OUTPUT -p udp --dport $DISC_PORT -j DROP"
        echo "INPUT -p udp --dport $DISC_PORT -j DROP"
    fi
}
part_cmd() {            # <-I|-D> : the remote one-liner that installs/removes
    local op=$1 c= r
    while IFS= read -r r; do c="$c iptables $op $r;"; done <<EOF
$(part_rules)
EOF
    printf '%s' "$c"
}
HEALED=0
heal() {                # idempotent, and it RUNS ON THE WAY OUT no matter what
    [ "$HEALED" = 1 ] && return 0
    HEALED=1
    rs 40 "$B" "$(part_cmd -D) iptables -S | grep -c -- $PORTPAT || true" > "$OUT/B_heal.txt" 2>/dev/null
    echo "STAGE healed the partition on $B (rules left naming $PORTPAT: $(tail -1 "$OUT/B_heal.txt" 2>/dev/null || echo '?')) at +$(el)s"
}
trap heal EXIT

# ---- 0. the fleet on the tree build
if [ ! -f mxfs.ko ]; then
    echo "ABORT: no mxfs.ko in the tree (build it first)"
    echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2
fi
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
MD5=$(md5sum mxfs.ko | cut -c1-32)
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
waitboot "$A" "$B"
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(el)s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep.log" | cut -c1-140)"
[ $prc = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
for n in "$A" "$B"; do
    value_now_into sv "$n" 30 "$OUT/${n}_srcversion.txt" '^[0-9A-F]{16,}$' "the loaded module's srcversion on $n" "cat /sys/module/mxfs/srcversion"
    ck "prep deployed the tree build on $n" "$sv" "$SV"
done
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=build evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; MXFS_DEV=$MXFS_DEV_RESOLVED; export MXFS_DEV

# ---- 1. identities and the target class
for n in "$A" "$B"; do
    value_now_into cl "$n" 30 "$OUT/${n}_claim.txt" '^claimed heartbeat slot [0-9]+' "the slot claim line on $n" "dmesg | grep -ao 'claimed heartbeat slot [0-9]*' | tail -1"
    printf -v "slot_$n" '%s' "${cl##* }"
done
eval "ASLOT=\$slot_$A; VSLOT=\$slot_$B"
dump_into() { measure "$1" 60 "$2" '^slot +[0-9]+ magic=' "$3" "python3 $DUMP $MXFS_DEV"; }
slot_of()  { grep -aE "^slot +$2 " "$1" | head -1; }
desc_of()  { awk -v s="$2" '$1=="slot" && $2==s {f=1; print; next} f && /^    desc/ {print; exit} /^slot/ {f=0}' "$1" | grep -a '^    desc' | head -1; }
dump_into "$A" "$OUT/hb_0.txt" "the disklock table before the partition"
PNODE=$(slot_of "$OUT/hb_0.txt" "$ASLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
VNODE=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'node=[0-9]*' | cut -d= -f2)
VEPOCH=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'epoch=[0-9]*' | cut -d= -f2)
VKEY=$(slot_of "$OUT/hb_0.txt" "$VSLOT" | grep -ao 'pr_key=0x[0-9a-f]*' | cut -d= -f2)
PKEY=$(slot_of "$OUT/hb_0.txt" "$ASLOT" | grep -ao 'pr_key=0x[0-9a-f]*' | cut -d= -f2)
if [ -z "$PNODE" ] || [ -z "$VNODE" ] || [ -z "$VKEY" ] || [ "$ASLOT" = "$VSLOT" ]; then
    echo "ABORT: the table did not yield two distinct live records for $A and $B"
    echo "RESULT: ABORT label=$LABEL stage=identity evidence=$OUT"; exit 2
fi
PRCLASS=$(mxfs_rig_pr_class)
echo "STAGE identities: unpartitioned A1=$PNODE slot $ASLOT key $PKEY; partitioned B1=$VNODE/$VEPOCH slot $VSLOT key $VKEY; registration on session loss: $PRCLASS"

keys_into() {
    measure "$1" 40 "$2" '^KEYS_END$' "$3" "$CHK --pr-keys $MXFS_DEV 2>&1; sg_persist -i -k $MXFS_DEV 2>&1 | grep -ao 'PR generation=0x[0-9a-f]*'; sg_persist -i -r $MXFS_DEV 2>&1 | grep -a 'Key=\|type:\|no reservation' | sed 's/^/RESV /'; echo KEYS_END"
}
key_present() { grep -aoE '^  0x[0-9a-f]+' "$1" | tr -d ' ' | grep -ac "^$2$"; }
normkey() { printf '0x%016x' "$(( $1 ))"; }
pr_gen() { grep -ao 'PR generation=0x[0-9a-f]*' "$1" | head -1 | cut -d= -f2; }
resv_of() {
    local t k
    grep -aiq 'RESV.*no reservation' "$1" && { echo none; return; }
    t=$(grep -a 'RESV.*scope:.*type:' "$1" | head -1 | sed 's/.*type: *//')
    k=$(grep -ao 'RESV.*Key=0x[0-9a-f]*' "$1" | head -1 | grep -ao '0x[0-9a-f]*')
    case "$t" in
        "Write Exclusive, all registrants"*) echo WEAR ;;
        "Write Exclusive"*) echo "WE1:$(normkey "${k:-0}")" ;;
        '') echo none ;;
        *) echo "other:$t" ;;
    esac
}
# A withdrawal through the cluster-fence entry is not bad news — it is what the
# authority machinery is for, and the node that contains itself prints it.  Any
# OTHER shutdown is.  Measured s125: without this exclusion the network arm
# counted the winner's own `mxfs_dlm_fence_notify` containment line against it
# and reported a crash on a node that had merely done its job.
bad_lines() { echo $(( $(grep -a 'hutting down filesystem' "$1" 2>/dev/null | grep -avc 'mxfs_dlm_fence_notify') + $(cnt "$1" 'BUG:\|Oops') )); }

keys_into "$A" "$OUT/K0.txt" "READ KEYS before the partition"
ck "before the partition: B1's key is registered" "$(key_present "$OUT/K0.txt" "$(normkey "$VKEY")")" 1
ck "before the partition: A1's key is registered" "$(key_present "$OUT/K0.txt" "$(normkey "$PKEY")")" 1
R0=$(resv_of "$OUT/K0.txt"); G0=$(pr_gen "$OUT/K0.txt")
echo "STAGE baseline: reservation=$R0 PR generation=${G0:-?}"

# ---- 2. the dirty-death oracle, written and fsynced by B while it is healthy
measure "$B" 60 "$OUT/B_files.txt" '^FILES_END$' "B's fsynced files" \
    "d=$MNT/fpart_${LABEL}_$ARM; mkdir -p \$d && for i in \$(seq $NFILES); do printf 'fpart %s arm $ARM file %s\n' $LABEL \$i > \$d/f\$i; done; sync -f $MNT; cd \$d && sha256sum f* | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/B_files.txt" > "$OUT/B_files_sha.txt"
ck "B fsynced $NFILES files before the partition" "$(grep -ac '^[0-9a-f]\{64\}  f' "$OUT/B_files_sha.txt")" "$NFILES"
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=oracle evidence=$OUT"; exit 2; }

# ---- 3. the write oracle on B.  Each attempt logs the nanosecond it STARTED,
#         the nanosecond it RETURNED and its rc.  The end stamp is the one the
#         verdicts use: an fsync that begins before the fence and completes
#         after it is a write from the fenced incarnation that LANDED, and an
#         attempt that blocks for the SCSI command timeout would be scored on
#         the wrong side of the boundary by its start stamp alone.
WRITER_B64=$(base64 -w0 <<'PY'
import os, sys, time
d, log = sys.argv[1], sys.argv[2]
for i in range(900):
    t0 = time.time_ns()
    try:
        fd = os.open(d + "/w", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        os.write(fd, (str(t0) + "\n").encode()); os.fsync(fd); os.close(fd); rc = 0
    except Exception:
        rc = 1
    t1 = time.time_ns()
    with open(log, "a") as f:
        f.write("%d %d rc=%d\n" % (t0, t1, rc))
    time.sleep(0.5)
PY
)
measure "$B" 30 "$OUT/B_writer_start.txt" '^WRITER_STARTED$' "the write oracle on $B" \
    "d=$MNT/fpart_${LABEL}_$ARM; echo $WRITER_B64 | base64 -d > /run/fpart_writer.py; nohup python3 /run/fpart_writer.py \$d /src/mxfs/$OUT/B_writer.txt > /dev/null 2>&1 & echo \$! > /run/fpart_writer.pid; sleep 3; echo WRITER_STARTED"

# ---- 4. the PR sampler on A.  The reconnect's subject is a TRANSITION, so the
#         target's state is sampled continuously from before the partition to
#         well after the heal, not read once at each end.  It runs on A, whose
#         path is never touched, and writes into this tree over NFS.
SAMPLER_B64=$(base64 -w0 <<'PY'
import subprocess, sys, time
dev, log, secs = sys.argv[1], sys.argv[2], int(sys.argv[3])
end = time.time() + secs
while time.time() < end:
    t = time.time_ns()
    out = []
    for c in (["sg_persist", "-i", "-k", dev], ["sg_persist", "-i", "-r", dev]):
        try:
            out.append(subprocess.run(c, capture_output=True, timeout=20).stdout.decode("utf-8", "replace"))
        except Exception as e:
            out.append("SAMPLER_ERR %s\n" % e)
    with open(log, "a") as f:
        f.write("SAMPLE %d\n%s%s" % (t, out[0], out[1]))
    time.sleep(2)
PY
)
SAMPLE_S=$(( PART_S + 120 ))
measure "$A" 30 "$OUT/A_sampler_start.txt" '^SAMPLER_STARTED$' "the PR sampler on $A" \
    "echo $SAMPLER_B64 | base64 -d > /run/fpart_sampler.py; nohup python3 /run/fpart_sampler.py $MXFS_DEV /src/mxfs/$OUT/A_keysamp.txt $SAMPLE_S > /dev/null 2>&1 & echo \$! > /run/fpart_sampler.pid; sleep 3; echo SAMPLER_STARTED"

# ---- 5. PARTITION
rs 20 "$A" "echo $MARK > /dev/kmsg" >/dev/null 2>&1
measure "$B" 40 "$OUT/B_part.txt" '^PART_RULES=[0-9]+$' "the partition rules on $B" \
    "echo $MARK > /dev/kmsg; $(part_cmd -I) echo PART_RULES=\$(iptables -S | grep -c -- $PORTPAT || true)"
NRULES=$(field "$OUT/B_part.txt" PART_RULES)
ckge "the partition is installed on $B (iptables rules naming $PORTPAT)" "${NRULES:-0}" 2
[ $fails = 0 ] || { echo "RESULT: ABORT label=$LABEL stage=partition evidence=$OUT"; exit 2; }
T_PART=$(date +%s)
echo "STAGE $B partitioned ($ARM) at +$(el)s — $( [ "$ARM" = storage ] && echo "its iSCSI session dies, its heartbeat stops, the 62 s dead window starts" || echo "its DLM link to $A is cut; both nodes keep the LUN and both keep heartbeating" )"

if [ "$ARM" = storage ]; then
    # ---- 6s. A must fence, certify and replay.  The bound is the dead window
    #          (62 s) plus the fence, certify, seal and replay measured at
    #          40-70 s on the sibling shapes, with margin: 200 s.
    wait_for_into certified "$A" 200 "$MARK" "P236-FENCE-CERTIFIED"
    echo "STAGE A certified=$certified at +$(el)s ($(( $(date +%s) - T_PART )) s after the partition)"
    if [ "$certified" = timeout ]; then
        window_into "$OUT/A_nofence.txt" "$A" 30 "$MARK"
        echo "  A never certified a fence for B1; its fencing lines:"
        grep -a 'P236-FENCE\|P238-FENCE\|P305-\|P308-\|MXFS-MEMBERSHIP' "$OUT/A_nofence.txt" | sed 's/.*mxfs: /    /; s/.*disklock: /    /' | cut -c1-180 | head -10
        echo "RESULT: VACUOUS label=$LABEL stage=no-fence wall=$(el)s evidence=$OUT"; exit 3
    fi
    T_FENCE=$(date +%s)
    keys_into "$A" "$OUT/K1.txt" "READ KEYS at the certificate"
    dump_into "$A" "$OUT/hb_1_fenced.txt" "the disklock table at the certificate"
    R1=$(resv_of "$OUT/K1.txt"); G1=$(pr_gen "$OUT/K1.txt")
    k1_v=$(key_present "$OUT/K1.txt" "$(normkey "$VKEY")"); k1_p=$(key_present "$OUT/K1.txt" "$(normkey "$PKEY")")
    window_into "$OUT/A_fence.txt" "$A" 30 "$MARK"
    KIND=$(grep -a 'P236-FENCE-CERTIFIED' "$OUT/A_fence.txt" | head -1 | grep -ao 'kind=[A-Za-z0-9_]*' | cut -d= -f2)
    echo "STAGE at the certificate: B1 key present=$k1_v A1 key present=$k1_p reservation $R0 -> $R1 PR generation ${G0:-?} -> ${G1:-?} kind=${KIND:-none}"
    echo "    $(desc_of "$OUT/hb_1_fenced.txt" "$VSLOT" | cut -c1-200)"
    ck "at the certificate: B1's key is gone from the target" "$k1_v" 0
    ck "at the certificate: A1's key is still registered" "$k1_p" 1
    ckge "A minted a durable certificate for B1" "$(cnt "$OUT/A_fence.txt" 'P236-FENCE-CERTIFIED')" 1
    # The mechanism and the generation have to agree.  A target-internal purge
    # of a dead session's registration issues no command, so the generation
    # does not move; a PREEMPT AND ABORT is a PROUT and moves it.  Reading the
    # kind without this check would accept a certificate whose story the
    # target's own counter contradicts.
    if [ -z "${G0:-}" ] || [ -z "${G1:-}" ]; then
        echo "ABORT: the PR generation was not readable at one or both ends (before='${G0:-}' at the certificate='${G1:-}'), so the mechanism that removed B1's key cannot be corroborated"
        echo "RESULT: ABORT label=$LABEL stage=pr-generation evidence=$OUT"; exit 2
    fi
    if [ "$PRCLASS" = purged ]; then
        ck "a purging target removed B1's key with no command: the PR generation did not move" "$G1" "$G0"
    else
        if [ "${G1:-x}" = "${G0:-y}" ]; then
            echo "  FAIL a persistent target can only lose B1's key to a PROUT, but the PR generation did not move (${G0:-?} -> ${G1:-?})"; fails=$((fails+1))
        else
            echo "  PASS a persistent target lost B1's key to a command: the PR generation moved (${G0:-?} -> ${G1:-?})"
        fi
    fi
    # the replay of B1's slice must COMPLETE, not merely start
    wait_for_into recovered "$A" 180 "$MARK" "P163-RECOVERY-COMPLETE"
    echo "STAGE A recovered=$recovered at +$(el)s"
    window_into "$OUT/A_recovered.txt" "$A" 30 "$MARK"
    ckge "A's replay of B1's slice completed (P163-RECOVERY-COMPLETE)" "$(cnt "$OUT/A_recovered.txt" 'P163-RECOVERY-COMPLETE')" 1
else
    # ---- 6n. NOBODY may be fenced.  Both nodes hold the LUN and both keep
    #          their heartbeat, so the disklock table is the arbiter and the
    #          DLM link's loss is not evidence of death.  Watch for the whole
    #          partition rather than sampling once: a fence that arrives at
    #          t+90 s is exactly as wrong as one at t+10 s.
    sleep "$PART_S"
    # THE GRACE IS READ, NEVER ASSUMED.  Which outcome this arm owes depends on
    # the module's own declared transient-flap tolerance, and that is a live
    # parameter a rig may have set differently.  Copying 40000 in here would
    # make the lap grade one build's behaviour against another build's promise.
    GRACE_MS=$(rs 20 "$A" "cat $PARM/tcp_death_grace_ms 2>/dev/null" | tr -dc '0-9')
    if [ -z "${GRACE_MS:-}" ]; then
        echo "ABORT: tcp_death_grace_ms is not readable on $A, so the partition this lap held cannot be graded against the tolerance the module declares"
        echo "RESULT: ABORT label=$LABEL stage=grace-unreadable evidence=$OUT"; exit 2
    fi
    # A FENCE THAT IS UNDER WAY IS NOT YET A CERTIFICATE.  Reading the verdict
    # at one fixed instant reads whichever half of the pipeline the clock
    # happened to land in, and the two halves are graded by OPPOSITE rules.
    # Measured s123a: the capture that concluded "nobody fenced" ended 24 s
    # BEFORE the certificate it was looking for, and the lap then asserted the
    # inverse of the design against a textbook-correct resolution.  So the
    # discriminator is the START of a fence — the PREEMPT that proves
    # exclusion, or the durable intent — and once one is seen the partition is
    # HELD while the pipeline settles.
    #
    # THE SETTLE BOUND, derived from what the pipeline is made of and not from
    # a round number: the victim stops heartbeating once its own data-path I/O
    # bounces with RESERVATION CONFLICT (~2 s, measured), the disklock dead
    # window is 62 s, and the queue, fence, LU reset, certify and seal took 5 s
    # end to end (s123a, A's clock 1168.7 -> 1173.4).  69 s measured; 100 s
    # bound.  A settle that times out is not a slow pass — it is a fence that
    # proved exclusion and never became durable, which the module's own
    # P236-FENCE-CERTIFY-FAIL text calls unreplayable by anyone.
    window_into "$OUT/A_fence.txt" "$A" 30 "$MARK"
    window_into "$OUT/B_part_win.txt" "$B" 30 "$MARK"
    FENCE_START='P-PR-FENCE preempt-and-aborted\|P236-FENCE-INTENT\|P309-DEATH-FENCE-QUEUED'
    started_a=$(cnt "$OUT/A_fence.txt" "$FENCE_START")
    started_b=$(cnt "$OUT/B_part_win.txt" "$FENCE_START")
    settle_a=n/a; settle_b=n/a
    if [ "$started_a" -gt 0 ] || [ "$started_b" -gt 0 ]; then
        echo "STAGE a fence is UNDER WAY (starts on $A=$started_a on $B=$started_b) at +$(el)s; holding the partition until it settles"
        [ "$started_a" -gt 0 ] && wait_for_into settle_a "$A" 100 "$MARK" "P236-FENCE-CERTIFIED"
        [ "$started_b" -gt 0 ] && wait_for_into settle_b "$B" 100 "$MARK" "P236-FENCE-CERTIFIED"
        window_into "$OUT/A_fence.txt" "$A" 30 "$MARK"
        window_into "$OUT/B_part_win.txt" "$B" 30 "$MARK"
    fi
    T_FENCE=$(date +%s)
    keys_into "$A" "$OUT/K1.txt" "READ KEYS during the network partition"
    dump_into "$A" "$OUT/hb_1_fenced.txt" "the disklock table during the network partition"
    R1=$(resv_of "$OUT/K1.txt"); G1=$(pr_gen "$OUT/K1.txt")
    k1_v=$(key_present "$OUT/K1.txt" "$(normkey "$VKEY")"); k1_p=$(key_present "$OUT/K1.txt" "$(normkey "$PKEY")")
    fen_a=$(cnt "$OUT/A_fence.txt" 'P236-FENCE-CERTIFIED')
    fen_b=$(cnt "$OUT/B_part_win.txt" 'P236-FENCE-CERTIFIED')
    # REBIND THE ROLES FROM THE OBSERVED DIRECTION.  A fence start without a
    # certificate is not a win, so the binding is taken from the certificates;
    # the split-brain assertion below is what covers "both certified", and when
    # nobody certified the bindings stay at their defaults and are unused.
    if [ "$fen_b" -gt 0 ] && [ "$fen_a" = 0 ]; then
        WIN=$B; LOSE=$A
    elif [ "$fen_a" -gt 0 ] && [ "$fen_b" = 0 ]; then
        WIN=$A; LOSE=$B
    fi
    if [ "$WIN" = "$A" ]; then
        WKEY=$PKEY; LKEY=$VKEY; WLOG=$OUT/A_fence.txt; LLOG=$OUT/B_part_win.txt
    else
        WKEY=$VKEY; LKEY=$PKEY; WLOG=$OUT/B_part_win.txt; LLOG=$OUT/A_fence.txt
    fi
    k1_w=$(key_present "$OUT/K1.txt" "$(normkey "$WKEY")")
    k1_l=$(key_present "$OUT/K1.txt" "$(normkey "$LKEY")")
    fen_w=$(cnt "$WLOG" 'P236-FENCE-CERTIFIED')
    echo "STAGE during the partition: B1 key present=$k1_v A1 key present=$k1_p reservation $R0 -> $R1 PR generation ${G0:-?} -> ${G1:-?}"
    echo "STAGE network partition: held ${PART_S}s against a declared grace of $(( GRACE_MS / 1000 ))s; fence starts $A=$started_a $B=$started_b; certificates $A=$fen_a $B=$fen_b (settle waits a=$settle_a b=$settle_b)"
    [ "$(( fen_a + fen_b ))" -gt 0 ] && echo "STAGE the direction this lap resolved in: $WIN fenced $LOSE"
    # The one thing NO shape may produce, whatever the grace says.
    ck "network partition: the two nodes did not certify each other (split brain)" \
       "$( [ "$fen_a" -gt 0 ] && [ "$fen_b" -gt 0 ] && echo both || echo "not-both" )" "not-both"
    # The WINNER's key stays — whichever side that turned out to be.  Asserting
    # it of a fixed node grades a correct outcome against the wrong side.
    ck "network partition: the winner ($WIN) keeps its key registered" "$k1_w" 1
    # THE GRADE IS ON THE OBSERVED OUTCOME; THE GRACE SAYS WHICH OUTCOMES ARE
    # ALLOWED.  Branching on the grace alone would fail a lap that sat in the
    # grey zone either side of it — PART_S is the partition's term, but the
    # socket needs time to notice the block (12 s, measured s123a), so a
    # partition a little past the grace may legitimately resolve either way.
    # What is never allowed is a fence INSIDE the declared tolerance, or a
    # partition that outlasts twice the tolerance with nothing resolving.
    if [ "$(( started_a + started_b ))" -gt 0 ]; then
        ck "a fence was started only after the declared flap tolerance had been exceeded" \
           "$( [ "$(( PART_S * 1000 ))" -lt "$GRACE_MS" ] && echo inside || echo past )" past
        echo "  one node fenced the other past the declared tolerance; that is the resolution the design forces, and the lap grades it to the end"
        # A fence that proves exclusion and stops there consumes the victim's
        # key, so no successor can ever prove exclusion again and the slice is
        # replayable by nobody.  The certificate is therefore an obligation of
        # the fence, not a bonus.
        ckge "network partition, a fence started: it became a DURABLE certificate" "$(( fen_a + fen_b ))" 1
        KIND=$(grep -ah 'P236-FENCE-CERTIFIED' "$OUT/A_fence.txt" "$OUT/B_part_win.txt" 2>/dev/null | head -1 | grep -ao 'kind=[A-Za-z0-9_]*' | cut -d= -f2)
        echo "STAGE the certificate's fence kind=${KIND:-none}"
        if [ "$fen_w" -gt 0 ]; then
            ck "network partition, $WIN fenced $LOSE: the loser's key is gone from the target" "$k1_l" 0
            # the victim's slice is the WINNER's to replay, and it must COMPLETE
            wait_for_into netrecov "$WIN" 180 "$MARK" "P163-RECOVERY-COMPLETE"
            window_into "$OUT/win_recovered.txt" "$WIN" 30 "$MARK"
            ckge "network partition, $WIN fenced $LOSE: $WIN replayed the loser's slice to completion (P163-RECOVERY-COMPLETE)" \
                 "$(cnt "$OUT/win_recovered.txt" 'P163-RECOVERY-COMPLETE')" 1
        fi
    else
        echo "  neither node fenced the other: the link loss was tolerated and both nodes stayed live"
        # Tolerating a blip is correct; tolerating a link that has been gone for
        # twice the declared grace is not tolerance, it is a cluster with no
        # resolution at all — both sides live, neither able to coordinate.
        ck "the link loss was tolerated only within a term the declared flap tolerance can account for" \
           "$( [ "$(( PART_S * 1000 ))" -gt "$(( GRACE_MS * 2 ))" ] && echo unresolved || echo tolerated )" tolerated
        ck "network partition, nobody fenced: B1's key stays registered" "$k1_v" 1
        ck "network partition, nobody fenced: the reservation is unchanged" "$R1" "$R0"
    fi
fi

# ---- 7. hold the partition for the rest of its term, then HEAL, and read the
#         target's state across the heal from the sampler that was already
#         running: the re-registration cannot be masked by a read taken after
#         it settled.
now=$(date +%s); left=$(( PART_S - ( now - T_PART ) ))
[ $left -gt 0 ] && sleep $left
heal
T_HEAL=$(date +%s)
# THE PATH DOES NOT COME BACK BY ITSELF AFTER A LONG PARTITION.  iscsid gives
# up on a dropped session at node.session.timeo.replacement_timeout (120 s by
# default) and tears it down; a storage partition held for PART_S=180 s is past
# that, so removing the iptables rules restores reachability and nothing else.
# A lap that stopped here would read "B1's key never came back" and score it as
# safety, when it is only iscsid having given up — the vacuity this whole
# record keeps being bitten by.  So the reconnect is DRIVEN, and which of the
# two happened is recorded rather than assumed.
#
# A SURVIVING SESSION DOES NOT MAKE THE LOGIN A NO-OP.  That is what this lap
# assumed and it is false: measured s123a, `iscsiadm -m node --login` with the
# session already restored (SESSIONS_BEFORE=1) never returned, and the arm died
# at rc=124 with every MXFS verdict before it already PASSed.  So the login is
# attempted only when the LUN does NOT already answer, every iscsiadm and dd
# runs under its own node-local bound, and which of the two paths was taken is
# printed.  The inner bounds are derived from what the operation is: a single
# 512-byte direct read of a live LUN is milliseconds (10 s), and an iSCSI login
# that has not completed in 30 s is not going to.
if [ "$ARM" = storage ]; then
    measure "$B" 90 "$OUT/B_reconnect.txt" '^RECONNECT_END$' "the iSCSI reconnect on $B" \
        "s0=\$(timeout 15 iscsiadm -m session 2>/dev/null | grep -ac tcp || true); echo SESSIONS_BEFORE=\$s0; \
         if timeout 10 dd if=$MXFS_DEV of=/dev/null bs=512 count=1 iflag=direct >/dev/null 2>&1; then \
             echo 'LOGIN skipped: the session survived and the LUN already answers'; echo LOGIN_RC=0; \
         else \
             timeout 30 iscsiadm -m node --login > /run/fpart_login.txt 2>&1; echo LOGIN_RC=\$?; \
             sed 's/^/LOGIN /' /run/fpart_login.txt; sleep 8; \
         fi; \
         s1=\$(timeout 15 iscsiadm -m session 2>/dev/null | grep -ac tcp || true); echo SESSIONS_AFTER=\$s1; \
         echo DEV_READABLE=\$(timeout 15 dd if=$MXFS_DEV of=/dev/null bs=512 count=1 iflag=direct >/dev/null 2>&1 && echo 1 || echo 0); \
         echo RECONNECT_END"
    SESS_B=$(field "$OUT/B_reconnect.txt" SESSIONS_BEFORE)
    SESS_A=$(field "$OUT/B_reconnect.txt" SESSIONS_AFTER)
    DEVOK=$(field "$OUT/B_reconnect.txt" DEV_READABLE)
    LOGIN_RC=$(field "$OUT/B_reconnect.txt" LOGIN_RC)
    RECON_MODE=$( [ "${SESS_B:-0}" -gt 0 ] 2>/dev/null && echo survived || echo relogin )
    echo "STAGE reconnect on $B: sessions ${SESS_B:-?} -> ${SESS_A:-?} ($RECON_MODE, login rc=${LOGIN_RC:-?}), the LUN readable again=${DEVOK:-?} at +$(el)s"
    if [ "${DEVOK:-0}" != 1 ]; then
        echo "  the partitioned node never got its path back, so nothing about a reconnect was measured"
        grep -a '^LOGIN' "$OUT/B_reconnect.txt" | cut -c1-200 | head -6
        echo "RESULT: VACUOUS label=$LABEL stage=no-reconnect wall=$(el)s evidence=$OUT"; exit 3
    fi
fi
# the module's own reaction to the restored path needs time to happen
sleep 45
# Read from the winner: in the network arm the loser is the node that withdrew,
# and asking it is asking the side whose view the lap just invalidated.
keys_into "$WIN" "$OUT/K2.txt" "READ KEYS after the reconnect"
R2=$(resv_of "$OUT/K2.txt"); G2=$(pr_gen "$OUT/K2.txt")
k2_v=$(key_present "$OUT/K2.txt" "$(normkey "$VKEY")"); k2_p=$(key_present "$OUT/K2.txt" "$(normkey "$PKEY")")
echo "STAGE after the reconnect: B1 key present=$k2_v A1 key present=$k2_p reservation $R1 -> $R2 PR generation ${G1:-?} -> ${G2:-?}"

# The ruling's transition test.  A re-registration on its own is NOT the
# finding — under plain Write Exclusive a registration restores nothing — so
# the assertion is on the reservation: its holder and its type must be the
# same object across the heal.  A preempt, a release, a type change or a
# relaxation back to all-registrants is what would hand the fenced
# incarnation write access, and each of them shows here as R2 != R1.
ck "across the reconnect the reservation is unchanged (no preempt, release, type change or relaxation)" "$R2" "$R1"
if [ "$ARM" = storage ]; then
    if [ "$k2_v" = 1 ]; then
        echo "  NOTE B1's key is registered again after the reconnect (reservation $R2)."
        echo "       Under an all-registrants reservation that alone restores write access; the"
        echo "       write oracle below is what says whether it did."
    fi
    # the sampler is the "before automatic re-registration masks a loss" half:
    # it says WHEN the key came back relative to the heal, not merely that the
    # endpoint shows it
    samp=$OUT/A_keysamp.txt
    if [ -s "$samp" ]; then
        first_back=$(awk -v k="$(normkey "$VKEY")" '/^SAMPLE /{t=$2} index($0,k){if(!p){print t; p=1}}' "$samp" | head -1)
        echo "STAGE PR sampler: $(grep -ac '^SAMPLE ' "$samp") samples; B1's key first seen again at $( [ -n "$first_back" ] && echo "$(( (first_back - T_HEAL * 1000000000) / 1000000000 )) s relative to the heal" || echo "never" )"
    else
        echo "  NOTE the PR sampler produced no samples ($samp); the reconnect transition was read only at its endpoints"
    fi
fi

# ---- 8. B after the reconnect: containment and the write oracle
sleep 20
# window_into, not a remote sed: it requires the mark to be IN the ring, so a
# wrapped ring aborts the lap instead of reading as "B never contained itself"
CONTAIN_PAT='P277-FENCED-SELF-WITHDRAW\|P-PR-OWNKEY-GONE\|P277-PR-FULLSTATUS\|P277-PR-READKEYS\|P305-RESV-SELF\|P-PR-SELFFENCE\|P131-SELF-FENCE\|P236-SELF-FENCE\|hutting down filesystem'
window_into "$OUT/B_contain.txt" "$B" 60 "$MARK"
contain=$(cnt "$OUT/B_contain.txt" "$CONTAIN_PAT")
# Containment is owed by the LOSER, and in the network arm that may be A.  A
# capture of B alone would report "the victim never contained itself" about a
# node that was never the victim.
if [ "$LOSE" = "$B" ]; then
    contain_lose=$contain
else
    window_into "$OUT/lose_contain.txt" "$LOSE" 60 "$MARK"
    contain_lose=$(cnt "$OUT/lose_contain.txt" "$CONTAIN_PAT")
fi
wl=$OUT/B_writer.txt
# The oracle's log is written by B into this tree over NFS.  A log that is
# missing or empty means the oracle never ran or could not write — an infra
# failure, and scoring it as "B logged no successful write" would turn a lap
# that measured nothing into the containment result the lap was hoping for.
# (`grep -c || echo 0` is also not the way to count it: grep prints its own 0
# and exits 1 on no-match, so the substitution yields two lines.)
if [ ! -s "$wl" ]; then
    echo "ABORT: the write oracle on $B produced no log at $wl; it never ran, or it could not write into this tree over NFS, so nothing about B's writes was measured"
    echo "RESULT: ABORT label=$LABEL stage=oracle-log evidence=$OUT"; exit 2
fi
count_file_into total_w "$wl" 'rc='
ckge "B's write oracle ran (attempts logged)" "$total_w" 20
# every verdict below is on the COMPLETION stamp (field 2), never the start
ok_after_fence=$(awk -v t="$(( T_FENCE * 1000000000 + 5000000000 ))" '$3=="rc=0" && $2+0 > t' "$wl" 2>/dev/null | wc -l)
ok_after_heal=$(awk -v t="$(( T_HEAL * 1000000000 ))" '$3=="rc=0" && $2+0 > t' "$wl" 2>/dev/null | wc -l)
last_ok=$(awk '$3=="rc=0"{t=$2} END{print t+0}' "$wl" 2>/dev/null)
echo "STAGE B write oracle: attempts=$total_w completed-ok after the certificate(+5 s)=$ok_after_fence after the heal=$ok_after_heal last completed-ok $(( (last_ok - T_PART * 1000000000) / 1000000000 )) s after the partition"
if [ "$ARM" = storage ]; then
    ck "no write from the fenced incarnation COMPLETED after A's certificate" "$ok_after_fence" 0
    ck "the reconnect did not restore write access to the fenced incarnation" "$ok_after_heal" 0
    ckge "B contained itself once it could see the LUN again" "$contain" 1
elif [ "${fen_a:-0}" = 0 ] && [ "${fen_b:-0}" = 0 ]; then
    # nobody was fenced, so B's writes were legitimate throughout and must have
    # resumed once the link came back; a node that can neither be fenced nor
    # make progress is the hang the release bar refuses
    ckge "network partition, nobody fenced: B was writing again after the reconnect" "$ok_after_heal" 1
    ck "network partition, nobody fenced: B did not self-fence" "$contain" 0
elif [ "$LOSE" = "$B" ]; then
    # exactly one side won and the write oracle's node LOST; the loser owes the
    # silence any fenced node owes.
    # T_FENCE is the END of the partition here, not the instant of the
    # certificate, so this is the conservative late boundary: a write that
    # completed after the partition was over, with B already fenced, is the
    # violation whatever moment inside the partition the certificate landed on.
    ck "network partition, $WIN fenced $B: no write from $B COMPLETED after the partition ended" "$ok_after_fence" 0
    ckge "network partition, $WIN fenced $B: $B contained itself" "$contain_lose" 1
else
    # THE WRITE ORACLE'S NODE WON.  Its writes are the survivor's and the
    # integrity question inverts: a winner that fenced its peer and then cannot
    # write is the hang the release bar refuses, and the silence is owed by A.
    # The oracle only ever runs on B, so there is no completion series for the
    # loser here — its containment is what the lap can assert, and the mount
    # check in section 10 carries the rest.
    ckge "network partition, $B fenced $A: $B — the winner — was still completing writes after the partition" "$ok_after_fence" 1
    ck "network partition, $B fenced $A: $B did not contain itself" \
       "$(cnt "$OUT/B_contain.txt" 'P277-FENCED-SELF-WITHDRAW\|P-PR-SELFFENCE\|P131-SELF-FENCE\|P236-SELF-FENCE')" 0
    ckge "network partition, $B fenced $A: $A contained itself" "$contain_lose" 1
fi

# ---- 9. the dirty-death oracle, read from the node that still has the mount
# Reading it from a node whose mount was withdrawn returns nothing and scores as
# "every file was lost" — measured s125, where the read was aimed at A after B
# had fenced it.  So it is read from the WINNER.
[ "$WIN" = "$B" ] && echo "  INFO the oracle's own node won, so this read is same-node: it still says the fence, the replay and the heal did not lose $B's fsynced files, but it is not a cross-node read"
measure "$WIN" 90 "$OUT/win_files.txt" '^FILES_END$' "the oracle files read from $WIN" \
    "cd $MNT/fpart_${LABEL}_$ARM 2>/dev/null && sha256sum f* 2>/dev/null | sort; echo FILES_END"
grep -av '^FILES_END' "$OUT/win_files.txt" > "$OUT/win_files_sha.txt"
LC_ALL=C sort "$OUT/B_files_sha.txt" > "$OUT/B_files_sorted.txt"
LC_ALL=C sort "$OUT/win_files_sha.txt" > "$OUT/win_files_sorted.txt"
same=$(LC_ALL=C comm -12 "$OUT/B_files_sorted.txt" "$OUT/win_files_sorted.txt" | grep -ac '^[0-9a-f]\{64\}  f')
ck "every file B fsynced before the partition is back byte-identical" "$same" "$NFILES"

# ---- 10. nothing crashed on the node that won
window_into "$OUT/win_final.txt" "$WIN" 40 "$MARK"
ck "no shutdown, BUG or Oops on the winner ($WIN)" "$(bad_lines "$OUT/win_final.txt")" 0
mounted_w=$(rs 20 "$WIN" "mountpoint -q $MNT && echo mounted=1 || echo mounted=0" | tail -1)
echo "STAGE $WIN (winner) $mounted_w at +$(el)s"
ck "the winner ($WIN) is still mounted" "$mounted_w" "mounted=1"
# The loser's kernel must still be free of a BUG or an Oops.  Its withdrawal is
# excluded by bad_lines; a hard fault in it is not, and it is a crash whichever
# side of the partition it lands on.
window_into "$OUT/lose_final.txt" "$LOSE" 40 "$MARK"
ck "no BUG or Oops on the loser ($LOSE)" "$(cnt "$OUT/lose_final.txt" 'BUG:\|Oops')" 0
if [ "$ARM" = network ]; then
    mounted_l=$(rs 20 "$LOSE" "mountpoint -q $MNT && echo mounted=1 || echo mounted=0" | tail -1)
    if [ "${fen_a:-0}" = 0 ] && [ "${fen_b:-0}" = 0 ]; then
        # nobody was fenced, so both mounts owe survival: a node that lost only
        # its DLM link and came back must still have its filesystem
        ck "network partition, nobody fenced: $B is still mounted after the reconnect" "$mounted_l" "mounted=1"
    else
        # one side won, and the arm above already graded that a legitimate
        # resolution: the loser owes containment, which IS leaving the mount.
        # Asserting it is still mounted here would fail the very behaviour this
        # harness just said was correct.
        echo "  INFO $WIN fenced $LOSE; $LOSE is $mounted_l, and a fenced node leaving its mount is the containment this arm requires, not a failure"
    fi
fi

heal
# the helpers are stopped by the pid each one recorded when it started; no
# process-table search is ever run against these hosts
rs 20 "$B" 'p=$(cat /run/fpart_writer.pid 2>/dev/null); [ -n "$p" ] && kill "$p" 2>/dev/null; true' >/dev/null 2>&1
rs 20 "$A" 'p=$(cat /run/fpart_sampler.pid 2>/dev/null); [ -n "$p" ] && kill "$p" 2>/dev/null; true' >/dev/null 2>&1
if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL arm=$ARM fails=0 wall=$(el)s evidence=$OUT"; exit 0
fi
echo "RESULT: FAIL label=$LABEL arm=$ARM fails=$fails wall=$(el)s evidence=$OUT"; exit 1
