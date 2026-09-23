#!/bin/bash
# tests/pr_absent_sark_probe.sh — what does THIS target do with a PREEMPT AND
# ABORT whose service-action key names a registration that is NOT in the table?
#
# WHY THIS EXISTS
#   The ordinary fence (dlm/scsipr.c, mxfs_scsipr_fence_node) mints a
#   completed-target-op retirement claim on the grounds that the victim's
#   registration was in the table at the CLASSIFYING READ and the PREEMPT AND
#   ABORT NAMED it.  The registration can leave between that read and the
#   target's scope selection.  The code already assumes the target answers such
#   a command with RESERVATION CONFLICT — scsipr_preempt_locked maps -EBUSY to
#   "the key was not registered, this command did nothing at all" and the fence
#   turns that into RACE_LOST with no claim — but nothing has ever measured
#   what this appliance actually does.  If it answers GOOD, the assumption is
#   wrong and the claim is minted over an execution nobody witnessed.
#
#   This probe answers that and nothing else.  It runs on an IDLE cluster with
#   no mxfs mount, builds the PR state by hand from two initiators, and puts it
#   back when it is done, so it touches no filesystem and no live mount.
#
# THE MEASUREMENT (all at the SCSI layer; no LBA is read or written)
#   setup  W registers KA, V registers KB, W reserves the same type the module
#          reserves (Write Exclusive - All Registrants, 7).
#   arm A  W: PREEMPT AND ABORT rk=KA sark=KX, where KX was NEVER registered.
#   arm B  V removes KB; W: PREEMPT AND ABORT rk=KA sark=KB — a key that WAS in
#          the table and left, which is the transition the fence races.
#   arm C  V re-registers KB; W: PREEMPT AND ABORT rk=KA sark=KB.  This one MUST
#          succeed: it is the control that proves the command shape, the rk, the
#          type and the apparatus can produce an acceptance at all, so a refusal
#          in A and B is about the absent key and not about a broken probe.
#   Every arm records the SCSI status AND the PR generation either side of the
#   command — a generation that advances on a refusal would mean the target did
#   something regardless of what it answered.
#
# the budget rule (derived): 18 PR round trips over ssh at ~1.3 s each plus two
# device resolutions ~ 30 s; bound 90 s.  A timeout is a failure.
#
# usage: pr_absent_sark_probe.sh <label> [W=test1] [V=test2]
set -u
LABEL=${1:?label}
W=${2:-test1}; V=${3:-test2}
DEV=
KA=0x5a5a0a01     # W's scratch key
KB=0x5a5a0b01     # V's scratch key
KX=0x5a5a0f01     # never registered anywhere
TYPE=7            # Write Exclusive - All Registrants, what the module reserves
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_prabs_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict is
# taken from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero or an empty value.
. "$(dirname "$0")/lib/rig.sh"
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
fails=0
SN=0

# pr_into <node> <file> <sg_persist args...>: one PR command across the
# boundary.  A PERSISTENT RESERVE IN must carry the 'PR generation=' header
# every answered PR IN prints (an error message is non-empty too); a PR OUT
# must carry sg_persist's own rc line, because a refusal IS the measured
# outcome there.  The target not answering at all is an ABORT.
pr_into() {
    local n=$1 f=$2 shape; shift 2
    case " $* " in *" -i "*) shape='PR generation=';; *) shape='^rc=[0-9]+$';; esac
    measure "$n" 25 "$f" "$shape" "sg_persist $* on $n" \
        "sg_persist $* \$(readlink -f $DEV) 2>&1 | tail -8; echo rc=\${PIPESTATUS[0]}"
}
keys_of() { grep -a '^    0x' "$1" | tr -d ' ' | tr '\n' ','; }
gen_of()  { sed -n 's/.*PR generation=\(0x[0-9a-f]*\).*/\1/p' "$1" | tail -1; }
resv_of() { grep -a 'scope\|Key=' "$1" | tr -d ' ' | tr '\n' ' '; }
rc_of()   { grep -aoE '^rc=[0-9]+$' "$1" | tail -1; }
# keys_now <keysvar> <genvar>: READ KEYS from W into both
keys_now() {
    SN=$((SN+1)); pr_into "$W" "$OUT/keys_$SN.txt" -i -k
    printf -v "$1" '%s' "$(keys_of "$OUT/keys_$SN.txt")"
    printf -v "$2" '%s' "$(gen_of  "$OUT/keys_$SN.txt")"
}
resv_now() { SN=$((SN+1)); pr_into "$W" "$OUT/resv_$SN.txt" -i -r; printf -v "$1" '%s' "$(resv_of "$OUT/resv_$SN.txt")"; }

say "=== pr_absent_sark_probe label=$LABEL W=$W V=$V out=$OUT ==="

# ── entry: an idle cluster.  The module's own PR machinery must not be running,
# because this probe measures the target and nothing else may mutate the table.
for n in "$W" "$V"; do
    m=$(rs 15 "$n" "grep -c ' mxfs ' /proc/mounts"); [ "$m" = 0 ] || \
        { echo "ABORT: $n has $m mxfs mount(s) — this probe needs an idle cluster"; \
          echo "RESULT: ABORT label=$LABEL stage=entry evidence=$OUT"; exit 2; }
done
mxfs_dev_same "$W" "$V"
DEV=$MXFS_DEV_RESOLVED
say "dev=$DEV (declared LUN, same fsid on both nodes)"

keys_now k0 g0; resv_now r0
say "entry: keys=[$k0] gen=$g0 resv=$r0"
ck "no registration at entry (nothing else owns the table)" "$(echo "$k0" | tr ',' '\n' | grep -c .)" "0"
ck "no reservation at entry" "$(echo "$r0" | grep -c 'Key=')" "0"

# ── setup
say "setup: $W registers $KA, $V registers $KB, $W reserves type $TYPE"
SN=$((SN+1)); pr_into "$W" "$OUT/reg_w.txt" --out --register --param-sark=$KA
ck "$W REGISTER accepted" "$(rc_of "$OUT/reg_w.txt")" "rc=0"
SN=$((SN+1)); pr_into "$V" "$OUT/reg_v.txt" --out --register --param-sark=$KB
ck "$V REGISTER accepted" "$(rc_of "$OUT/reg_v.txt")" "rc=0"
SN=$((SN+1)); pr_into "$W" "$OUT/reserve.txt" --out --reserve --param-rk=$KA --prout-type=$TYPE
ck "$W RESERVE type $TYPE accepted" "$(rc_of "$OUT/reserve.txt")" "rc=0"
keys_now k1 g1; resv_now r1
say "setup done: keys=[$k1] gen=$g1 resv=$r1"
ck "both scratch keys registered" "$(echo "$k1" | tr ',' '\n' | grep -c .)" "2"
ck "all-registrants Write Exclusive held" "$(echo "$r1" | grep -c allregistrants)" "1"

# ── arm A: sark names a key that was NEVER registered
say "arm A: $W PREEMPT AND ABORT rk=$KA sark=$KX (never registered) type=$TYPE"
SN=$((SN+1)); pr_into "$W" "$OUT/armA_pa.txt" --out --preempt-abort --param-rk=$KA --param-sark=$KX --prout-type=$TYPE
A_RC=$(rc_of "$OUT/armA_pa.txt"); A_TXT=$(tr '\n' ' ' < "$OUT/armA_pa.txt")
say "  arm A status: $A_RC   target said: $A_TXT"
keys_now kA gA
say "  arm A after: keys=[$kA] gen=$gA (was $g1)"
ck "arm A REFUSED (a P&A naming a never-registered key is not accepted)" \
   "$( [ "$A_RC" = rc=0 ] && echo ACCEPTED || echo refused )" "refused"
ck "arm A removed no registration" "$kA" "$k1"
ck "arm A did not advance the PR generation" "$gA" "$g1"

# ── arm B: sark names a key that WAS registered and left — the raced transition
say "arm B: $V removes $KB, then $W PREEMPT AND ABORT rk=$KA sark=$KB type=$TYPE"
SN=$((SN+1)); pr_into "$V" "$OUT/armB_unreg.txt" --out --register --param-rk=$KB --param-sark=0
ck "$V unregistered $KB" "$(rc_of "$OUT/armB_unreg.txt")" "rc=0"
keys_now kB0 gB0
say "  arm B before: keys=[$kB0] gen=$gB0"
ck "arm B precondition: only $W remains registered" "$(echo "$kB0" | tr ',' '\n' | grep -c .)" "1"
SN=$((SN+1)); pr_into "$W" "$OUT/armB_pa.txt" --out --preempt-abort --param-rk=$KA --param-sark=$KB --prout-type=$TYPE
B_RC=$(rc_of "$OUT/armB_pa.txt"); B_TXT=$(tr '\n' ' ' < "$OUT/armB_pa.txt")
say "  arm B status: $B_RC   target said: $B_TXT"
keys_now kB1 gB1
say "  arm B after: keys=[$kB1] gen=$gB1 (was $gB0)"
ck "arm B REFUSED (a P&A naming a departed registration is not accepted)" \
   "$( [ "$B_RC" = rc=0 ] && echo ACCEPTED || echo refused )" "refused"
ck "arm B removed no registration" "$kB1" "$kB0"
ck "arm B did not advance the PR generation" "$gB1" "$gB0"

# ── arm C: the control.  Same command, same rk, same type, key present.
say "arm C (control): $V re-registers $KB, then $W PREEMPT AND ABORT rk=$KA sark=$KB type=$TYPE"
SN=$((SN+1)); pr_into "$V" "$OUT/armC_reg.txt" --out --register --param-sark=$KB
ck "$V re-registered $KB" "$(rc_of "$OUT/armC_reg.txt")" "rc=0"
keys_now kC0 gC0
say "  arm C before: keys=[$kC0] gen=$gC0"
ck "arm C precondition: both keys registered again" "$(echo "$kC0" | tr ',' '\n' | grep -c .)" "2"
SN=$((SN+1)); pr_into "$W" "$OUT/armC_pa.txt" --out --preempt-abort --param-rk=$KA --param-sark=$KB --prout-type=$TYPE
C_RC=$(rc_of "$OUT/armC_pa.txt"); C_TXT=$(tr '\n' ' ' < "$OUT/armC_pa.txt")
say "  arm C status: $C_RC   target said: $C_TXT"
keys_now kC1 gC1
say "  arm C after: keys=[$kC1] gen=$gC1 (was $gC0)"
ck "arm C ACCEPTED (the apparatus CAN produce an accepted P&A)" "$C_RC" "rc=0"
ck "arm C removed the named registration" "$kC1" "$KA,"
ck "arm C advanced the PR generation" \
   "$( [ "$gC1" = "$gC0" ] && echo unchanged || echo advanced )" "advanced"

# ── cleanup: put the table back the way an idle cluster leaves it
say "cleanup: release the reservation and remove both scratch keys"
SN=$((SN+1)); pr_into "$W" "$OUT/cl_rel.txt"   --out --release  --param-rk=$KA --prout-type=$TYPE
say "  release: $(tr '\n' ' ' < "$OUT/cl_rel.txt")"
SN=$((SN+1)); pr_into "$W" "$OUT/cl_unreg.txt" --out --register --param-rk=$KA --param-sark=0
say "  $W unregister: $(tr '\n' ' ' < "$OUT/cl_unreg.txt")"
keys_now kZ gZ; resv_now rZ
say "exit: keys=[$kZ] gen=$gZ resv=$rZ"
ck "the table is empty again (nothing left behind for the next mount)" \
   "$(echo "$kZ" | tr ',' '\n' | grep -c .)" "0"

{
  echo "entry   keys=[$k0] gen=$g0 resv=$r0"
  echo "setup   keys=[$k1] gen=$g1 resv=$r1"
  echo "armA    sark=$KX (never registered)  status=$A_RC  gen $g1 -> $gA  keys=[$kA]"
  echo "armA    target: $A_TXT"
  echo "armB    sark=$KB (registered, then removed)  status=$B_RC  gen $gB0 -> $gB1  keys=[$kB1]"
  echo "armB    target: $B_TXT"
  echo "armC    sark=$KB (present, control)  status=$C_RC  gen $gC0 -> $gC1  keys=[$kC1]"
  echo "armC    target: $C_TXT"
  echo "exit    keys=[$kZ] gen=$gZ resv=$rZ"
} > "$OUT/summary.txt"
cat "$OUT/summary.txt"

if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL evidence=$OUT"
else echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; fi
exit $fails
