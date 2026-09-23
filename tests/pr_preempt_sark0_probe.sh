#!/bin/bash
# tests/pr_preempt_sark0_probe.sh — can the sole survivor of a 2-node cluster
# fence WITHOUT the victim's key, by preempting the all-registrants
# reservation itself?  And does the resulting single-holder Write Exclusive
# reservation keep a RE-REGISTERED victim off the LUN?
#
# WHY THIS EXISTS (2026-09-04, follows tests/pr_session_drop_probe.sh)
#   On the QNAP TS-453 Pro the victim's registration is gone by the time the
#   survivor fences, so PREEMPT AND ABORT of the victim key (the only proving
#   fence kind) can never be issued.  SPC-4 5.9.10.4.4: a PREEMPT (AND ABORT)
#   whose service-action key is ZERO against an all-registrants reservation
#   releases that reservation, removes EVERY other I_T nexus's registration
#   (aborting their tasks), and installs a reservation of the requested type
#   for the preempting nexus alone.  That needs no victim key at all.  And a
#   plain Write Exclusive reservation (type 1) refuses writes from every
#   nexus but the holder — registered or not — which is the durable host
#   fence D-FENCED-VICTIM-MAY-REREGISTER says PREEMPT AND ABORT of a key is
#   not.  Measure what THIS target does with each step.
#
# STATE EXPECTED AT ENTRY (what pr_session_drop_probe.sh leaves behind)
#   W mounted, registered (the only key), WE-AR held; V up, NOT mounted, a
#   fresh iSCSI session, no registration.
#
# THE MEASUREMENT (all at the SCSI layer; the scratch LBA is written back with
# the bytes it already holds, so content never changes)
#   1. V REGISTERs a fresh key KS and writes the scratch LBA -> under WE-AR a
#      registrant writes: this is the returning-victim hazard on this target.
#   2. W issues PREEMPT AND ABORT rk=KW sark=0 type=WE(1).  Then READ KEYS
#      (expect KW only) and READ RESERVATION (expect Write Exclusive, KW).
#   3. V writes the scratch LBA -> must be REFUSED (non-registrant).
#      V REGISTERs KS2 (allowed?) and writes again -> must be REFUSED
#      (registered but not the holder under type 1).
#   4. W converts back to WE-AR by preempting its own reservation
#      (rk=KW sark=KW type=7); if the target refuses that, RELEASE + RESERVE.
#      READ RESERVATION; V writes again -> allowed iff KS2 is registered.
#   5. V removes KS2.  W is left registered and holding WE-AR again.
#
# Leaves W with the victim still dead in its view; re-prep afterwards.
#
# the budget rule (derived): ~12 PROUT/PRIN round trips + 4 dd + ssh ~ 60 s; bound 120 s.
#
# usage: pr_preempt_sark0_probe.sh <label> [W=test1] [V=test2]
set -u
LABEL=${1:?label}
W=${2:-test1}; V=${3:-test2}
DEV=   # resolved below from W's live mount (mxfs_dev_resolve), MXFS_DEV overriding
LBA=${MXFS_SCRATCH_LBA:-131087}
KS=0xfeed0904 ; KS2=0xfeed0905
cd "$(dirname "$0")/.." || exit 2
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_prsk0_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
# sw_into <file> <sg_persist args>: a PR command from W into <file>, across
# the boundary.  A PERSISTENT RESERVE IN must carry the 'PR generation='
# header every answered PR IN prints (an error message is non-empty too,
# and a probe that parsed one reported 'keys=0' about MXFS's fencing state,
# sess41); a PR OUT must carry sg_persist's own rc line, because a refusal
# (rc!=0) IS the measured outcome there.  The target not answering at all
# is an ABORT, never an empty key list.
sw_into() {
    local f=$1 shape; shift
    case " $* " in *" -i "*) shape='PR generation=';; *) shape='^rc=[0-9]+$';; esac
    measure "$W" 25 "$f" "$shape" "sg_persist $* on $W" "sg_persist $* \$(readlink -f $DEV) 2>&1 | tail -4; echo rc=\${PIPESTATUS[0]}"
}
sv() { timeout 25 $SSH "$V" "sg_persist $* \$(readlink -f $DEV) 2>&1 | tail -4; echo rc=\${PIPESTATUS[0]}" 2>/dev/null | filt; }
keys_of() { grep -a '^    0x' "$1" | tr -d ' ' | tr '\n' ','; }
resv_of() { grep -a 'scope\|Key=' "$1" | tr -d ' ' | tr '\n' ' '; }
SWN=0
keysw_into() { SWN=$((SWN+1)); sw_into "$OUT/pr_keys_$SWN.txt" -i -k; printf -v "$1" '%s' "$(keys_of "$OUT/pr_keys_$SWN.txt")"; }
resvw_into() { SWN=$((SWN+1)); sw_into "$OUT/pr_resv_$SWN.txt" -i -r; printf -v "$1" '%s' "$(resv_of "$OUT/pr_resv_$SWN.txt")"; }
# write the scratch LBA back with its own bytes from V; the capture carries
# wrc=<dd rc> (the write's outcome, refused or not, is the measurement) and
# the ssh's status is what ABORTs
vwrite_into() {
    SWN=$((SWN+1))
    measure "$V" 40 "$OUT/vwrite_$SWN.txt" '^wrc=[0-9]+$' "V's write of the scratch LBA" "R=\$(readlink -f $DEV); dd if=\$R of=/root/prsk0_lba.bin bs=512 skip=$LBA count=1 iflag=direct 2>/dev/null; dd if=/root/prsk0_lba.bin of=\$R bs=512 seek=$LBA count=1 oflag=direct conv=notrunc 2>/root/prsk0_dd.err; echo wrc=\$?; tail -1 /root/prsk0_dd.err; dmesg | grep -ai 'reservation conflict' | tail -1"
    printf -v "$1" '%s' "$(tr '\n' ' ' < "$OUT/vwrite_$SWN.txt")"
}

say "=== pr_preempt_sark0_probe label=$LABEL W=$W V=$V out=$OUT ==="
m=$(timeout 15 $SSH "$W" "grep -c ' mxfs ' /proc/mounts" 2>/dev/null | filt); [ "$m" = 1 ] || { echo "ABORT: $W not mounted ($m)"; exit 2; }
m=$(timeout 15 $SSH "$V" "grep -c ' mxfs ' /proc/mounts" 2>/dev/null | filt); [ "$m" = 0 ] || { echo "ABORT: $V is mounted ($m)"; exit 2; }
# the LUN as W's live mount uses it (never another rig's hardcoded path)
mxfs_dev_resolve "$W"
DEV=$MXFS_DEV_RESOLVED
say "dev=$DEV (resolved from $W's live mount)"
keysw_into k0; resvw_into r0
say "entry: keys=$k0 resv=$r0"
KW=$(echo "$k0" | tr ',' '\n' | head -1)
ck "exactly one registration at entry (the survivor's)" "$(echo "$k0" | tr ',' '\n' | grep -c .)" "1"
ck "all-registrants Write Exclusive held at entry" "$(echo "$r0" | grep -c 'allregistrants')" "1"

say "1. $V registers $KS and writes the scratch LBA (returning-victim hazard under WE-AR)"
r=$(sv --out --register --param-sark=$KS); echo "  INFO register: $(echo "$r" | tr '\n' ' ')"
vwrite_into w1; echo "  INFO write after register: $w1"
keysw_into know; echo "  INFO keys now: $know"
ck "a re-registered victim CAN write under WE-AR (the D-FENCED-VICTIM-MAY-REREGISTER shape)" "$(echo "$w1" | grep -oE 'wrc=[0-9]+')" "wrc=0"

say "2. $W PREEMPT AND ABORT rk=$KW sark=0 type=1 (Write Exclusive, single holder)"
sw_into "$OUT/pa_sark0.txt" --out --preempt-abort --param-rk=$KW --param-sark=0 --prout-type=1; r=$(cat "$OUT/pa_sark0.txt"); echo "  INFO P&A sark=0: $(echo "$r" | tr '\n' ' ')"
ck "P&A sark=0 accepted by the target" "$(echo "$r" | grep -oE 'rc=[0-9]+')" "rc=0"
keysw_into k2; resvw_into r2; say "after P&A: keys=$k2 resv=$r2"
ck "only the survivor's key remains registered" "$k2" "$KW,"
ck "reservation is now single-holder Write Exclusive" "$(echo "$r2" | grep -c 'type:WriteExclusive$\|type:WriteExclusive ')" "1"
ck "reservation holder is the survivor" "$(echo "$r2" | grep -c "Key=$KW")" "1"

say "3. $V writes as a non-registrant, then re-registers $KS2 and writes again"
vwrite_into w3; echo "  INFO write (non-registrant): $w3"
ck "non-registrant write REFUSED under WE" "$( [ "$(echo "$w3" | grep -oE 'wrc=[0-9]+')" = wrc=0 ] && echo ALLOWED || echo refused)" "refused"
r=$(sv --out --register --param-sark=$KS2); echo "  INFO re-register $KS2: $(echo "$r" | tr '\n' ' ')"
keysw_into know; echo "  INFO keys now: $know"
vwrite_into w3b; echo "  INFO write (registered, not holder): $w3b"
ck "re-registered non-holder write REFUSED under WE (the durable host fence)" "$( [ "$(echo "$w3b" | grep -oE 'wrc=[0-9]+')" = wrc=0 ] && echo ALLOWED || echo refused)" "refused"

say "4. $W converts back to WE-AR (self-preempt rk=$KW sark=$KW type=7)"
sw_into "$OUT/self_preempt.txt" --out --preempt --param-rk=$KW --param-sark=$KW --prout-type=7; r=$(cat "$OUT/self_preempt.txt"); echo "  INFO self-preempt to type 7: $(echo "$r" | tr '\n' ' ')"
resvw_into r4; keysw_into know; say "after self-preempt: keys=$know resv=$r4"
if ! echo "$r4" | grep -q allregistrants; then
    say "   self-preempt did not yield WE-AR; RELEASE type 1 then RESERVE type 7"
    sw_into "$OUT/release.txt" --out --release --param-rk=$KW --prout-type=1; echo "  INFO release: $(tr '\n' ' ' < "$OUT/release.txt")"
    sw_into "$OUT/reserve7.txt" --out --reserve --param-rk=$KW --prout-type=7; echo "  INFO reserve 7: $(tr '\n' ' ' < "$OUT/reserve7.txt")"
    resvw_into r4; say "after release+reserve: resv=$r4"
    ck "WE-AR restored only via release+reserve (window with no reservation)" "1" "1"
else
    ck "WE-AR restored atomically by self-preempt" "1" "1"
fi
ck "all-registrants Write Exclusive held again" "$(echo "$r4" | grep -c allregistrants)" "1"
vwrite_into w4; echo "  INFO write (registered $KS2 under WE-AR): $w4"
ck "registered victim writes again under WE-AR (fence lifted with the type)" "$(echo "$w4" | grep -oE 'wrc=[0-9]+')" "wrc=0"

say "5. $V removes $KS2"
r=$(sv --out --register --param-rk=$KS2 --param-sark=0); echo "  INFO unregister: $(echo "$r" | tr '\n' ' ')"
keysw_into know; resvw_into rexit; say "exit: keys=$know resv=$rexit"
{ echo "entry keys=$k0 resv=$r0"; echo "afterPA keys=$k2 resv=$r2"; echo "w1=$w1"; echo "w3=$w3"; echo "w3b=$w3b"; echo "w4=$w4"; echo "r4=$r4"; } > "$OUT/summary.txt"
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails evidence=$OUT"; fi
exit $fails
