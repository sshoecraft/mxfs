#!/bin/bash
# f2_iclus_refusal.sh — D-FOREIGN-REPLAY-UNGATED-IMAGES default-on gate
# item 2 (sess404 ruling: "ICLUS clean-release markers OR explicit refusal
# of ICLUS configs"), sess419 landing: foreign_replay_token_enforce=1 is
# REFUSED at set time under icluster_dlm=1, because cluster-routed tenures
# release through the ICLUS pipeline with no RELMARK certificate
# (mxfs_relmark_iclus_unmarked) and can never earn an enforceable verdict.
#
# icluster_dlm is a load-time (0444) parameter, so the test must reload
# the module on one node: umount, rmmod, insmod icluster_dlm=1, attempt to
# arm (expect REFUSED + the P-line in dmesg), then arm under the F2-ok
# knobs to prove it is the ICLUS predicate alone that refuses; reload
# plain and leave the node UNMOUNTED — the caller preps afterwards.
#
# Usage: tests/f2_iclus_refusal.sh <label> [node] (default test5)
# the budget rule (derived): srcgate 5s + umount <=45s + rmmod/insmod 2x ~6s +
# ~8 bounded param pokes ~10s => ~70s.  Caller bound 90s.
set -u
LABEL=${1:?label}
NODE=${2:-test5}
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
SSH=tools/mxfs_sshpass.sh
P=/sys/module/mxfs/parameters
MNT=${MXFS_MNT:-/mnt/shared}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_f2iclus
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rsx/measure/capture_require (tests/lib/rig.sh): the kernel-log capture a
# verdict is counted from crosses the boundary in the parent shell first; a
# failed acquisition is an ABORT, never a count of zero.  Adopted by reading
# (a CAW-rig harness: no fault/healthy lap on the 2-node TCP rig).
. "$(dirname "$0")/lib/rig.sh"
pget() { timeout 10 $SSH "$NODE" "cat $P/$1" 2>/dev/null | filt | tr -dc '0-9-'; }
pset() { timeout 10 $SSH "$NODE" "echo $2 > $P/$1 2>/dev/null && echo OK || echo REFUSED" 2>/dev/null | filt | grep -E 'OK|REFUSED' | head -1; }

echo "=== f2_iclus_refusal label=$LABEL node=$NODE out=$OUT $(date -u +%FT%TZ) ==="
want=$(modinfo mxfs.ko | awk '/^srcversion:/{print $2}')
value_now_into nsv "$NODE" 15 "$OUT/rv_nsv_1.txt" '^[0-9A-F]+$' "nsv on $NODE" "cat /sys/module/mxfs/srcversion"
ck "srcgate $NODE runs the tree build $want" "$nsv" "$want"
[ "$nsv" = "$want" ] || { echo "=== f2_iclus_refusal $LABEL: fails=$fails (srcgate) ==="; exit 1; }

MARK="F2ICLUS-$LABEL-$$"
timeout 12 $SSH "$NODE" "echo '$MARK' > /dev/kmsg" >/dev/null 2>&1
value_now_into urc "$NODE" 60 "$OUT/rv_urc_2.txt" '^rc=' "urc on $NODE" "if grep -q ' $MNT ' /proc/mounts; then timeout 45 umount $MNT; echo rc=\$?; else echo rc=0; fi"; urc=$(printf '%s\n' "$urc" | sed -n 's/^rc=//p')
ck "$NODE unmounted for the reload" "$urc" "0"
value_now_into rl "$NODE" 30 "$OUT/rv_rl_3.txt" '^-?[0-9]+$' "rl on $NODE" "rmmod mxfs && insmod /src/mxfs/mxfs.ko dyndbg=+p icluster_dlm=1 && cat $P/icluster_dlm"
ck "module reloaded with icluster_dlm=1" "$rl" "1"

# F2-ok knobs so the ICLUS predicate is the ONLY unmet one
pset fua_disable 0 >/dev/null
value_now_into pgetv1 "$NODE" 10 "$OUT/pget_1.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/release_proof_enforce"
ck "release_proof_enforce is 1 (load-time default)" "$pgetv1" "1"
echo "  INFO knobs fua=$(pget fua_disable) rpe=$(pget release_proof_enforce) tcp=$(pget target_cache_protected)"
# the value the refused set must leave untouched is whatever the load left:
# the knob has defaulted to 1 since the default-on gate landed (a module
# default bypasses the setter), so "stayed 0" was a stale expectation that
# FAILed a correct refusal (s59h: REFUSED, P-line present, value 1 -> 1)
value_now_into pgetv0 "$NODE" 10 "$OUT/pget_0.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/foreign_replay_token_enforce"
echo "  INFO foreign_replay_token_enforce at load under icluster_dlm=1: $pgetv0"
value_now_into psetv1 "$NODE" 10 "$OUT/pset_1.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 1 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "arm REFUSED under icluster_dlm=1" "$psetv1" "REFUSED"
value_now_into pgetv2 "$NODE" 10 "$OUT/pget_2.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/foreign_replay_token_enforce"
ck "the refused set left the knob unchanged" "$pgetv2" "$pgetv0"
measure "$NODE" 25 "$OUT/dmesg_$NODE.txt" '^DMESG_END$' "the kernel log on $NODE from the lap marker" "dmesg | sed -n \"/$MARK/,\\\$p\"; echo DMESG_END"
ck "refusal names icluster_dlm (P-line)" "$(grep -ac 'foreign_replay_token_enforce=1 REFUSED: icluster_dlm=1' "$OUT/dmesg_$NODE.txt")" "1"
ck "exactly one unmet prerequisite counted" "$(grep -ac 'stays 0 — 1 prerequisite(s) unmet' "$OUT/dmesg_$NODE.txt")" "1"
value_now_into psetv2 "$NODE" 10 "$OUT/pset_2.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 0 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "disarm still allowed" "$psetv2" "OK"

# control: same knobs, icluster_dlm=0 -> arm accepted
value_now_into rl "$NODE" 30 "$OUT/rv_rl_4.txt" '^-?[0-9]+$' "rl on $NODE" "rmmod mxfs && insmod /src/mxfs/mxfs.ko dyndbg=+p && cat $P/icluster_dlm"
ck "module reloaded plain (icluster_dlm=0)" "$rl" "0"
pset fua_disable 0 >/dev/null
value_now_into pgetv3 "$NODE" 10 "$OUT/pget_3.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/release_proof_enforce"
ck "release_proof_enforce is 1 (load-time default)" "$pgetv3" "1"
value_now_into psetv3 "$NODE" 10 "$OUT/pset_3.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 1 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "control: arm ACCEPTED under icluster_dlm=0" "$psetv3" "OK"
pset foreign_replay_token_enforce 0 >/dev/null
window_into "$OUT/rv_s_5.txt" "$NODE" 25 "$MARK"; s=$(cat "$OUT/rv_s_5.txt" | grep -aEc 'BUG:|Oops' | tr -dc '0-9')
ck "zero splats on $NODE" "${s:-nossh}" "0"
echo "=== f2_iclus_refusal $LABEL: fails=$fails out=$OUT ==="
echo "NOTE: $NODE is unmounted with a freshly loaded module — prep_cluster before further rig work."
[ "$fails" -eq 0 ]
