#!/bin/bash
# f2_config_matrix.sh — sess404 Option-A gate item 5: the F2 knob-combination
# matrix, asserted against the LIVE setters on one node.
#
#   A: fua_disable=1, target_cache_protected=0 -> enforce=1 REFUSED (fail-closed)
#   B: target_cache_protected=1               -> enforce=1 ACCEPTED
#   C: while armed, target_cache_protected 1->0 withdrawal REFUSED
#   D: fua_disable=0 (FUA-honouring), tcp=0    -> enforce=1 ACCEPTED (crash-
#      durable domain); then fua_disable 0->1 while armed && tcp=0 REFUSED
#   E: disarm (enforce=0) always ACCEPTED
#
# NOT covered here (not built yet): the Option-A MOUNT-TIME refusal of a
# clustered RW mount under (fua_disable=1, tcp=0) once defaults flip — that
# lands with the default-on change itself.
#
# Snapshot/restore: original values restored on exit (trap), in a safe order
# (disarm first).  NEVER run while an armed campaign/board is in flight —
# this test deliberately toggles the enforcement knobs.
#
# Usage: tests/f2_config_matrix.sh [node] (default test5)
# Budget: ~10s (a dozen bounded ssh param pokes on one node); bound 60s.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"
NODE=${1:-test5}
SSH=tools/mxfs_sshpass.sh
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_f2cfg_$NODE
mkdir -p "$OUT"
# value_now_into (tests/lib/rig.sh): every knob read or set a verdict is
# taken from crosses the boundary in the parent shell first; a failed ssh is
# an ABORT, never an empty value that fails to equal OK
. "$(dirname "$0")/lib/rig.sh"
P=/sys/module/mxfs/parameters
fails=0

pget() { timeout 10 $SSH "$NODE" "cat $P/$1" 2>/dev/null | tr -dc '0-9-'; }
pset() { timeout 10 $SSH "$NODE" "echo $2 > $P/$1 2>/dev/null && echo OK || echo REFUSED" 2>/dev/null | grep -E 'OK|REFUSED' | head -1; }
ck() { # ck <name> <got> <want>
    if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi
}

orig_enf=$(pget foreign_replay_token_enforce)
orig_tcp=$(pget target_cache_protected)
orig_fua=$(pget fua_disable)
echo "=== f2_config_matrix node=$NODE orig enf=$orig_enf tcp=$orig_tcp fua=$orig_fua $(date -u +%FT%TZ) ==="
if [ -z "$orig_enf" ] || [ -z "$orig_tcp" ] || [ -z "$orig_fua" ]; then
    echo "ABORT: cannot read params on $NODE (module loaded?)"; exit 2
fi
restore() {
    pset foreign_replay_token_enforce 0 >/dev/null
    pset fua_disable "$orig_fua" >/dev/null
    pset target_cache_protected "$orig_tcp" >/dev/null
    [ "$orig_enf" = "1" ] && pset foreign_replay_token_enforce 1 >/dev/null
    echo "restored enf=$(pget foreign_replay_token_enforce) tcp=$(pget target_cache_protected) fua=$(pget fua_disable)"
}
trap restore EXIT

# Start from disarmed baseline
pset foreign_replay_token_enforce 0 >/dev/null

# Case A: fua=1 tcp=0 -> arm refused
pset fua_disable 1 >/dev/null; pset target_cache_protected 0 >/dev/null
value_now_into psetv1 "$NODE" 10 "$OUT/pset_1.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 1 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "A arm refused under (fua=1,tcp=0)" "$psetv1" "REFUSED"
value_now_into pgetv1 "$NODE" 10 "$OUT/pget_1.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/foreign_replay_token_enforce"
ck "A enforce stayed 0" "$pgetv1" "0"

# Case B: tcp=1 -> arm accepted
pset target_cache_protected 1 >/dev/null
value_now_into psetv2 "$NODE" 10 "$OUT/pset_2.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 1 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "B arm accepted under (fua=1,tcp=1)" "$psetv2" "OK"
value_now_into pgetv2 "$NODE" 10 "$OUT/pget_2.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/foreign_replay_token_enforce"
ck "B enforce reads 1" "$pgetv2" "1"

# Case C: withdraw tcp while armed -> refused
value_now_into psetv3 "$NODE" 10 "$OUT/pset_3.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 0 > $P/target_cache_protected 2>/dev/null && echo OK || echo REFUSED"
ck "C tcp withdrawal refused while armed" "$psetv3" "REFUSED"
value_now_into pgetv3 "$NODE" 10 "$OUT/pget_3.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/target_cache_protected"
ck "C tcp still 1" "$pgetv3" "1"

# Case E1: disarm always allowed
value_now_into psetv4 "$NODE" 10 "$OUT/pset_4.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 0 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "E disarm accepted" "$psetv4" "OK"

# Case D: crash-durable domain (fua=0, tcp=0) -> arm accepted; then
# fua_disable 0->1 while armed && tcp=0 -> refused
pset fua_disable 0 >/dev/null; pset target_cache_protected 0 >/dev/null
value_now_into psetv5 "$NODE" 10 "$OUT/pset_5.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 1 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "D arm accepted under (fua=0,tcp=0)" "$psetv5" "OK"
value_now_into psetv6 "$NODE" 10 "$OUT/pset_6.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 1 > $P/fua_disable 2>/dev/null && echo OK || echo REFUSED"
ck "D fua_disable 0->1 refused while armed && tcp=0" "$psetv6" "REFUSED"
value_now_into pgetv4 "$NODE" 10 "$OUT/pget_4.txt" '^-?[0-9]+$' "a knob read on $NODE" "cat $P/fua_disable"
ck "D fua still 0" "$pgetv4" "0"

# Case E2: disarm again
value_now_into psetv7 "$NODE" 10 "$OUT/pset_7.txt" '^(OK|REFUSED)$' "a knob set on $NODE" "echo 0 > $P/foreign_replay_token_enforce 2>/dev/null && echo OK || echo REFUSED"
ck "E disarm accepted (2)" "$psetv7" "OK"

if [ "$fails" -eq 0 ]; then echo "VERDICT PASS: F2 config matrix 10/10"; else echo "VERDICT FAIL: $fails assertion(s)"; fi
exit $fails
