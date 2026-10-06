#!/bin/bash
# tests/mpath/path_flap.sh — F4 of docs/mpath-verification.md: a path that will
# not stay up or down.  The victim's path on network a is taken down and
# brought back FLAPS times, each state held FLAP_S seconds: shorter than the
# time multipathd takes to settle a path either way, so failovers and
# reinstatements start before the previous one has finished.
#
# Host-coordinated, on a mounted cluster under tests/mpath/pathload.py on every
# node.
#
# What a PASS claims: across the whole flapping window no operation errored
# on any node, every node's longest stall is under the bound of
# tools/mpath_settings.sh, and every node kept completing operations; when the
# flapping stops the victim is back on 2 usable paths within 60 s; no double
# grant; no node left, shut down or was fenced; the target's reservation keys
# unchanged; every acknowledged file read back intact from another node.
#
# derived time budget: warm-up 20 s + FLAPS x 2 x FLAP_S (10 x 2 x 4 = 80 s)
# + settle (bound 60 s) + 30 s of load on the settled paths + stop, verify and
# audit ~6 s per node.  Typical at 2 nodes ~170 s.
set -u
ROW=path_flap
. "$(dirname "$0")/lib.sh"
FLAPS=${PF_FLAPS:-10}
FLAP_S=${PF_FLAP_S:-4}
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
pf_start_gate
pf_load_start

T0=$(now_ms)
echo "  INFO F4: $V path a flapping $FLAPS times, ${FLAP_S}s down / ${FLAP_S}s up, from $(date -u +%T)"
for i in $(seq 1 "$FLAPS"); do
    link "$V" a down; sleep "$FLAP_S"
    link "$V" a up;   sleep "$FLAP_S"
done
T1=$(now_ms)
pf_window F4 "$T0" "$T1"
r=$(wait_usable "$V" F4_settled)
cklt "F4: once the flapping stops $V is back on 2 usable paths, seconds" "$r" 61
T2=$(now_ms)
sleep 30
pf_window F4_after "$T2" "$(now_ms)"

pf_load_stop
pf_verify
pf_health
pf_done "victim=$V flaps=$FLAPS flap_s=$FLAP_S stall_ms=$(stall_of F4 "$V") settle_s=$r"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
