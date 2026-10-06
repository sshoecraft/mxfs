#!/bin/bash
# tests/mpath/path_all_lost.sh — F7 of docs/mpath-verification.md: one node
# loses every path for longer than the death window.
#
# Multipath can do nothing for a node with no path left.  What is tested is
# containment: that node stops, it does not hang holding its locks; the
# others fence it and go on; and whatever it had queued is refused when its
# paths return.
#
#   1. every node runs the load
#   2. both paths of the victim (last node) are taken down
#   3. multipath queues for no_path_retry intervals and then fails the I/O;
#      the victim's authority lease ends; the others declare it dead and
#      fence it: the target then holds only their registrations
#   4. both paths are restored and multipathd reinstates them
#   5. for 30 s the target is sampled: the victim's key must not come back
#   6. the victim must have stopped by itself, a write on it must be refused
#      and return, and nothing it wrote after the fence may be acknowledged
#   7. the victim unmounts, mounts again as a new incarnation and runs the load
#
# What a PASS claims: the victim's registrations left the target within 110 s
# of the paths going down; the others resumed within 60 s of that, their
# longest stall under 120 s with no error; after the paths returned the
# target held exactly the others' registrations at every sample; the victim's
# kernel log shows its authority closed or the filesystem shut down, its
# probe write failed and returned, its load ended when told, and no fsynced
# write it started after the fence was acknowledged; it unmounted and
# remounted (rc 0, 0); no other node shut down or withdrew; no double grant;
# at the end every node is registered on both paths, and every acknowledged
# file, the victim's from before the loss included, reads back with its
# checksum from another node.
#
# derived time budget: warm-up 20 s + death window 62 s + fence and replay
# 15-25 s + reinstatement 15-20 s + hold 30 s + stop ~10 s + remount ~20 s +
# load 20 s + stop, verify and audit ~10 s per node: about 240 s at 2 nodes.
set -u
ROW=path_all_lost
. "$(dirname "$0")/lib.sh"
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_DEATH=1
PF_STOPS=$V
OTHERS=$(for n in $NODES; do [ "$n" = "$V" ] || printf '%s ' "$n"; done)
pf_start_gate
pf_load_start

# 2. no path left
T0=$(now_ms)
link "$V" a down
link "$V" b down
echo "  INFO both paths of $V DOWN at $(date -u +%T)"

# 3. fenced
tf=$(pf_wait_keys $(( 2 * (N - 1) )) 110 fenced)
cklt "the others fenced $V: its registrations left the target, seconds after its paths went down" "$tf" 111
TF=$(now_ms)
rr=$(pf_resumed "$TF" 60 "$OTHERS")
cklt "every other node's load completed operations again after the fence, seconds" "$rr" 61

# 4. the paths return
link "$V" a up
link "$V" b up
ru=$(wait_usable "$V" paths_back)
cklt "multipathd reinstated both of $V's paths, seconds" "$ru" 61

# 5. nothing comes back with them
pf_keys_hold $(( 2 * (N - 1) )) 30 after_return
PF_BOUND_MS=$DEATH_BOUND_MS pf_window loss "$T0" "$(now_ms)" "$OTHERS"

# 6. it stopped
pf_victim_stopped lost "$TF"

# 7. a new incarnation
pf_remount "$V" rejoin
[ "$fails" = 0 ] || { finish FAIL "stage=rejoin"; exit 1; }
pf_load_start "$V"
keys rejoined
ck "every node is registered on both paths once $V is back ($(( 2 * N )))" "$(grep -c . "$OUT/keys_rejoined.txt")" "$(( 2 * N ))"

pf_load_stop "$OTHERS"
stop_loads "$V"
i=0; while [ $i -lt 45 ] && ! grep -aq '^PATHLOAD ' "$OUT/load_$V/run.out" 2>/dev/null; do sleep 1; i=$((i + 1)); done
pl=$(grep -a '^PATHLOAD ' "$OUT/load_$V/run.out" 2>/dev/null | tail -1)
echo "  INFO $V after rejoining: ${pl:-no PATHLOAD line}"
[ -n "$pl" ] || pf_stuck_capture "$V"
ck "$V's load after rejoining completed operations and returned no error" "$(echo "$pl" | grep -c ' err=0 ')" 1
ck "$V: the mutual-exclusion witness saw no double grant after rejoining" "$(sed -n 's/.*double_grant=\([0-9]*\).*/\1/p' <<<"$pl")" 0
PF_VERIFY_ON=$V pf_verify "$OTHERS"
PF_VERIFY_ON=$W pf_verify "$V"
PF_NO_KEYCMP=1 pf_health
pf_done "victim=$V fenced_s=$tf resumed_s=$rr reinstate_s=$ru other_stall_ms=$(stall_of loss "$W")"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
