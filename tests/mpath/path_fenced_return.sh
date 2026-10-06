#!/bin/bash
# tests/mpath/path_fenced_return.sh — F6 of docs/mpath-verification.md: a
# node is fenced while one of its paths is down, and the path comes back.
#
# A fence removes a node's key from the target, and a key is held per path.
# The path that was down when the fence was issued is the one a fence could
# miss, and the one a node could wrongly put its key back on when it returns.
#
#   1. every node runs the load
#   2. the victim's (last node's) path a is taken down and multipathd fails it
#   3. the victim is frozen (virsh suspend): it stops heartbeating without
#      knowing it, with its mount, its queued I/O and its sessions intact
#   4. the others declare it dead and fence it: the target then holds only
#      their registrations
#   5. the victim's path a is restored, and the victim is thawed
#   6. for 40 s the target is sampled: the victim's key must appear on
#      NEITHER path
#   7. the victim must have stopped by itself, a write on it must be refused
#      and return, and nothing it wrote after the fence may be acknowledged
#   8. the victim unmounts, mounts again as a new incarnation and runs the load
#
# What a PASS claims: the victim's registrations left the target within 110 s
# of the freeze; the others resumed within 60 s of that, their longest stall
# under 120 s with no error; after the thaw the target held exactly the
# others' registrations at every sample; the victim's kernel log shows its
# authority closed or the filesystem shut down, its probe write failed and
# returned, its load ended when told, and no fsynced write it started after
# the fence was acknowledged; it unmounted and remounted (rc 0, 0); no other
# node shut down or withdrew; no double grant; at the end every node is
# registered on both paths, and every acknowledged file, the victim's from
# before the freeze included, reads back with its checksum from another node.
#
# derived time budget: warm-up 20 s + path failure 16-20 s + death window
# 62 s + fence and replay 15-25 s + hold 40 s + stop ~10 s + remount ~20 s +
# load 20 s + stop, verify and audit ~10 s per node: about 260 s at 2 nodes.
set -u
ROW=path_fenced_return
. "$(dirname "$0")/lib.sh"
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_DEATH=1
PF_STOPS=$V
OTHERS=$(for n in $NODES; do [ "$n" = "$V" ] || printf '%s ' "$n"; done)
pf_start_gate
pf_load_start
trap 'timeout 30 $VIRSH resume "$V" >/dev/null 2>&1; stop_loads "$NODES"; links_all_up; kmsg_stop' EXIT

# 2. one path down
link "$V" a down
s=$SECONDS; one=0
while [ $((SECONDS - s)) -lt 40 ]; do
    state "$V" a_failed
    [ "$(usable "$OUT/state_${V}_a_failed.txt")" = 1 ] && { one=1; break; }
    sleep 2
done
ck "multipathd failed $V's path a (within 40 s)" "$one" 1

# 3. frozen
T0=$(now_ms)
timeout 30 $VIRSH suspend "$V" >/dev/null 2>&1
ck "$V is frozen" "$($VIRSH domstate "$V" 2>/dev/null | head -1)" paused
echo "  INFO $V frozen at $(date -u +%T) with its path a down"

# 4. fenced
tf=$(pf_wait_keys $(( 2 * (N - 1) )) 110 fenced)
cklt "the others fenced $V: its registrations left the target, seconds after the freeze" "$tf" 111
TF=$(now_ms)
rr=$(pf_resumed "$TF" 60 "$OTHERS")
cklt "every other node's load completed operations again after the fence, seconds" "$rr" 61

# 5. the dead path returns, then the node.  The frozen node's clock stops
# with it, so "after the fence" on its own log is "after the last operation
# it logged before it was frozen" (its log cannot have moved since).
sleep 2
TV=$(( $(pf_last_op_ms "$V") + 1000 ))
link "$V" a up
timeout 30 $VIRSH resume "$V" >/dev/null 2>&1
TT=$(now_ms)
ck "$V is running again" "$($VIRSH domstate "$V" 2>/dev/null | head -1)" running
echo "  INFO $V thawed at $(date -u +%T) with its path a restored"

# 6. refused on both paths
pf_keys_hold $(( 2 * (N - 1) )) 40 after_thaw
state "$V" after_thaw
echo "  INFO $V's paths 40 s after the thaw: $(grep -a '^PATH' "$OUT/state_${V}_after_thaw.txt" | sed 's/reads=.*//' | tr '\n' ' ')"
PF_BOUND_MS=$DEATH_BOUND_MS pf_window fence "$T0" "$(now_ms)" "$OTHERS"

# 7. it stopped
pf_victim_stopped fenced "$TV"

# 8. a new incarnation
pf_remount "$V" rejoin
[ "$fails" = 0 ] || { finish FAIL "stage=rejoin"; exit 1; }
ru=$(wait_usable "$V" rejoined_paths)
cklt "$V is on 2 usable paths again, seconds" "$ru" 61
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
pf_done "victim=$V fenced_s=$tf resumed_s=$rr other_stall_ms=$(stall_of fence "$W")"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
