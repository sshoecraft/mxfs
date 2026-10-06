#!/bin/bash
# tests/mpath/path_fence_degraded.sh — F5 of docs/mpath-verification.md: a
# node dies while every survivor is down to one path.
#
# Fencing is a persistent-reservation command and the replay of the dead
# node's journal is I/O; both have to work for a survivor that has lost a
# path, and the fence has to remove the dead node's key from BOTH of its
# paths although the survivor that issues it can reach the target on one.
#
#   1. every node runs the load
#   2. network a is taken down on every survivor (all nodes but the victim,
#      which is the last); multipathd fails those paths
#   3. the victim is killed (virsh destroy), mid-load
#   4. the survivors declare it dead, fence it and replay its journal: the
#      target then holds only the survivors' registrations
#   5. every file the victim had acknowledged reads back with its checksum on
#      a survivor, through that survivor's one path
#   6. network a is restored; the victim is started, logs in on its paths,
#      mounts, and runs the load again
#
# What a PASS claims: the victim's registrations left the target within 110 s
# of the kill (death window 62 s + fence); every survivor's load completed
# operations again within 60 s of that and its longest stall across the death
# is under 120 s with no operation returning an error; between the kill and
# the end of the read-back each survivor's remaining path carried writes and
# the removed one none; the victim's acknowledged files are all intact; the
# victim rejoined (mount rc 0) and its load ran; no survivor shut down or
# withdrew; no double grant; at the end every node is registered on both
# paths and every acknowledged file reads back from another node.
#
# derived time budget: warm-up 20 s + path failure 16-20 s + death window
# 62 s + fence and replay 15-25 s + read-back ~10 s + reinstatement 15-20 s +
# boot ~40 s + rejoin ~15 s + load 20 s + stop, verify and audit ~10 s per
# node: about 270 s at 2 nodes.
set -u
ROW=path_fence_degraded
. "$(dirname "$0")/lib.sh"
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_DEATH=1
OTHERS=$(for n in $NODES; do [ "$n" = "$V" ] || printf '%s ' "$n"; done)
pf_start_gate
pf_load_start

# 2. the survivors are on one path
links a down "$OTHERS"
s=$SECONDS; one=0
while [ $((SECONDS - s)) -lt 40 ]; do
    states a_failed "$OTHERS"; one=1
    for n in $OTHERS; do [ "$(usable "$OUT/state_${n}_a_failed.txt")" = 1 ] || one=0; done
    [ "$one" = 1 ] && break
    sleep 2
done
ck "multipathd failed path a on every survivor (within 40 s)" "$one" 1

# 3. the victim dies
T0=$(now_ms)
timeout 60 $VIRSH destroy "$V" >/dev/null 2>&1
echo "  INFO $V killed at $(date -u +%T) with every survivor on one path"
LOAD_NODES=$OTHERS
states death_mid "$OTHERS"

# 4. fenced and replayed
tf=$(pf_wait_keys $(( 2 * (N - 1) )) 110 fenced)
cklt "the survivors fenced $V: its registrations left the target, seconds after the kill" "$tf" 111
TF=$(now_ms)
rr=$(pf_resumed "$TF" 60 "$OTHERS")
cklt "every survivor's load completed operations again after the fence, seconds" "$rr" 61

# 5. what the victim had acknowledged, read through one path
PF_VERIFY_ON=$W pf_verify "$V"
# how often the reader met a number it still cached as an earlier incarnation
# of another type, and replaced it at the lookup (the check a sole survivor
# used to skip: those names then opened as what the number used to be)
echo "  INFO $W while reading $V's files: $(rs 20 "$W" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -ac 'INODE-REUSE-EVICT'" | grep -aE '^[0-9]+$' | tail -1) stale shell(s) of another type replaced at lookup (the line is rate-limited: a floor, not a count)"
states death_end "$OTHERS"
T1=$(now_ms)
for n in $OTHERS; do pf_carried "$n" death b a; done
PF_BOUND_MS=$DEATH_BOUND_MS pf_window death "$T0" "$T1" "$OTHERS"

# 6. whole again
links a up "$OTHERS"
ra=$(wait_usable_all a_back 60 "$OTHERS")
cklt "every survivor reinstated path a, seconds" "$ra" 61
pf_boot_rejoin "$V" rejoin
[ "$fails" = 0 ] || { finish FAIL "stage=rejoin"; exit 1; }
LOAD_NODES=$NODES
pf_load_start "$V"
keys rejoined
ck "every node is registered on both paths once $V is back ($(( 2 * N )))" "$(grep -c . "$OUT/keys_rejoined.txt")" "$(( 2 * N ))"

pf_load_stop
acked=0
pf_verify
PF_NO_KEYCMP=1 pf_health
pf_done "victim=$V fenced_s=$tf resumed_s=$rr reinstate_s=$ra survivor_stall_ms=$(stall_of death "$W")"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
