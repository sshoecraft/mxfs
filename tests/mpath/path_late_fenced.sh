#!/bin/bash
# tests/mpath/path_late_fenced.sh — a node is fenced in the middle of
# registering a path that came back, and the registration is undone.
#
# A path that was down when a node mounted is registered when it returns
# (docs/mpath-verification.md, "How a node's registrations follow its
# paths").  That is the one registration made after a mount, so it is the one
# that can follow a fence: the node reads the key table, finds its key still
# there, and registers the late path — and a peer may have preempted the key
# in between.  A fenced node whose key is back on a path can write to a
# journal its peers have replayed.  The node therefore reads the table again
# after registering and unregisters the path at once unless its key is still
# held by another of its paths.  This row makes the fence land in exactly
# that gap and checks the registration does not survive it.
#
#   1. the others run the load throughout; the victim (last node) unmounts,
#      its path a is taken down, and it mounts on path b alone and runs the
#      load
#   2. the victim is told to hold for 20 s between reading the key table and
#      registering a late path (module parameter dbg_pr_fill_pause_ms, test
#      only), and path a is restored: its reservation worker finds the path,
#      reads the table and holds
#   3. inside the hold, the first node preempts the victim's key
#      (sg_persist, PREEMPT): the victim is fenced
#   4. the hold ends: the victim registers path a, finds its key on no other
#      path, unregisters path a and treats itself as fenced
#   5. the victim unmounts, mounts again and runs the load
#
# What a PASS claims: the victim's kernel log shows the hold, then the
# registration undone (P-PR-PATH-FILL-UNDONE) and no path filled; from the
# preempt until the victim remounts the target holds exactly the others'
# registrations at every sample taken after the undo; the victim stopped by
# itself, a write on it failed and returned, and no fsynced write it started
# after the preempt was acknowledged; the others resumed (their stall across
# the victim's recovery under 120 s, no error); the victim remounted (rc 0, 0)
# and its load ran without error; no double grant; every acknowledged file
# reads back with its checksum from another node; every node is registered on
# both paths at the end.
#
# derived time budget: warm-up 20 s + unmount 5 s + path failure 16-20 s +
# mount ~8 s + load 20 s + relogin and hold 20-35 s + undo, withdrawal and the
# others' recovery of the victim (up to the death window, 62 s, + replay) +
# hold check 15 s + remount ~20 s + load 20 s + stop, verify and audit ~10 s
# per node: about 280 s at 2 nodes.
set -u
ROW=path_late_fenced
. "$(dirname "$0")/lib.sh"
PAUSE_MS=20000
main() {
[ "$N" -ge 2 ] || { why="needs 2 nodes, got $N"; finish FAIL "nodes=$N"; exit 1; }
PF_LEAVES=1
PF_DEATH=1
PF_STOPS=$V
OTHERS=$(for n in $NODES; do [ "$n" = "$V" ] || printf '%s ' "$n"; done)
LOAD_NODES=$OTHERS
pf_start_gate
pf_load_start
klog() {  # <pattern> -> the victim's kernel-log lines since the row's mark that match
    rs 20 "$V" "sed -n '/$PFMARK/,\$p' $KFILE 2>/dev/null | grep -a '$1' | cut -c1-400"
}

# 1. the victim joins on path b alone
measure "$V" 70 "$OUT/umount_first.txt" '^UMOUNT_RC=[0-9]+$' "the victim's unmount" "timeout 60 umount $MNT; echo UMOUNT_RC=\$?"
ck "$V unmounted" "$(grep -a '^UMOUNT_RC=' "$OUT/umount_first.txt" | head -1)" UMOUNT_RC=0
link "$V" a down
s=$SECONDS; one=0
while [ $((SECONDS - s)) -lt 40 ]; do
    state "$V" a_failed
    [ "$(usable "$OUT/state_${V}_a_failed.txt")" = 1 ] && { one=1; break; }
    sleep 2
done
ck "multipathd failed $V's path a (within 40 s)" "$one" 1
measure "$V" 70 "$OUT/mount_one.txt" '^MOUNT_RC=[0-9]+$' "the victim's mount on one path" "timeout 60 mount -t mxfs $DEV $MNT; echo MOUNT_RC=\$?"
ck "$V mounted on path b alone" "$(grep -a '^MOUNT_RC=' "$OUT/mount_one.txt" | head -1)" MOUNT_RC=0
[ "$fails" = 0 ] || { finish FAIL "stage=degraded-mount"; exit 1; }
KV=$(klog 'P-PR-PATHS-REGISTERED' | tail -1 | sed -n 's/.* key=\(0x[0-9a-f]*\) .*/\1/p')
ck "$V's reservation key is known from its mount (registered on 1 of 2 paths)" "$(klog 'P-PR-PATHS-REGISTERED' | tail -1 | grep -c "key=$KV .*registered=1 unreachable=1")" 1
[ -n "$KV" ] || { finish FAIL "stage=key"; exit 1; }
pf_load_start "$V"

# 2. the late path appears, and the victim holds in the gap
rs 15 "$V" "echo $PAUSE_MS > /sys/module/mxfs/parameters/dbg_pr_fill_pause_ms" >/dev/null
link "$V" a up
s=$SECONDS; held=0
while [ $((SECONDS - s)) -lt 60 ]; do
    [ "$(klog 'P-DBG-PR-FILL-PAUSE' | grep -c .)" -ge 1 ] && { held=1; break; }
    sleep 1
done
ck "$V read the key table for its late path and is holding before the REGISTER (within 60 s)" "$held" 1
[ "$held" = 1 ] || { finish FAIL "stage=hold"; exit 1; }

# 3. fenced inside the gap: PREEMPT of the victim's key from the first node.
# Its own key is whichever registered key the target accepts as the sender's.
keys before_preempt
TF=$(now_ms)
pre=""
for k in $(sort -u "$OUT/keys_before_preempt.txt"); do
    [ "$k" = "$KV" ] && continue
    r=$(rsx 30 "$W" "sg_persist -n --out --preempt --param-rk=$k --param-sark=$KV --prout-type=7 \$(awk '\$2 == \"$MNT\" && \$3 == \"mxfs\" {print \$1}' /proc/mounts | head -1) >/dev/null 2>&1; echo PREEMPT_RC=\$?" | grep -a '^PREEMPT_RC=' | tail -1)
    pre="$pre $k:$r"
    [ "$r" = PREEMPT_RC=0 ] && break
done
echo "  INFO $W preempted $V's key $KV at $(date -u +%T):$pre"
ck "$W's PREEMPT of $V's key was accepted" "$(echo "$pre" | grep -c 'PREEMPT_RC=0')" 1
keys after_preempt
ck "the target holds no registration of $V's key right after the preempt" "$(grep -c "^$KV\$" "$OUT/keys_after_preempt.txt")" 0

# 4. the hold ends: the late registration must not survive
s=$SECONDS; undone=0
while [ $((SECONDS - s)) -lt $((PAUSE_MS / 1000 + 20)) ]; do
    [ "$(klog 'P-PR-PATH-FILL-UNDONE\|P-PR-PATH-FILL-KEY-GONE' | grep -c .)" -ge 1 ] && { undone=1; break; }
    sleep 1
done
klog 'P-PR-PATH-FILL\|P-PR-FILL-FENCED\|P-DBG-PR-FILL' > "$OUT/fill_$V.txt"
echo "  INFO $V: $(tail -2 "$OUT/fill_$V.txt" | cut -c1-330 | tr '\n' ' ')"
ck "$V undid the registration it made after the fence (P-PR-PATH-FILL-UNDONE)" "$(grep -ac 'P-PR-PATH-FILL-UNDONE' "$OUT/fill_$V.txt")" 1
ck "$V did not keep a late path registered (no P-PR-PATH-FILLED)" "$(grep -ac 'P-PR-PATH-FILLED' "$OUT/fill_$V.txt")" 0
pf_keys_hold $(( 2 * (N - 1) )) 15 after_undo
rr=$(pf_resumed "$(now_ms)" 100 "$OTHERS")
cklt "every other node's load completed operations again once $V was recovered, seconds" "$rr" 101
PF_BOUND_MS=$DEATH_BOUND_MS pf_window fence "$TF" "$(now_ms)" "$OTHERS"
pf_victim_stopped fenced "$TF"

# 5. a new incarnation
ru=$(wait_usable "$V" paths_back)
cklt "$V is on 2 usable paths, seconds" "$ru" 61
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
pf_done "victim=$V key=$KV resumed_s=$rr other_stall_ms=$(stall_of fence "$W")"
}
main 2>&1 | tee "$OUT/row.log"
exit "${PIPESTATUS[0]}"
